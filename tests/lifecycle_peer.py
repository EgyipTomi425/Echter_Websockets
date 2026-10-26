"""Local TLS regressions for buffered upgrades, pending sends and final messages."""
import asyncio
import base64
import hashlib
import os
import ssl
import subprocess
import sys
import tempfile

from loopback_wss import compress_message, encode_frame, read_frame


async def run(client, openssl):
    with tempfile.TemporaryDirectory(prefix="echter-lifecycle-") as directory:
        certificate = os.path.join(directory, "cert.pem")
        private_key = os.path.join(directory, "key.pem")
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-subj", "/CN=localhost",
            "-addext", "subjectAltName=IP:127.0.0.1",
            "-keyout", private_key, "-out", certificate,
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certificate, private_key)
        tasks = set()

        async def serve(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                mode = request.split(b" ")[1].strip(b"/").decode("ascii")
                headers = dict(line.split(b": ", 1) for line in request.split(b"\r\n")[1:]
                    if b": " in line)
                accept = base64.b64encode(hashlib.sha1(headers[b"Sec-WebSocket-Key"]
                    + b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest())
                compressed = mode in ("compressed", "negotiated_plain")
                response = (b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                    b"Connection: Upgrade\r\nSec-WebSocket-Accept: " + accept + b"\r\n")
                if compressed:
                    response += b"Sec-WebSocket-Extensions: permessage-deflate\r\n"
                if mode == "largeheader":
                    response += b"X-Padding: " + b"a" * 5000 + b"\r\n"
                writer.write(response + b"\r\n")
                await writer.drain()
                if mode == "largeheader":
                    # No socket traffic may rescue an upgrade stalled in SSL's buffer.
                    await asyncio.sleep(3)
                payload = b"last message"
                if mode == "early":
                    opcode, payload, _, _ = await asyncio.wait_for(read_frame(reader), 3)
                    if opcode != 1 or payload != b"early":
                        raise RuntimeError("pending send was lost or corrupted")
                wire_compressed = mode == "compressed"
                if wire_compressed:
                    payload = compress_message(payload)
                # A single TLS write makes the message and close arrive together.
                writer.write(encode_frame(1, payload, compressed=wire_compressed)
                    + encode_frame(8, b"\x03\xe8"))
                await writer.drain()
                opcode, _, _, _ = await asyncio.wait_for(read_frame(reader), 3)
                if opcode != 8:
                    raise RuntimeError("expected close reply")
            finally:
                writer.close()
                try:
                    await writer.wait_closed()
                except (OSError, ssl.SSLError):
                    # The WebSocket close reply was checked above; TCP/TLS
                    # teardown can race with the client's process exit.
                    pass

        def accept(reader, writer):
            task = asyncio.create_task(serve(reader, writer))
            tasks.add(task)

        server = await asyncio.start_server(accept, "127.0.0.1", 0, ssl=context)
        environment = dict(os.environ, SSL_CERT_FILE=certificate)
        try:
            port = server.sockets[0].getsockname()[1]
            for mode in ("plain", "compressed", "negotiated_plain", "early", "largeheader"):
                process = await asyncio.create_subprocess_exec(client,
                    f"wss://127.0.0.1:{port}/{mode}", mode, env=environment)
                try:
                    result = await asyncio.wait_for(process.wait(), 8)
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    raise RuntimeError(f"{mode}: client timed out")
                if result:
                    raise RuntimeError(f"{mode}: client exited with {result}")
            await asyncio.gather(*tasks)
        finally:
            server.close()
            await server.wait_closed()
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


if __name__ == "__main__":
    asyncio.run(run(*sys.argv[1:]))
