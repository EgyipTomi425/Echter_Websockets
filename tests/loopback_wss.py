import asyncio
import base64
import hashlib
import os
import random
import resource
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import urllib.parse


FLOOD_CLIENT_ID = 50_001
CANCEL_CLIENT_ID = 50_002
NO_RESPONSE_CLIENT_ID = 50_003


async def read_exact(reader, size):
    try:
        return await reader.readexactly(size)
    except asyncio.IncompleteReadError as error:
        raise EOFError("peer disconnected") from error


async def read_frame(reader):
    header = await read_exact(reader, 2)
    first, second = header
    length = second & 0x7f
    if length == 126:
        length = struct.unpack("!H", await read_exact(reader, 2))[0]
    elif length == 127:
        length = struct.unpack("!Q", await read_exact(reader, 8))[0]
    mask = await read_exact(reader, 4) if second & 0x80 else b""
    payload = await read_exact(reader, length)
    if mask:
        payload = bytes(value ^ mask[index % 4] for index, value in enumerate(payload))
    return first & 0x0f, payload


def encode_frame(opcode, payload):
    first = 0x80 | opcode
    length = len(payload)
    if length < 126:
        header = bytes((first, length))
    elif length <= 0xffff:
        header = bytes((first, 126)) + struct.pack("!H", length)
    else:
        header = bytes((first, 127)) + struct.pack("!Q", length)
    return header + payload


async def write_frame(writer, opcode, payload):
    writer.write(encode_frame(opcode, payload))
    await writer.drain()


async def serve_one(reader, writer, metrics, drop_id):
    try:
        request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        if len(request) > 16 * 1024:
            return
        request_lines = request.decode("ascii").split("\r\n")
        headers = {}
        for line in request_lines[1:]:
            if not line:
                break
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()
        request_target = request_lines[0].split()[1]
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(request_target).query)
        client_id = int(query["client"][0])
        run_id = int(query["run"][0])
        identity = (run_id, client_id)

        if client_id == NO_RESPONSE_CLIENT_ID:
            metrics["no_responses"].add(identity)
            while await reader.read(4096):
                pass
            return

        key = headers["sec-websocket-key"]
        accept = base64.b64encode(hashlib.sha1(
            (key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode("ascii")
        ).digest()).decode("ascii")
        writer.write(( 
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
        ).encode("ascii"))
        await writer.drain()

        if client_id == drop_id:
            metrics["drops"].add(identity)
            peer_socket = writer.get_extra_info("socket")
            if peer_socket is not None:
                peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER,
                    struct.pack("ii", 1, 0))
            writer.transport.abort()
            return

        if client_id == FLOOD_CLIENT_ID:
            peer_socket = writer.get_extra_info("socket")
            if peer_socket is not None:
                peer_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            payload = b"p" * 125
            flood_frames = b"".join(encode_frame(9, payload) for _ in range(512))
            sent = 0
            try:
                writer.write(flood_frames)
                await writer.drain()
                sent = 512
            except (OSError, ssl.SSLError):
                pass
            metrics["control_floods"][identity] = sent
            while await reader.read(1):
                pass
            return

        rng = random.Random(2026 + run_id * 100 + client_id)
        colors = ("red", "green", "blue", "gold")
        for _ in range(2):
            await write_frame(writer, 1,
                f"server-{client_id}-{rng.choice(colors)}".encode("ascii"))
        ping = rng.getrandbits(64).to_bytes(8, "big")
        await write_frame(writer, 9, ping)
        echoes = 0
        received_pong = False

        while True:
            opcode, payload = await read_frame(reader)
            if opcode in (1, 2):
                await write_frame(writer, opcode, payload)
                echoes += 1
            elif opcode == 9:
                await write_frame(writer, 10, payload)
            elif opcode == 8:
                await asyncio.sleep(0.05)
                await write_frame(writer, 8, payload)
                metrics["echoes"][identity] = echoes
                if received_pong:
                    metrics["pongs"].add(identity)
                metrics["closes"].add(identity)
                return
            elif opcode == 10:
                if payload == ping:
                    received_pong = True
                continue
            else:
                return
    except (EOFError, asyncio.LimitOverrunError, OSError, ssl.SSLError,
            asyncio.TimeoutError, KeyError, ValueError):
        return
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except (OSError, ssl.SSLError):
            pass


async def run_peer(client_test, openssl, client_count):
    with tempfile.TemporaryDirectory(prefix="echter-wss-test-") as directory:
        certificate = os.path.join(directory, "test-ca.pem")
        private_key = os.path.join(directory, "test-key.pem")
        subprocess.run([
            openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-days", "1", "-keyout", private_key, "-out", certificate,
            "-subj", "/CN=localhost",
            "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
            "-addext", "basicConstraints=critical,CA:TRUE",
        ], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls_context.load_cert_chain(certificate, private_key)
        metrics = {"drops": set(), "echoes": {}, "pongs": set(), "closes": set(),
            "control_floods": {}, "no_responses": set()}
        peer_tasks = set()
        drop_id = 0

        def accept_client(reader, writer):
            task = asyncio.create_task(serve_one(reader, writer, metrics, drop_id))
            peer_tasks.add(task)
            task.add_done_callback(peer_tasks.discard)

        server = await asyncio.start_server(accept_client, "127.0.0.1", 0,
            ssl=tls_context, limit=16 * 1024,
            backlog=min(client_count + 16, 65_535))
        port = server.sockets[0].getsockname()[1]
        environment = os.environ.copy()
        environment["SSL_CERT_FILE"] = certificate
        try:
            for run_id, host in enumerate(("localhost", "127.0.0.1")):
                drop_id = random.Random(2026 + run_id).randrange(client_count)
                process = await asyncio.create_subprocess_exec(
                    client_test, f"wss://{host}:{port}/?run={run_id}",
                    str(client_count), str(drop_id),
                    env=environment)
                try:
                    return_code = await asyncio.wait_for(process.wait(),
                        timeout=max(25, 20 + client_count / 100))
                except asyncio.TimeoutError:
                    process.kill()
                    await process.wait()
                    raise SystemExit("C++ localhost client test timed out")
                if return_code != 0:
                    raise SystemExit(return_code)

                if peer_tasks:
                    _, pending = await asyncio.wait(tuple(peer_tasks), timeout=2)
                    if pending:
                        raise SystemExit("loopback WSS peer did not observe client shutdown")
                for client_id in range(1, client_count):
                    if client_id == drop_id:
                        continue
                    identity = (run_id, client_id)
                    if metrics["echoes"].get(identity) != 2:
                        raise SystemExit(f"server did not observe two echoes for {identity}")
                    if identity not in metrics["pongs"]:
                        raise SystemExit(f"server did not receive the matching pong for {identity}")
                    if identity not in metrics["closes"]:
                        raise SystemExit(f"server did not observe clean close for {identity}")
                if (run_id, drop_id) not in metrics["drops"]:
                    raise SystemExit("seeded transport drop was not selected")
                if metrics["control_floods"].get((run_id, FLOOD_CLIENT_ID), 0) == 0:
                    raise SystemExit("ping-flood peer sent no control frames")
                if (run_id, NO_RESPONSE_CLIENT_ID) not in metrics["no_responses"]:
                    raise SystemExit("no-response handshake scenario was not selected")
                print(f"localhost WSS run {run_id} via {host}: "
                    f"{client_count - 1} clean sessions, seeded RST on client {drop_id}")
            child_peak_kib = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
            peer_peak_kib = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            print(f"peak RSS: largest child {child_peak_kib} KiB; Python peer {peer_peak_kib} KiB")
        finally:
            server.close()
            await server.wait_closed()
            for task in tuple(peer_tasks):
                task.cancel()
            if peer_tasks:
                await asyncio.gather(*tuple(peer_tasks), return_exceptions=True)


def main():
    if len(sys.argv) not in (3, 4):
        raise SystemExit("usage: loopback_wss.py CLIENT_TEST OPENSSL [CLIENT_COUNT]")
    client_test, openssl = sys.argv[1:3]
    client_count = int(sys.argv[3]) if len(sys.argv) == 4 else 5
    if client_count < 2 or client_count > 50_000:
        raise SystemExit("CLIENT_COUNT must be in range 2..50000")
    soft_limit, _ = resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft_limit != resource.RLIM_INFINITY and soft_limit < client_count + 64:
        raise SystemExit(f"RLIMIT_NOFILE soft limit {soft_limit} is below the requested peer FD count")
    asyncio.run(run_peer(client_test, openssl, client_count))


if __name__ == "__main__":
    main()