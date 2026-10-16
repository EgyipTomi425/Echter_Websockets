# Echter_Websockets

A generic Linux C++23 WSS client built on nonblocking sockets, `io_uring`, and
OpenSSL 3. It is a client-only library; Python is used only as the local test
peer. The project is not tied to GGE.

The named modules are `echter.ws.client` (public client and runtime),
`echter.ws.frame` (RFC 6455 frames, UTF-8, close validation), and
`echter.ws.handshake` (WSS URL and HTTP Upgrade parsing). The empty `echter`
module name is a shared prefix for sibling repositories.

## Build and run

Requirements: CMake 3.28+, Ninja, a C++23 compiler with named-module support,
OpenSSL 3+, and liburing development files (`liburing-dev` on Debian).

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/localtest wss://example.org/path
ctest --test-dir build --output-on-failure
```

The example needs a reachable WSS endpoint and verifies its CA and peer
identity. The test suite creates a temporary local certificate and runs a
Python WSS peer; no external service is used by CTest.

## Client API

One `Client` owns the shared runtime. Each successful `connect()` returns a
copyable, non-owning `Connection` handle immediately; TCP, TLS, and the HTTP
Upgrade happen asynchronously. A callback may capture move-only state.

```cpp
#include <array>
#include <chrono>
#include <cstddef>
#include <span>
#include <string_view>
#include <thread>

import echter.ws.client;

echter::ws::client::Client websocket_client(
	echter::ws::client::ClientOptions{
		.max_connections = 4096,
		.callback_workers = 8,
		.resolver_workers = 4,
	});

auto session = client.connect("wss://example.org/game?room=7",
	echter::ws::client::Callbacks{
		.on_open = [](echter::ws::client::Connection connection) {
			connection.send_message("join");
		},
		.on_message = [](echter::ws::client::Connection,
						 echter::ws::MessageType type,
						 std::span<const std::byte> payload) {
			// The span is valid only for the duration of this callback.
		},
		.on_close = [](echter::ws::client::Connection, std::uint16_t code,
					   std::string_view reason) {},
		.on_error = [](echter::ws::client::Connection, std::string_view error) {},
	},
	echter::ws::client::Timeouts{
		.connect = std::chrono::seconds(10),
		.handshake = std::chrono::seconds(10),
		.idle = std::chrono::seconds(60),
		.close = std::chrono::seconds(5),
	});

// A copied handle can be used from another application thread.
auto sender = session;
const std::array<std::byte, 3> payload{std::byte{1}, std::byte{2}, std::byte{3}};
std::jthread producer([sender, payload] { sender.send_binary(payload); });
```

`send_message()` checks UTF-8 and the 8 MiB message limit. `send_binary()` takes
a byte span and copies it before returning. Both methods enqueue work and never
wait for socket readiness. They throw `std::length_error` if the outgoing-byte
budget or command queue is full. `close()` starts a normal 1000 close handshake
and returns whether the close command was accepted, not whether the handshake
has completed. `Connection::state()` reports `pending`, `open`, `closing`,
`closed`, or `failed` using an atomic snapshot of the current lifecycle. Since
callbacks are queued independently, a callback may observe a later state than
the event that queued it (for example, `on_open` may run after an immediate
transport reset has already marked the connection `failed`). A rejected
`close()` does not change state. Sending on a terminal handle throws `std::logic_error`.
`Client` destruction shuts down owned connections via RAII.
Destroying the last `Client` owner inside one of its callbacks transfers the
join work to a reaper thread, avoiding a worker joining itself. Do not move or
destroy a `Client` concurrently with another call on that same `Client` object.

Callback work is serialized per connection and dispatched across four worker
threads. User callbacks can block a worker; they never execute on the network
reactor, but one slow callback can delay callbacks assigned to that worker and
callbacks for the same connection. Callbacks on different connections can run
concurrently. Unhandled exceptions thrown by callbacks are contained by the
worker. Terminal callback capacity and bytes are reserved separately from
ordinary message callbacks; a normal callback backlog is bounded and overload
fails the affected connection instead of growing without limit. Admission
capacity remains occupied until the connection's queued callbacks have drained,
so rapid reconnect loops cannot overwhelm terminal event delivery.

## Runtime and protocol

The reactor owns one `io_uring` ring and one-shot poll registrations. This
implementation uses `io_uring` to multiplex readiness; OpenSSL then performs
TLS operations on nonblocking sockets in the reactor thread. There is no
sleep-based polling loop. `eventfd` wakes the reactor for commands and deferred
work; one `timerfd` drives connect, handshake, idle, and close deadlines. Ready
work is bounded per reactor turn so a TLS connection with buffered plaintext
cannot monopolize the loop. There is at most one outstanding readiness poll for
a socket. Completion events are matched by connection ID, and poll replacement
is cancelled before the new interest mask is armed.

TLS roots come from OpenSSL's default verification paths. DNS names use SNI and
DNS hostname verification; IPv4/IPv6 URL literals use IP SAN verification.
`SSL_MODE_RELEASE_BUFFERS` reduces idle TLS buffer retention. Before each TLS
I/O operation the OpenSSL error queue is cleared, and `SSL_get_error()` is
called immediately on the same thread as the operation to preserve retry
semantics.

DNS resolution uses four resolver workers and caches successful answers for
one minute, up to 4,096 entries. `getaddrinfo()` itself is blocking and cannot
be forcibly cancelled; shutdown waits for an in-progress resolver call to
return. Connect timeout expiry can close the associated connection, but it
cannot interrupt a resolver thread blocked inside the system resolver.

| Operation | Execution context | Blocking behavior |
| --- | --- | --- |
| `connect()`, `send_message()`, `send_binary()`, `close()` | Calling application thread | Parse/copy/enqueue only; no network wait. Bounded admission may throw. |
| DNS `getaddrinfo()` | One of four resolver workers | Synchronous system call; may block that worker and cannot be forcibly cancelled. |
| TCP/TLS/HTTP Upgrade and frame I/O | One `io_uring` reactor thread | Socket is nonblocking; reactor sleeps in `io_uring_wait_cqe()` until readiness/timer/wakeup. OpenSSL CPU work is synchronous on this thread. |
| User callbacks | One of four callback workers | User code may block its worker; the reactor remains independent. Per-connection callback order is preserved. |
| Client shutdown | Calling thread, or reaper after callback-originated last-owner destruction | Joins workers and waits for in-progress resolver calls to return. |

The URL parser accepts case-insensitive `wss://`, bracketed IPv6 literals,
numeric ports 1..65535, and escaped ASCII request targets. It rejects userinfo,
fragments, whitespace/control characters, malformed percent escapes, URLs over
16 KiB, and request targets over 8 KiB. Upgrade validation requires exactly
HTTP/1.1 status 101, `Upgrade: websocket`, a `Connection` `Upgrade` token, one
correct `Sec-WebSocket-Accept`, and no unsolicited subprotocol or extension.

The frame layer rejects masked server frames, RSV/reserved opcodes,
non-canonical lengths, fragmented or oversized control frames, and frames or
reassembled messages above 8 MiB. Client frames have fresh cryptographic masks.
Text is validated as UTF-8 after message reassembly; close codes and UTF-8
reasons are checked before callback delivery. Ping is answered with a matching
pong, including while a fragmented data message is in progress.

## Resource limits

`ClientOptions::max_connections` defaults to 8,192 and is configurable up to
1,000,000. `callback_workers` and `resolver_workers` are explicit tuning
knobs; when left at zero the runtime auto-selects a safe pool from the host CPU
count. The 50,000-connection integration benchmark sets the connection count
explicitly while leaving the worker pool at the default auto-sized policy. The
terminal callback task and byte budgets scale with this value (two terminal
tasks and 768 accounted bytes per admitted connection), keeping close/error
delivery bounded and observable during a shutdown wave.
`max_outgoing_bytes` defaults to 64 MiB per client.
The command and resolver task queues each cap at 262,144 entries; ordinary
callback tasks cap at 131,072 and terminal callback tasks at 131,072. Ordinary
and terminal callback payload budgets are 64 MiB each, with a fixed per-task
accounting overhead; closure allocations are opaque and therefore not an exact
heap measurement. The DNS cache is capped at 4,096 entries.

## Test and measured scale

The deterministic Python peer creates a temporary local certificate containing
both `DNS:localhost` and `IP:127.0.0.1` SANs. It sends two seeded random server
messages, sends a ping and verifies the matching pong, echoes two client
messages in order, and cleanly closes sessions. A per-run fixed seed selects one connection for an abrupt TCP reset so the C++
test verifies `on_error`. Dedicated query IDs select a 512-ping flood (to verify
bounded automatic-pong memory), a pre-open cancellation, and a TLS connection
that never sends an HTTP Upgrade response (to verify the handshake timeout).
A separate scenario destroys a `Client` in `on_open`. The Python peer uses
`asyncio` streams rather than a thread per connection. The suite runs the same
cases via both `localhost` and `127.0.0.1`.

Run the deterministic test at a selected connection count (the harness accepts
2..50,000):

```sh
python3 tests/loopback_wss.py build/echter_ws_client_integration_tests \
	"$(command -v openssl)" 1000
```

Before large runs, check the process FD limit (`ulimit -n`) and available memory.
The peer rejects a requested run when its soft FD limit is below the requested
connection count plus test overhead. The C++ runtime also needs one socket per
connection and memory for TLS state, callback queues, and test bookkeeping. Use
staged counts and treat the first resource failure as the host's measured limit;
the configured API ceiling is not a promise that every host can sustain it.
The largest completed run on the current host was 5,000 clients, with both
`localhost` and `127.0.0.1` passes (4,999 clean sessions per pass). Reported
peak RSS was 1,669,008 KiB for the largest child and 2,328,976 KiB for the
Python peer. These are separate process high-water marks, not a combined total.
The host preflight showed a 524,288 FD soft limit but only about 4.7 GiB of
available memory, so larger runs were not attempted. Benchmark results are
machine- and build-dependent; no 50,000-client result is claimed until that
count has completed successfully.

The GCC 14.2 build and full CTest pass. GCC 14.2 crashes internally while
generating sanitizer-instrumented named modules (`cp/module.cc`); the full
ASan+UBSan build and CTest pass with Clang 19.1.7. ThreadSanitizer was not
run.

## Implementation map

- `Client::connect()` parses the WSS URI, reserves an active slot, posts a start
	command, and returns a weak `Connection` handle. `ClientOptions` supplies the
	active-connection and outgoing-byte limits.
- `Runtime::post()` bounds cross-thread commands and send bytes. `drain_commands()`
	creates independent `SocketConnection` state machines; `resolve_loop()` runs
	`getaddrinfo()` on the fixed resolver pool and populates the one-minute cache.
- `connect_next()` tries each DNS address nonblockingly. `begin_tls()` configures
	CA verification, DNS SNI/hostname checks or IP SAN checks, and begins TLS.
- `arm_connection()` installs one-shot `io_uring` poll readiness. CQEs route
	through `process_completion()` by connection ID. `drive_impl()` performs
	nonblocking TLS and WebSocket handshake/read/write transitions. Its bounded
	16-iteration quantum uses `defer_drive()` for remaining OpenSSL-buffered work.
- `SocketConnection` owns each socket, SSL session, URL, deadlines, decoder,
	message assembler, and outgoing frame queue. `Connection::send_message()`,
	`send_binary()`, and `close()` enqueue commands; frames are encoded on the
	reactor so a partially written frame remains immutable across TLS retries.
- `post_callback()` accounts payload bytes plus fixed per-task overhead and
	sends work to per-connection callback queues. `callback_loop()` preserves
	that connection's callback ordering. Slots are released after queued work
	drains; callback-originated last-owner destruction uses a reaper to avoid
	self-join.
- `parse_url()` and `validate_upgrade()` own URL and HTTP Upgrade checks.
	`FrameDecoder::consume()` handles incremental/coalesced framing;
	`MessageAssembler::consume()` enforces fragmentation and whole-message UTF-8;
	`validate_close_payload()` checks close status and reason.
- `tests/frame_tests.cpp` covers URI/handshake and frame edge cases, including a
	maximum-sized frame coalesced with later frames. `tests/client_integration.cpp`
	checks independent connections, ordering, limits, callback teardown, and
	expected error delivery. `tests/loopback_wss.py` is the deterministic local
	TLS/WebSocket peer, not production networking code.

This library is a client only. Proxy support, extension negotiation,
subprotocol negotiation, automatic reconnect/backoff, and a server API are
not implemented.