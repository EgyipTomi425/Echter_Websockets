# Echter_Websockets

[![CI](https://github.com/EgyipTomi425/Echter_Websockets/actions/workflows/ci.yml/badge.svg)](https://github.com/EgyipTomi425/Echter_Websockets/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![C++23](https://img.shields.io/badge/C%2B%2B-23-blue.svg)](https://isocpp.org/)
[![Linux](https://img.shields.io/badge/Platform-Linux-1f4d7b.svg)](https://www.kernel.org/)

A Linux-first C++23 WebSocket client built for nonblocking sockets, `io_uring`,
and OpenSSL 3. The project focuses on one goal: reliable client-side WSS
connectivity with bounded memory usage, explicit lifecycle states, and a clear
separation between the network reactor, resolver workers, and user callbacks.

This repository is intentionally client-only. The Python peer is used only for
local validation and integration testing.

## Highlights

- Linux-native event-driven runtime powered by `io_uring`
- Nonblocking TLS handshake and WebSocket I/O
- Optional RFC 7692 `permessage-deflate` on a bounded compression worker
- Resolver worker pool for DNS lookups
- Per-connection callback ordering with bounded callback queues
- Strict lifecycle states: `pending`, `open`, `closing`, `closed`, `failed`
- CPU and memory limits to avoid runaway connection storms
- RAII ownership for sockets, TLS contexts, and the `io_uring` runtime
- Deterministic local WSS validation peer for tests

## Project layout

```text
Echter_Websockets/
├── CMakeLists.txt
├── README.md
├── examples/
│   └── main.cpp
├── src/
│   ├── echter.cppm
│   └── ws/
│       ├── client.cppm
│   │   ├── client.cpp
│   │   ├── compression.cppm
│   │   ├── compression.cpp
│   │   ├── frame.cppm
│   │   ├── frame.cpp
│   │   ├── handshake.cppm
│   │   └── handshake.cpp
├── tests/
│   ├── client_integration.cpp
│   ├── frame_tests.cpp
│   └── loopback_wss.py
└── .gitignore
```

## Modules

The named modules are:

- `echter.ws.client` — public client API and runtime
- `echter.ws.frame` — RFC 6455 frame API; implementation is in `frame.cpp`
- `echter.ws.handshake` — WSS URL API; implementation is in `handshake.cpp`
- `echter.ws.compression` — optional RFC 7692 API; implementation is in `compression.cpp`

The `.cppm` files contain exported declarations; module implementations live in
the corresponding `.cpp` files.

## Requirements

- CMake 3.28+
- Ninja
- C++23 compiler with named-module support
- OpenSSL 3
- zlib
- `liburing` development files (`liburing-dev` on Debian/Ubuntu)

## Quick start

```sh
cmake -S . -B build -G Ninja
cmake --build build
./build/localtest wss://example.org/path
ctest --test-dir build --output-on-failure
```

The example requires a reachable WSS endpoint and validates the peer's CA and
identity. The test suite creates a temporary local certificate and uses a
Python WSS peer; no external service is required for CTest.

## Client example

```cpp
#include <array>
#include <chrono>
#include <cstddef>
#include <span>
#include <string_view>

import echter.ws.client;

echter::ws::client::Client client({
    .max_connections = 4096,
    .max_outgoing_bytes = 64 * 1024 * 1024,
    .callback_workers = 8,
    .resolver_workers = 4,
    .enable_permessage_deflate = true,
    .max_compression_queue_bytes = 64 * 1024 * 1024,
    .origin = "https://example.org",
    .user_agent = "ExampleClient/1.0",
});

auto session = client.connect(
    "wss://example.org/game?room=7",
    echter::ws::client::Callbacks{
        .on_open = [](echter::ws::client::Connection connection) {
            connection.send_message("join");
        },
        .on_message = [](echter::ws::client::Connection,
                         echter::ws::MessageType,
                         std::span<const std::byte> payload) {
            // Message payload is valid for the duration of the callback.
        },
        .on_close = [](echter::ws::client::Connection,
                       std::uint16_t code,
                       std::string_view reason) {
            // Normal close or transport close.
        },
        .on_error = [](echter::ws::client::Connection,
                       std::string_view error) {
            // Connection failed or timed out.
        },
    },
    echter::ws::client::Timeouts{
        .connect = std::chrono::seconds(10),
        .handshake = std::chrono::seconds(10),
        .idle = std::chrono::seconds(60),
        .close = std::chrono::seconds(5),
    }
);

// Copyable handle: can be used from another thread.
auto sender = session;
std::array<std::byte, 3> payload{std::byte{1}, std::byte{2}, std::byte{3}};
sender.send_binary(payload);
```

### API behavior

- `send_message()` validates UTF-8 and enforces the 8 MiB message limit.
- `send_binary()` copies the provided byte span before enqueueing.
- `close()` requests a normal close handshake and returns whether the command was accepted.
- `Connection::state()` reports the atomic lifecycle snapshot: `pending`, `open`,
  `closing`, `closed`, or `failed`.
- An accepted `close()` request immediately reports `closing`; `on_close` runs
    after transport cleanup and observes `closed`.
- Callback delivery is queued and serialized per connection; user callbacks run on
  worker threads, not on the network reactor.
- Sending on a terminal connection throws `std::logic_error`.
- A TLS shutdown without a WebSocket close frame is reported through `on_close`
    with status code `1006`; this indicates an abnormal transport close, not a
    completed WebSocket close handshake.
- Destroying the client from one of its callback workers defers runtime teardown
    to a reaper thread so that teardown does not attempt to join the current worker.

## Runtime architecture

The runtime is deliberately split into three execution domains:

1. Reactor thread
   - owns the `io_uring` ring
   - handles socket readiness and nonblocking TLS operations
   - drives the WebSocket state machine
   - performs handshake, reads, writes, and close/fail transitions

2. Resolver workers
   - run `getaddrinfo()` calls
   - cache successful DNS answers for one minute
   - isolate the blocking DNS path from the main reactor

3. Callback workers
   - execute user callbacks like `on_open`, `on_message`, `on_close`, and `on_error`
   - preserve per-connection callback order
   - protect the reactor from blocking application logic

4. Compression worker
    - exists only when `enable_permessage_deflate` is enabled
    - runs raw-DEFLATE compression/decompression outside the reactor and callback workers
    - uses one bounded worker queue to preserve per-connection codec ordering
    - leaves frame encoding, socket readiness, and TLS writes to the reactor

Worker queues are bounded. Applications should keep callbacks short and move
blocking work to their own executor; a saturated callback queue fails the
connection rather than growing without limit. DNS resolution itself uses the
blocking system resolver, isolated on resolver workers.

### Event flow

```text
Client::connect()
    -> Command(start)
    -> Resolver worker
    -> TCP connect
    -> TLS handshake
    -> HTTP Upgrade
    -> optional permessage-deflate negotiation
    -> WebSocket open
    -> on_open callback
    -> on_message / on_close / on_error callbacks
```

## Protocol and safety

The implementation enforces a strict subset of the WebSocket protocol:

- validates upgrade responses and peer identity
- rejects masked server frames
- rejects reserved opcodes, oversized control frames, and invalid close payloads
- validates UTF-8 for text messages before callback delivery
- responds to ping with a matching pong
- negotiates only the supported `permessage-deflate` parameters; a declined offer
    leaves the connection uncompressed
- validates decompressed text as UTF-8 and enforces the 8 MiB expanded-message limit
- maintains explicit close/fail states instead of silently dropping connections

## Limits and tuning

`ClientOptions` exposes the main operating bounds:

- `max_connections` — maximum active client connections
- `max_outgoing_bytes` — total outgoing budget for queued frames
- `callback_workers` — number of callback worker threads
- `resolver_workers` — number of DNS resolver threads
- `enable_permessage_deflate` — opt-in RFC 7692 compression, disabled by default
- `max_compression_queue_bytes` — bounded memory budget for accepted, queued,
  in-flight, and deferred compression work
- `origin` and `user_agent` — optional opening-handshake headers; empty by default

The default runtime keeps these values bounded automatically, and the library
stops overloaded workloads instead of letting callback queues or memory usage
grow without limit.

## Testing and local validation

The repository includes a deterministic local validation peer in
`tests/loopback_wss.py`. It simulates:

- normal open/echo flows
- abrupt reset behavior
- ping flood handling
- negotiated compression, compressed fragmented messages, binary messages,
  context takeover, uncompressed fallback, and expansion-limit rejection
- idle timeout/no-response cases
- close handshake completion

The integration tests validate the full lifecycle under real TLS and local WSS
traffic, and they also cover failure recovery and callback teardown.

```sh
cmake -S . -B build -G Ninja
cmake --build build
ctest --test-dir build --output-on-failure
```

## Notes

- This library is client-only; server implementation is not included.
- Proxy support, subprotocol negotiation, and automatic reconnect logic are out
    of scope for this project. The only implemented extension is RFC 7692
    `permessage-deflate`.
- Compression over TLS can expose CRIME-style risks when secrets and attacker-
    controlled data share a compression context. This client always starts each
    outbound message with a fresh DEFLATE context. It honors server context
    takeover for inbound messages when the server does not negotiate
    `server_no_context_takeover`; applications should avoid mixing secrets with
    attacker-controlled content in compressed traffic.
- `io_uring` and Linux-only APIs are central to the design; this is not a
  cross-platform network library.

## License

This project is licensed under the terms of the repository's chosen license.
If needed, add a `LICENSE` file before publication in a broader environment.
