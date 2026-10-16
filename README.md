# Echter_Websockets

A Linux-first C++23 WebSocket client built for nonblocking sockets, `io_uring`,
and OpenSSL 3. The project focuses on one goal: reliable client-side WSS
connectivity with bounded memory usage, explicit lifecycle states, and a clear
separation between the network reactor, resolver workers, and user callbacks.

This repository is intentionally client-only. The Python peer is used only for
local validation and integration testing.

## Highlights

- Linux-native event-driven runtime powered by `io_uring`
- Nonblocking TLS handshake and WebSocket I/O
- Resolver worker pool for DNS lookups
- Per-connection callback ordering with bounded callback queues
- Strict lifecycle states: `pending`, `open`, `closing`, `closed`, `failed`
- CPU and memory limits to avoid runaway connection storms
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
│       ├── frame.cppm
│       └── handshake.cppm
├── tests/
│   ├── client_integration.cpp
│   ├── frame_tests.cpp
│   └── loopback_wss.py
└── .gitignore
```

## Modules

The named modules are:

- `echter.ws.client` — public client API and runtime
- `echter.ws.frame` — RFC 6455 frame parsing and framing logic
- `echter.ws.handshake` — WSS URL parsing and HTTP upgrade validation

## Requirements

- CMake 3.28+
- Ninja
- C++23 compiler with named-module support
- OpenSSL 3
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
- Callback delivery is queued and serialized per connection; user callbacks run on
  worker threads, not on the network reactor.
- Sending on a terminal connection throws `std::logic_error`.

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

### Event flow

```text
Client::connect()
    -> Command(start)
    -> Resolver worker
    -> TCP connect
    -> TLS handshake
    -> HTTP Upgrade
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
- maintains explicit close/fail states instead of silently dropping connections

## Limits and tuning

`ClientOptions` exposes the main operating bounds:

- `max_connections` — maximum active client connections
- `max_outgoing_bytes` — total outgoing budget for queued frames
- `callback_workers` — number of callback worker threads
- `resolver_workers` — number of DNS resolver threads

The default runtime keeps these values bounded automatically, and the library
stops overloaded workloads instead of letting callback queues or memory usage
grow without limit.

## Testing and local validation

The repository includes a deterministic local validation peer in
`tests/loopback_wss.py`. It simulates:

- normal open/echo flows
- abrupt reset behavior
- ping flood handling
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
- Proxy support, extension negotiation, subprotocol negotiation, and automatic
  reconnect logic are out of scope for this project.
- `io_uring` and Linux-only APIs are central to the design; this is not a
  cross-platform network library.

## License

This project is licensed under the terms of the repository's chosen license.
If needed, add a `LICENSE` file before publication in a broader environment.
