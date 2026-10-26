#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <iostream>
#include <mutex>
#include <span>
#include <string>
#include <string_view>

import echter.ws.client;

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    const std::string_view mode(argv[2]);
    std::mutex mutex;
    std::condition_variable changed;
    bool finished = false;
    bool opened = false;
    std::string received;
    std::string error;
    // The client must be destroyed before the callback state on every exit path.
    echter::ws::client::Client client({.enable_permessage_deflate = true});
    auto connection = client.connect(argv[1], {
        .on_open = [&](auto) {
            std::lock_guard lock(mutex);
            opened = true;
        },
        .on_message = [&](auto, auto, std::span<const std::byte> bytes) {
            std::lock_guard lock(mutex);
            received.append(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        },
        .on_close = [&](auto, auto code, auto) {
            std::lock_guard lock(mutex);
            if (code != 1000) error = "unexpected close status";
            finished = true;
            changed.notify_one();
        },
        .on_error = [&](auto, std::string_view reason) {
            std::lock_guard lock(mutex);
            error.assign(reason);
            finished = true;
            changed.notify_one();
        },
    }, {.handshake = std::chrono::seconds(2)});
    if (mode == "early") connection.send_message("early");
    std::unique_lock lock(mutex);
    if (!changed.wait_for(lock, std::chrono::seconds(5), [&] { return finished; })) {
        std::cerr << mode << ": timed out\n";
        return 1;
    }
    const std::string expected = mode == "early" ? "early" : "last message";
    if (!error.empty() || !opened || received != expected) {
        std::cerr << mode << ": " << error << "; received='" << received << "'\n";
        return 1;
    }
    std::cout << mode << ": message delivered before close\n";
}
