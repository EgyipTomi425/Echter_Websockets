#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <future>
#include <iostream>
#include <mutex>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <stdexcept>
#include <thread>
#include <vector>

import echter.ws.client;

namespace {
int runtime_lifetime_test(const char* url) {
    using namespace std::chrono_literals;
    // Exercise both ownership orders: Client can own the final reference, or
    // a callback's concurrent send can release it after Client has disappeared.
    for (const auto delay : {0us, 200us, 1000us, 5000us}) {
        std::mutex mutex;
        std::condition_variable changed;
        bool sending = false, finished = false;
        std::string error;
        const auto retirement = std::make_shared<std::promise<void>>();
        auto retired = retirement->get_future();
        auto lifetime = std::shared_ptr<int>(new int(1), [retirement](int* value) {
            delete value;
            retirement->set_value();
        });
        std::vector<std::byte> payload(echter::ws::max_message_size, std::byte{1});
        auto client = std::make_unique<echter::ws::client::Client>();
        auto connection = client->connect(url, {
            .on_open = [&, lifetime](auto active) {
                { std::lock_guard lock(mutex); sending = true; changed.notify_all(); }
                try { active.send_binary(payload); } catch (const std::logic_error&) {
                    // The owner may already have completed shutdown.
                }
                { std::lock_guard lock(mutex); finished = true; changed.notify_all(); }
            },
            .on_message = {},
            .on_close = {},
            .on_error = [&, lifetime](auto, std::string_view reason) {
                std::lock_guard lock(mutex);
                error.assign(reason); finished = true; changed.notify_all();
            },
        });
        lifetime.reset();
        {
            std::unique_lock lock(mutex);
            if (!changed.wait_for(lock, 3s, [&] { return sending || finished; })) return 1;
        }
        std::this_thread::sleep_for(delay);
        client.reset();
        {
            std::unique_lock lock(mutex);
            if (!changed.wait_for(lock, 3s, [&] { return finished; }) || !error.empty()) return 1;
        }
        // State becomes closed before the callback worker is fully drained.
        // Wait for callback captures to retire before their referenced locals
        // leave scope or the next runtime is created.
        if (retired.wait_for(3s) != std::future_status::ready) return 1;
        if (connection.state() != echter::ws::client::ConnectionState::closed) return 1;
    }
    std::cout << "runtime_race: concurrent send and owner destruction completed\n";
    return 0;
}
} // namespace

int main(int argc, char** argv) {
    if (argc != 3) return 2;
    const std::string_view mode(argv[2]);
    if (mode == "runtime_race") return runtime_lifetime_test(argv[1]);
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
    if (mode == "fallback_bad") {
        if (opened || !received.empty() || error.find("unoffered") == std::string::npos) {
            std::cerr << mode << ": unoffered fallback extension accepted: " << error << '\n';
            return 1;
        }
        std::cout << mode << ": unoffered fallback extension rejected\n";
        return 0;
    }
    const std::string expected = mode == "early" ? "early" : "last message";
    if (!error.empty() || !opened || received != expected) {
        std::cerr << mode << ": " << error << "; received='" << received << "'\n";
        return 1;
    }
    std::cout << mode << ": message delivered before close\n";
}
