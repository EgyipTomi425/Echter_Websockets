#include <cstddef>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <span>
#include <string_view>

import echter.ws.client;

int main(int argc, char** argv) {
    if (argc != 2) {
        std::cerr << "usage: localtest wss://host/path\n";
        return 2;
    }
    std::mutex mutex;
    std::condition_variable finished_condition;
    bool finished = false;

    echter::ws::client::Client client;
    [[maybe_unused]] auto connection = client.connect(
        argv[1],
        echter::ws::client::Callbacks{
            .on_open = [](echter::ws::client::Connection) {
                std::cout << "WebSocket connected\n" << std::flush;
            },
            .on_message = [](echter::ws::client::Connection,
                             echter::ws::MessageType type,
                             std::span<const std::byte> message) {
                if (type == echter::ws::MessageType::text) {
                    std::cout << "text: "
                        << std::string_view(
                            reinterpret_cast<const char*>(message.data()), message.size())
                        << '\n' << std::flush;
                } else {
                    std::cout << "binary: " << message.size() << " bytes\n" << std::flush;
                }
            },
            .on_close = [&](echter::ws::client::Connection, std::uint16_t code,
                            std::string_view reason) {
                std::cout << "WebSocket closed (" << code << "): " << reason << '\n';
                {
                    std::lock_guard lock(mutex);
                    finished = true;
                }
                finished_condition.notify_one();
            },
            .on_error = [&](echter::ws::client::Connection, std::string_view error) {
                std::cerr << "WebSocket error: " << error << '\n';
                {
                    std::lock_guard lock(mutex);
                    finished = true;
                }
                finished_condition.notify_one();
            },
        });

    std::unique_lock lock(mutex);
    finished_condition.wait(lock, [&] { return finished; });
    return 0;
}