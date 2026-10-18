#include <array>
#include <charconv>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <vector>

import echter.ws.client;

namespace {

struct TestState {
	explicit TestState(std::size_t size)
		: opened(size), invalid_text_rejected(size), server_messages(size),
		  echoed_messages(size), closed(size), failed(size), late_send_rejected(size) {}
	std::mutex mutex;
	std::condition_variable changed;
	std::vector<bool> opened;
	std::vector<bool> invalid_text_rejected;
	std::vector<int> server_messages;
	std::vector<int> echoed_messages;
	std::vector<bool> closed;
	std::vector<bool> failed;
	std::vector<bool> late_send_rejected;
	std::string error;
};

std::string as_string(std::span<const std::byte> bytes) {
	return {reinterpret_cast<const char*>(bytes.data()), bytes.size()};
}

} // namespace

int main(int argc, char** argv) {
	if (argc < 2 || argc > 4) {
		std::cerr << "usage: echter_ws_client_integration_tests wss-url [client-count [drop-id]]\n";
		return 2;
	}
	std::size_t connection_count = 5;
	if (argc >= 3) {
		const std::string_view value(argv[2]);
		const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
			connection_count);
		if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()
			|| connection_count < 2 || connection_count > 50'000) {
			std::cerr << "client-count must be in range 2..50000\n";
			return 2;
		}
	}
	std::size_t expected_drop = 0;
	if (argc == 4) {
		const std::string_view value(argv[3]);
		const auto parsed = std::from_chars(value.data(), value.data() + value.size(),
			expected_drop);
		if (parsed.ec != std::errc{} || parsed.ptr != value.data() + value.size()
			|| expected_drop >= connection_count) {
			std::cerr << "drop-id must be in range 0..client-count-1\n";
			return 2;
		}
	}

	{
		echter::ws::client::Client custom_workers(
			echter::ws::client::ClientOptions{.max_connections = 64,
				.max_outgoing_bytes = 4 * 1024 * 1024,
				.callback_workers = 2,
				.resolver_workers = 2});
		(void)custom_workers;
	}

	bool rejected_zero_limit = false;
	try {
		echter::ws::client::Client invalid_client(
			echter::ws::client::ClientOptions{.max_connections = 0});
	} catch (const std::invalid_argument&) {
		rejected_zero_limit = true;
	}
	if (!rejected_zero_limit) {
		std::cerr << "client accepted a zero active-connection limit\n";
		return 1;
	}
	bool rejected_excessive_limit = false;
	try {
		echter::ws::client::Client invalid_client(
			echter::ws::client::ClientOptions{.max_connections = 1'000'001});
	} catch (const std::invalid_argument&) {
		rejected_excessive_limit = true;
	}
	if (!rejected_excessive_limit) {
		std::cerr << "client accepted a connection limit beyond the terminal callback budget\n";
		return 1;
	}
	{
		echter::ws::client::Client limited_client(
			echter::ws::client::ClientOptions{.max_connections = 1, .max_outgoing_bytes = 1});
		auto connection = limited_client.connect(argv[1]);
		bool rejected_second = false;
				bool rejected_outgoing = false;
				try {
					connection.send_message("x");
				} catch (const std::length_error&) {
					rejected_outgoing = true;
				}
				if (!rejected_outgoing) {
					std::cerr << "client exceeded max_outgoing_bytes\n";
					return 1;
				}
		try {
			(void)limited_client.connect(argv[1]);
		} catch (const std::length_error&) {
			rejected_second = true;
		}
		if (!rejected_second) {
			std::cerr << "client exceeded max_connections\n";
			return 1;
		}
	}

	TestState state(connection_count);
	echter::ws::client::Client client(
		echter::ws::client::ClientOptions{.max_connections = connection_count});
	std::vector<echter::ws::client::Connection> handles(connection_count);
	const echter::ws::client::Timeouts session_timeouts{
		.connect = std::chrono::seconds(60),
		.handshake = std::chrono::seconds(60),
		.idle = std::chrono::minutes(5),
		.close = std::chrono::seconds(30),
	};

	for (std::size_t index = 0; index < connection_count; ++index) {
		const std::string first = "first-" + std::to_string(index);
		const std::string second = "second-" + std::to_string(index);
		std::string url(argv[1]);
		url += url.find('?') == std::string::npos ? "?" : "&";
		url += "client=" + std::to_string(index);
		handles[index] = client.connect(url, echter::ws::client::Callbacks{
			.on_open = [&, index, first, second](echter::ws::client::Connection connection) {
				const auto observed_state = connection.state();
				bool invalid_text_rejected = false;
				try {
					connection.send_message(std::string_view("\xc0\xaf", 2));
				} catch (const std::invalid_argument&) {
					invalid_text_rejected = true;
				}
				{
					std::lock_guard lock(state.mutex);
					state.opened[index] = true;
					state.invalid_text_rejected[index] = invalid_text_rejected;
					if (index != expected_drop && observed_state != echter::ws::client::ConnectionState::open) {
						state.error = "on_open observed an unexpected live connection state";
					}
				}
				if (observed_state == echter::ws::client::ConnectionState::failed
					|| observed_state == echter::ws::client::ConnectionState::closed) {
					state.changed.notify_all();
					return;
				}
				connection.send_message(first);
				connection.send_message(second);
				state.changed.notify_all();
			},
			.on_message = [&, index, first, second](echter::ws::client::Connection connection,
											   echter::ws::MessageType type,
										   std::span<const std::byte> message) {
				std::lock_guard lock(state.mutex);
				if (type != echter::ws::MessageType::text) {
					state.error = "received a non-text response";
				} else {
					const std::string payload = as_string(message);
					const std::string server_prefix = "server-" + std::to_string(index) + "-";
					if (payload.starts_with(server_prefix)) {
						const std::string_view color(payload.data() + server_prefix.size(),
							payload.size() - server_prefix.size());
						if (color != "red" && color != "green" && color != "blue" && color != "gold") {
							state.error = "random server message payload was malformed";
						}
						++state.server_messages[index];
					} else {
						const std::string& expected = state.echoed_messages[index] == 0 ? first : second;
						if (payload != expected) state.error = "echo message was misrouted or reordered";
						++state.echoed_messages[index];
						if (state.echoed_messages[index] == 2) {
							if (!connection.close()) {
								state.error = "close request was rejected";
							} else {
								if (connection.state() != echter::ws::client::ConnectionState::closing) {
									state.error = "accepted close request did not publish closing state";
								}
								bool late_send_rejected = false;
								try {
									connection.send_message("late-send");
								} catch (const std::logic_error&) {
									late_send_rejected = true;
								}
								if (!late_send_rejected) {
									state.error = "send was accepted after close request";
								}
							}
						}
					}
				}
				state.changed.notify_all();
			},
			.on_close = [&, index](echter::ws::client::Connection connection, std::uint16_t code,
								  std::string_view) {
				std::lock_guard lock(state.mutex);
				state.closed[index] = true;
				if (code != 1000) state.error = "close handshake did not report normal closure";
				if (connection.state() != echter::ws::client::ConnectionState::closed) {
					state.error = "on_close observed a connection outside the closed state";
				}
				state.changed.notify_all();
			},
			.on_error = [&, index](echter::ws::client::Connection connection, std::string_view error) {
				bool late_send_rejected = false;
				try {
					connection.send_message("late-send");
				} catch (const std::logic_error&) {
					late_send_rejected = true;
				}
				std::lock_guard lock(state.mutex);
				state.failed[index] = true;
				state.late_send_rejected[index] = late_send_rejected;
				if (connection.state() != echter::ws::client::ConnectionState::failed) {
					state.error = "on_error observed a connection outside the failed state";
				}
				if (index != expected_drop) state.error.assign(error);
				state.changed.notify_all();
			}}, session_timeouts);
	}

	{
		std::unique_lock lock(state.mutex);
		const auto timeout = std::chrono::seconds(20 + connection_count / 100);
		const bool completed = state.changed.wait_for(lock, timeout, [&] {
			if (!state.error.empty()) return true;
			if (!state.failed[expected_drop]) return false;
			for (std::size_t index = 0; index < connection_count; ++index) {
				if (index == expected_drop) continue;
				if (!state.opened[index] || state.server_messages[index] != 2
					|| state.echoed_messages[index] != 2 || !state.closed[index]
					|| !state.invalid_text_rejected[index]) return false;
			}
			return true;
		});
		if (!completed) {
			std::cerr << "timed out waiting for randomized WSS sessions and the scripted drop\n";
			return 1;
		}
		if (!state.error.empty()) {
			std::cerr << state.error << '\n';
			return 1;
		}
		if (handles[expected_drop].state() != echter::ws::client::ConnectionState::failed
			|| !state.late_send_rejected[expected_drop]) {
			std::cerr << "failed connection state or late-send rejection was not observable\n";
			return 1;
		}
	}

	std::mutex flood_mutex;
	std::condition_variable flood_changed;
	bool flood_error_received = false;
	std::string flood_error;
	{
		echter::ws::client::Client flood_client(
			echter::ws::client::ClientOptions{
				.max_connections = 1,
				.max_outgoing_bytes = 4 * 1024,
			});
		std::string flood_url(argv[1]);
		flood_url += flood_url.find('?') == std::string::npos ? "?" : "&";
		flood_url += "client=50001";
		[[maybe_unused]] auto flood_connection = flood_client.connect(flood_url,
			echter::ws::client::Callbacks{
				.on_open = {},
				.on_message = {},
				.on_close = {},
				.on_error = [&](echter::ws::client::Connection, std::string_view error) {
					{
						std::lock_guard lock(flood_mutex);
						flood_error.assign(error);
						flood_error_received = true;
					}
					flood_changed.notify_one();
				},
			});
		std::unique_lock lock(flood_mutex);
		if (!flood_changed.wait_for(lock, std::chrono::seconds(10),
				[&] { return flood_error_received; })) {
			std::cerr << "ping flood did not trigger outbound queue backpressure\n";
			return 1;
		}
		if (flood_error.find("control-frame queue limit exceeded") == std::string::npos) {
			std::cerr << "ping flood failed for an unexpected reason: " << flood_error << '\n';
			return 1;
		}
	}

	std::mutex cancellation_mutex;
	std::condition_variable cancellation_changed;
	bool cancellation_notified = false;
	std::string cancellation_error;
	{
		echter::ws::client::Client cancellation_client;
		std::string cancellation_url(argv[1]);
		cancellation_url += cancellation_url.find('?') == std::string::npos ? "?" : "&";
		cancellation_url += "client=7";
		auto cancellation_connection = cancellation_client.connect(cancellation_url,
			echter::ws::client::Callbacks{
				.on_open = {},
				.on_message = {},
				.on_close = {},
				.on_error = [&](echter::ws::client::Connection connection,
						std::string_view error) {
					std::lock_guard lock(cancellation_mutex);
					cancellation_notified = connection.state()
						== echter::ws::client::ConnectionState::failed;
					cancellation_error.assign(error);
					cancellation_changed.notify_one();
				},
			});
		if (!cancellation_connection.close()) {
			std::cerr << "pending connection cancellation was rejected\n";
			return 1;
		}
		std::unique_lock lock(cancellation_mutex);
		if (!cancellation_changed.wait_for(lock, std::chrono::seconds(5),
				[&] { return !cancellation_error.empty(); })) {
			std::cerr << "pending connection cancellation did not notify on_error\n";
			return 1;
		}
		if (!cancellation_notified
			|| cancellation_error.find("cancelled before WebSocket open") == std::string::npos
			|| cancellation_connection.state() != echter::ws::client::ConnectionState::failed) {
			std::cerr << "pending connection cancellation state was not observable\n";
			return 1;
		}
	}
	std::mutex no_response_mutex;
	std::condition_variable no_response_changed;
	std::string no_response_error;
	{
		echter::ws::client::Client no_response_client;
		std::string no_response_url(argv[1]);
		no_response_url += no_response_url.find('?') == std::string::npos ? "?" : "&";
		no_response_url += "client=50003";
		auto no_response_connection = no_response_client.connect(no_response_url,
			echter::ws::client::Callbacks{
				.on_open = {},
				.on_message = {},
				.on_close = {},
				.on_error = [&](echter::ws::client::Connection connection,
						std::string_view error) {
					std::lock_guard lock(no_response_mutex);
					if (connection.state() != echter::ws::client::ConnectionState::failed) {
						no_response_error = "handshake timeout did not mark connection failed";
					} else {
						no_response_error.assign(error);
					}
					no_response_changed.notify_one();
				},
			}, echter::ws::client::Timeouts{
				.handshake = std::chrono::milliseconds(750),
			});
		std::unique_lock lock(no_response_mutex);
		if (!no_response_changed.wait_for(lock, std::chrono::seconds(5),
				[&] { return !no_response_error.empty(); })) {
			std::cerr << "no-response peer did not trigger the handshake timeout\n";
			return 1;
		}
		if (no_response_error.find("handshake") == std::string::npos
			|| no_response_connection.state() != echter::ws::client::ConnectionState::failed) {
			std::cerr << "no-response handshake failed for an unexpected reason: "
				<< no_response_error << '\n';
			return 1;
		}
	}

	std::mutex teardown_mutex;
	std::condition_variable teardown_changed;
	bool connect_returned = false;
	bool client_destroyed_in_callback = false;
	auto callback_client = std::make_unique<echter::ws::client::Client>();
	std::string teardown_url(argv[1]);
	teardown_url += teardown_url.find('?') == std::string::npos ? "?" : "&";
	teardown_url += "client=5";
	const auto teardown_connection = callback_client->connect(teardown_url,
		echter::ws::client::Callbacks{
			.on_open = [&](echter::ws::client::Connection) {
				{
					std::unique_lock lock(teardown_mutex);
					teardown_changed.wait(lock, [&] { return connect_returned; });
				}
				callback_client.reset();
				{
					std::lock_guard lock(teardown_mutex);
					client_destroyed_in_callback = true;
				}
				teardown_changed.notify_all();
			},
			.on_message = {},
			.on_close = {},
			.on_error = {},
		});
	{
		std::lock_guard lock(teardown_mutex);
		connect_returned = true;
	}
	teardown_changed.notify_all();
	{
		std::unique_lock lock(teardown_mutex);
		if (!teardown_changed.wait_for(lock, std::chrono::seconds(10),
				[&] { return client_destroyed_in_callback; })) {
			std::cerr << "Client destruction from on_open callback timed out\n";
			return 1;
		}
	}

	echter::ws::client::Connection orphaned_connection;
	{
		echter::ws::client::Client short_lived_client;
		orphaned_connection = short_lived_client.connect(argv[1]);
	}
	if (orphaned_connection.state() != echter::ws::client::ConnectionState::closed) {
		std::cerr << "connection handle outlived its Client without entering closed state\n";
		return 1;
	}
	bool orphaned_send_rejected = false;
	try {
		orphaned_connection.send_message("after-client-destruction");
	} catch (const std::logic_error&) {
		orphaned_send_rejected = true;
	}
	if (!orphaned_send_rejected) {
		std::cerr << "connection handle accepted a send after Client destruction\n";
		return 1;
	}

	std::cout << connection_count << " concurrent WSS sessions passed; "
		<< connection_count - 1 << " exchanged randomized server messages, "
		"ordered echoes, ping/pong, and clean close; seeded RST and handshake timeout reached on_error; "
		"Client destruction from on_open completed\n";
	return 0;
}