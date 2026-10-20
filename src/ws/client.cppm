module;

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>
#include <string>
#include <string_view>

export module echter.ws.client;

export import echter.ws.frame;

export namespace echter::ws::client {

namespace detail {
struct Runtime;
struct ClientImpl;
struct ConnectionImpl;
struct ConnectionLifecycle;
}

class Connection;

struct Callbacks {
	std::move_only_function<void(Connection)> on_open;
	std::move_only_function<void(Connection, MessageType, std::span<const std::byte>)> on_message;
	std::move_only_function<void(Connection, std::uint16_t, std::string_view)> on_close;
	std::move_only_function<void(Connection, std::string_view)> on_error;
};

struct Timeouts {
	std::chrono::milliseconds connect{10'000};
	std::chrono::milliseconds handshake{10'000};
	std::chrono::milliseconds idle{60'000};
	std::chrono::milliseconds close{5'000};
};

struct ClientOptions {
	std::size_t max_connections = 8'192;
	std::size_t max_outgoing_bytes = 64 * 1024 * 1024;
	std::size_t callback_workers = 0;
	std::size_t resolver_workers = 0;
	bool enable_permessage_deflate = false;
	std::size_t max_compression_queue_bytes = 64 * 1024 * 1024;
	std::string origin{};
	std::string user_agent{};
};

enum class ConnectionState : unsigned char {
	invalid,
	pending,
	open,
	closing,
	closed,
	failed,
};

class Connection {
public:
	Connection();
	Connection(const Connection& other);
	Connection& operator=(const Connection& other);
	Connection(Connection&&) noexcept;
	Connection& operator=(Connection&&) noexcept;
	~Connection();
	void send_message(std::string_view message) const;
	void send_binary(std::span<const std::byte> message) const;
	[[nodiscard]] bool close() const;
	[[nodiscard]] ConnectionState state() const noexcept;
	[[nodiscard]] explicit operator bool() const noexcept;

private:
	friend class Client;
	friend struct detail::Runtime;
	Connection(std::weak_ptr<detail::Runtime> runtime, std::uint64_t id,
		std::shared_ptr<detail::ConnectionLifecycle> lifecycle);
	std::unique_ptr<detail::ConnectionImpl> impl_;
};

class Client {
public:
	explicit Client(ClientOptions options = {});
	~Client();
	Client(const Client&) = delete;
	Client& operator=(const Client&) = delete;
	Client(Client&&) noexcept;
	Client& operator=(Client&&) noexcept;
	[[nodiscard]] Connection connect(std::string_view url, Callbacks callbacks = {},
		Timeouts timeouts = {});

private:
	std::unique_ptr<detail::ClientImpl> impl_;
};

} // namespace echter::ws::client