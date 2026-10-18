module;

#include <liburing.h>
#include <arpa/inet.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <netdb.h>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <unistd.h>

export module echter.ws.client;

export import echter.ws.frame;
import echter.ws.handshake;

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

namespace echter::ws::client::detail {

enum class CommandType { start, resolved, send, close };

struct ConnectionLifecycle {
	std::atomic<ConnectionState> state{ConnectionState::pending};
};

struct ResolvedAddress {
	sockaddr_storage address{};
	socklen_t length = 0;
	int family = AF_UNSPEC;
	int type = SOCK_STREAM;
	int protocol = IPPROTO_TCP;
};

struct Command {
	CommandType type = CommandType::start;
	std::uint64_t id = 0;
	echter::ws::detail::Url url{};
	Callbacks callbacks{};
	std::vector<std::byte> payload{};
	MessageType message_type = MessageType::text;
	int error = 0;
	std::vector<ResolvedAddress> addresses{};
	Timeouts timeouts{};
	std::size_t accounted_bytes = 0;
	std::shared_ptr<ConnectionLifecycle> lifecycle{};
};

struct ResolveTask {
	std::uint64_t id;
	echter::ws::detail::Url url;
};

struct CachedAddress {
	std::vector<ResolvedAddress> addresses;
	std::chrono::steady_clock::time_point expires;
};

struct OutgoingFrame {
	std::vector<std::byte> bytes;
	std::size_t accounted_bytes = 0;
	FrameType type = FrameType::continuation;
};

struct SocketConnection {
	enum class Stage { connecting, tls, upgrade_write, upgrade_read, open };
	std::uint64_t id;
	echter::ws::detail::Url url;
	std::shared_ptr<Callbacks> callbacks;
	std::shared_ptr<ConnectionLifecycle> lifecycle;
	Timeouts timeouts;
	std::chrono::steady_clock::time_point deadline{};
	bool has_deadline = false;
	int socket = -1;
	std::vector<ResolvedAddress> addresses;
	std::size_t next_address = 0;
	SSL* ssl = nullptr;
	Stage stage = Stage::connecting;
	bool poll_armed = false;
	bool cancel_pending = false;
	short poll_events = 0;
	short wanted = 0;
	std::string key;
	std::string request;
	std::size_t request_offset = 0;
	std::string response;
	std::vector<std::byte> prefetched;
	std::size_t prefetched_offset = 0;
	std::deque<OutgoingFrame> outgoing;
	std::size_t outgoing_offset = 0;
	FrameDecoder decoder;
	MessageAssembler assembler;
	bool closing = false;
	bool close_sent = false;
	bool close_received = false;
	bool close_notified = false;
	std::uint16_t close_code = 1006;
	std::string close_reason;

	~SocketConnection() {
		if (ssl != nullptr) SSL_free(ssl);
		if (socket >= 0) ::close(socket);
	}
};

struct Runtime : std::enable_shared_from_this<Runtime> {
	static constexpr std::size_t max_pending_commands = 262'144;
	static constexpr std::size_t max_resolve_tasks = 262'144;
	static constexpr std::size_t max_dns_cache_entries = 4'096;
	static constexpr std::size_t max_callback_tasks = 131'072;
	static constexpr std::size_t max_callback_bytes = 64 * 1024 * 1024;
	const std::size_t max_active_connections;
	const std::size_t max_outgoing_bytes;
	const std::size_t max_terminal_callback_tasks;
	const std::size_t max_terminal_callback_bytes;
	const std::size_t callback_worker_count;
	const std::size_t resolver_worker_count;
	std::atomic<std::size_t> active_connections{0};

	explicit Runtime(ClientOptions options)
		: max_active_connections(options.max_connections),
		  max_outgoing_bytes(options.max_outgoing_bytes),
		  max_terminal_callback_tasks(options.max_connections <= 1'000'000
			? options.max_connections * 2 : 0),
		  max_terminal_callback_bytes(options.max_connections <= 1'000'000
			? options.max_connections * 768 : 0),
		  callback_worker_count(options.callback_workers == 0
			? std::clamp<std::size_t>(std::max<std::size_t>(
				std::thread::hardware_concurrency() > 0 ? static_cast<std::size_t>(std::thread::hardware_concurrency()) : 4,
				4), 4, 16) : std::clamp<std::size_t>(options.callback_workers, std::size_t{1}, std::size_t{16})),
		  resolver_worker_count(options.resolver_workers == 0
			? std::clamp<std::size_t>(std::max<std::size_t>(
				std::thread::hardware_concurrency() > 0 ? (static_cast<std::size_t>(std::thread::hardware_concurrency()) / 2) : 2,
				2), 2, 8) : std::clamp<std::size_t>(options.resolver_workers, std::size_t{1}, std::size_t{8})) {
		if (max_active_connections == 0 || max_active_connections > 1'000'000
			|| max_outgoing_bytes == 0 || callback_worker_count == 0 || resolver_worker_count == 0) {
			throw std::invalid_argument("client limits must be positive and max_connections <= 1000000");
		}
		if (options.callback_workers > 16 || options.resolver_workers > 8) {
			throw std::invalid_argument("callback_workers and resolver_workers must be <= 16 and <= 8");
		}
		wake_fd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
		if (wake_fd < 0) throw std::system_error(errno, std::generic_category(), "eventfd");
		timer_fd = ::timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
		if (timer_fd < 0) {
			::close(wake_fd);
			wake_fd = -1;
			throw std::system_error(errno, std::generic_category(), "timerfd_create");
		}
		io_uring_params ring_params{};
		ring_params.flags = IORING_SETUP_CQSIZE;
		ring_params.cq_entries = 32'768;
		const int result = io_uring_queue_init_params(4096, &ring, &ring_params);
		if (result < 0) {
			::close(timer_fd);
			timer_fd = -1;
			::close(wake_fd);
			wake_fd = -1;
			throw std::system_error(-result, std::generic_category(), "io_uring_queue_init");
		}
		tls_context = SSL_CTX_new(TLS_client_method());
		if (tls_context == nullptr
			|| SSL_CTX_set_min_proto_version(tls_context, TLS1_2_VERSION) != 1
			|| SSL_CTX_set_default_verify_paths(tls_context) != 1) {
			if (tls_context != nullptr) SSL_CTX_free(tls_context);
			tls_context = nullptr;
			io_uring_queue_exit(&ring);
			::close(timer_fd);
			::close(wake_fd);
			timer_fd = -1;
			wake_fd = -1;
			throw std::runtime_error("TLS context setup failed");
		}
		SSL_CTX_set_verify(tls_context, SSL_VERIFY_PEER, nullptr);
		SSL_CTX_set_mode(tls_context, SSL_MODE_RELEASE_BUFFERS);
		for (std::size_t index = 0; index < resolver_worker_count; ++index) {
			resolvers.emplace_back([this](std::stop_token stop) { resolve_loop(stop); });
		}
		for (std::size_t index = 0; index < callback_worker_count; ++index) {
			callback_workers.emplace_back([this](std::stop_token stop) { callback_loop(stop); });
		}
		reactor = std::jthread([this](std::stop_token) { run(); });
	}

	~Runtime() {
		for (auto& worker : resolvers) worker.request_stop();
		resolve_cv.notify_all();
		resolvers.clear();
		stopping.store(true, std::memory_order_release);
		wake();
		if (reactor.joinable()) reactor.join();
		{
			std::lock_guard lock(callback_mutex);
			callbacks_stopping = true;
		}
		callback_cv.notify_all();
		callback_workers.clear();
		io_uring_queue_exit(&ring);
		if (tls_context != nullptr) SSL_CTX_free(tls_context);
		if (timer_fd >= 0) ::close(timer_fd);
		if (wake_fd >= 0) ::close(wake_fd);
	}

	void wake() noexcept {
		if (wake_pending.exchange(true, std::memory_order_acq_rel)) return;
		const std::uint64_t one = 1;
		(void)::write(wake_fd, &one, sizeof(one));
	}

	bool post(Command command) {
		{
			std::lock_guard lock(command_mutex);
			if (commands.size() >= max_pending_commands) return false;
			if ((command.type == CommandType::send || command.type == CommandType::close)
				&& command.lifecycle) {
				const ConnectionState state = command.lifecycle->state.load(
					std::memory_order_acquire);
				if (state == ConnectionState::closing || state == ConnectionState::closed
					|| state == ConnectionState::failed) return false;
			}
			if (command.type == CommandType::send) {
				command.accounted_bytes = command.payload.size() + 14;
				if (command.accounted_bytes > max_outgoing_bytes - pending_outgoing_bytes) return false;
			}
			bool active_slot_reserved = false;
			if (command.type == CommandType::start) {
				std::size_t active = active_connections.load(std::memory_order_relaxed);
				for (;;) {
					if (active >= max_active_connections) return false;
					if (active_connections.compare_exchange_weak(active, active + 1,
							std::memory_order_acq_rel, std::memory_order_relaxed)) {
						active_slot_reserved = true;
						break;
					}
				}
			}
			try {
				commands.push_back(std::move(command));
			} catch (...) {
				if (active_slot_reserved) active_connections.fetch_sub(1, std::memory_order_acq_rel);
				throw;
			}
			if (commands.back().type == CommandType::send) {
				pending_outgoing_bytes += commands.back().accounted_bytes;
			}
			if (commands.back().type == CommandType::close && commands.back().lifecycle) {
				commands.back().lifecycle->state.store(ConnectionState::closing,
					std::memory_order_release);
			}
		}
		wake();
		return true;
	}

	void release_outgoing(std::size_t bytes) {
		if (bytes == 0) return;
		std::lock_guard lock(command_mutex);
		pending_outgoing_bytes -= std::min(bytes, pending_outgoing_bytes);
	}

	bool reserve_outgoing(std::size_t bytes) {
		std::lock_guard lock(command_mutex);
		if (bytes > max_outgoing_bytes - pending_outgoing_bytes) return false;
		pending_outgoing_bytes += bytes;
		return true;
	}

	bool post_callback(std::uint64_t id, std::move_only_function<void()> callback,
		std::size_t bytes = 0, bool terminal = false) {
		constexpr std::size_t retained_task_overhead = 256;
		const std::size_t byte_limit = terminal
			? max_terminal_callback_bytes : max_callback_bytes;
		if (bytes > byte_limit - retained_task_overhead) return false;
		bytes += retained_task_overhead;
		bool notify_worker = false;
		{
			std::lock_guard lock(callback_mutex);
			if ((!terminal && pending_callback_tasks >= max_callback_tasks)
				|| (terminal && pending_terminal_callback_tasks >= max_terminal_callback_tasks)
				|| (terminal
					? bytes > max_terminal_callback_bytes - pending_terminal_callback_bytes
					: bytes > max_callback_bytes - pending_callback_bytes)) return false;
			auto& queue = callback_queues[id];
			queue.callbacks.push_back({.callback = std::move(callback), .bytes = bytes,
				.terminal = terminal});
			++pending_callback_tasks;
			if (terminal) ++pending_terminal_callback_tasks;
			if (terminal) pending_terminal_callback_bytes += bytes;
			else pending_callback_bytes += bytes;
			if (!queue.active) {
				queue.active = true;
				ready_callbacks.push_back(id);
				notify_worker = true;
			}
		}
		if (notify_worker) callback_cv.notify_one();
		return true;
	}

	void callback_loop(std::stop_token stop) {
		for (;;) {
			std::uint64_t id = 0;
			CallbackTask task;
			{
				std::unique_lock lock(callback_mutex);
				callback_cv.wait(lock, stop, [&] { return callbacks_stopping || !ready_callbacks.empty(); });
				if (ready_callbacks.empty() && (callbacks_stopping || stop.stop_requested())) return;
				id = ready_callbacks.front();
				ready_callbacks.pop_front();
				auto& queue = callback_queues.at(id);
				task = std::move(queue.callbacks.front());
				queue.callbacks.pop_front();
			}
			try { task.callback(); } catch (...) {}
			bool notify_worker = false;
			bool release_connection_slot = false;
			{
				std::lock_guard lock(callback_mutex);
				--pending_callback_tasks;
				if (task.terminal) {
					--pending_terminal_callback_tasks;
					pending_terminal_callback_bytes -= task.bytes;
				} else {
					pending_callback_bytes -= task.bytes;
				}
				auto found = callback_queues.find(id);
				if (found != callback_queues.end()) {
					if (found->second.callbacks.empty()) {
						release_connection_slot = found->second.release_connection_slot;
						callback_queues.erase(found);
					}
					else ready_callbacks.push_back(id);
				}
				notify_worker = !ready_callbacks.empty();
			}
			if (release_connection_slot) {
				active_connections.fetch_sub(1, std::memory_order_acq_rel);
			}
			if (notify_worker) callback_cv.notify_one();
		}
	}

	Connection handle(std::uint64_t id) {
		auto found = connections.find(id);
		if (found == connections.end()) return {};
		return Connection(weak_from_this(), id, found->second->lifecycle);
	}

	bool is_callback_worker() const noexcept {
		const std::thread::id current = std::this_thread::get_id();
		return std::any_of(callback_workers.begin(), callback_workers.end(),
			[current](const std::jthread& worker) { return worker.get_id() == current; });
	}

	bool enqueue_resolve(ResolveTask task) {
		{
			std::lock_guard lock(resolve_mutex);
			if (resolve_tasks.size() >= max_resolve_tasks) return false;
			resolve_tasks.push_back(std::move(task));
		}
		resolve_cv.notify_one();
		return true;
	}

	void resolve_loop(std::stop_token stop) {
		while (!stop.stop_requested()) {
			ResolveTask task;
			{
				std::unique_lock lock(resolve_mutex);
				resolve_cv.wait(lock, stop, [&] { return !resolve_tasks.empty(); });
				if (stop.stop_requested()) return;
				task = std::move(resolve_tasks.front());
				resolve_tasks.pop_front();
			}
			addrinfo hints{};
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			Command result{.type = CommandType::resolved, .id = task.id};
			const std::string cache_key = task.url.host + '\0' + task.url.port;
			{
				std::lock_guard lock(resolve_mutex);
				auto cached = dns_cache.find(cache_key);
				if (cached != dns_cache.end()) {
					if (cached->second.expires > std::chrono::steady_clock::now()) {
						result.addresses = cached->second.addresses;
					} else {
						dns_cache.erase(cached);
					}
				}
			}
			if (result.addresses.empty()) {
				addrinfo* list = nullptr;
				const int status = ::getaddrinfo(task.url.host.c_str(), task.url.port.c_str(), &hints, &list);
				if (status != 0) {
					result.error = EHOSTUNREACH;
				} else {
					for (addrinfo* item = list; item != nullptr; item = item->ai_next) {
						if (item->ai_addrlen <= sizeof(sockaddr_storage)) {
							ResolvedAddress address{.length = static_cast<socklen_t>(item->ai_addrlen),
								.family = item->ai_family, .type = item->ai_socktype,
								.protocol = item->ai_protocol};
							std::memcpy(&address.address, item->ai_addr, item->ai_addrlen);
							result.addresses.push_back(address);
						}
					}
					::freeaddrinfo(list);
					if (result.addresses.empty()) result.error = EHOSTUNREACH;
					else {
						std::lock_guard lock(resolve_mutex);
						if (dns_cache.size() >= max_dns_cache_entries
							&& !dns_cache.contains(cache_key)) dns_cache.erase(dns_cache.begin());
						dns_cache[cache_key] = CachedAddress{
							.addresses = result.addresses,
							.expires = std::chrono::steady_clock::now() + std::chrono::minutes(1)};
					}
				}
			}
			post(std::move(result));
		}
	}

	bool arm(int fd, std::uint64_t id, unsigned mask) {
		io_uring_sqe* sqe = io_uring_get_sqe(&ring);
		if (sqe == nullptr) {
			if (io_uring_submit(&ring) < 0) return false;
			sqe = io_uring_get_sqe(&ring);
			if (sqe == nullptr) return false;
		}
		io_uring_prep_poll_add(sqe, fd, mask);
		io_uring_sqe_set_data64(sqe, id);
		return true;
	}

	void arm_wake() {
		if (!wake_armed) {
			if (!arm(wake_fd, 0, POLLIN)) {
				stopping.store(true, std::memory_order_release);
				return;
			}
			wake_armed = true;
		}
	}

	void arm_timer() {
		if (suppress_timer_updates) return;
		itimerspec timer{};
		if (!deadlines.empty()) {
			auto remaining = deadlines.begin()->first - std::chrono::steady_clock::now();
			if (remaining <= std::chrono::steady_clock::duration::zero()) {
				remaining = std::chrono::milliseconds(1);
			}
			const auto nanoseconds = std::chrono::duration_cast<std::chrono::nanoseconds>(remaining);
			timer.it_value.tv_sec = static_cast<time_t>(nanoseconds.count() / 1'000'000'000);
			timer.it_value.tv_nsec = static_cast<long>(nanoseconds.count() % 1'000'000'000);
		}
		if (::timerfd_settime(timer_fd, 0, &timer, nullptr) != 0) {
			stopping.store(true, std::memory_order_release);
			wake();
			return;
		}
		if (!timer_armed) {
			if (!arm(timer_fd, timer_tag, POLLIN)) {
				stopping.store(true, std::memory_order_release);
				wake();
				return;
			}
			timer_armed = true;
		}
	}

	void set_timeout(std::uint64_t id, std::chrono::milliseconds duration) {
		auto found = connections.find(id);
		if (found == connections.end()) return;
		SocketConnection& connection = *found->second;
		const auto previous_earliest = deadlines.empty()
			? std::chrono::steady_clock::time_point::max() : deadlines.begin()->first;
		if (connection.has_deadline) deadlines.erase({connection.deadline, id});
		connection.has_deadline = duration.count() > 0;
		if (connection.has_deadline) {
			connection.deadline = std::chrono::steady_clock::now() + duration;
			deadlines.emplace(connection.deadline, id);
		}
		const auto new_earliest = deadlines.empty()
			? std::chrono::steady_clock::time_point::max() : deadlines.begin()->first;
		if (new_earliest < previous_earliest) arm_timer();
	}

	void erase_connection(std::uint64_t id) {
		auto found = connections.find(id);
		if (found == connections.end()) return;
		if (found->second->lifecycle) {
			const ConnectionState current = found->second->lifecycle->state.load(
				std::memory_order_acquire);
			if (current != ConnectionState::failed) {
				found->second->lifecycle->state.store(ConnectionState::closed,
					std::memory_order_release);
				notify_close(*found->second);
			}
		}
		if (found->second->has_deadline) deadlines.erase({found->second->deadline, id});
		std::size_t unsent_bytes = 0;
		for (const OutgoingFrame& frame : found->second->outgoing) unsent_bytes += frame.accounted_bytes;
		release_outgoing(unsent_bytes);
		connections.erase(found);
		bool release_slot = true;
		{
			std::lock_guard lock(callback_mutex);
			auto callbacks = callback_queues.find(id);
			if (callbacks != callback_queues.end() && callbacks->second.active) {
				callbacks->second.release_connection_slot = true;
				release_slot = false;
			}
		}
		if (release_slot) active_connections.fetch_sub(1, std::memory_order_acq_rel);
	}

	void expire_timeouts() {
		const auto now = std::chrono::steady_clock::now();
		suppress_timer_updates = true;
		while (!deadlines.empty() && deadlines.begin()->first <= now) {
			const std::uint64_t id = deadlines.begin()->second;
			auto connection = connections.find(id);
			if (connection == connections.end()) {
				deadlines.erase(deadlines.begin());
				continue;
			}
			std::string_view reason = "TLS/WebSocket handshake timed out";
			if (connection->second->stage == SocketConnection::Stage::connecting) {
				reason = "DNS/TCP connection timed out";
			} else if (connection->second->stage == SocketConnection::Stage::open) {
				reason = connection->second->closing
					? "WebSocket close handshake timed out"
					: "idle timeout: no incoming WebSocket message";
			}
			fail(id, reason);
		}
		suppress_timer_updates = false;
		arm_timer();
	}

	void process_completion(io_uring_cqe* cqe) {
			const std::uint64_t id = io_uring_cqe_get_data64(cqe);
			const int events = cqe->res;
			if ((id & (std::uint64_t{1} << 63)) != 0) return;
			if (id == timer_tag) {
				timer_armed = false;
				std::uint64_t expirations = 0;
				while (::read(timer_fd, &expirations, sizeof(expirations)) > 0) {}
				if (events < 0) {
					stopping.store(true, std::memory_order_release);
					wake();
				} else {
					expire_timeouts();
				}
			} else if (id == 0) {
				wake_armed = false;
				std::uint64_t value;
				while (::read(wake_fd, &value, sizeof(value)) > 0) {}
				wake_pending.store(false, std::memory_order_release);
				drain_commands();
				arm_wake();
			} else {
				auto found = connections.find(id);
				if (found != connections.end()) {
					found->second->poll_armed = false;
					found->second->poll_events = 0;
					if (events == -ECANCELED && found->second->cancel_pending) {
						found->second->cancel_pending = false;
						const short wanted = found->second->wanted;
						found->second->wanted = 0;
						arm_connection(*found->second, wanted);
						return;
					}
					found->second->cancel_pending = false;
					found->second->wanted = 0;
					if (events < 0) fail(id, "io_uring poll failed");
					else if (!drive(*found->second, events)) {
						erase_connection(id);
					}
				}
			}
	}

	void run() {
		arm_wake();
		arm_timer();
		if (io_uring_submit(&ring) < 0) {
			stopping.store(true, std::memory_order_release);
			return;
		}
		std::array<io_uring_cqe*, 256> batch{};
		while (!stopping.load(std::memory_order_acquire)) {
			io_uring_cqe* first = nullptr;
			const int result = io_uring_wait_cqe(&ring, &first);
			if (result < 0) {
				if (result == -EINTR) continue;
				break;
			}
			unsigned count = io_uring_peek_batch_cqe(&ring, batch.data(), batch.size());
			if (count == 0) {
				batch[0] = first;
				count = 1;
			}
			for (unsigned index = 0; index < count; ++index) {
				process_completion(batch[index]);
				io_uring_cqe_seen(&ring, batch[index]);
			}
			if (io_uring_submit(&ring) < 0) {
				stopping.store(true, std::memory_order_release);
			}
		}
		for (auto& [id, connection] : connections) {
			(void)id;
			if (!connection->lifecycle) continue;
			const ConnectionState state = connection->lifecycle->state.load(
				std::memory_order_acquire);
			if (state != ConnectionState::failed) {
				connection->lifecycle->state.store(ConnectionState::closed,
					std::memory_order_release);
			}
		}
		connections.clear();
		{
			std::lock_guard lock(command_mutex);
			for (Command& command : commands) {
				if (!command.lifecycle) continue;
				const ConnectionState state = command.lifecycle->state.load(
					std::memory_order_acquire);
				if (state != ConnectionState::failed) {
					command.lifecycle->state.store(ConnectionState::closed,
						std::memory_order_release);
				}
			}
			commands.clear();
		}
		deadlines.clear();
	}

	void drain_commands() {
		std::deque<Command> batch;
		{
			std::lock_guard lock(command_mutex);
			batch.swap(commands);
		}
		for (Command& command : batch) {
			if (command.type == CommandType::start) {
				auto connection = std::make_unique<SocketConnection>();
				connection->id = command.id;
				connection->url = std::move(command.url);
				connection->callbacks = std::make_shared<Callbacks>(std::move(command.callbacks));
				connection->lifecycle = std::move(command.lifecycle);
				connection->timeouts = command.timeouts;
				connections.emplace(command.id, std::move(connection));
				set_timeout(command.id, connections.at(command.id)->timeouts.connect);
				if (!enqueue_resolve({command.id, connections.at(command.id)->url})) {
					fail(command.id, "DNS resolver queue limit exceeded");
				}
			} else if (command.type == CommandType::resolved) {
				auto found = connections.find(command.id);
				if (found == connections.end()) continue;
				SocketConnection& connection = *found->second;
				if (command.error != 0 || command.addresses.empty()) {
					fail(command.id, "DNS lookup failed");
					continue;
				}
				connection.addresses = std::move(command.addresses);
				if (!connect_next(connection)) {
					const std::uint64_t id = command.id;
					if (connections.contains(id)) {
						fail(id, "TCP connect failed for all resolved addresses");
					}
				}
			} else if (command.type == CommandType::send) {
				auto found = connections.find(command.id);
				if (found != connections.end() && !found->second->closing) {
					try {
						found->second->outgoing.push_back({
							.bytes = encode_client_frame(static_cast<FrameType>(command.message_type), command.payload),
							.accounted_bytes = command.accounted_bytes,
							.type = static_cast<FrameType>(command.message_type)});
					} catch (const std::exception& error) {
						release_outgoing(command.accounted_bytes);
						fail(command.id, error.what());
						continue;
					}
					if (!drive(*found->second, 0)) {
						erase_connection(command.id);
					}
				} else release_outgoing(command.accounted_bytes);
			} else if (command.type == CommandType::close) {
				auto found = connections.find(command.id);
				if (found != connections.end()) {
					if (found->second->stage != SocketConnection::Stage::open) {
						fail(command.id, "connection cancelled before WebSocket open");
					} else if (!found->second->closing) {
						try {
							const std::array<std::byte, 2> close_code{
								std::byte{0x03}, std::byte{0xe8}};
							found->second->outgoing.push_back({
								.bytes = encode_client_frame(FrameType::close, close_code),
								.type = FrameType::close});
						} catch (const std::exception& error) {
							fail(command.id, error.what());
							continue;
						}
						found->second->closing = true;
						found->second->lifecycle->state.store(ConnectionState::closing,
							std::memory_order_release);
						set_timeout(command.id, found->second->timeouts.close);
						if (!drive(*found->second, 0)) {
							erase_connection(command.id);
						}
					}

				}
			}
		}
		drain_deferred_drives();
	}

	void defer_drive(std::uint64_t id) {
		if (deferred_drive_set.insert(id).second) {
			deferred_drives.push_back(id);
			wake();
		}
	}

	void drain_deferred_drives() {
		const std::size_t budget = std::min<std::size_t>(deferred_drives.size(), 16);
		for (std::size_t index = 0; index < budget; ++index) {
			const std::uint64_t id = deferred_drives.front();
			deferred_drives.pop_front();
			deferred_drive_set.erase(id);
			auto found = connections.find(id);
			if (found != connections.end() && !drive(*found->second, POLLIN)) {
				erase_connection(id);
			}
		}
		if (!deferred_drives.empty()) wake();
	}

	bool connect_next(SocketConnection& connection) {
		while (connection.next_address < connection.addresses.size()) {
			const ResolvedAddress& candidate = connection.addresses[connection.next_address++];
			connection.socket = ::socket(candidate.family,
				candidate.type | SOCK_CLOEXEC | SOCK_NONBLOCK, candidate.protocol);
			if (connection.socket < 0) continue;
			const auto* address = reinterpret_cast<const sockaddr*>(&candidate.address);
			const int connected = ::connect(connection.socket, address, candidate.length);
			if (connected == 0) {
				if (!begin_tls(connection)) return false;
				return connections.contains(connection.id);
			}
			if (errno == EINPROGRESS) {
				connection.stage = SocketConnection::Stage::connecting;
				return arm_connection(connection, POLLIN | POLLOUT);
			}
			::close(connection.socket);
			connection.socket = -1;
		}
		return false;
	}

	bool arm_connection(SocketConnection& connection, short events) {
		if (connection.socket < 0) {
			fail(connection.id, "cannot poll a closed socket");
			return false;
		}
		if (connection.poll_armed) {
			if ((connection.poll_events & events) == events) return true;
			connection.wanted = static_cast<short>(connection.wanted | events);
			if (connection.cancel_pending) return true;
			io_uring_sqe* sqe = io_uring_get_sqe(&ring);
			if (sqe == nullptr) {
				if (io_uring_submit(&ring) < 0) {
					fail(connection.id, "io_uring submission failed");
					return false;
				}
				sqe = io_uring_get_sqe(&ring);
				if (sqe == nullptr) {
					fail(connection.id, "io_uring submission queue exhausted");
					return false;
				}
			}
			io_uring_prep_cancel64(sqe, connection.id, 0);
			io_uring_sqe_set_data64(sqe, connection.id | (std::uint64_t{1} << 63));
			connection.cancel_pending = true;
			return true;
		}
		if (!arm(connection.socket, connection.id, static_cast<unsigned>(events))) {
			fail(connection.id, "io_uring submission queue exhausted");
			return false;
		}
		connection.poll_armed = true;
		connection.poll_events = events;
		return true;
	}

	bool begin_tls(SocketConnection& connection) {
		set_timeout(connection.id, connection.timeouts.handshake);
		connection.ssl = SSL_new(tls_context);
		if (!connection.ssl || SSL_set_fd(connection.ssl, connection.socket) != 1) {
			fail(connection.id, "TLS setup failed");
			return false;
		}
		in_addr ipv4{};
		in6_addr ipv6{};
		const bool is_ip = ::inet_pton(AF_INET, connection.url.host.c_str(), &ipv4) == 1
			|| ::inet_pton(AF_INET6, connection.url.host.c_str(), &ipv6) == 1;
		const int identity_configured = is_ip
			? X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(connection.ssl),
				connection.url.host.c_str())
			: (SSL_set_tlsext_host_name(connection.ssl, connection.url.host.c_str()) == 1
				&& SSL_set1_host(connection.ssl, connection.url.host.c_str()) == 1);
		if (identity_configured != 1) {
			fail(connection.id, "TLS peer identity setup failed");
			return false;
		}
		SSL_set_connect_state(connection.ssl);
		connection.stage = SocketConnection::Stage::tls;
		if (!drive(connection, 0)) return false;
		return connections.contains(connection.id);
	}

	bool wait_for(SocketConnection& connection, int ssl_error) {
		if (ssl_error == SSL_ERROR_WANT_READ) return arm_connection(connection, POLLIN);
		else if (ssl_error == SSL_ERROR_WANT_WRITE) return arm_connection(connection, POLLOUT);
		else { fail(connection.id, "TLS/WebSocket I/O failed"); return false; }
	}

	bool drive(SocketConnection& connection, int events) {
		try {
			return drive_impl(connection, events);
		} catch (const std::exception& error) {
			fail(connection.id, error.what());
		} catch (...) {
			fail(connection.id, "unknown WebSocket connection failure");
		}
		return false;
	}

	bool drive_impl(SocketConnection& connection, int events) {
		if (connection.stage == SocketConnection::Stage::connecting) {
			if ((events & (POLLOUT | POLLERR | POLLHUP)) == 0) {
				return arm_connection(connection, POLLIN | POLLOUT);
			}
			int error = 0; socklen_t size = sizeof(error);
			if (::getsockopt(connection.socket, SOL_SOCKET, SO_ERROR, &error, &size) != 0 || error != 0) {
				::close(connection.socket);
				connection.socket = -1;
				if (connect_next(connection)) return true;
				const std::uint64_t id = connection.id;
				if (connections.contains(id)) {
					fail(id, "TCP connect failed for all resolved addresses");
				}
				return false;
			}
			if (!begin_tls(connection)) return false;
			return connections.contains(connection.id);
		}

		if (connection.stage == SocketConnection::Stage::tls) {
			ERR_clear_error();
			const int result = SSL_connect(connection.ssl);
			if (result != 1) return wait_for(connection, SSL_get_error(connection.ssl, result));
			connection.key = echter::ws::detail::make_websocket_key();
			connection.request = "GET " + connection.url.target + " HTTP/1.1\r\nHost: "
				+ connection.url.host_header + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: "
				+ connection.key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
			connection.stage = SocketConnection::Stage::upgrade_write;
		}

		if (connection.stage == SocketConnection::Stage::upgrade_write) {
			ERR_clear_error();
			const int count = SSL_write(connection.ssl, connection.request.data() + connection.request_offset,
				static_cast<int>(connection.request.size() - connection.request_offset));
			if (count <= 0) return wait_for(connection, SSL_get_error(connection.ssl, count));
			connection.request_offset += static_cast<std::size_t>(count);
			if (connection.request_offset < connection.request.size()) return arm_connection(connection, POLLOUT);
			connection.stage = SocketConnection::Stage::upgrade_read;
		}

		if (connection.stage == SocketConnection::Stage::upgrade_read) {
			std::array<char, 4096> buffer{};
			std::size_t count = 0;
			ERR_clear_error();
			const int result = SSL_read_ex(connection.ssl, buffer.data(), buffer.size(), &count);
			if (result != 1) return wait_for(connection, SSL_get_error(connection.ssl, result));
			connection.response.append(buffer.data(), count);
			if (connection.response.size() > 16 * 1024) { fail(connection.id, "upgrade headers too large"); return false; }
			const std::size_t headers_end = connection.response.find("\r\n\r\n");
			if (headers_end == std::string::npos) return arm_connection(connection, POLLIN);
			const std::size_t body_start = headers_end + 4;
			if (body_start < connection.response.size()) {
				const auto* bytes = reinterpret_cast<const std::byte*>(connection.response.data() + body_start);
				connection.prefetched.assign(bytes, bytes + (connection.response.size() - body_start));
			}
			connection.response.resize(body_start);
			try { echter::ws::detail::validate_upgrade(connection.response, connection.key); }
			catch (const std::exception& error) { fail(connection.id, error.what()); return false; }
			connection.stage = SocketConnection::Stage::open;
			ConnectionState expected_state = ConnectionState::pending;
			connection.lifecycle->state.compare_exchange_strong(expected_state,
				ConnectionState::open, std::memory_order_release,
				std::memory_order_acquire);
			set_timeout(connection.id, connection.timeouts.idle);
			if (connection.callbacks->on_open) {
				auto callbacks = connection.callbacks;
				Connection connection_handle = handle(connection.id);
				const bool queued = post_callback(connection.id, [callbacks = std::move(callbacks), connection_handle = std::move(connection_handle)]() mutable {
					if (callbacks->on_open) callbacks->on_open(std::move(connection_handle));
				});
				if (!queued) {
					fail(connection.id, "callback queue limit exceeded during open");
					return false;
				}
			}
		}

		if (connection.stage == SocketConnection::Stage::open) {
			for (unsigned work = 0; work < 16; ++work) {
			if (!connection.outgoing.empty()) {
				auto& frame = connection.outgoing.front();
				ERR_clear_error();
				const int count = SSL_write(connection.ssl, frame.bytes.data() + connection.outgoing_offset,
					static_cast<int>(frame.bytes.size() - connection.outgoing_offset));
				if (count <= 0) return wait_for(connection, SSL_get_error(connection.ssl, count));
				connection.outgoing_offset += static_cast<std::size_t>(count);
				if (connection.outgoing_offset == frame.bytes.size()) {
					const bool sent_close = frame.type == FrameType::close;
					release_outgoing(frame.accounted_bytes);
					connection.outgoing.pop_front();
					connection.outgoing_offset = 0;
					if (sent_close) connection.close_sent = true;
				}
				if (connection.close_sent && connection.close_received) return false;
				if (!connection.outgoing.empty()) return arm_connection(connection, POLLOUT);
			}
			std::array<std::byte, 16 * 1024> buffer{};
			std::size_t count = 0;
			int result = 1;
			if (connection.prefetched_offset < connection.prefetched.size()) {
				count = std::min(buffer.size(), connection.prefetched.size() - connection.prefetched_offset);
				std::memcpy(buffer.data(), connection.prefetched.data() + connection.prefetched_offset, count);
				connection.prefetched_offset += count;
				if (connection.prefetched_offset == connection.prefetched.size()) {
					connection.prefetched.clear();
					connection.prefetched_offset = 0;
				}
			} else {
				ERR_clear_error();
				result = SSL_read_ex(connection.ssl, buffer.data(), buffer.size(), &count);
			}
			if (result != 1) {
				const int error = SSL_get_error(connection.ssl, result);
				if (error == SSL_ERROR_ZERO_RETURN) {
					connection.close_code = 1006;
					connection.close_reason = "TLS closed without a WebSocket close frame";
					return false;
				}
				return wait_for(connection, error);
			}
			for (Frame& frame : connection.decoder.consume(std::span<const std::byte>(buffer.data(), count))) {
				if (frame.type == FrameType::ping) {
					auto pong = encode_client_frame(FrameType::pong, frame.payload);
					const std::size_t accounted_bytes = pong.size();
					if (!reserve_outgoing(accounted_bytes)) {
						fail(connection.id, "WebSocket control-frame queue limit exceeded");
						return false;
					}
					try {
						connection.outgoing.push_back({
							.bytes = std::move(pong),
							.accounted_bytes = accounted_bytes,
							.type = FrameType::pong});
					} catch (...) {
						release_outgoing(accounted_bytes);
						throw;
					}
				} else if (frame.type == FrameType::close) {
					validate_close_payload(frame.payload);
					const std::uint16_t code = frame.payload.size() >= 2
							? static_cast<std::uint16_t>((std::to_integer<unsigned char>(frame.payload[0]) << 8)
								| std::to_integer<unsigned char>(frame.payload[1])) : 1005;
					const std::string reason = frame.payload.size() > 2
							? std::string(reinterpret_cast<const char*>(frame.payload.data() + 2), frame.payload.size() - 2)
							: std::string{};
					connection.close_received = true;
					connection.close_code = code;
					connection.close_reason = reason;
					connection.closing = true;
					connection.lifecycle->state.store(ConnectionState::closing,
						std::memory_order_release);
					if (connection.close_sent) return false;
					const bool partial_frame = connection.outgoing_offset > 0;
					const bool partial_close = partial_frame
						&& connection.outgoing.front().type == FrameType::close;
					const std::size_t first_discarded = partial_frame ? 1 : 0;
					std::size_t discarded_bytes = 0;
					for (std::size_t index = first_discarded; index < connection.outgoing.size(); ++index) {
						discarded_bytes += connection.outgoing[index].accounted_bytes;
					}
					release_outgoing(discarded_bytes);
					if (partial_frame) {
						OutgoingFrame in_flight = std::move(connection.outgoing.front());
						connection.outgoing.clear();
						connection.outgoing.push_back(std::move(in_flight));
					} else {
						connection.outgoing.clear();
						connection.outgoing_offset = 0;
					}
					if (!partial_close) {
						connection.outgoing.push_back({
							.bytes = encode_client_frame(FrameType::close, frame.payload),
							.type = FrameType::close});
					}
					set_timeout(connection.id, connection.timeouts.close);
					return arm_connection(connection, POLLOUT);
				} else {
					auto message = connection.assembler.consume(std::move(frame));
					if (message && !notify_message(connection, message->type,
						std::move(message->payload))) return false;
				}
			}
			if (SSL_has_pending(connection.ssl)) continue;
			if (!arm_connection(connection, POLLIN | (connection.outgoing.empty() ? 0 : POLLOUT))) return false;
			return true;
			}
			defer_drive(connection.id);
			return true;
		}
		return true;
	}

	void notify_close(SocketConnection& connection) {
		if (connection.close_notified) return;
		connection.close_notified = true;
		auto callbacks = connection.callbacks;
		if (!callbacks->on_close) return;
		Connection connection_handle = handle(connection.id);
		post_callback(connection.id, [callbacks = std::move(callbacks),
			connection_handle = std::move(connection_handle), code = connection.close_code,
			reason = std::move(connection.close_reason)]() mutable {
			if (callbacks->on_close) {
				callbacks->on_close(std::move(connection_handle), code, reason);
			}
		}, 0, true);
	}

	void fail(std::uint64_t id, std::string_view message) {
		auto found = connections.find(id);
		if (found == connections.end()) return;
		found->second->lifecycle->state.store(ConnectionState::failed,
			std::memory_order_release);
		auto callbacks = found->second->callbacks;
		Connection connection_handle = handle(id);
		std::string error(message);
		post_callback(id, [callbacks = std::move(callbacks), connection_handle = std::move(connection_handle), error = std::move(error)]() mutable {
			if (callbacks->on_error) callbacks->on_error(std::move(connection_handle), error);
		}, 0, true);
		erase_connection(id);
	}

	bool notify_message(SocketConnection& connection, MessageType type, std::vector<std::byte> message) {
		set_timeout(connection.id, connection.timeouts.idle);
		auto callbacks = connection.callbacks;
		if (!callbacks->on_message) return true;
		Connection connection_handle = handle(connection.id);
		const std::size_t message_size = message.size();
		const bool queued = post_callback(connection.id, [callbacks = std::move(callbacks), connection_handle = std::move(connection_handle),
			type, message = std::move(message)]() mutable {
			if (callbacks->on_message) callbacks->on_message(std::move(connection_handle), type, message);
		}, message_size);
		if (!queued) {
			fail(connection.id, "callback queue limit exceeded");
			return false;
		}
		return true;
	}

	static constexpr std::uint64_t timer_tag = std::uint64_t{1} << 62;
	io_uring ring{};
	SSL_CTX* tls_context = nullptr;
	int wake_fd = -1;
	int timer_fd = -1;
	bool wake_armed = false;
	bool timer_armed = false;
	bool suppress_timer_updates = false;
	std::atomic<bool> stopping{false};
	std::atomic<bool> wake_pending{false};
	std::atomic<std::uint64_t> next_id{1};
	std::jthread reactor;
	std::vector<std::jthread> resolvers;
	struct CallbackTask {
		std::move_only_function<void()> callback;
		std::size_t bytes = 0;
		bool terminal = false;
	};
	struct CallbackQueue {
		std::deque<CallbackTask> callbacks;
		bool active = false;
		bool release_connection_slot = false;
	};
	std::vector<std::jthread> callback_workers;
	std::mutex callback_mutex;
	std::condition_variable_any callback_cv;
	std::deque<std::uint64_t> ready_callbacks;
	std::unordered_map<std::uint64_t, CallbackQueue> callback_queues;
	std::size_t pending_callback_tasks = 0;
	std::size_t pending_terminal_callback_tasks = 0;
	std::size_t pending_callback_bytes = 0;
	std::size_t pending_terminal_callback_bytes = 0;
	bool callbacks_stopping = false;
	std::mutex command_mutex;
	std::deque<Command> commands;
	std::size_t pending_outgoing_bytes = 0;
	std::mutex resolve_mutex;
	std::condition_variable_any resolve_cv;
	std::deque<ResolveTask> resolve_tasks;
	std::unordered_map<std::string, CachedAddress> dns_cache;
	std::unordered_map<std::uint64_t, std::unique_ptr<SocketConnection>> connections;
	std::set<std::pair<std::chrono::steady_clock::time_point, std::uint64_t>> deadlines;
	std::deque<std::uint64_t> deferred_drives;
	std::unordered_set<std::uint64_t> deferred_drive_set;
};

struct ConnectionImpl {
	std::weak_ptr<Runtime> runtime;
	std::uint64_t id;
	std::shared_ptr<ConnectionLifecycle> lifecycle;
};

struct ClientImpl {
	explicit ClientImpl(ClientOptions options) : runtime(std::make_shared<Runtime>(options)) {}
	std::shared_ptr<Runtime> runtime;
	~ClientImpl() {
		if (!runtime || !runtime->is_callback_worker()) return;
		auto keep_alive = std::move(runtime);
		std::thread([runtime = std::move(keep_alive)]() mutable {
			runtime.reset();
		}).detach();
	}
};

} // namespace echter::ws::client::detail

namespace echter::ws::client {

Client::Client(ClientOptions options)
	: impl_(std::make_unique<detail::ClientImpl>(options)) {}
Client::~Client() = default;
Client::Client(Client&&) noexcept = default;
Client& Client::operator=(Client&&) noexcept = default;

Connection::Connection() = default;

Connection Client::connect(std::string_view url, Callbacks callbacks, Timeouts timeouts) {
	if (!impl_ || !impl_->runtime) throw std::logic_error("client has been moved from");
	if (timeouts.connect.count() < 0 || timeouts.handshake.count() < 0
		|| timeouts.idle.count() < 0 || timeouts.close.count() < 0) {
		throw std::invalid_argument("connection timeouts must not be negative");
	}
	auto runtime = impl_->runtime;
	const std::uint64_t id = runtime->next_id.fetch_add(1, std::memory_order_relaxed);
	auto lifecycle = std::make_shared<detail::ConnectionLifecycle>();
	detail::Command command{.type = detail::CommandType::start, .id = id,
		.url = echter::ws::detail::parse_url(url), .callbacks = std::move(callbacks),
		.timeouts = timeouts, .lifecycle = lifecycle};
	if (!runtime->post(std::move(command))) {
		throw std::length_error("WebSocket command queue limit exceeded");
	}
	return Connection(runtime, id, std::move(lifecycle));
}

Connection::Connection(std::weak_ptr<detail::Runtime> runtime, std::uint64_t id,
	std::shared_ptr<detail::ConnectionLifecycle> lifecycle)
	: impl_(std::make_unique<detail::ConnectionImpl>(detail::ConnectionImpl{
		.runtime = std::move(runtime), .id = id, .lifecycle = std::move(lifecycle)})) {}

Connection::Connection(const Connection& other) {
	if (other.impl_) impl_ = std::make_unique<detail::ConnectionImpl>(*other.impl_);
}

Connection& Connection::operator=(const Connection& other) {
	if (this != &other) {
		impl_ = other.impl_ ? std::make_unique<detail::ConnectionImpl>(*other.impl_) : nullptr;
	}
	return *this;
}

Connection::Connection(Connection&&) noexcept = default;
Connection& Connection::operator=(Connection&&) noexcept = default;
Connection::~Connection() = default;

Connection::operator bool() const noexcept {
	return impl_ && impl_->id != 0;
}

ConnectionState Connection::state() const noexcept {
	if (!impl_ || !impl_->lifecycle) return ConnectionState::invalid;
	return impl_->lifecycle->state.load(std::memory_order_acquire);
}

void Connection::send_message(std::string_view message) const {
	if (message.size() > max_message_size) throw std::length_error("WebSocket message exceeds the 8 MiB limit");
	const auto* data = reinterpret_cast<const std::byte*>(message.data());
	if (!valid_utf8(std::span<const std::byte>(data, message.size()))) {
		throw std::invalid_argument("WebSocket text message is not valid UTF-8");
	}
	if (!impl_) return;
	const ConnectionState current_state = state();
	if (current_state == ConnectionState::closing || current_state == ConnectionState::closed
		|| current_state == ConnectionState::failed) {
		throw std::logic_error("cannot send on a closed WebSocket connection");
	}
	if (auto runtime = impl_->runtime.lock()) {
		detail::Command command{.type = detail::CommandType::send, .id = impl_->id,
			.message_type = MessageType::text, .lifecycle = impl_->lifecycle};
		command.payload.resize(message.size());
		std::memcpy(command.payload.data(), message.data(), message.size());
		if (!runtime->post(std::move(command))) {
			const ConnectionState state_after_rejection = state();
			if (state_after_rejection == ConnectionState::closing
				|| state_after_rejection == ConnectionState::closed
				|| state_after_rejection == ConnectionState::failed) {
				throw std::logic_error("cannot send on a closed WebSocket connection");
			}
			throw std::length_error("WebSocket outbound queue limit exceeded");
		}
	} else {
		throw std::logic_error("cannot send on a closed WebSocket connection");
	}
}

void Connection::send_binary(std::span<const std::byte> message) const {
	if (message.size() > max_message_size) throw std::length_error("WebSocket message exceeds the 8 MiB limit");
	if (!impl_) return;
	const ConnectionState current_state = state();
	if (current_state == ConnectionState::closing || current_state == ConnectionState::closed
		|| current_state == ConnectionState::failed) {
		throw std::logic_error("cannot send on a closed WebSocket connection");
	}
	if (auto runtime = impl_->runtime.lock()) {
		detail::Command command{.type = detail::CommandType::send, .id = impl_->id,
			.payload = std::vector<std::byte>(message.begin(), message.end()),
			.message_type = MessageType::binary, .lifecycle = impl_->lifecycle};
		if (!runtime->post(std::move(command))) {
			const ConnectionState state_after_rejection = state();
			if (state_after_rejection == ConnectionState::closing
				|| state_after_rejection == ConnectionState::closed
				|| state_after_rejection == ConnectionState::failed) {
				throw std::logic_error("cannot send on a closed WebSocket connection");
			}
			throw std::length_error("WebSocket outbound queue limit exceeded");
		}
	} else {
		throw std::logic_error("cannot send on a closed WebSocket connection");
	}
}

bool Connection::close() const {
	if (impl_) {
		if (state() == ConnectionState::closing || state() == ConnectionState::closed
			|| state() == ConnectionState::failed) return false;
		if (auto runtime = impl_->runtime.lock()) {
			return runtime->post({.type = detail::CommandType::close, .id = impl_->id,
				.lifecycle = impl_->lifecycle});
		}
	}
	return false;
}

} // namespace echter::ws::client