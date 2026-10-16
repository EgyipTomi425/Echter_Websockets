module;

#include <arpa/inet.h>
#include <array>
#include <cctype>
#include <cstddef>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module echter.ws.handshake;

export namespace echter::ws::detail {

inline bool contains_control_chars(std::string_view value) {
	for (const unsigned char ch : value) {
		if (ch <= 0x1f || ch == 0x7f) {
			return true;
		}
	}
	return false;
}

inline bool is_numeric_port(std::string_view value) {
	if (value.empty() || value.size() > 5) {
		return false;
	}
	for (const unsigned char ch : value) {
		if (!std::isdigit(ch)) {
			return false;
		}
	}
	const unsigned long port = std::stoul(std::string(value));
	return port >= 1 && port <= 65535;
}

inline std::string trim_ascii(std::string_view value) {
	std::size_t begin = 0;
	while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) {
		++begin;
	}
	std::size_t end = value.size();
	while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) {
		--end;
	}
	return std::string(value.substr(begin, end - begin));
}

inline std::string lower_ascii(std::string_view value) {
	std::string lowered(value);
	for (char& ch : lowered) {
		ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
	}
	return lowered;
}

inline std::vector<std::pair<std::string, std::string>> parse_response_headers(
	std::string_view response) {
	const std::size_t status_end = response.find("\r\n");
	if (status_end == std::string_view::npos || !response.ends_with("\r\n\r\n")) {
		throw std::runtime_error("malformed WebSocket upgrade response headers");
	}
	std::vector<std::pair<std::string, std::string>> headers;
	std::size_t line_start = status_end + 2;
	while (line_start < response.size()) {
		const std::size_t line_end = response.find("\r\n", line_start);
		if (line_end == std::string_view::npos) {
			throw std::runtime_error("malformed WebSocket upgrade header line");
		}
		if (line_end == line_start) {
			if (line_end + 2 != response.size()) {
				throw std::runtime_error("unexpected data after WebSocket upgrade headers");
			}
			return headers;
		}
		const std::string_view line = response.substr(line_start, line_end - line_start);
		const std::size_t colon = line.find(':');
		if (colon == std::string_view::npos || colon == 0
			|| line.front() == ' ' || line.front() == '\t') {
			throw std::runtime_error("malformed WebSocket upgrade header line");
		}
		const std::string_view name = line.substr(0, colon);
		for (const unsigned char ch : name) {
			const bool token = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
				|| (ch >= '0' && ch <= '9') || std::string_view("!#$%&'*+-.^_`|~").find(ch)
					!= std::string_view::npos;
			if (!token) throw std::runtime_error("invalid WebSocket upgrade header name");
		}
		const std::string_view value = line.substr(colon + 1);
		for (const unsigned char ch : value) {
			if ((ch < 0x20 && ch != '\t') || ch == 0x7f) {
				throw std::runtime_error("invalid control character in WebSocket upgrade header");
			}
		}
		headers.emplace_back(lower_ascii(name), trim_ascii(value));
		line_start = line_end + 2;
	}
	throw std::runtime_error("malformed WebSocket upgrade response headers");
}

inline std::vector<std::string> response_header_values(
	const std::vector<std::pair<std::string, std::string>>& headers,
	std::string_view requested_name) {
	const std::string wanted = lower_ascii(requested_name);
	std::vector<std::string> values;
	for (const auto& [name, value] : headers) {
		if (name == wanted) values.push_back(value);
	}
	return values;
}

struct Url {
	std::string host;
	std::string port;
	std::string host_header;
	std::string target;
};

inline Url parse_url(std::string_view url) {
	constexpr std::string_view scheme = "wss://";
	constexpr std::size_t max_url_size = 16 * 1024;
	if (url.size() > max_url_size) {
		throw std::length_error("WebSocket URL exceeds the 16 KiB limit");
	}
	if (url.size() < scheme.size()
		|| lower_ascii(url.substr(0, scheme.size())) != scheme) {
		throw std::invalid_argument("only wss:// URLs are supported");
	}
	if (contains_control_chars(url)) {
		throw std::invalid_argument("WebSocket URL contains forbidden control characters");
	}
	url.remove_prefix(scheme.size());

	const std::size_t authority_end = url.find_first_of("/?#");
	const std::string_view authority = url.substr(0, authority_end);
	if (authority.empty() || authority.find('@') != std::string_view::npos) {
		throw std::invalid_argument("invalid WebSocket URL authority");
	}
	if (contains_control_chars(authority)) {
		throw std::invalid_argument("WebSocket URL authority contains forbidden control characters");
	}

	std::string_view host;
	std::string_view port = "443";
	std::string host_header;
	bool ipv6_literal = false;
	if (authority.front() == '[') {
		const std::size_t close = authority.find(']');
		if (close == std::string_view::npos) {
			throw std::invalid_argument("invalid IPv6 URL host");
		}
		host = authority.substr(1, close - 1);
		ipv6_literal = true;
		host_header = std::string(authority.substr(0, close + 1));
		if (close + 1 < authority.size()) {
			if (authority[close + 1] != ':') {
				throw std::invalid_argument("invalid URL port");
			}
			port = authority.substr(close + 2);
		}
	} else {
		const std::size_t colon = authority.rfind(':');
		if (colon != std::string_view::npos) {
			if (authority.find(':') != colon) {
				throw std::invalid_argument("IPv6 URL hosts must be bracketed");
			}
			host = authority.substr(0, colon);
			port = authority.substr(colon + 1);
		} else {
			host = authority;
		}
		host_header = std::string(host);
	}
	if (host.empty() || port.empty()) {
		throw std::invalid_argument("URL host and port must not be empty");
	}
	if (contains_control_chars(host) || contains_control_chars(port)) {
		throw std::invalid_argument("URL host or port contains forbidden control characters");
	}
	if (!is_numeric_port(port)) {
		throw std::invalid_argument("URL port must be a numeric value in range 1..65535");
	}
	if (ipv6_literal) {
		in6_addr address{};
		const std::string host_string(host);
		if (::inet_pton(AF_INET6, host_string.c_str(), &address) != 1) {
			throw std::invalid_argument("invalid IPv6 URL host");
		}
	} else {
		if (host.size() > 253) throw std::invalid_argument("URL host is too long");
		std::string_view labels = host;
		if (labels.ends_with('.')) labels.remove_suffix(1);
		while (!labels.empty()) {
			const std::size_t dot = labels.find('.');
			const std::string_view label = labels.substr(0, dot);
			if (label.empty() || label.size() > 63 || label.front() == '-'
				|| label.back() == '-') {
				throw std::invalid_argument("invalid DNS URL host");
			}
			for (const unsigned char ch : label) {
				if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
					|| (ch >= '0' && ch <= '9') || ch == '-')) {
					throw std::invalid_argument("invalid DNS URL host character");
				}
			}
			if (dot == std::string_view::npos) break;
			labels.remove_prefix(dot + 1);
		}
	}
	if (port != "443") {
		host_header += ":";
		host_header += port;
	}

	const std::size_t target_offset = authority_end == std::string_view::npos
		? url.size()
		: authority_end;
	std::string target(url.substr(target_offset));
	if (target.size() > 8 * 1024) {
		throw std::length_error("WebSocket request target exceeds the 8 KiB limit");
	}
	if (contains_control_chars(target)) {
		throw std::invalid_argument("WebSocket target contains forbidden control characters");
	}
	for (std::size_t index = 0; index < target.size(); ++index) {
		const unsigned char ch = static_cast<unsigned char>(target[index]);
		if (ch > 0x7e || ch == ' ' || ch == '\t') {
			throw std::invalid_argument("WebSocket target must be an escaped ASCII URI");
		}
		if (ch == '%') {
			const auto is_hex = [](unsigned char value) {
				return (value >= '0' && value <= '9') || (value >= 'a' && value <= 'f')
					|| (value >= 'A' && value <= 'F');
			};
			if (index + 2 >= target.size()
				|| !is_hex(static_cast<unsigned char>(target[index + 1]))
				|| !is_hex(static_cast<unsigned char>(target[index + 2]))) {
				throw std::invalid_argument("invalid percent escape in WebSocket target");
			}
			index += 2;
		}
	}
	if (target.find('#') != std::string::npos) {
		throw std::invalid_argument("URL fragments are not supported");
	}
	if (target.empty()) {
		target = "/";
	} else if (target.front() == '?') {
		target.insert(target.begin(), '/');
	}

	return Url{
		.host = std::string(host),
		.port = std::string(port),
		.host_header = std::move(host_header),
		.target = std::move(target),
	};
}

inline std::string make_websocket_key() {
	std::array<unsigned char, 16> random{};
	if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
		throw std::runtime_error("failed to generate WebSocket key");
	}
	std::array<unsigned char, 32> encoded{};
	const int size = EVP_EncodeBlock(encoded.data(), random.data(),
		static_cast<int>(random.size()));
	if (size <= 0) {
		throw std::runtime_error("failed to encode WebSocket key");
	}
	return std::string(reinterpret_cast<const char*>(encoded.data()),
		static_cast<std::size_t>(size));
}

inline std::string websocket_accept(std::string_view key) {
	constexpr std::string_view guid =
		"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
	const std::string input = std::string(key) + std::string(guid);
	std::array<unsigned char, EVP_MAX_MD_SIZE> digest{};
	unsigned digest_size = 0;
	if (EVP_Digest(input.data(), input.size(), digest.data(), &digest_size,
			EVP_sha1(), nullptr) != 1) {
		throw std::runtime_error("failed to calculate WebSocket accept value");
	}
	std::array<unsigned char, 64> encoded{};
	const int size = EVP_EncodeBlock(encoded.data(), digest.data(),
		static_cast<int>(digest_size));
	if (size <= 0) {
		throw std::runtime_error("failed to encode WebSocket accept value");
	}
	return std::string(reinterpret_cast<const char*>(encoded.data()),
		static_cast<std::size_t>(size));
}

inline void validate_upgrade(std::string_view response, std::string_view key) {
	const std::size_t status_end = response.find("\r\n");
	if (status_end == std::string_view::npos) {
		throw std::runtime_error("malformed WebSocket upgrade response");
	}
	const std::string_view status = response.substr(0, status_end);
	if (status.size() < 12 || status.substr(0, 9) != "HTTP/1.1 "
		|| status.substr(9, 3) != "101"
		|| (status.size() > 12 && status[12] != ' ')) {
		throw std::runtime_error("server rejected the WebSocket upgrade: "
			+ std::string(status));
	}
	const auto headers = parse_response_headers(response);
	const std::vector<std::string> upgrade = response_header_values(headers, "upgrade");
	if (upgrade.size() != 1 || lower_ascii(upgrade[0]) != "websocket") {
		throw std::runtime_error("missing or invalid Upgrade header");
	}
	const std::vector<std::string> connection = response_header_values(headers, "connection");
	if (connection.empty()) {
		throw std::runtime_error("missing Connection header");
	}
	bool has_upgrade_token = false;
	for (const std::string& value : connection) {
		std::string_view remaining = value;
		while (!remaining.empty()) {
			const std::size_t comma = remaining.find(',');
			const std::string_view candidate = comma == std::string_view::npos
				? remaining
				: remaining.substr(0, comma);
			if (lower_ascii(trim_ascii(candidate)) == "upgrade") {
				has_upgrade_token = true;
				break;
			}
			if (comma == std::string_view::npos) break;
			remaining = remaining.substr(comma + 1);
		}
		if (has_upgrade_token) break;
	}
	if (!has_upgrade_token) {
		throw std::runtime_error("Connection header does not contain Upgrade token");
	}
	const std::vector<std::string> accept_values = response_header_values(headers,
		"sec-websocket-accept");
	if (accept_values.size() != 1 || accept_values[0] != websocket_accept(key)) {
		throw std::runtime_error("invalid Sec-WebSocket-Accept response");
	}
	if (!response_header_values(headers, "sec-websocket-protocol").empty()
		|| !response_header_values(headers, "sec-websocket-extensions").empty()) {
		throw std::runtime_error("server selected an unrequested WebSocket option");
	}
}

} // namespace echter::ws::detail