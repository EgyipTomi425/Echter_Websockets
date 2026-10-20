module;

#include <string>
#include <string_view>
#include <utility>
#include <vector>

export module echter.ws.handshake;

export namespace echter::ws::detail {

struct Url {
	std::string host;
	std::string port;
	std::string host_header;
	std::string target;
};

struct PerMessageDeflateSelection {
	bool enabled = false;
	bool client_no_context_takeover = false;
	bool server_no_context_takeover = false;
};

[[nodiscard]] bool contains_control_chars(std::string_view value);
[[nodiscard]] bool is_numeric_port(std::string_view value);
[[nodiscard]] std::string trim_ascii(std::string_view value);
[[nodiscard]] std::string lower_ascii(std::string_view value);
[[nodiscard]] std::vector<std::pair<std::string, std::string>> parse_response_headers(
	std::string_view response);
[[nodiscard]] std::vector<std::string> response_header_values(
	const std::vector<std::pair<std::string, std::string>>& headers,
	std::string_view requested_name);
[[nodiscard]] PerMessageDeflateSelection parse_permessage_deflate_selection(
	const std::vector<std::string>& values, bool offered);
[[nodiscard]] Url parse_url(std::string_view url);
[[nodiscard]] std::string make_websocket_key();
[[nodiscard]] std::string websocket_accept(std::string_view key);

PerMessageDeflateSelection validate_upgrade(std::string_view response,
	std::string_view key, bool offered_permessage_deflate = false);

} // namespace echter::ws::detail