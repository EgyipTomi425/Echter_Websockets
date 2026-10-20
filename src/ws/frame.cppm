module;

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

export module echter.ws.frame;

export namespace echter::ws {

enum class MessageType : unsigned char { text = 0x1, binary = 0x2 };
enum class FrameType : unsigned char {
	continuation = 0x0,
	text = 0x1,
	binary = 0x2,
	close = 0x8,
	ping = 0x9,
	pong = 0xa,
};

struct Frame {
	FrameType type;
	bool final;
	std::vector<std::byte> payload;
	bool compressed = false;
};

struct Message {
	MessageType type;
	std::vector<std::byte> payload;
	bool compressed = false;
};

inline constexpr std::size_t max_message_size = 8 * 1024 * 1024;

[[nodiscard]] bool valid_utf8(std::span<const std::byte> bytes) noexcept;
[[nodiscard]] Message make_message(MessageType type, std::vector<std::byte> payload,
	bool compressed = false);
[[nodiscard]] bool valid_close_code(std::uint16_t code) noexcept;
void validate_close_payload(std::span<const std::byte> payload);
[[nodiscard]] std::vector<std::byte> encode_client_frame(FrameType type,
	std::span<const std::byte> payload, bool compressed = false);

class MessageAssembler {
public:
	[[nodiscard]] std::optional<Message> consume(Frame frame,
		bool compression_negotiated = false);
	void reset() noexcept;

private:
	bool fragmented_ = false;
	bool fragmented_compressed_ = false;
	MessageType fragmented_type_ = MessageType::text;
	std::vector<std::byte> fragmented_payload_;
};

class FrameDecoder {
public:
	[[nodiscard]] std::vector<Frame> consume(std::span<const std::byte> bytes);

private:
	std::vector<std::byte> buffer_;
};

} // namespace echter::ws