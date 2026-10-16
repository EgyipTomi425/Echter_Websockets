module;

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>
#include <openssl/rand.h>

export module echter.ws.frame;

export namespace echter::ws {

enum class MessageType : unsigned char {
	text = 0x1,
	binary = 0x2,
};

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
};

struct Message {
	MessageType type;
	std::vector<std::byte> payload;
};

inline constexpr std::size_t max_message_size = 8 * 1024 * 1024;

inline bool valid_utf8(std::span<const std::byte> bytes) noexcept {
	std::size_t index = 0;
	while (index < bytes.size()) {
		const unsigned char first = std::to_integer<unsigned char>(bytes[index++]);
		if (first <= 0x7f) continue;

		std::uint32_t code_point = 0;
		std::uint32_t minimum = 0;
		std::size_t continuation_count = 0;
		if (first >= 0xc2 && first <= 0xdf) {
			code_point = first & 0x1f;
			minimum = 0x80;
			continuation_count = 1;
		} else if (first >= 0xe0 && first <= 0xef) {
			code_point = first & 0x0f;
			minimum = 0x800;
			continuation_count = 2;
		} else if (first >= 0xf0 && first <= 0xf4) {
			code_point = first & 0x07;
			minimum = 0x10000;
			continuation_count = 3;
		} else {
			return false;
		}

		if (continuation_count > bytes.size() - index) return false;
		for (std::size_t offset = 0; offset < continuation_count; ++offset) {
			const unsigned char next = std::to_integer<unsigned char>(bytes[index++]);
			if ((next & 0xc0) != 0x80) return false;
			code_point = (code_point << 6) | (next & 0x3f);
		}
		if (code_point < minimum || code_point > 0x10ffff
			|| (code_point >= 0xd800 && code_point <= 0xdfff)) return false;
	}
	return true;
}

inline Message make_message(MessageType type, std::vector<std::byte> payload) {
	if (type == MessageType::text && !valid_utf8(payload)) {
		throw std::runtime_error("WebSocket text message is not valid UTF-8");
	}
	return {type, std::move(payload)};
}

inline bool valid_close_code(std::uint16_t code) noexcept {
	if (code < 1000 || code >= 5000 || code == 1004 || code == 1005
		|| code == 1006 || code == 1015) {
		return false;
	}
	return code <= 1014 || code >= 3000;
}

inline void validate_close_payload(std::span<const std::byte> payload) {
	if (payload.size() == 1 || payload.size() > 125) {
		throw std::runtime_error("invalid WebSocket close payload length");
	}
	if (payload.size() < 2) return;
	const auto code = static_cast<std::uint16_t>(
		(std::to_integer<unsigned char>(payload[0]) << 8)
		| std::to_integer<unsigned char>(payload[1]));
	if (!valid_close_code(code)) {
		throw std::runtime_error("invalid WebSocket close status code");
	}
	if (!valid_utf8(payload.subspan(2))) {
		throw std::runtime_error("WebSocket close reason is not valid UTF-8");
	}
}

inline std::vector<std::byte> encode_client_frame(FrameType type,
	std::span<const std::byte> payload) {
	const auto opcode = static_cast<unsigned char>(type);
	if (opcode != 0x0 && opcode != 0x1 && opcode != 0x2
		&& opcode != 0x8 && opcode != 0x9 && opcode != 0xa) {
		throw std::invalid_argument("unsupported WebSocket frame opcode");
	}
	if (type == FrameType::text && !valid_utf8(payload)) {
		throw std::runtime_error("WebSocket text frame is not valid UTF-8");
	}
	if (type == FrameType::close) validate_close_payload(payload);
	if (payload.size() > max_message_size) {
		throw std::length_error("WebSocket frame exceeds the 8 MiB limit");
	}
	const bool control = (opcode & 0x08) != 0;
	if (control && payload.size() > 125) {
		throw std::length_error("WebSocket control frame exceeds 125 bytes");
	}

	std::vector<std::byte> result;
	result.reserve(payload.size() + 14);
	result.push_back(static_cast<std::byte>(0x80 | opcode));
	if (payload.size() < 126) {
		result.push_back(static_cast<std::byte>(0x80 | payload.size()));
	} else if (payload.size() <= 0xffff) {
		result.push_back(static_cast<std::byte>(0x80 | 126));
		result.push_back(static_cast<std::byte>(payload.size() >> 8));
		result.push_back(static_cast<std::byte>(payload.size()));
	} else {
		result.push_back(static_cast<std::byte>(0x80 | 127));
		const std::uint64_t length = payload.size();
		for (int shift = 56; shift >= 0; shift -= 8) {
			result.push_back(static_cast<std::byte>(length >> shift));
		}
	}

	std::array<unsigned char, 4> mask{};
	if (RAND_bytes(mask.data(), static_cast<int>(mask.size())) != 1) {
		throw std::runtime_error("failed to generate WebSocket mask");
	}
	for (const unsigned char value : mask) {
		result.push_back(static_cast<std::byte>(value));
	}
	for (std::size_t index = 0; index < payload.size(); ++index) {
		result.push_back(payload[index]
			^ static_cast<std::byte>(mask[index % mask.size()]));
	}
	return result;
}

class MessageAssembler {
public:
	std::optional<Message> consume(Frame frame) {
		if (frame.type == FrameType::ping || frame.type == FrameType::pong
			|| frame.type == FrameType::close) return std::nullopt;

		if (frame.type == FrameType::text || frame.type == FrameType::binary) {
			if (fragmented_) throw std::runtime_error("new data frame during fragmented message");
			const MessageType type = frame.type == FrameType::text
				? MessageType::text : MessageType::binary;
			if (frame.final) return make_message(type, std::move(frame.payload));
			fragmented_ = true;
			fragmented_type_ = type;
			fragmented_payload_ = std::move(frame.payload);
			return std::nullopt;
		}

		if (frame.type != FrameType::continuation || !fragmented_) {
			throw std::runtime_error("unexpected WebSocket continuation frame");
		}
		if (frame.payload.size() > max_message_size - fragmented_payload_.size()) {
			throw std::length_error("fragmented WebSocket message exceeds the 8 MiB limit");
		}
		fragmented_payload_.insert(fragmented_payload_.end(),
			frame.payload.begin(), frame.payload.end());
		if (!frame.final) return std::nullopt;

		fragmented_ = false;
		return make_message(fragmented_type_, std::exchange(fragmented_payload_, {}));
	}

	void reset() noexcept {
		fragmented_ = false;
		fragmented_payload_.clear();
	}

private:
	bool fragmented_ = false;
	MessageType fragmented_type_ = MessageType::text;
	std::vector<std::byte> fragmented_payload_;
};

class FrameDecoder {
public:
	std::vector<Frame> consume(std::span<const std::byte> bytes) {
		std::vector<Frame> frames;
		std::size_t input_offset = 0;
		do {
			const std::size_t capacity = max_message_size + 14 - buffer_.size();
			const std::size_t append_size = std::min(capacity, bytes.size() - input_offset);
			if (append_size == 0 && input_offset < bytes.size()) {
				throw std::length_error("WebSocket receive buffer limit exceeded");
			}
			buffer_.insert(buffer_.end(), bytes.begin() + static_cast<std::ptrdiff_t>(input_offset),
				bytes.begin() + static_cast<std::ptrdiff_t>(input_offset + append_size));
			input_offset += append_size;

			std::size_t consumed = 0;
			while (buffer_.size() - consumed >= 2) {
				const unsigned char first = std::to_integer<unsigned char>(buffer_[consumed]);
				const unsigned char second = std::to_integer<unsigned char>(buffer_[consumed + 1]);
				const bool final = (first & 0x80) != 0;
				const unsigned char opcode = first & 0x0f;
				if ((first & 0x70) != 0 || (second & 0x80) != 0) {
					throw std::runtime_error("invalid WebSocket frame flags");
				}

				std::uint64_t payload_size = second & 0x7f;
				std::size_t header_size = 2;
				if (payload_size == 126) {
					if (buffer_.size() - consumed < 4) {
						break;
					}
					payload_size = (static_cast<std::uint64_t>(
						std::to_integer<unsigned char>(buffer_[consumed + 2])) << 8)
						| std::to_integer<unsigned char>(buffer_[consumed + 3]);
					if (payload_size < 126) {
						throw std::runtime_error("non-canonical WebSocket payload length");
					}
					header_size = 4;
				} else if (payload_size == 127) {
					if (buffer_.size() - consumed < 10) {
						break;
					}
					payload_size = 0;
					for (std::size_t index = 0; index < 8; ++index) {
						payload_size = (payload_size << 8)
							| std::to_integer<unsigned char>(buffer_[consumed + 2 + index]);
					}
					if ((payload_size >> 63) != 0) {
						throw std::runtime_error("invalid WebSocket payload length");
					}
					if (payload_size <= 0xffff) {
						throw std::runtime_error("non-canonical WebSocket payload length");
					}
					header_size = 10;
				}

				const bool control = (opcode & 0x08) != 0;
				if ((control && (!final || payload_size > 125))
					|| payload_size > max_message_size) {
					throw std::runtime_error("invalid or oversized WebSocket frame");
				}
				if (opcode != 0x0 && opcode != 0x1 && opcode != 0x2
					&& opcode != 0x8 && opcode != 0x9 && opcode != 0xa) {
					throw std::runtime_error("unsupported WebSocket opcode");
				}
				if (payload_size > buffer_.size() - consumed - header_size) {
					break;
				}

				Frame frame{
					.type = static_cast<FrameType>(opcode),
					.final = final,
					.payload = {},
				};
				const auto payload_start = buffer_.begin()
					+ static_cast<std::ptrdiff_t>(consumed + header_size);
				frame.payload.assign(payload_start,
					payload_start + static_cast<std::ptrdiff_t>(payload_size));
				frames.push_back(std::move(frame));
				consumed += header_size + static_cast<std::size_t>(payload_size);
			}

			buffer_.erase(buffer_.begin(),
				buffer_.begin() + static_cast<std::ptrdiff_t>(consumed));
		} while (input_offset < bytes.size());
		return frames;
	}

private:
	std::vector<std::byte> buffer_;
};

} // namespace echter::ws