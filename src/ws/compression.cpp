module;

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>
#include <span>
#include <stdexcept>
#include <vector>
#include <zlib.h>

module echter.ws.compression;

import echter.ws.frame;

namespace echter::ws {

struct PerMessageDeflate::Impl {
	explicit Impl(bool server_no_context_takeover) noexcept
		: server_no_context_takeover_(server_no_context_takeover) {}

	~Impl() {
		if (deflater_initialized_) (void)deflateEnd(&deflater_);
		if (inflater_initialized_) (void)inflateEnd(&inflater_);
	}

	DeflateResult compress(std::span<const std::byte> input) {
		if (input.size() > max_message_size) {
			throw std::length_error("WebSocket message exceeds the 8 MiB limit");
		}
		initialize_deflater();
		if (input.size() > std::numeric_limits<uInt>::max()) {
			throw std::length_error("DEFLATE input exceeds zlib's size limit");
		}

		deflater_.next_in = reinterpret_cast<Bytef*>(
			const_cast<std::byte*>(input.data()));
		deflater_.avail_in = static_cast<uInt>(input.size());
		std::vector<std::byte> output;
		std::array<std::byte, 16 * 1024> chunk{};
		int result = Z_OK;
		do {
			deflater_.next_out = reinterpret_cast<Bytef*>(chunk.data());
			deflater_.avail_out = static_cast<uInt>(chunk.size());
			result = deflate(&deflater_, Z_SYNC_FLUSH);
			if (result != Z_OK) {
				throw std::runtime_error("raw DEFLATE compression failed");
			}
			const std::size_t produced = chunk.size() - deflater_.avail_out;
			output.insert(output.end(), chunk.begin(), chunk.begin()
				+ static_cast<std::ptrdiff_t>(produced));
		} while (deflater_.avail_in != 0 || deflater_.avail_out == 0);

		if (output.size() < sync_flush_tail.size()
			|| !std::equal(sync_flush_tail.begin(), sync_flush_tail.end(),
				output.end() - static_cast<std::ptrdiff_t>(sync_flush_tail.size()))) {
			throw std::runtime_error("raw DEFLATE sync-flush trailer is missing");
		}
		output.resize(output.size() - sync_flush_tail.size());
		if (deflateReset(&deflater_) != Z_OK) {
			throw std::runtime_error("raw DEFLATE compressor reset failed");
		}
		if (output.size() >= input.size()) {
			return {std::vector<std::byte>(input.begin(), input.end()), false};
		}
		return {std::move(output), true};
	}

	std::vector<std::byte> decompress(std::span<const std::byte> input) {
		if (input.size() > max_message_size
			|| input.size() > std::numeric_limits<uInt>::max() - sync_flush_tail.size()) {
			throw std::length_error("compressed WebSocket message exceeds the wire limit");
		}
		initialize_inflater();
		std::vector<std::byte> framed(input.begin(), input.end());
		framed.insert(framed.end(), sync_flush_tail.begin(), sync_flush_tail.end());
		inflater_.next_in = reinterpret_cast<Bytef*>(framed.data());
		inflater_.avail_in = static_cast<uInt>(framed.size());

		std::vector<std::byte> output;
		std::array<std::byte, 16 * 1024> chunk{};
		bool stream_ended = false;
		for (;;) {
			const std::size_t remaining = max_message_size - output.size();
			const std::size_t capacity = std::min(chunk.size(), remaining + 1);
			inflater_.next_out = reinterpret_cast<Bytef*>(chunk.data());
			inflater_.avail_out = static_cast<uInt>(capacity);
			const uInt input_before = inflater_.avail_in;
			const int result = inflate(&inflater_, Z_SYNC_FLUSH);
			const std::size_t produced = capacity - inflater_.avail_out;
			if (produced > remaining) {
				throw std::length_error("decompressed WebSocket message exceeds the 8 MiB limit");
			}
			output.insert(output.end(), chunk.begin(), chunk.begin()
				+ static_cast<std::ptrdiff_t>(produced));
			if (result == Z_STREAM_END) {
				const auto* trailing_bytes = reinterpret_cast<const std::byte*>(inflater_.next_in);
				const bool plain_tail = inflater_.avail_in == sync_flush_tail.size()
					&& std::equal(sync_flush_tail.begin(), sync_flush_tail.end(), trailing_bytes);
				const bool empty_block_tail = inflater_.avail_in == sync_flush_tail.size() + 1
					&& trailing_bytes[0] == std::byte{0x00}
					&& std::equal(sync_flush_tail.begin(), sync_flush_tail.end(), trailing_bytes + 1);
				if (inflater_.avail_in != 0 && !plain_tail && !empty_block_tail) {
					throw std::runtime_error("trailing data in raw DEFLATE WebSocket payload");
				}
				stream_ended = true;
				break;
			}
			if (result != Z_OK && result != Z_BUF_ERROR) {
				throw std::runtime_error("invalid raw DEFLATE WebSocket payload");
			}
			if (inflater_.avail_in == 0 && inflater_.avail_out != 0) break;
			if (result == Z_BUF_ERROR && produced == 0) {
				throw std::runtime_error("incomplete raw DEFLATE WebSocket payload");
			}
			if (inflater_.avail_in == input_before && produced == 0) {
				throw std::runtime_error("raw DEFLATE decompressor made no progress");
			}
		}

		if ((server_no_context_takeover_ || stream_ended)
			&& inflateReset(&inflater_) != Z_OK) {
			throw std::runtime_error("raw DEFLATE inflater reset failed");
		}
		return output;
	}

	static constexpr std::array<std::byte, 4> sync_flush_tail{
		std::byte{0x00}, std::byte{0x00}, std::byte{0xff}, std::byte{0xff}};

	void initialize_deflater() {
		if (deflater_initialized_) return;
		if (deflateInit2(&deflater_, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
			-15, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
			throw std::runtime_error("raw DEFLATE compressor initialization failed");
		}
		deflater_initialized_ = true;
	}

	void initialize_inflater() {
		if (inflater_initialized_) return;
		if (inflateInit2(&inflater_, -15) != Z_OK) {
			throw std::runtime_error("raw DEFLATE inflater initialization failed");
		}
		inflater_initialized_ = true;
	}

	z_stream deflater_{};
	z_stream inflater_{};
	bool deflater_initialized_ = false;
	bool inflater_initialized_ = false;
	bool server_no_context_takeover_ = false;
};

PerMessageDeflate::PerMessageDeflate(bool server_no_context_takeover)
	: impl_(std::make_unique<Impl>(server_no_context_takeover)) {}

PerMessageDeflate::~PerMessageDeflate() = default;

DeflateResult PerMessageDeflate::compress(std::span<const std::byte> input) {
	return impl_->compress(input);
}

std::vector<std::byte> PerMessageDeflate::decompress(std::span<const std::byte> input) {
	return impl_->decompress(input);
}

} // namespace echter::ws