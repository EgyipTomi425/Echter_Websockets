#include <array>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

import echter.ws.frame;
import echter.ws.handshake;
import echter.ws.compression;

namespace {

echter::ws::Frame make_frame(echter::ws::FrameType type, bool final,
	std::string_view payload) {
	std::vector<std::byte> bytes;
	bytes.reserve(payload.size());
	for (const unsigned char value : payload) bytes.push_back(static_cast<std::byte>(value));
	return {type, final, std::move(bytes)};
}

std::string_view view(const std::vector<std::byte>& payload) {
	return {reinterpret_cast<const char*>(payload.data()), payload.size()};
}

void test_consecutive_complete_messages() {
	echter::ws::MessageAssembler assembler;
	auto first = assembler.consume(make_frame(echter::ws::FrameType::text, true, "one"));
	assert(first && first->type == echter::ws::MessageType::text && view(first->payload) == "one");
	auto second = assembler.consume(make_frame(echter::ws::FrameType::binary, true, "two"));
	assert(second && second->type == echter::ws::MessageType::binary && view(second->payload) == "two");
}

void test_permessage_deflate_round_trip() {
	const std::string input(4096, 'a');
	const auto* bytes = reinterpret_cast<const std::byte*>(input.data());
	echter::ws::PerMessageDeflate compressor(true);
	echter::ws::PerMessageDeflate decompressor(true);
	const auto compressed = compressor.compress(std::span<const std::byte>(bytes, input.size()));
	assert(compressed.compressed);
	const auto expanded = decompressor.decompress(compressed.payload);
	assert(expanded.size() == input.size());
	assert(std::equal(expanded.begin(), expanded.end(), bytes));

	const auto repeated = compressor.compress(std::span<const std::byte>(bytes, input.size()));
	assert(repeated.compressed);
	assert(decompressor.decompress(repeated.payload) == expanded);
}

void test_permessage_deflate_final_block_and_exact_limit() {
	const std::array<std::byte, 8> final_block{
		std::byte{0xf3}, std::byte{0x48}, std::byte{0xcd}, std::byte{0xc9},
		std::byte{0xc9}, std::byte{0x07}, std::byte{0x00}, std::byte{0x00}};
	echter::ws::PerMessageDeflate inflater;
	const auto hello = inflater.decompress(final_block);
	assert(std::string_view(reinterpret_cast<const char*>(hello.data()), hello.size()) == "Hello");

	const std::string input(echter::ws::max_message_size, 'q');
	const auto* bytes = reinterpret_cast<const std::byte*>(input.data());
	echter::ws::PerMessageDeflate compressor;
	echter::ws::PerMessageDeflate limit_inflater;
	const auto compressed = compressor.compress(std::span<const std::byte>(bytes, input.size()));
	assert(compressed.compressed);
	const auto expanded = limit_inflater.decompress(compressed.payload);
	assert(expanded.size() == echter::ws::max_message_size);
	assert(std::equal(expanded.begin(), expanded.end(), bytes));
}

void test_permessage_deflate_rejects_invalid_payloads() {
	echter::ws::PerMessageDeflate invalid_decompressor(true);
	const std::array<std::byte, 1> invalid{std::byte{0xff}};
	bool rejected_invalid = false;
	try {
		(void)invalid_decompressor.decompress(invalid);
	} catch (const std::runtime_error&) {
		rejected_invalid = true;
	}
	assert(rejected_invalid);

	const std::string input(4096, 'x');
	const auto* bytes = reinterpret_cast<const std::byte*>(input.data());
	echter::ws::PerMessageDeflate compressor(true);
	echter::ws::PerMessageDeflate decompressor(true);
	const auto compressed = compressor.compress(std::span<const std::byte>(bytes, input.size()));
	assert(compressed.compressed);
	auto expanded = decompressor.decompress(compressed.payload);
	assert(echter::ws::valid_utf8(expanded));

	std::vector<std::byte> invalid_text;
	for (std::size_t index = 0; index < 128; ++index) {
		invalid_text.push_back(std::byte{0xc0});
		invalid_text.push_back(std::byte{0xaf});
	}
	auto text_compressed = compressor.compress(invalid_text);
	assert(text_compressed.compressed);
	auto invalid_expanded = decompressor.decompress(text_compressed.payload);
	assert(!echter::ws::valid_utf8(invalid_expanded));
}

void test_control_frame_inside_fragmented_message() {
	echter::ws::MessageAssembler assembler;
	const auto first_fragment = assembler.consume(
		make_frame(echter::ws::FrameType::text, false, "hel"));
	assert(!first_fragment);
	const auto ping = assembler.consume(make_frame(echter::ws::FrameType::ping, true, "p"));
	assert(!ping);
	const auto second_fragment = assembler.consume(
		make_frame(echter::ws::FrameType::continuation, false, "l"));
	assert(!second_fragment);
	auto complete = assembler.consume(make_frame(echter::ws::FrameType::continuation, true, "o"));
	assert(complete && complete->type == echter::ws::MessageType::text);
	assert(view(complete->payload) == "hello");
}

void test_invalid_fragment_transitions() {
	echter::ws::MessageAssembler assembler;
	bool unexpected_continuation = false;
	try {
		(void)assembler.consume(make_frame(echter::ws::FrameType::continuation, true, "x"));
	} catch (const std::runtime_error&) {
		unexpected_continuation = true;
	}
	assert(unexpected_continuation);

	const auto first_fragment = assembler.consume(
		make_frame(echter::ws::FrameType::text, false, "x"));
	assert(!first_fragment);
	bool interleaved_data = false;
	try {
		(void)assembler.consume(make_frame(echter::ws::FrameType::binary, true, "y"));
	} catch (const std::runtime_error&) {
		interleaved_data = true;
	}
	assert(interleaved_data);
}

void test_frame_decoder() {
	const std::byte raw[]{std::byte{0x81}, std::byte{0x02}, std::byte{'o'}, std::byte{'k'}};
	echter::ws::FrameDecoder decoder;
	auto frames = decoder.consume(raw);
	assert(frames.size() == 1);
	assert(frames.front().type == echter::ws::FrameType::text);
	assert(frames.front().final);
	assert(view(frames.front().payload) == "ok");
}

void test_compressed_frame_and_fragment_rules() {
	const std::byte compressed_text[]{std::byte{0xc1}, std::byte{0x01}, std::byte{0x00}};
	echter::ws::FrameDecoder decoder;
	auto frames = decoder.consume(compressed_text);
	assert(frames.size() == 1 && frames.front().compressed);

	echter::ws::MessageAssembler assembler;
	auto message = assembler.consume(std::move(frames.front()), true);
	assert(message && message->compressed && message->type == echter::ws::MessageType::text);

	bool rejected_unnegotiated = false;
	try {
		(void)echter::ws::MessageAssembler{}.consume(
			{.type = echter::ws::FrameType::binary, .final = true, .payload = {}, .compressed = true});
	} catch (const std::runtime_error&) {
		rejected_unnegotiated = true;
	}
	assert(rejected_unnegotiated);

	const std::byte compressed_continuation[]{std::byte{0xc0}, std::byte{0x00}};
	bool rejected_continuation = false;
	try {
		(void)echter::ws::FrameDecoder{}.consume(compressed_continuation);
	} catch (const std::runtime_error&) {
		rejected_continuation = true;
	}
	assert(rejected_continuation);
}

void test_max_frame_with_coalesced_frames() {
	std::vector<std::byte> bytes;
	bytes.reserve(echter::ws::max_message_size + 10 + 300);
	bytes.push_back(std::byte{0x82});
	bytes.push_back(std::byte{127});
	for (int shift = 56; shift >= 0; shift -= 8) {
		bytes.push_back(static_cast<std::byte>(echter::ws::max_message_size >> shift));
	}
	bytes.resize(bytes.size() + echter::ws::max_message_size, std::byte{0x61});
	for (int index = 0; index < 100; ++index) {
		bytes.push_back(std::byte{0x81});
		bytes.push_back(std::byte{0x01});
		bytes.push_back(std::byte{'x'});
	}

	echter::ws::FrameDecoder decoder;
	const auto frames = decoder.consume(bytes);
	assert(frames.size() == 101);
	assert(frames.front().payload.size() == echter::ws::max_message_size);
	assert(view(frames.back().payload) == "x");
}

void test_noncanonical_payload_lengths() {
	const std::byte short_form[]{std::byte{0x82}, std::byte{126}, std::byte{0}, std::byte{125}};
	echter::ws::FrameDecoder short_decoder;
	bool rejected_short = false;
	try {
		(void)short_decoder.consume(short_form);
	} catch (const std::runtime_error&) {
		rejected_short = true;
	}
	assert(rejected_short);

	const std::byte extended_form[]{std::byte{0x82}, std::byte{127}, std::byte{0},
		std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0}, std::byte{0},
		std::byte{0}, std::byte{0xff}};
	echter::ws::FrameDecoder extended_decoder;
	bool rejected_extended = false;
	try {
		(void)extended_decoder.consume(extended_form);
	} catch (const std::runtime_error&) {
		rejected_extended = true;
	}
	assert(rejected_extended);
}

void test_text_utf8_validation_after_reassembly() {
	echter::ws::MessageAssembler assembler;
	const auto first_fragment = assembler.consume(
		make_frame(echter::ws::FrameType::text, false, "\xc3"));
	assert(!first_fragment);
	auto valid = assembler.consume(make_frame(echter::ws::FrameType::continuation, true, "\xa9"));
	assert(valid && view(valid->payload) == "\xc3\xa9");

	bool rejected_overlong = false;
	try {
		(void)assembler.consume(make_frame(echter::ws::FrameType::text, true, "\xc0\xaf"));
	} catch (const std::runtime_error&) {
		rejected_overlong = true;
	}
	assert(rejected_overlong);

	bool rejected_surrogate = false;
	try {
		(void)assembler.consume(make_frame(echter::ws::FrameType::text, true, "\xed\xa0\x80"));
	} catch (const std::runtime_error&) {
		rejected_surrogate = true;
	}
	assert(rejected_surrogate);
}

void test_close_payload_validation() {
	const std::array<std::byte, 4> valid_close{
		std::byte{0x03}, std::byte{0xe8}, std::byte{'o'}, std::byte{'k'}};
	echter::ws::validate_close_payload(valid_close);
	echter::ws::validate_close_payload({});

	constexpr std::array<std::uint16_t, 6> invalid_codes{1004, 1005, 1006, 1015, 2000, 5000};
	for (const std::uint16_t code : invalid_codes) {
		const std::array<std::byte, 2> payload{
			static_cast<std::byte>(code >> 8), static_cast<std::byte>(code)};
		bool rejected = false;
		try {
			echter::ws::validate_close_payload(payload);
		} catch (const std::runtime_error&) {
			rejected = true;
		}
		assert(rejected);
	}

	const std::array<std::byte, 3> invalid_reason{
		std::byte{0x03}, std::byte{0xe8}, std::byte{0xff}};
	bool rejected_reason = false;
	try {
		echter::ws::validate_close_payload(invalid_reason);
	} catch (const std::runtime_error&) {
		rejected_reason = true;
	}
	assert(rejected_reason);

	const std::array<std::byte, 1> invalid_length{std::byte{0x03}};
	bool rejected_length = false;
	try {
		echter::ws::validate_close_payload(invalid_length);
	} catch (const std::runtime_error&) {
		rejected_length = true;
	}
	assert(rejected_length);
}

void test_client_frame_encoder_validates_text_and_close() {
	const std::array<std::byte, 2> invalid_utf8{std::byte{0xc0}, std::byte{0xaf}};
	bool rejected_text = false;
	try {
		(void)echter::ws::encode_client_frame(echter::ws::FrameType::text, invalid_utf8);
	} catch (const std::runtime_error&) {
		rejected_text = true;
	}
	assert(rejected_text);

	const std::array<std::byte, 2> invalid_close_code{std::byte{0x03}, std::byte{0xed}};
	bool rejected_close = false;
	try {
		(void)echter::ws::encode_client_frame(echter::ws::FrameType::close, invalid_close_code);
	} catch (const std::runtime_error&) {
		rejected_close = true;
	}
	assert(rejected_close);
}

void test_url_rejects_control_and_invalid_ports() {
	const auto uppercase_scheme = echter::ws::detail::parse_url("WSS://example.com/path");
	assert(uppercase_scheme.host == "example.com");
	assert(uppercase_scheme.target == "/path");

	bool rejected_crlf = false;
	try {
		(void)echter::ws::detail::parse_url("wss://example.com/\r\nHost: evil");
	} catch (const std::invalid_argument&) {
		rejected_crlf = true;
	}
	assert(rejected_crlf);

	bool rejected_port = false;
	try {
		(void)echter::ws::detail::parse_url("wss://example.com:99999/");
	} catch (const std::invalid_argument&) {
		rejected_port = true;
	}
	assert(rejected_port);
	
	for (const std::string_view invalid_url : {
			std::string_view("wss://example.com/has space"),
			std::string_view("wss://example.com/%xz"),
			std::string_view("wss://[not-ipv6]/")}) {
		bool rejected = false;
		try {
			(void)echter::ws::detail::parse_url(invalid_url);
		} catch (const std::invalid_argument&) {
			rejected = true;
		}
		assert(rejected);
	}

	const std::string oversized_url = "wss://example.com/" + std::string(16 * 1024, 'a');
	bool rejected_oversized_url = false;
	try {
		(void)echter::ws::detail::parse_url(oversized_url);
	} catch (const std::length_error&) {
		rejected_oversized_url = true;
	}
	assert(rejected_oversized_url);
}

void test_upgrade_requires_required_websocket_tokens() {
	constexpr std::string_view key = "dGhlIHNhbXBsZSBub25jZQ==";
	const std::string good = std::string("HTTP/1.1 101 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\n"
		+ "Connection: Upgrade\r\n"
		+ "Sec-WebSocket-Accept: " + echter::ws::detail::websocket_accept(key) + "\r\n\r\n";
	bool accepted = true;
	try {
		echter::ws::detail::validate_upgrade(good, key);
	} catch (const std::exception&) {
		accepted = false;
	}
	assert(accepted);

	bool missing_connection = false;
	const std::string bad = std::string("HTTP/1.1 101 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\n"
		+ "Sec-WebSocket-Accept: " + echter::ws::detail::websocket_accept(key) + "\r\n\r\n";
	try {
		echter::ws::detail::validate_upgrade(bad, key);
	} catch (const std::runtime_error&) {
		missing_connection = true;
	}
	assert(missing_connection);

	const std::string accept = echter::ws::detail::websocket_accept(key);
	const std::string status_1012 = std::string("HTTP/1.1 1012 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
		+ accept + "\r\n\r\n";
	bool rejected_non_101 = false;
	try {
		echter::ws::detail::validate_upgrade(status_1012, key);
	} catch (const std::runtime_error&) {
		rejected_non_101 = true;
	}
	assert(rejected_non_101);

	for (const std::string_view unsolicited_header : {
			std::string_view("Sec-WebSocket-Protocol: chat\r\n"),
			std::string_view("Sec-WebSocket-Extensions: permessage-deflate\r\n")}) {
		const std::string unexpected = std::string("HTTP/1.1 101 Switching Protocols\r\n")
			+ "Upgrade: websocket\r\nConnection: keep-alive, Upgrade\r\n"
			+ "Sec-WebSocket-Accept: " + accept + "\r\n"
			+ std::string(unsolicited_header) + "\r\n";
		bool rejected_unsolicited = false;
		try {
			echter::ws::detail::validate_upgrade(unexpected, key);
		} catch (const std::runtime_error&) {
			rejected_unsolicited = true;
		}
		assert(rejected_unsolicited);
	}

	const std::string duplicate_accept = std::string("HTTP/1.1 101 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\nConnection: Upgrade\r\n"
		+ "Sec-WebSocket-Accept: " + accept + "\r\n"
		+ "Sec-WebSocket-Accept: " + accept + "\r\n\r\n";
	bool rejected_duplicate = false;
	try {
		echter::ws::detail::validate_upgrade(duplicate_accept, key);
	} catch (const std::runtime_error&) {
		rejected_duplicate = true;
	}
	assert(rejected_duplicate);

	const std::string malformed_header = std::string("HTTP/1.1 101 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\nConnection: Upgrade\r\n"
		+ "Sec-WebSocket-Accept: " + accept + "\r\nnot-a-header\r\n\r\n";
	bool rejected_malformed = false;
	try {
		echter::ws::detail::validate_upgrade(malformed_header, key);
	} catch (const std::runtime_error&) {
		rejected_malformed = true;
	}
	assert(rejected_malformed);
}

void test_permessage_deflate_negotiation() {
	constexpr std::string_view key = "dGhlIHNhbXBsZSBub25jZQ==";
	const std::string accept = echter::ws::detail::websocket_accept(key);
	const std::string response = std::string("HTTP/1.1 101 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
		+ accept + "\r\nSec-WebSocket-Extensions: permessage-deflate; "
		+ "client_no_context_takeover; server_no_context_takeover\r\n\r\n";
	const auto selected = echter::ws::detail::validate_upgrade(response, key, true);
	assert(selected.enabled && selected.client_no_context_takeover
		&& selected.server_no_context_takeover);

	const std::string declined = std::string("HTTP/1.1 101 Switching Protocols\r\n")
		+ "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
		+ accept + "\r\n\r\n";
	assert(!echter::ws::detail::validate_upgrade(declined, key, true).enabled);

	for (const std::string_view extension : {
			std::string_view("permessage-deflate; unknown=value"),
			std::string_view("permessage-deflate; server_no_context_takeover; server_no_context_takeover")}) {
		const std::string invalid = std::string("HTTP/1.1 101 Switching Protocols\r\n")
			+ "Upgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: "
			+ accept + "\r\nSec-WebSocket-Extensions: " + std::string(extension) + "\r\n\r\n";
		bool rejected = false;
		try {
			(void)echter::ws::detail::validate_upgrade(invalid, key, true);
		} catch (const std::runtime_error&) {
			rejected = true;
		}
		assert(rejected);
	}
	bool rejected_unoffered = false;
	try {
		(void)echter::ws::detail::validate_upgrade(response, key);
	} catch (const std::runtime_error&) {
		rejected_unoffered = true;
	}
	assert(rejected_unoffered);
}

} // namespace

int main() {
	test_permessage_deflate_round_trip();
	test_permessage_deflate_final_block_and_exact_limit();
	test_permessage_deflate_rejects_invalid_payloads();
	test_consecutive_complete_messages();
	test_control_frame_inside_fragmented_message();
	test_invalid_fragment_transitions();
	test_frame_decoder();
	test_compressed_frame_and_fragment_rules();
	test_max_frame_with_coalesced_frames();
	test_noncanonical_payload_lengths();
	test_text_utf8_validation_after_reassembly();
	test_close_payload_validation();
	test_client_frame_encoder_validates_text_and_close();
	test_url_rejects_control_and_invalid_ports();
	test_upgrade_requires_required_websocket_tokens();
	test_permessage_deflate_negotiation();
}