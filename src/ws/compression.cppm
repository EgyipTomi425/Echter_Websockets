module;

#include <cstddef>
#include <memory>
#include <span>
#include <vector>

export module echter.ws.compression;

import echter.ws.frame;

export namespace echter::ws {

struct DeflateResult {
	std::vector<std::byte> payload;
	bool compressed = false;
};

class PerMessageDeflate {
public:
	explicit PerMessageDeflate(bool server_no_context_takeover = false);
	PerMessageDeflate(const PerMessageDeflate&) = delete;
	PerMessageDeflate& operator=(const PerMessageDeflate&) = delete;
	~PerMessageDeflate();

	[[nodiscard]] DeflateResult compress(std::span<const std::byte> input);
	[[nodiscard]] std::vector<std::byte> decompress(std::span<const std::byte> input);

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

} // namespace echter::ws