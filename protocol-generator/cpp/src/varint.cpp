// varint.cpp — multicodec-style unsigned LEB128 varints. SPDX-License-Identifier: Apache-2.0
#include "entity_core/varint.hpp"

namespace entity_core::varint {

std::vector<std::byte> encode(std::uint64_t n) {
    std::vector<std::byte> out;
    do {
        auto b = static_cast<std::uint8_t>(n & 0x7f);
        n >>= 7;
        if (n != 0) b |= 0x80;
        out.push_back(std::byte{b});
    } while (n != 0);
    return out;
}

Result<Decoded> decode(std::span<const std::byte> in) {
    std::uint64_t v = 0;
    unsigned shift = 0;
    std::size_t i = 0;
    for (;;) {
        if (i >= in.size()) return std::unexpected(EcfError::Truncated);
        if (shift >= 64) return std::unexpected(EcfError::NonCanonicalEcf);  // > 64 bits
        const auto b = static_cast<std::uint8_t>(in[i++]);
        v |= static_cast<std::uint64_t>(b & 0x7f) << shift;
        if ((b & 0x80) == 0) {
            // Reject a non-minimal trailing 0x00 continuation (LEB128 minimality).
            if (b == 0 && shift != 0) return std::unexpected(EcfError::NonCanonicalEcf);
            return Decoded{v, i};
        }
        shift += 7;
    }
}

}  // namespace entity_core::varint
