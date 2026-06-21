// entity_core/varint.hpp — multicodec-style unsigned LEB128 varints (V7 §1.5/§7.3).
//
// Invariant N1: every format-code / key-type / hash-type prefix routes through a
// REAL varint primitive, NOT a fixed byte. All currently-allocated codes are
// < 0x80 (single byte), but a code >= 0x80 MUST extend (128 -> 0x80 0x01). The
// corpus exercises this with synthetic high codes (content_hash.4 fc=128,
// peer_id.3 key_type=128).
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_VARINT_HPP
#define ENTITY_CORE_VARINT_HPP

#include <cstddef>
#include <cstdint>
#include <expected>
#include <span>
#include <vector>

#include "entity_core/ecf.hpp"  // EcfError + Result

namespace entity_core::varint {

using ecf::EcfError;
using ecf::Result;

// Encode `n` as a multicodec LEB128 varint (1..10 bytes).
std::vector<std::byte> encode(std::uint64_t n);

struct Decoded {
    std::uint64_t value;
    std::size_t consumed;
};

// Decode a minimal LEB128 varint from a borrowed span (rejects non-minimal /
// >64-bit / truncated forms).
Result<Decoded> decode(std::span<const std::byte> in);

}  // namespace entity_core::varint

#endif  // ENTITY_CORE_VARINT_HPP
