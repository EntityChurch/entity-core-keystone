// entity_core/base58.hpp — Base58 (Bitcoin alphabet) encode/decode, hand-rolled.
//
// Used for peer_id formatting/parsing (V7 §1.2/§7.3). Leading zero bytes map to a
// leading '1' each (leading-zero preserving in both directions). Byte-wise long
// division / multiplication, no bignum dep. SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_BASE58_HPP
#define ENTITY_CORE_BASE58_HPP

#include <cstddef>
#include <span>
#include <string>
#include <vector>

#include "entity_core/ecf.hpp"  // EcfError + Result

namespace entity_core::base58 {

using ecf::EcfError;
using ecf::Result;

std::string encode(std::span<const std::byte> in);
Result<std::vector<std::byte>> decode(std::string_view str);

}  // namespace entity_core::base58

#endif  // ENTITY_CORE_BASE58_HPP
