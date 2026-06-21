// entity_core/identity.hpp — content_hash + peer_id construction (the identity
// layer of the codec). SPDX-License-Identifier: Apache-2.0
//
//   content_hash = varint(format_code) || HASH(ECF({type, data}))
//   peer_id      = Base58(varint(key_type) || varint(hash_type) || digest)
//
// §1.5 canonical-form (P1): an Ed25519 (32 B) key is identity-multihash
// (hash_type=0x00, digest = RAW pubkey); a larger key is SHA-256-form
// (hash_type=0x01, digest = SHA-256(key)). The stale §7.4 SHA-256 skeleton is
// NOT a construction path for v7.65+.
#ifndef ENTITY_CORE_IDENTITY_HPP
#define ENTITY_CORE_IDENTITY_HPP

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "entity_core/ecf.hpp"

namespace entity_core::identity {

using ecf::EcfError;
using ecf::Result;

inline constexpr std::uint64_t kFormatSha256 = 0x00;  // §9.1 floor
inline constexpr std::uint64_t kFormatSha384 = 0x01;  // agility — not on the core path

inline constexpr std::uint64_t kKeyTypeEd25519 = 0x01;
inline constexpr std::uint64_t kKeyTypeEd448 = 0x02;
inline constexpr std::uint64_t kHashTypeIdentity = 0x00;  // digest IS the key
inline constexpr std::uint64_t kHashTypeSha256 = 0x01;

// content_hash = varint(format_code) || SHA-256(ECF({type, data})). The
// format_code is serialized verbatim (content_hash.4 fc=128 emits 0x80 0x01) and
// the digest is SHA-256 on the core path; the hashed input is only {type, data}.
Result<std::vector<std::byte>> content_hash(const ecf::EcfValue& type,
                                            const ecf::EcfValue& data,
                                            std::uint64_t format_code);

// Lowercase hex (P2 / A-CL-009 — pinned lowercase, never uppercase).
std::string hex_lower(std::span<const std::byte> in);

// Format a peer_id string from abstract components.
std::string peer_id_format(std::uint64_t key_type, std::uint64_t hash_type,
                           std::span<const std::byte> digest);

struct PeerIdParts {
    std::uint64_t key_type;
    std::uint64_t hash_type;
    std::vector<std::byte> digest;
};

// Parse a peer_id string back to its components.
Result<PeerIdParts> peer_id_parse(std::string_view peer_id);

// Derive the §1.5 canonical-form peer_id from a RAW public key (P1):
// key <= 32 B => (key_type, 0x00, raw pubkey); key > 32 B => (key_type, 0x01,
// SHA-256(pubkey)). Ed25519 (32 B) => (0x01, 0x00, pubkey).
Result<std::string> peer_id_from_pubkey(std::uint64_t key_type,
                                        std::span<const std::byte> pubkey);

}  // namespace entity_core::identity

#endif  // ENTITY_CORE_IDENTITY_HPP
