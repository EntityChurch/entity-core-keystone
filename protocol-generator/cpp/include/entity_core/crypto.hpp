// entity_core/crypto.hpp — Ed25519 + SHA-256 via libsodium (the one authorized
// runtime dep, D1). §9.1 floor: Ed25519 (RFC-8032 deterministic detached) +
// SHA-256, both from one audited source. Wrapped behind a small value-based
// (std::expected) facade; libsodium's C handles never escape. Ed448 / SHA-384
// agility is DEFERRED (A-CPP-002): libsodium has no Ed448.
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_CRYPTO_HPP
#define ENTITY_CORE_CRYPTO_HPP

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

#include "entity_core/ecf.hpp"  // EcfError + Result + EcfValue

namespace entity_core::crypto {

using ecf::EcfError;
using ecf::Result;

inline constexpr std::size_t kSha256Len = 32;
inline constexpr std::size_t kEd25519SeedLen = 32;
inline constexpr std::size_t kEd25519PubkeyLen = 32;
inline constexpr std::size_t kEd25519SigLen = 64;

using Sha256Digest = std::array<std::byte, kSha256Len>;
using Ed25519Pubkey = std::array<std::byte, kEd25519PubkeyLen>;
using Ed25519Sig = std::array<std::byte, kEd25519SigLen>;

// Initialize libsodium (idempotent; safe to call repeatedly).
Result<void> init();

Result<Sha256Digest> sha256(std::span<const std::byte> in);

// Derive the Ed25519 public key from a 32-byte seed.
Result<Ed25519Pubkey> ed25519_pubkey(std::span<const std::byte> seed);

// RFC-8032 deterministic detached signature over `msg`.
Result<Ed25519Sig> ed25519_sign(std::span<const std::byte> seed,
                                std::span<const std::byte> msg);

// Verify a detached signature. Returns {} on success, EcfError::BadInput on a
// verification failure or malformed argument (codec-internal verdict).
Result<void> ed25519_verify(std::span<const std::byte> pubkey,
                            std::span<const std::byte> sig,
                            std::span<const std::byte> msg);

// Sign the ECF encoding of {type, data} (the signed-entity message).
Result<Ed25519Sig> sign_entity(std::span<const std::byte> seed,
                               const ecf::EcfValue& type, const ecf::EcfValue& data);

}  // namespace entity_core::crypto

#endif  // ENTITY_CORE_CRYPTO_HPP
