// entity_core/protocol.hpp — entity-core-protocol-cpp public umbrella header.
//
// Peer: C++20/23 "reach" peer. Hand-rolled canonical ECF (CBOR) codec + base58 +
// multicodec LEB128 varint + libsodium crypto (Ed25519 + SHA-256). Core types
// only (Entity, system/hash, system/peer, system/signature, system/capability
// token shape, envelopes, protocol messages) — NO extension types.
//
// Idiom (per profile.toml): RAII ownership (value containers / smart pointers,
// no raw new/delete/free, deterministic destruction); value-based std::expected
// error channel (no exceptions on the hot path); zero-copy decode reads via a
// size-carrying std::span; native std::uint64_t head-form; lowercase {:02x} hex.
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_PROTOCOL_HPP
#define ENTITY_CORE_PROTOCOL_HPP

#include "entity_core/base58.hpp"
#include "entity_core/crypto.hpp"
#include "entity_core/ecf.hpp"
#include "entity_core/identity.hpp"
#include "entity_core/varint.hpp"

#endif  // ENTITY_CORE_PROTOCOL_HPP
