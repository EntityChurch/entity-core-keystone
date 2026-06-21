// entity_core/peer_identity.hpp — L1 identity: an Ed25519 keypair bound to a §1.5 peer_id,
// the system/peer entity, and the §3.5 signature target rules (sign a target entity → a
// system/signature entity; verify against a signer's system/peer entity).
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_PEER_IDENTITY_HPP
#define ENTITY_CORE_PEER_IDENTITY_HPP

#include <array>
#include <cstdint>
#include <span>
#include <string>

#include "entity_core/crypto.hpp"
#include "entity_core/entity.hpp"

namespace entity_core {

// A loaded peer identity: seed + derived pubkey + §1.5 peer_id + the system/peer entity
// (and its content_hash, the "identity hash" used as granter/grantee/author/signer).
class PeerIdentity {
public:
    static Result<PeerIdentity> from_seed(std::span<const std::byte> seed);

    const std::string& peer_id() const noexcept { return peer_id_; }
    const crypto::Ed25519Pubkey& public_key() const noexcept { return pubkey_; }
    const EntityPtr& peer_entity() const noexcept { return peer_entity_; }
    const Hash& identity_hash() const noexcept { return peer_entity_->hash(); }

    // Sign a target entity → a system/signature entity {target, signer, signature[, key_type]}.
    Result<EntityPtr> sign(const Entity& target) const;

    // Default-constructed identity is empty (no keypair); a Peer holds one as a member and
    // moves in the real one from create(). Public so Peer's default ctor is well-formed.
    PeerIdentity() = default;

private:
    std::array<std::byte, crypto::kEd25519SeedLen> seed_{};
    crypto::Ed25519Pubkey pubkey_{};
    std::string peer_id_;
    EntityPtr peer_entity_;
};

// Build a system/peer entity {public_key, key_type:"ed25519"} for a raw 32-byte pubkey.
Result<EntityPtr> peer_entity_of_pubkey(std::span<const std::byte> pubkey);

// §1.5 peer_id for a raw Ed25519 pubkey.
Result<std::string> peer_id_of_pubkey(std::span<const std::byte> pubkey);

// Verify a system/signature entity against the signer's system/peer entity.
bool verify_signature(const Entity& signature, const Entity& signer_peer);

}  // namespace entity_core

#endif  // ENTITY_CORE_PEER_IDENTITY_HPP
