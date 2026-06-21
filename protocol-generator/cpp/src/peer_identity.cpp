// peer_identity.cpp — L1 identity. See peer_identity.hpp. Wire shapes match the cohort:
//   system/peer       {public_key, key_type:"ed25519"}                       (§3.5 v7.65)
//   system/signature  {target, signer, algorithm:"ed25519", signature}       (§3.5)
// Signing covers the full 33-byte content_hash (format byte + digest, §7.3).
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/peer_identity.hpp"

#include <cstring>

namespace entity_core {

using ecf::EcfError;

Result<EntityPtr> peer_entity_of_pubkey(std::span<const std::byte> pubkey) {
    auto data = EcfValue::map();
    data.put(EcfValue::text("public_key"), EcfValue::bytes(pubkey));
    data.put(EcfValue::text("key_type"), EcfValue::text("ed25519"));
    return Entity::make("system/peer", std::move(data));
}

Result<std::string> peer_id_of_pubkey(std::span<const std::byte> pubkey) {
    // §1.5: Ed25519 (32B) → (key_type=0x01, hash_type=0x00 identity, digest=pubkey).
    return identity::peer_id_from_pubkey(identity::kKeyTypeEd25519, pubkey);
}

Result<PeerIdentity> PeerIdentity::from_seed(std::span<const std::byte> seed) {
    if (auto i = crypto::init(); !i) return std::unexpected(i.error());
    if (seed.size() != crypto::kEd25519SeedLen) return std::unexpected(EcfError::BadInput);

    PeerIdentity id;
    std::memcpy(id.seed_.data(), seed.data(), crypto::kEd25519SeedLen);
    auto pub = crypto::ed25519_pubkey(seed);
    if (!pub) return std::unexpected(pub.error());
    id.pubkey_ = *pub;

    auto pe = peer_entity_of_pubkey(id.pubkey_);
    if (!pe) return std::unexpected(pe.error());
    id.peer_entity_ = *pe;

    auto pid = peer_id_of_pubkey(id.pubkey_);
    if (!pid) return std::unexpected(pid.error());
    id.peer_id_ = *pid;
    return id;
}

Result<EntityPtr> PeerIdentity::sign(const Entity& target) const {
    auto sig = crypto::ed25519_sign(seed_, target.hash());
    if (!sig) return std::unexpected(sig.error());
    auto data = EcfValue::map();
    data.put(EcfValue::text("target"), value::bytes_value(target.hash()));
    data.put(EcfValue::text("signer"), value::bytes_value(identity_hash()));
    data.put(EcfValue::text("algorithm"), EcfValue::text("ed25519"));
    data.put(EcfValue::text("signature"), EcfValue::bytes(*sig));
    return Entity::make("system/signature", std::move(data));
}

bool verify_signature(const Entity& signature, const Entity& signer_peer) {
    auto target = signature.bytes("target");
    auto sig = signature.bytes("signature");
    auto pub = signer_peer.bytes("public_key");
    if (!target || !sig || !pub) return false;
    if (pub->size() != crypto::kEd25519PubkeyLen || sig->size() != crypto::kEd25519SigLen) {
        return false;
    }
    return crypto::ed25519_verify(*pub, *sig, *target).has_value();
}

}  // namespace entity_core
