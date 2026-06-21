// crypto.cpp — Ed25519 + SHA-256 via libsodium. SPDX-License-Identifier: Apache-2.0
#include "entity_core/crypto.hpp"

#include <sodium.h>

#include <cstring>

namespace entity_core::crypto {

namespace {
// RAII guard for libsodium's secret-key material: zeroes on scope exit so a key
// never lingers in freed memory (sodium_memzero is not optimized away).
struct SecretKey {
    unsigned char sk[crypto_sign_SECRETKEYBYTES];
    ~SecretKey() { sodium_memzero(sk, sizeof(sk)); }
};

const unsigned char* uc(std::span<const std::byte> s) {
    return reinterpret_cast<const unsigned char*>(s.data());
}
}  // namespace

Result<void> init() {
    if (sodium_init() < 0) return std::unexpected(EcfError::BadInput);
    return {};
}

Result<Sha256Digest> sha256(std::span<const std::byte> in) {
    Sha256Digest out{};
    if (crypto_hash_sha256(reinterpret_cast<unsigned char*>(out.data()), uc(in),
                           in.size()) != 0)
        return std::unexpected(EcfError::BadInput);
    return out;
}

Result<Ed25519Pubkey> ed25519_pubkey(std::span<const std::byte> seed) {
    if (seed.size() != kEd25519SeedLen) return std::unexpected(EcfError::BadInput);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    SecretKey k;
    if (crypto_sign_seed_keypair(pk, k.sk, uc(seed)) != 0)
        return std::unexpected(EcfError::BadInput);
    Ed25519Pubkey out{};
    std::memcpy(out.data(), pk, kEd25519PubkeyLen);
    return out;
}

Result<Ed25519Sig> ed25519_sign(std::span<const std::byte> seed,
                                std::span<const std::byte> msg) {
    if (seed.size() != kEd25519SeedLen) return std::unexpected(EcfError::BadInput);
    unsigned char pk[crypto_sign_PUBLICKEYBYTES];
    SecretKey k;
    if (crypto_sign_seed_keypair(pk, k.sk, uc(seed)) != 0)
        return std::unexpected(EcfError::BadInput);
    Ed25519Sig out{};
    unsigned long long siglen = 0;
    if (crypto_sign_detached(reinterpret_cast<unsigned char*>(out.data()), &siglen,
                             uc(msg), msg.size(), k.sk) != 0 ||
        siglen != kEd25519SigLen)
        return std::unexpected(EcfError::BadInput);
    return out;
}

Result<void> ed25519_verify(std::span<const std::byte> pubkey,
                            std::span<const std::byte> sig,
                            std::span<const std::byte> msg) {
    if (pubkey.size() != kEd25519PubkeyLen || sig.size() != kEd25519SigLen)
        return std::unexpected(EcfError::BadInput);
    if (crypto_sign_verify_detached(uc(sig), uc(msg), msg.size(), uc(pubkey)) != 0)
        return std::unexpected(EcfError::BadInput);
    return {};
}

Result<Ed25519Sig> sign_entity(std::span<const std::byte> seed,
                               const ecf::EcfValue& type, const ecf::EcfValue& data) {
    // Build {type, data} and ECF-encode it as the signed message.
    auto entity = ecf::EcfValue::map();
    entity.put(ecf::EcfValue::text("type"), type);
    entity.put(ecf::EcfValue::text("data"), data);
    auto enc = ecf::encode(entity);
    if (!enc) return std::unexpected(enc.error());
    return ed25519_sign(seed, *enc);
}

}  // namespace entity_core::crypto
