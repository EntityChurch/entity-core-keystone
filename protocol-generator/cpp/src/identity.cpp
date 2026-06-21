// identity.cpp — content_hash + peer_id construction. SPDX-License-Identifier: Apache-2.0
#include "entity_core/identity.hpp"

#include "entity_core/base58.hpp"
#include "entity_core/crypto.hpp"
#include "entity_core/varint.hpp"

namespace entity_core::identity {

Result<std::vector<std::byte>> content_hash(const ecf::EcfValue& type,
                                            const ecf::EcfValue& data,
                                            std::uint64_t format_code) {
    auto entity = ecf::EcfValue::map();
    entity.put(ecf::EcfValue::text("type"), type);
    entity.put(ecf::EcfValue::text("data"), data);
    auto enc = ecf::encode(entity);
    if (!enc) return std::unexpected(enc.error());

    auto digest = crypto::sha256(*enc);
    if (!digest) return std::unexpected(digest.error());

    std::vector<std::byte> out = varint::encode(format_code);
    out.insert(out.end(), digest->begin(), digest->end());
    return out;
}

std::string hex_lower(std::span<const std::byte> in) {
    static constexpr char kHex[] = "0123456789abcdef";  // lowercase pinned (P2/A-CL-009)
    std::string s;
    s.reserve(in.size() * 2);
    for (auto b : in) {
        const auto u = static_cast<std::uint8_t>(b);
        s.push_back(kHex[u >> 4]);
        s.push_back(kHex[u & 0xf]);
    }
    return s;
}

std::string peer_id_format(std::uint64_t key_type, std::uint64_t hash_type,
                           std::span<const std::byte> digest) {
    std::vector<std::byte> raw = varint::encode(key_type);
    auto ht = varint::encode(hash_type);
    raw.insert(raw.end(), ht.begin(), ht.end());
    raw.insert(raw.end(), digest.begin(), digest.end());
    return base58::encode(raw);
}

Result<PeerIdParts> peer_id_parse(std::string_view peer_id) {
    auto raw = base58::decode(peer_id);
    if (!raw) return std::unexpected(raw.error());

    auto kt = varint::decode(*raw);
    if (!kt) return std::unexpected(kt.error());
    std::span<const std::byte> rest{*raw};
    rest = rest.subspan(kt->consumed);

    auto ht = varint::decode(rest);
    if (!ht) return std::unexpected(ht.error());
    rest = rest.subspan(ht->consumed);

    return PeerIdParts{kt->value, ht->value, std::vector<std::byte>(rest.begin(), rest.end())};
}

Result<std::string> peer_id_from_pubkey(std::uint64_t key_type,
                                        std::span<const std::byte> pubkey) {
    if (pubkey.empty()) return std::unexpected(EcfError::BadInput);
    if (pubkey.size() <= 32) {
        // identity-multihash: digest IS the public key
        return peer_id_format(key_type, kHashTypeIdentity, pubkey);
    }
    auto digest = crypto::sha256(pubkey);
    if (!digest) return std::unexpected(digest.error());
    return peer_id_format(key_type, kHashTypeSha256, *digest);
}

}  // namespace entity_core::identity
