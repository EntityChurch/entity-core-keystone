// entity.cpp — materialized entity {type,data,content_hash} + envelope (§3.1) +
// EcfValue field helpers, on the S2 codec. See entity.hpp for the contract.
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/entity.hpp"

#include <cstring>

namespace entity_core {

using ecf::EcfError;

namespace {

// content_hash = varint(0x00) || SHA-256(ECF({type,data})) → 33 bytes.
Result<Hash> compute_hash(const std::string& type, const EcfValue& data) {
    auto ch = identity::content_hash(EcfValue::text(type), data, identity::kFormatSha256);
    if (!ch) return std::unexpected(ch.error());
    if (ch->size() != kHashLen) return std::unexpected(EcfError::BadInput);
    Hash h{};
    std::memcpy(h.data(), ch->data(), kHashLen);
    return h;
}

}  // namespace

Result<EntityPtr> Entity::make(std::string type, EcfValue data) {
    auto h = compute_hash(type, data);
    if (!h) return std::unexpected(h.error());
    // private ctor → shared_ptr via a small adapter (make_shared can't reach a private ctor).
    struct Access : Entity {
        Access(std::string t, EcfValue d, Hash hh) : Entity(std::move(t), std::move(d), hh) {}
    };
    return std::static_pointer_cast<const Entity>(
        std::make_shared<Access>(std::move(type), std::move(data), *h));
}

Result<EntityPtr> Entity::from_cbor(const EcfValue& m) {
    const auto* type_v = m.find("type");
    const auto* data_v = m.find("data");
    if (!type_v || !data_v) return std::unexpected(EcfError::BadInput);
    const auto* t = std::get_if<ecf::Text>(&type_v->as_variant());
    if (!t) return std::unexpected(EcfError::BadInput);
    std::string type(reinterpret_cast<const char*>(t->data()), t->size());

    auto e = make(type, *data_v);
    if (!e) return e;

    // §1.8 fidelity: a carried content_hash MUST match the recompute.
    if (const auto* ch = m.find("content_hash")) {
        const auto* cb = std::get_if<ecf::Bytes>(&ch->as_variant());
        if (cb) {
            if (cb->size() != kHashLen ||
                std::memcmp(cb->data(), (*e)->hash().data(), kHashLen) != 0) {
                return std::unexpected(EcfError::NonCanonicalEcf);
            }
        }
    }
    return e;
}

EcfValue Entity::to_cbor() const {
    auto m = EcfValue::map();
    m.put(EcfValue::text("type"), EcfValue::text(type_));
    m.put(EcfValue::text("data"), data_);
    m.put(EcfValue::text("content_hash"), value::bytes_value(hash_));
    return m;
}

const EcfValue* Entity::field(std::string_view key) const noexcept {
    return data_.find(key);
}

const EcfValue* Entity::map_field(std::string_view key) const noexcept {
    const auto* v = data_.find(key);
    return (v && v->is<ecf::Map>()) ? v : nullptr;
}

std::optional<std::string> Entity::text(std::string_view key) const {
    return value::text(data_, key);
}

std::optional<std::vector<std::byte>> Entity::bytes(std::string_view key) const {
    return value::bytes(data_, key);
}

std::optional<std::uint64_t> Entity::uint(std::string_view key) const {
    return value::uint(data_, key);
}

EntityPtr Entity::entity_field(std::string_view key) const {
    const auto* m = map_field(key);
    if (!m) return nullptr;
    auto e = from_cbor(*m);
    return e ? *e : nullptr;
}

// ── EcfValue value helpers ───────────────────────────────────────────────────────
namespace value {

const EcfValue* get(const EcfValue& m, std::string_view key) noexcept {
    return m.find(key);
}

std::optional<std::string> text(const EcfValue& m, std::string_view key) {
    const auto* v = m.find(key);
    if (!v) return std::nullopt;
    const auto* t = std::get_if<ecf::Text>(&v->as_variant());
    if (!t) return std::nullopt;
    return std::string(reinterpret_cast<const char*>(t->data()), t->size());
}

std::optional<std::vector<std::byte>> bytes(const EcfValue& m, std::string_view key) {
    const auto* v = m.find(key);
    if (!v) return std::nullopt;
    const auto* b = std::get_if<ecf::Bytes>(&v->as_variant());
    if (!b) return std::nullopt;
    return *b;
}

std::optional<std::uint64_t> uint(const EcfValue& m, std::string_view key) {
    const auto* v = m.find(key);
    if (!v) return std::nullopt;
    const auto* i = std::get_if<ecf::Int>(&v->as_variant());
    if (!i || i->negative) return std::nullopt;
    return i->arg;
}

bool is_true(const EcfValue* v) noexcept {
    if (!v) return false;
    const auto* b = std::get_if<bool>(&v->as_variant());
    return b && *b;
}

EcfValue text_array(std::span<const std::string_view> items) {
    auto a = EcfValue::array();
    for (auto s : items) a.push(EcfValue::text(s));
    return a;
}

EcfValue bytes_value(std::span<const std::byte> b) {
    return EcfValue::bytes(b);
}

}  // namespace value

// ── envelope ─────────────────────────────────────────────────────────────────────
void Envelope::add(const EntityPtr& e) {
    if (!e) return;
    for (const auto& cur : included_) {
        if (std::memcmp(cur->hash().data(), e->hash().data(), kHashLen) == 0) return;  // dedup
    }
    included_.push_back(e);
}

EntityPtr Envelope::find(std::span<const std::byte> h33) const {
    if (h33.size() != kHashLen) return nullptr;
    if (root_ && std::memcmp(root_->hash().data(), h33.data(), kHashLen) == 0) return root_;
    for (const auto& e : included_) {
        if (std::memcmp(e->hash().data(), h33.data(), kHashLen) == 0) return e;
    }
    return nullptr;
}

Result<std::vector<std::byte>> Envelope::to_wire() const {
    auto m = EcfValue::map();
    m.put(EcfValue::text("root"), root_->to_cbor());
    auto inc = EcfValue::map();
    for (const auto& e : included_) {
        inc.put(value::bytes_value(e->hash()), e->to_cbor());
    }
    m.put(EcfValue::text("included"), std::move(inc));
    return ecf::encode(m);
}

Result<Envelope> Envelope::from_wire(std::span<const std::byte> in) {
    auto m = ecf::decode(in);
    if (!m) return std::unexpected(m.error());
    const auto* root_v = m->find("root");
    if (!root_v || !root_v->is<ecf::Map>()) return std::unexpected(EcfError::BadInput);
    auto root = Entity::from_cbor(*root_v);
    if (!root) return std::unexpected(root.error());
    Envelope env(*root);
    if (const auto* inc = m->find("included"); inc && inc->is<ecf::Map>()) {
        const auto& map = std::get<ecf::Map>(inc->as_variant());
        for (const auto& kv : map) {
            const auto* kb = std::get_if<ecf::Bytes>(&kv.key->as_variant());
            if (!kb || kb->size() != kHashLen || !kv.value->is<ecf::Map>()) {
                return std::unexpected(EcfError::BadInput);
            }
            auto ent = Entity::from_cbor(*kv.value);
            if (!ent) return std::unexpected(ent.error());
            // §3.1 (N5): the included key MUST equal the entity's content_hash.
            if (std::memcmp(kb->data(), (*ent)->hash().data(), kHashLen) != 0) {
                return std::unexpected(EcfError::NonCanonicalEcf);
            }
            env.add(*ent);
        }
    }
    return env;
}

}  // namespace entity_core
