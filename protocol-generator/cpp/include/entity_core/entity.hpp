// entity_core/entity.hpp — the materialized entity {type, data, content_hash} (§1.1/§3.4)
// + the §3.1 envelope (root + included), plus EcfValue field-read helpers.
//
// Idiom (per profile [memory]): RAII + value semantics. An Entity OWNS its `data` EcfValue
// (value container; the destructor frees deterministically — no raw new/delete). Entities
// shared across dispatch threads (store / envelope / outcome) are held by
// std::shared_ptr<const Entity>, whose control-block refcount is atomic by the C++ standard
// — this PRE-RESOLVES the C peer's A-C-009 hand-rolled atomic_int (the shared_ptr atomic
// control block gives the same guarantee for free). shared_ptr buys lifetime-safety;
// data-race-safety of the *store* is the store's shared_mutex (store.hpp).
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_ENTITY_HPP
#define ENTITY_CORE_ENTITY_HPP

#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "entity_core/ecf.hpp"
#include "entity_core/identity.hpp"

namespace entity_core {

using ecf::EcfValue;
using ecf::Result;

// content_hash is 33 bytes: varint(format_code=0x00) || SHA-256(ECF({type,data})).
inline constexpr std::size_t kHashLen = 33;
using Hash = std::array<std::byte, kHashLen>;

// ── materialized entity ─────────────────────────────────────────────────────────
//
// Immutable once made: {type, data, content_hash}. Held by shared_ptr<const Entity> when
// shared (store / envelope / outcome), so it is never mutated in place. `data` is an
// ARBITRARY EcfValue (P4/A-JAVA-010 — never forced to a map), so a scalar-data entity
// round-trips.
class Entity {
public:
    // Build an entity, computing content_hash over ECF({type,data}) via the S2 codec.
    static Result<std::shared_ptr<const Entity>> make(std::string type, EcfValue data);

    // Decode a wire entity cbor-map {type,data[,content_hash]}; recompute + verify the
    // carried content_hash (§1.8 fidelity → NonCanonicalEcf on mismatch).
    static Result<std::shared_ptr<const Entity>> from_cbor(const EcfValue& m);

    const std::string& type() const noexcept { return type_; }
    const EcfValue& data() const noexcept { return data_; }
    const Hash& hash() const noexcept { return hash_; }
    std::string hash_hex() const { return identity::hex_lower(hash_); }

    // Wire form as an EcfValue map {type, data, content_hash}.
    EcfValue to_cbor() const;

    // ── typed field reads off `data` (null-safe; data may be scalar) ──
    const EcfValue* field(std::string_view key) const noexcept;          // borrow
    const EcfValue* map_field(std::string_view key) const noexcept;      // borrow if a map
    std::optional<std::string> text(std::string_view key) const;
    std::optional<std::vector<std::byte>> bytes(std::string_view key) const;
    std::optional<std::uint64_t> uint(std::string_view key) const;
    // Decode a nested entity carried at `key` (a wire cbor-map); nullptr if absent/bad.
    std::shared_ptr<const Entity> entity_field(std::string_view key) const;

private:
    Entity(std::string type, EcfValue data, Hash hash)
        : type_(std::move(type)), data_(std::move(data)), hash_(hash) {}

    std::string type_;
    EcfValue data_;
    Hash hash_;
};

using EntityPtr = std::shared_ptr<const Entity>;

// ── EcfValue map field helpers (the peer-layer value reads) ──────────────────────
namespace value {
const EcfValue* get(const EcfValue& m, std::string_view key) noexcept;     // borrow
std::optional<std::string> text(const EcfValue& m, std::string_view key);
std::optional<std::vector<std::byte>> bytes(const EcfValue& m, std::string_view key);
std::optional<std::uint64_t> uint(const EcfValue& m, std::string_view key);
bool is_true(const EcfValue* v) noexcept;
EcfValue text_array(std::span<const std::string_view> items);
EcfValue bytes_value(std::span<const std::byte> b);
}  // namespace value

// ── envelope (§3.1): root + included (content_hash → entity), unique keys ─────────
class Envelope {
public:
    explicit Envelope(EntityPtr root) : root_(std::move(root)) {}

    const EntityPtr& root() const noexcept { return root_; }

    // Append an included entry (dedup by content_hash — §3.1 unique key).
    void add(const EntityPtr& e);

    // Find an included entity by 33-byte content_hash (borrow; nullptr if absent).
    EntityPtr find(std::span<const std::byte> h33) const;

    const std::vector<EntityPtr>& included() const noexcept { return included_; }

    Result<std::vector<std::byte>> to_wire() const;
    static Result<Envelope> from_wire(std::span<const std::byte> in);

private:
    EntityPtr root_;
    std::vector<EntityPtr> included_;
};

}  // namespace entity_core

#endif  // ENTITY_CORE_ENTITY_HPP
