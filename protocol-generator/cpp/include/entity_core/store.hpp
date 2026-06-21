// entity_core/store.hpp — the foundation storage (§1.7): content store (hash → entity,
// content-addressed, dedup) + entity tree (path → hash, mutable location index).
//
// §4.8 data-race safety (N6): a std::shared_mutex guards BOTH maps — many concurrent
// readers (std::shared_lock) / one exclusive writer (std::unique_lock); reads dominate the
// dispatch path, so a shared_mutex beats a plain mutex (profile [concurrency].store_safety).
// Entities are std::shared_ptr<const Entity> (atomic refcount by the standard → lifetime is
// safe even when an entry is overwritten while another thread reads it). A data race here is
// a FAIL; the shared_mutex + shared_ptr make consistency structural, not bolted-on.
//
// §6.13(c) emit bus: tree binds fire registered consumers — LIVE with zero consumers so a
// future extension can register WITHOUT rebuilding the peer. A core peer registers none.
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_STORE_HPP
#define ENTITY_CORE_STORE_HPP

#include <functional>
#include <map>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>

#include "entity_core/entity.hpp"

namespace entity_core {

// One-level listing row (§3.9).
struct ListEntry {
    std::string segment;
    std::optional<Hash> hash;   // absent for a pure intermediate node
    bool has_children = false;
};

class Store {
public:
    using TreeConsumer = std::function<void(const std::string& path)>;

    // Put an entity in the content store (dedup by hash). Holds its own shared_ptr.
    void put(const EntityPtr& e);
    // Borrow-by-hash (nullptr if absent).
    EntityPtr get_by_hash(std::span<const std::byte> h33) const;

    // Bind path → entity (also puts in the content store). Fires consumers on a change.
    void bind(const std::string& path, const EntityPtr& e);
    void unbind(const std::string& path);

    // Entity at path (nullptr if absent).
    EntityPtr get_at(const std::string& path) const;
    // Hex hash bound at path (nullopt if absent).
    std::optional<std::string> hash_hex_at(const std::string& path) const;

    // One-level listing under `prefix`, sorted by segment.
    std::vector<ListEntry> listing(const std::string& prefix) const;

    // Register a tree-change consumer (live any time; §6.13(c)).
    void register_tree_consumer(TreeConsumer fn);

private:
    mutable std::shared_mutex mu_;
    std::map<std::string, EntityPtr> content_;   // hash-hex → entity
    std::map<std::string, std::string> tree_;    // path → hash-hex
    std::vector<TreeConsumer> consumers_;

    void fire(const std::string& path) const;    // snapshot consumers, call outside lock
};

}  // namespace entity_core

#endif  // ENTITY_CORE_STORE_HPP
