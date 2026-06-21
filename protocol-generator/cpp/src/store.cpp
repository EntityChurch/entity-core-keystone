// store.cpp — the §1.7 foundation storage, std::shared_mutex-guarded (§4.8). See store.hpp.
//
// Implementation note: std::map keyed by hash-hex / path. The conformance/loopback surface
// holds O(100) entries, so an ordered map is the dependency-minimal idiomatic choice (no
// hashtable churn, and listing's prefix scan is naturally ordered). Correct under the lock.
//
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/store.hpp"

#include <algorithm>
#include <mutex>

namespace entity_core {

void Store::put(const EntityPtr& e) {
    if (!e) return;
    std::unique_lock lk(mu_);
    content_.try_emplace(e->hash_hex(), e);   // dedup: keep the first (content-addressed)
}

EntityPtr Store::get_by_hash(std::span<const std::byte> h33) const {
    std::string hex = identity::hex_lower(h33);
    std::shared_lock lk(mu_);
    auto it = content_.find(hex);
    return it != content_.end() ? it->second : nullptr;
}

void Store::bind(const std::string& path, const EntityPtr& e) {
    if (!e) return;
    bool changed = false;
    {
        std::unique_lock lk(mu_);
        content_.try_emplace(e->hash_hex(), e);
        std::string hex = e->hash_hex();
        auto it = tree_.find(path);
        if (it == tree_.end()) {
            tree_.emplace(path, hex);
            changed = true;
        } else if (it->second != hex) {
            it->second = hex;
            changed = true;
        }
    }
    if (changed) fire(path);
}

void Store::unbind(const std::string& path) {
    bool changed = false;
    {
        std::unique_lock lk(mu_);
        changed = tree_.erase(path) > 0;
    }
    if (changed) fire(path);
}

EntityPtr Store::get_at(const std::string& path) const {
    std::shared_lock lk(mu_);
    auto it = tree_.find(path);
    if (it == tree_.end()) return nullptr;
    auto c = content_.find(it->second);
    return c != content_.end() ? c->second : nullptr;
}

std::optional<std::string> Store::hash_hex_at(const std::string& path) const {
    std::shared_lock lk(mu_);
    auto it = tree_.find(path);
    if (it == tree_.end()) return std::nullopt;
    return it->second;
}

std::vector<ListEntry> Store::listing(const std::string& prefix) const {
    std::string p = prefix;
    if (p.empty() || p.back() != '/') p.push_back('/');

    // segment → (row index); preserve insertion via a vector, dedup via the index map.
    std::vector<ListEntry> rows;
    std::map<std::string, std::size_t> idx;

    auto hex_to_hash = [](const std::string& hex) -> std::optional<Hash> {
        if (hex.size() != kHashLen * 2) return std::nullopt;
        Hash h{};
        for (std::size_t i = 0; i < kHashLen; ++i) {
            auto nyb = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                return 0;
            };
            h[i] = std::byte(static_cast<std::uint8_t>(
                (nyb(hex[i * 2]) << 4) | nyb(hex[i * 2 + 1])));
        }
        return h;
    };

    std::shared_lock lk(mu_);
    for (const auto& [path, hex] : tree_) {
        if (path.size() <= p.size() || path.compare(0, p.size(), p) != 0) continue;
        std::string rest = path.substr(p.size());
        auto slash = rest.find('/');
        bool deeper = slash != std::string::npos;
        std::string seg = deeper ? rest.substr(0, slash) : rest;

        auto it = idx.find(seg);
        ListEntry* row;
        if (it == idx.end()) {
            idx.emplace(seg, rows.size());
            rows.push_back(ListEntry{seg, std::nullopt, false});
            row = &rows.back();
        } else {
            row = &rows[it->second];
        }
        if (deeper) {
            row->has_children = true;
        } else {
            row->hash = hex_to_hash(hex);
        }
    }
    // rows are gathered in tree_ order; sort by segment for a deterministic listing.
    std::sort(rows.begin(), rows.end(),
              [](const ListEntry& a, const ListEntry& b) { return a.segment < b.segment; });
    return rows;
}

void Store::register_tree_consumer(TreeConsumer fn) {
    if (!fn) return;
    std::unique_lock lk(mu_);
    consumers_.push_back(std::move(fn));
}

void Store::fire(const std::string& path) const {
    std::vector<TreeConsumer> snap;
    {
        std::shared_lock lk(mu_);
        snap = consumers_;
    }
    for (auto& fn : snap) fn(path);
}

}  // namespace entity_core
