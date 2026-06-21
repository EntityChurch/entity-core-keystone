// capability.cpp — the §5 capability verification core (L3). A faithful port of the §5
// pseudocode (spec-first): pattern matching (§5.4), request verification (§5.2), delegation
// chain (§5.5) with genuine §3.6 multi-sig K-of-N at the root, attenuation (§5.6),
// delegation caveats (§5.7), revocation (§5.1), and the §4.10(b) chain-depth pre-check.
//
// The §PR-8 / §5.5a granter-frame refinement: the RESOURCE dimension canonicalizes against
// the GRANTER's peer_id; handlers/operations/peers stay on the local frame. For the self-
// issued dominant path (granter == local) this equals a pure-local frame.
//
// Multi-sig (the keystone-mandated genuine K-of-N, NOT rejection-only): the granter is a
// union (single system/hash | {signers, threshold} map, root-only). At the chain root, a
// multi-granter token runs §3.6 M3 structure (root-only, n≥2, 2≤threshold≤n, distinct
// signers) BEFORE sig counting, then §5.5 M6 (local ∈ signers) + M4 (distinct valid-sig
// count ≥ threshold). Single-sig is a strict superset of multi-sig (the off-root path).
//
// Idiom: free functions over borrowed const refs; std::optional results; no exceptions on
// the verdict path. canonicalize is the one allocator.
//
// SPDX-License-Identifier: Apache-2.0
#include "entity_core/capability.hpp"
#include "entity_core/peer_identity.hpp"

#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <vector>

namespace entity_core::cap {

std::uint64_t now_ms() {
    using namespace std::chrono;
    return static_cast<std::uint64_t>(
        duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

namespace {

constexpr int kMaxChainDepth = 64;

constexpr std::string_view kBase58 =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

// Resolve a cap-referenced entity: envelope first, then the content store.
EntityPtr resolve(const Envelope& env, const Store& store, std::span<const std::byte> h) {
    if (auto e = env.find(h)) return e;
    return store.get_by_hash(h);
}

// ── §5.4 pattern matching ──────────────────────────────────────────────────────
bool matches_pattern(std::string_view path, std::string_view pattern) {
    if (pattern == "*") return true;
    if (starts_with("/*/", pattern)) {
        std::string_view remainder = pattern.substr(3);
        // path.indexOf('/', 1)
        if (path.empty()) return false;
        auto i = path.find('/', 1);
        if (i == std::string_view::npos) return false;
        return matches_pattern(path.substr(i + 1), remainder);
    }
    if (pattern.size() >= 2 && pattern.back() == '*' && pattern[pattern.size() - 2] == '/') {
        // ends with slash-star → startsWith(prefix-slash, path)
        std::string_view prefix = pattern.substr(0, pattern.size() - 1);
        return path.size() >= prefix.size() && path.compare(0, prefix.size(), prefix) == 0;
    }
    return path == pattern;
}

// ── scope (borrowed views into the cap's ECF tree) ─────────────────────────────
struct Scope {
    const EcfValue* incl = nullptr;   // array or null
    const EcfValue* excl = nullptr;   // array or null
};

const EcfValue* as_array(const EcfValue* v) {
    return (v && v->is<ecf::Array>()) ? v : nullptr;
}

Scope parse_scope(const EcfValue* m) {
    Scope s;
    if (m && m->is<ecf::Map>()) {
        s.incl = as_array(m->find("include"));
        s.excl = as_array(m->find("exclude"));
    }
    return s;
}

const EcfValue* grant_dim(const EcfValue* grant, std::string_view dim) {
    return (grant && grant->is<ecf::Map>()) ? grant->find(dim) : nullptr;
}

std::string text_of(const EcfValue& v) {
    const auto* t = std::get_if<ecf::Text>(&v.as_variant());
    if (!t) return {};
    return std::string(reinterpret_cast<const char*>(t->data()), t->size());
}

// any pattern in `pats` (text array, frame-canonicalized) covering value `cv`?
bool covered(std::string_view frame, const EcfValue* pats, std::string_view cv) {
    if (!pats) return false;
    for (const auto& box : std::get<ecf::Array>(pats->as_variant())) {
        if (!box->is<ecf::Text>()) continue;
        auto cp = canonicalize(frame, text_of(*box));
        if (cp && matches_pattern(cv, *cp)) return true;
    }
    return false;
}

bool matches_scope(std::string_view local_peer, std::string_view value, Scope s) {
    auto cv = canonicalize(local_peer, value);
    if (!cv) return false;
    return covered(local_peer, s.incl, *cv) && !covered(local_peer, s.excl, *cv);
}

const EcfValue* token_grants(const Entity& token) {
    return as_array(token.field("grants"));
}

// §6.3 resource scope test for one grant's resources dimension.
bool check_resource_scope(std::string_view local_peer, std::string_view granter_peer,
                          const EcfValue& resource_map, const EcfValue* res_scope_v) {
    const auto* targets = as_array(value::get(resource_map, "targets"));
    const auto* caller_excl = as_array(value::get(resource_map, "exclude"));
    if (!targets || std::get<ecf::Array>(targets->as_variant()).empty()) return false;
    Scope s = parse_scope(res_scope_v);
    for (const auto& tbox : std::get<ecf::Array>(targets->as_variant())) {
        if (!tbox->is<ecf::Text>()) return false;
        auto ct = canonicalize(local_peer, text_of(*tbox));
        if (!ct) return false;
        bool excluded = caller_excl && covered(local_peer, caller_excl, *ct);
        if (excluded) continue;
        bool ok = covered(granter_peer, s.incl, *ct) && !covered(granter_peer, s.excl, *ct);
        if (!ok) return false;
    }
    return true;
}

// §5.6 scope subset: every child include ⊆ some parent include; every parent exclude ⊆
// some child exclude.
bool scope_subset(std::string_view child_peer, std::string_view parent_peer,
                  Scope child, Scope parent) {
    if (child.incl) {
        for (const auto& cbox : std::get<ecf::Array>(child.incl->as_variant())) {
            if (!cbox->is<ecf::Text>()) continue;
            auto cc = canonicalize(child_peer, text_of(*cbox));
            if (!cc || !covered(parent_peer, parent.incl, *cc)) return false;
        }
    }
    if (parent.excl) {
        for (const auto& pbox : std::get<ecf::Array>(parent.excl->as_variant())) {
            if (!pbox->is<ecf::Text>()) continue;
            auto cpe = canonicalize(parent_peer, text_of(*pbox));
            if (!cpe || !covered(child_peer, child.excl, *cpe)) return false;
        }
    }
    return true;
}

// ── chain collection + the multi-sig root ──────────────────────────────────────
struct Chain {
    std::vector<EntityPtr> items;
    bool ok = false;
};

Chain collect_chain(const EntityPtr& cap, const Envelope& env, const Store& store) {
    Chain c;
    EntityPtr current = cap;  // the cap came from env.find() — already a live shared_ptr
    int depth = 0;
    for (;;) {
        if (depth > kMaxChainDepth) return c;  // ok stays false
        c.items.push_back(current);
        auto ph = current->bytes("parent");
        if (!ph || ph->size() != kHashLen) {
            c.ok = true;
            return c;
        }
        auto parent = resolve(env, store, *ph);
        if (!parent) return c;  // unreachable → not ok
        current = parent;
        depth++;
    }
}

std::optional<std::string> granter_peer_id(const Entity& g_owner) {
    auto pk = g_owner.bytes("public_key");
    if (!pk || pk->size() != 32) return std::nullopt;
    auto pid = peer_id_of_pubkey(*pk);
    if (!pid) return std::nullopt;
    return *pid;
}

// §5.5a per-link canonicalization frame = the link's granter peer_id (or local for a
// multi-sig root with no single granter hash). nullopt = unresolvable → deny.
std::optional<std::string> link_granter_peer(const Envelope& env, const Store& store,
                                             const std::string& local_peer,
                                             const Entity& cap) {
    auto gh = cap.bytes("granter");
    if (!gh || gh->size() != kHashLen) {
        return local_peer;  // multi-sig root (M3) → local frame
    }
    auto g = resolve(env, store, *gh);
    if (!g) return std::nullopt;
    return granter_peer_id(*g);
}

EntityPtr find_signature(std::span<const std::byte> target, const Envelope& env) {
    for (const auto& e : env.included()) {
        if (e->type() != "system/signature") continue;
        auto tg = e->bytes("target");
        if (tg && tg->size() == kHashLen &&
            std::equal(tg->begin(), tg->end(), target.begin())) {
            return e;
        }
    }
    return nullptr;
}

// True when the token's granter is the {signers, threshold} multi-granter shape.
bool is_multi_sig(const Entity& cap) {
    const auto* g = cap.field("granter");
    return g && g->is<ecf::Map>();
}

// §3.6 M3 / §5.5 M4+M6 genuine K-of-N multi-sig root validation. Returns ALLOW only if the
// structure is well-formed AND a distinct-signer quorum (incl. the local peer) signs.
// Structure precedes signature counting (precedence 25). Every failure → Deny (→403).
bool verify_multi_sig_root(const Entity& cap, const Envelope& env, const Store& store,
                           const std::string& local_peer, std::uint64_t tnow) {
    const auto* g = cap.field("granter");
    if (!g || !g->is<ecf::Map>()) return false;
    const auto* signers_v = as_array(g->find("signers"));
    auto threshold = value::uint(*g, "threshold");

    // §3.6 M3 structure — root-only; n≥2; 2≤threshold≤n; distinct signers.
    if (cap.field("parent")) {
        if (cap.bytes("parent")) return false;  // a real parent → not a root
    }
    if (!signers_v || !threshold) return false;
    std::vector<std::vector<std::byte>> signers;
    for (const auto& sb : std::get<ecf::Array>(signers_v->as_variant())) {
        const auto* b = std::get_if<ecf::Bytes>(&sb->as_variant());
        if (b) signers.push_back(*b);
    }
    const std::size_t n = signers.size();
    if (n < 2) return false;
    if (*threshold < 2 || *threshold > n) return false;
    {
        std::set<std::string> seen;
        for (const auto& s : signers) {
            if (!seen.insert(identity::hex_lower(s)).second) return false;  // duplicate
        }
    }

    // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
    bool local_in_signers = false;
    for (const auto& s : signers) {
        auto p = resolve(env, store, s);
        if (p) {
            if (auto pid = granter_peer_id(*p); pid && *pid == local_peer) {
                local_in_signers = true;
                break;
            }
        }
    }
    if (!local_in_signers) return false;

    // temporal validity + grantee resolution (as for any root).
    if (auto nb = cap.uint("not_before"); nb && tnow < *nb) return false;
    if (auto ex = cap.uint("expires_at"); ex && *ex < tnow) return false;
    if (auto ge = cap.bytes("grantee")) {
        if (ge->size() != kHashLen || !resolve(env, store, *ge)) return false;
    } else {
        return false;
    }

    // §5.5 M4 k-of-n: ≥ threshold distinct quorum members produced a valid signature over
    // the cap's content hash.
    std::set<std::string> valid_signers;
    for (const auto& signer_hash : signers) {
        auto signer_peer = resolve(env, store, signer_hash);
        if (!signer_peer) continue;
        for (const auto& sig : env.included()) {
            if (sig->type() != "system/signature") continue;
            auto tg = sig->bytes("target");
            if (!tg || tg->size() != kHashLen ||
                !std::equal(tg->begin(), tg->end(), cap.hash().begin())) {
                continue;
            }
            auto sgnr = sig->bytes("signer");
            if (sgnr && sgnr->size() == kHashLen &&
                std::equal(sgnr->begin(), sgnr->end(), signer_hash.begin()) &&
                verify_signature(*sig, *signer_peer)) {
                valid_signers.insert(identity::hex_lower(signer_hash));
                break;
            }
        }
    }
    return static_cast<std::uint64_t>(valid_signers.size()) >= *threshold;
}

// §5.6 token-level attenuation: every child grant ⊆ some parent grant + TTL monotone.
bool is_attenuated(const std::string& local_peer, const std::string& child_peer,
                   const std::string& parent_peer, const Entity& child, const Entity& parent) {
    const auto* cg = token_grants(child);
    const auto* pg = token_grants(parent);
    if (cg) {
        for (const auto& cbox : std::get<ecf::Array>(cg->as_variant())) {
            bool some = false;
            if (pg) {
                for (const auto& pbox : std::get<ecf::Array>(pg->as_variant())) {
                    if (grant_subset(local_peer, child_peer, parent_peer, *cbox, *pbox)) {
                        some = true;
                        break;
                    }
                }
            }
            if (!some) return false;
        }
    }
    auto pe = parent.uint("expires_at");
    auto ce = child.uint("expires_at");
    if (pe && !ce) return false;          // child infinite, parent finite
    if (pe) return ce && *ce <= *pe;
    return true;
}

bool check_delegation_caveats(const Entity& parent, const Entity& child, int depth) {
    const auto* caveats = parent.map_field("delegation_caveats");
    if (!caveats) return true;
    if (value::is_true(caveats->find("no_delegation"))) return false;
    if (auto mdd = value::uint(*caveats, "max_delegation_depth")) {
        if (static_cast<std::uint64_t>(depth) >= *mdd) return false;
    }
    if (auto max_ttl = value::uint(*caveats, "max_delegation_ttl")) {
        auto ex = child.uint("expires_at");
        auto cr = child.uint("created_at");
        if (ex && cr) {
            if (*ex - *cr > *max_ttl) return false;
        } else if (ex) {
            // created_at absent — can't bound, admit
        } else {
            return false;  // infinite child lifetime exceeds any limit
        }
    }
    return true;
}

Verdict verify_chain(const std::string& local_peer, const Store& store, const EntityPtr& cap,
                     const Envelope& env, bool& unresolvable) {
    unresolvable = false;
    Chain c = collect_chain(cap, env, store);
    if (!c.ok) return Verdict::Deny;
    const Entity& root = *c.items.back();

    // Root authority: a multi-sig root runs k-of-n; a single-sig root must root at local.
    if (is_multi_sig(root)) {
        return verify_multi_sig_root(root, env, store, local_peer, now_ms())
                   ? Verdict::Allow : Verdict::Deny;
    }

    bool root_ok = false;
    if (auto rgh = root.bytes("granter"); rgh && rgh->size() == kHashLen) {
        if (auto g = resolve(env, store, *rgh)) {
            if (auto pid = granter_peer_id(*g)) root_ok = (*pid == local_peer);
        }
    }
    if (!root_ok) return Verdict::Deny;

    bool good = true;
    for (std::size_t i = 0; i < c.items.size() && good; ++i) {
        const Entity& current = *c.items[i];
        // a single-sig link's granter must sign it (signer == granter, verify vs granter).
        auto gh = current.bytes("granter");
        if (gh && gh->size() == kHashLen) {
            auto sgn = find_signature(current.hash(), env);
            auto granter = resolve(env, store, *gh);
            if (sgn && granter) {
                auto signer = sgn->bytes("signer");
                if (!(signer && signer->size() == kHashLen &&
                      std::equal(signer->begin(), signer->end(), gh->begin()) &&
                      verify_signature(*sgn, *granter))) {
                    good = false;
                }
            } else {
                good = false;
            }
        } else {
            good = false;
        }
        // grantee resolution → 401 carve-out
        if (auto geh = current.bytes("grantee"); geh && geh->size() == kHashLen) {
            if (!resolve(env, store, *geh)) {
                unresolvable = true;
                return Verdict::Deny;
            }
        } else {
            unresolvable = true;
            return Verdict::Deny;
        }
        // temporal validity
        std::uint64_t tnow = now_ms();
        if (auto nb = current.uint("not_before"); nb && tnow < *nb) good = false;
        if (auto ex = current.uint("expires_at"); ex && *ex < tnow) good = false;
        // delegation link to the parent
        if (i + 1 < c.items.size()) {
            const Entity& parent = *c.items[i + 1];
            auto child_peer = link_granter_peer(env, store, local_peer, current);
            auto parent_peer = link_granter_peer(env, store, local_peer, parent);
            if (!child_peer || !parent_peer) {
                good = false;
            } else {
                auto pg = parent.bytes("grantee");
                auto cgg = current.bytes("granter");
                if (!(pg && cgg && pg->size() == kHashLen && cgg->size() == kHashLen &&
                      std::equal(pg->begin(), pg->end(), cgg->begin()) &&
                      is_attenuated(local_peer, *child_peer, *parent_peer, current, parent) &&
                      check_delegation_caveats(parent, current, static_cast<int>(i)))) {
                    good = false;
                }
            }
        }
    }
    return good ? Verdict::Allow : Verdict::Deny;
}

bool is_revoked(const std::string& local_peer, const Store& store, const EntityPtr& cap,
                const Envelope& env) {
    auto revoked_at = [&](std::span<const std::byte> h) {
        std::string path = "/" + local_peer + "/system/capability/revocations/" +
                           identity::hex_lower(h);
        return store.get_at(path) != nullptr;
    };
    if (revoked_at(cap->hash())) return true;
    Chain c = collect_chain(cap, env, store);
    std::span<const std::byte> root = c.ok ? std::span<const std::byte>(c.items.back()->hash())
                                           : std::span<const std::byte>(cap->hash());
    return revoked_at(root);
}

}  // namespace

// ── path helpers (public) ──────────────────────────────────────────────────────
bool starts_with(std::string_view prefix, std::string_view s) {
    return s.size() >= prefix.size() && s.compare(0, prefix.size(), prefix) == 0;
}

std::optional<std::string> canonicalize(std::string_view local_peer, std::string_view path) {
    if (starts_with("./", path) || starts_with("../", path) || starts_with("*/", path)) {
        return std::nullopt;  // reserved / ambiguous
    }
    if (starts_with("/", path)) return std::string(path);
    return "/" + std::string(local_peer) + "/" + std::string(path);
}

std::string normalize_uri(std::string_view uri) {
    if (starts_with("entity://", uri)) return "/" + std::string(uri.substr(9));
    return std::string(uri);
}

bool is_peer_id(std::string_view seg) {
    if (seg.size() < 46) return false;
    for (char c : seg) {
        if (kBase58.find(c) == std::string_view::npos) return false;
    }
    return true;
}

std::string extract_peer(std::string_view local_peer, std::string_view uri) {
    std::string norm = normalize_uri(uri);
    std::string_view u = starts_with("/", norm) ? std::string_view(norm).substr(1) : norm;
    auto slash = u.find('/');
    std::string_view first = (slash == std::string_view::npos) ? u : u.substr(0, slash);
    if (is_peer_id(first)) return std::string(first);
    return std::string(local_peer);
}

std::optional<std::string> resolve_granter_peer(const Envelope& env, const Store& store,
                                                const Entity& cap) {
    auto gh = cap.bytes("granter");
    if (!gh || gh->size() != kHashLen) return std::nullopt;
    auto g = resolve(env, store, *gh);
    if (!g) return std::nullopt;
    return granter_peer_id(*g);
}

bool chain_exceeds_depth(const Store& store, const Entity& cap, const Envelope& env) {
    const Entity* current = &cap;
    EntityPtr owned;  // keeps the resolved parent alive
    int depth = 0;
    for (;;) {
        if (depth > kMaxChainDepth) return true;
        auto ph = current->bytes("parent");
        if (!ph || ph->size() != kHashLen) return false;  // root within bound
        auto parent = resolve(env, store, *ph);
        if (!parent) return false;  // unreachable — NOT a depth problem (stays 403)
        owned = parent;
        current = owned.get();
        depth++;
    }
}

bool grant_subset(const std::string& local_peer, const std::string& child_peer,
                  const std::string& parent_peer, const EcfValue& child_grant,
                  const EcfValue& parent_grant) {
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(&child_grant, "handlers")),
                      parse_scope(grant_dim(&parent_grant, "handlers")))) {
        return false;
    }
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(&child_grant, "operations")),
                      parse_scope(grant_dim(&parent_grant, "operations")))) {
        return false;
    }
    if (!scope_subset(child_peer, parent_peer,
                      parse_scope(grant_dim(&child_grant, "resources")),
                      parse_scope(grant_dim(&parent_grant, "resources")))) {
        return false;
    }
    const auto* cp = grant_dim(&child_grant, "peers");
    const auto* pp = grant_dim(&parent_grant, "peers");
    if (cp && pp) {
        return scope_subset(local_peer, local_peer, parse_scope(cp), parse_scope(pp));
    }
    if (!cp && !pp) return true;  // both default [local] → subset
    if (cp) return matches_scope(local_peer, local_peer, parse_scope(cp));
    return matches_scope(local_peer, local_peer, parse_scope(pp));
}

Verdict check_permission(const std::string& local_peer, const std::string& granter_peer,
                         const Entity& exec, const Entity& token,
                         const std::string& handler_pattern) {
    std::string operation = exec.text("operation").value_or("");
    std::string uri = exec.text("uri").value_or("");
    std::string target_peer = extract_peer(local_peer, uri);
    const auto* resource = exec.map_field("resource");
    const auto* grants = token_grants(token);
    if (!grants) return Verdict::Deny;
    for (const auto& gbox : std::get<ecf::Array>(grants->as_variant())) {
        const EcfValue& g = *gbox;
        bool ok = matches_scope(local_peer, operation, parse_scope(grant_dim(&g, "operations"))) &&
                  matches_scope(local_peer, handler_pattern, parse_scope(grant_dim(&g, "handlers")));
        if (ok) {
            const auto* peers_v = grant_dim(&g, "peers");
            if (peers_v) {
                ok = matches_scope(local_peer, target_peer, parse_scope(peers_v));
            } else {
                ok = (target_peer == local_peer);  // default peers = [local]
            }
        }
        if (ok && resource) {
            ok = check_resource_scope(local_peer, granter_peer, *resource,
                                      grant_dim(&g, "resources"));
        }
        if (ok) return Verdict::Allow;
    }
    return Verdict::Deny;
}

ReqVerdict verify_request(const std::string& local_peer, const Store& store,
                          const Envelope& env) {
    const Entity& exec = *env.root();
    auto sgn = find_signature(exec.hash(), env);
    if (!sgn) return ReqVerdict::AuthnFail;
    auto author_h = exec.bytes("author");
    auto signer = sgn->bytes("signer");
    if (!(signer && author_h && signer->size() == kHashLen && author_h->size() == kHashLen &&
          std::equal(signer->begin(), signer->end(), author_h->begin()))) {
        return ReqVerdict::AuthnFail;
    }
    auto author = env.find(*author_h);
    if (!author) return ReqVerdict::AuthnFail;
    if (!verify_signature(*sgn, *author)) return ReqVerdict::AuthnFail;

    auto ch = exec.bytes("capability");
    EntityPtr cap = (ch && ch->size() == kHashLen) ? env.find(*ch) : nullptr;
    if (!cap) return ReqVerdict::AuthzDeny;

    // §4.10(b): chain-depth pre-check BEFORE the per-link authz walk → 400, not 403.
    if (chain_exceeds_depth(store, *cap, env)) return ReqVerdict::ChainTooDeep;

    bool unresolvable = false;
    Verdict chain = verify_chain(local_peer, store, cap, env, unresolvable);
    if (unresolvable) return ReqVerdict::Unresolvable;
    if (chain == Verdict::Deny) return ReqVerdict::AuthzDeny;

    auto grantee = cap->bytes("grantee");
    if (!(grantee && grantee->size() == kHashLen &&
          std::equal(grantee->begin(), grantee->end(), author_h->begin()))) {
        return ReqVerdict::AuthzDeny;
    }
    if (is_revoked(local_peer, store, cap, env)) return ReqVerdict::AuthzDeny;
    return ReqVerdict::Allow;
}

}  // namespace entity_core::cap
