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

std::string text_of(const EcfValue& v);   // defined with the scope helpers below

// The unmatchable value (0.8.2.20). Unreachable as a canonical path by CONSTRUCTION:
// its first segment cannot be a peer_id, since is_peer_id requires >= 46 Base58
// characters and '-' is outside kBase58.
constexpr std::string_view kNeverMatch = "/never-match";

// canonicalize FOR THE MATCHERS, which have no error channel. TOTAL (0.8.2.20): the
// return domain is "a canonical path OR kNeverMatch".
//
// canonicalize() itself keeps its std::optional, because dispatch.cpp's address gate
// and tree-path consumers use the nullopt as a refusal and are exactly the callers
// 0.8.2.20 says SHOULD have the diagnostic. The defect was HERE: `covered` did
// `if (cp && ...)`, so a reserved form was SKIPPED — which is the desired outcome in
// an INCLUDE and the opposite of it in an EXCLUDE, so a grant exclude carrying
// "../x" carved out nothing and the grant was silently wider than its author wrote
// (measured on the wire 2026-09-14).
std::string canon_match(std::string_view frame, std::string_view path) {
    return canonicalize(frame, path).value_or(std::string(kNeverMatch));
}

// AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
// in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
// exclude (carves out nothing), so the reading is chosen where the POSITION is known
// and matches_pattern stays uniform over its operands.
//
// PATH-SCOPE ONLY (0.8.2.24, N2/N3) — every caller must gate this on the dimension's
// scope type. The two live callers do: matches_scope tests `kind == ScopeKind::Path`,
// and check_resource_scope is the RESOURCES dimension, path-scope by definition.
bool exclude_is_unmatchable(std::string_view frame, const EcfValue* excl) {
    if (!excl) return false;
    for (const auto& box : std::get<ecf::Array>(excl->as_variant())) {
        if (!box->is<ecf::Text>()) continue;
        if (canon_match(frame, text_of(*box)) == kNeverMatch) return true;
    }
    return false;
}

// ── §5.4 pattern matching ──────────────────────────────────────────────────────
bool matches_pattern(std::string_view path, std::string_view pattern) {
    // kNeverMatch never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
    // rule rather than a property of the string: the line below returns true for a
    // bare "*", so safety must not rest on a value merely looking unmatchable.
    if (path == kNeverMatch || pattern == kNeverMatch) return false;
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
        if (matches_pattern(cv, canon_match(frame, text_of(*box)))) return true;
    }
    return false;
}

// §5.2 id-scope match (0.8.1, F40) — `operations` and `peers`. Literal comparison with
// exactly two wildcard forms: bare "*" and a trailing "/*" segment-prefix. None of the
// §5.4 path transforms apply, so a pattern carrying path syntax ("/*/get") is matched as
// a literal string: a non-match, never a fault.
bool matches_id_pattern(std::string_view value, std::string_view pattern) {
    if (pattern == "*") return true;
    if (pattern.size() >= 2 && pattern.substr(pattern.size() - 2) == "/*") {
        return value.substr(0, pattern.size() - 1) == pattern.substr(0, pattern.size() - 1);
    }
    return value == pattern;
}

// any id-scope pattern in `pats` covering `value` — no canonicalization
bool covered_id(const EcfValue* pats, std::string_view value) {
    if (!pats) return false;
    for (const auto& box : std::get<ecf::Array>(pats->as_variant())) {
        if (!box->is<ecf::Text>()) continue;
        if (matches_id_pattern(value, text_of(*box))) return true;
    }
    return false;
}

// Which §5.2 matcher a grant dimension uses (0.8.1, F40). Passed explicitly at every
// call site — no default — so a new one cannot inherit the wrong matcher silently,
// which is exactly the F40 defect.
enum class ScopeKind { Id, Path };

bool matches_scope(std::string_view local_peer, std::string_view value, Scope s, ScopeKind kind) {
    // SCOPED TO PATH-SCOPE (0.8.2.24, N2/N3). §5.2's exclude loop now tests the sentinel
    // INSIDE `if dimension_type == "system/capability/path-scope"`, and §5.4 says the
    // same from the other side: "a capability carrying an unmatchable PATH-SCOPE pattern
    // is INVALID ... It does NOT reach `operations` or `peers` [MUST]". This guard was
    // UNCONDITIONAL until 0.8.2.24 — which was the text at the time (F82 was our own
    // ask, and the grant created this work) — and under it an ordinary namespaced
    // operation name (a bare star, a slash, then "apply") path-canonicalizes to the
    // sentinel and DENIES THE WHOLE DIMENSION. Over-denial, invisible on well-formed
    // grants.
    //
    // The two id-scope dimensions reach covered_id's literal arm below unguarded, which
    // is correct: under §3.6's id-scope grammar every non-"*" pattern is a literal and a
    // literal is never structurally unmatchable, so there is nothing here for the
    // sentinel to detect. §5.4 says so outright and leaves the id-scope form of the
    // carves-out-nothing hazard deliberately open rather than minting a second sentinel
    // for it — a scope boundary, not an omission.
    if (kind == ScopeKind::Path && exclude_is_unmatchable(local_peer, s.excl)) {
        return false;  // 0.8.2.21 — deny, do not carve out nothing
    }
    if (kind == ScopeKind::Id) {
        return covered_id(s.incl, value) && !covered_id(s.excl, value);
    }
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
    // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    // target: the coverage test below is correct in isolation and is simply never
    // reached on a sentinel, because matches_pattern answers false.
    if (exclude_is_unmatchable(granter_peer, s.excl)) return false;
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

// One side of a §5.5a subset comparison, dispatching on the dimension's SCOPE KIND.
bool subset_covered(std::string_view frame, const EcfValue* pats, std::string_view value,
                    ScopeKind kind) {
    return kind == ScopeKind::Id ? covered_id(pats, value) : covered(frame, pats, value);
}

// §5.5a subset check: every child include must be covered by some parent include, and
// every parent exclude must be inherited by some child exclude.
//
// TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
// §3.6's id-scope grammar binds the scope TYPE, not one function — "An implementation on
// the canonicalizing reading is non-conformant and MUST adopt the literal matcher" — so
// the rule F40 landed on matches_scope reaches here too, with delegation-chain WIDENING
// named as the reason: on the canonicalizing reading "/tree/get" is covered by "*" in one
// direction and a star-slash-apply form is not, so a child grant can come out WIDER than
// its parent. `lean`'s differential put it at 2 of 64 include pairs and 2 of 64 exclude
// pairs, fail-closed, with a 16-pair control alphabet reporting 0 — which is why every
// hand-tried example missed it.
//
// `kind` has NO DEFAULT and is named at every call site, because a default is how the
// next dimension inherits the wrong matcher silently — the original F40 defect.
// handlers/resources -> Path; operations/peers -> Id. The per-link granter frames are
// meaningless on the Id arm (an id pattern is never canonicalized) and are simply unread
// there rather than being a second parameter to get wrong.
bool scope_subset(std::string_view child_peer, std::string_view parent_peer,
                  Scope child, Scope parent, ScopeKind kind) {
    auto frame = [kind](std::string_view peer, std::string_view p) -> std::string {
        return kind == ScopeKind::Path ? canon_match(peer, p) : std::string(p);
    };
    if (child.incl) {
        for (const auto& cbox : std::get<ecf::Array>(child.incl->as_variant())) {
            if (!cbox->is<ecf::Text>()) continue;
            if (!subset_covered(parent_peer, parent.incl, frame(child_peer, text_of(*cbox)), kind)) return false;
        }
    }
    if (parent.excl) {
        for (const auto& pbox : std::get<ecf::Array>(parent.excl->as_variant())) {
            if (!pbox->is<ecf::Text>()) continue;
            if (!subset_covered(child_peer, child.excl, frame(parent_peer, text_of(*pbox)), kind)) return false;
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

// ── §6.2 CAP-6a: unrepresentable temporal fields on INGEST ──────────────────────
//
// True when every CAP-6a temporal field on a RECEIVED token is either absent (legal)
// or representable as a uint64.
//
// This is the reader-side half of CAP-6 and it is where a peer fails OPEN. The idiomatic
// accessor answers std::nullopt both when a field is ABSENT and when it is PRESENT but
// not a uint -- `if (!i || i->negative) return std::nullopt;` -- so a token carrying
// expires_at:-1 silently skipped the expiry check and was honored with 200. §6.2 CAP-6a
// is explicit: such a token "is malformed. A verifier MUST refuse it and MUST NOT treat
// the unrepresentable field as absent." An absent expires_at stays legal and is
// deliberately NOT rejected here.
//
// Refusal must be the §5.2 capability_denied disposition (a status-bearing response),
// never a decode-layer silent drop or a transport close.
bool temporal_fields_representable(const Entity& tok) {
    for (auto key : {"expires_at", "not_before", "created_at"}) {
        const auto* v = tok.field(key);
        if (!v) continue;  // absent is legal
        const auto* i = std::get_if<ecf::Int>(&v->as_variant());
        if (!i || i->negative) return false;  // present but not a uint64 => malformed
    }
    return true;
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
        // temporal validity.
        //
        // CAP-6a FIRST: a present-but-unrepresentable expires_at / not_before /
        // created_at is MALFORMED and must be refused outright. This has to run BEFORE
        // the two range checks below, because those use uint(), which cannot tell
        // "absent" from "present but not a uint64" -- so on its own it would skip the
        // check and honor the token (fail-open).
        if (!temporal_fields_representable(current)) good = false;
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

// ── §5.6 temporal ceiling terms (public) ───────────────────────────────────────
std::optional<std::uint64_t> add_ttl(std::uint64_t created_at, std::uint64_t ttl) {
    const std::uint64_t sum = created_at + ttl;
    if (sum < created_at) return std::nullopt;  // uint64 wrap => drop the term
    return sum;
}

std::optional<std::uint64_t> parent_expiry(const Envelope& env, const Store& store,
                                           std::span<const std::byte> parent_hash) {
    auto parent = resolve(env, store, parent_hash);
    if (!parent) return std::nullopt;
    return parent->uint("expires_at");
}

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
    // The scope KIND is a property of the DIMENSION, named here, never defaulted
    // (F50 / 0.8.2.16). Only RESOURCES takes the §5.5a per-link granter frames; handlers
    // stays local, and the two id dimensions do not canonicalize at all.
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(&child_grant, "handlers")),
                      parse_scope(grant_dim(&parent_grant, "handlers")), ScopeKind::Path)) {
        return false;
    }
    if (!scope_subset(local_peer, local_peer,
                      parse_scope(grant_dim(&child_grant, "operations")),
                      parse_scope(grant_dim(&parent_grant, "operations")), ScopeKind::Id)) {
        return false;
    }
    if (!scope_subset(child_peer, parent_peer,
                      parse_scope(grant_dim(&child_grant, "resources")),
                      parse_scope(grant_dim(&parent_grant, "resources")), ScopeKind::Path)) {
        return false;
    }
    const auto* cp = grant_dim(&child_grant, "peers");
    const auto* pp = grant_dim(&parent_grant, "peers");
    if (cp && pp) {
        return scope_subset(local_peer, local_peer, parse_scope(cp), parse_scope(pp), ScopeKind::Id);
    }
    if (!cp && !pp) return true;  // both default [local] → subset
    if (cp) return matches_scope(local_peer, local_peer, parse_scope(cp), ScopeKind::Id);
    return matches_scope(local_peer, local_peer, parse_scope(pp), ScopeKind::Id);
}

// ── §5.2 effective targets and §6.3 check_path_permission ─────────────────────

// effective_targets derives §5.2's effective target list (0.8.2.20): the caller's own
// `resource.exclude` removes entries from the request BEFORE anything else looks at it.
//
// The survivors are in the caller's OWN SPELLING, not canonicalized — 0.8.2.21 is
// explicit that effective_targets yields raw survivors, and the distinction is
// load-bearing here because the value flows on to Store::get_at, which canonicalizes for
// itself.
//
// `had_resource` says whether a `resource` carrying a `targets` key was present at all.
// An ABSENT resource and a resource whose every target was excluded are different inputs
// to §3.3, and for a resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT
// REQUESTS with different answers rather than merely different inputs to one.
//
// THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11): "where an
// implementation projects resource.targets onto the effective set ahead of the handler,
// that projection MUST NOT be lossy about its own emptiness — narrow when narrowing
// leaves something, and retain the raw pair when narrowing would empty it." A function
// returning only a list cannot satisfy that: collapsing [qA] exclude [qA] to [] deletes
// the two-empties discriminator before any handler can read it, and the handler's
// refusal arm becomes dead code only a WIRE drive can detect.
//
// This peer has exactly ONE narrowing seam — this function, called by the tree handler.
// §6.5's dispatch chain does not project: check_permission reads `resource` for itself.
// So there is no second door to keep in step, and adding a projection at dispatch would
// create one.
//
// A PRESENT-BUT-ILL-TYPED `targets` is PRESENT: a non-array yields an empty survivor list
// rather than "absent", so {"targets": 42} answers the present-but-empty disposition and
// never the WIDER absent-case one. That is N11's own defect one field over, and it is the
// cell the two vanguards initially disagreed on.
Effective effective_targets(std::string_view local_peer, const Entity& exec) {
    Effective out;
    const auto* r = exec.field("resource");
    if (!r || !r->is<ecf::Map>()) return out;
    const auto* targets = value::get(*r, "targets");
    if (!targets) return out;          // no `targets` key at all — the ABSENT case
    out.had_resource = true;
    if (!targets->is<ecf::Array>()) return out;   // present-but-ill-typed: NOT absent
    const auto* caller_excl = as_array(value::get(*r, "exclude"));
    for (const auto& tbox : std::get<ecf::Array>(targets->as_variant())) {
        if (!tbox->is<ecf::Text>()) continue;
        std::string raw = text_of(*tbox);
        // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's table
        // rules it separately from the grant arm): canon_match answers the sentinel and
        // matches_pattern then answers false, so the target simply SURVIVES. That
        // asymmetry is 0.8.2.21's whole point and it is INHERITED from `covered` here,
        // never restated.
        if (caller_excl && covered(local_peer, caller_excl, canon_match(local_peer, raw))) {
            continue;
        }
        out.survivors.push_back(std::move(raw));
    }
    return out;
}

// check_path_permission is §6.3's handler-level path check.
//
// IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
// subject is derived after dispatch, and the dispatch-level check can be made VACUOUS by
// caller-controlled input: a caller who excludes the one target its capability does not
// cover removes that target from check_permission's view entirely, and a handler that
// then acts on it has authorized nothing.
//
// THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by
// construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
// step 3, before any handler runs), and §6.3's signature names only handlers, operations
// and resources.
//
// THE FRAME IS local_peer, NOT THE GRANTER, and that is the spec's own signature rather
// than a choice: §6.3's block reads `matches_scope(canonical_path, grant.resources,
// "path-scope", local_peer_id)` — there is no granter parameter to pass. §5.5a governs
// chain ATTENUATION, where the subject is a PATTERN compared against a parent's pattern;
// this call site compares a CONCRETE LOCAL PATH the handler is about to touch. Adding a
// frame here is the over-scoping defect this cohort has recorded three times.
//
// There is no caller-exclude set at this call site: the subject is a single concrete path
// and the caller's exclusions have already been applied in deriving it. Every grant
// exclude covering the subject therefore denies — which matches_scope already implements,
// including 0.8.2.21's sentinel rule, so this function is three calls to it and nothing
// else. An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no
// tree paths) and DENIES every path here, which is what that note says it should:
// `covered` over a null/empty include list is false.
bool check_path_permission(std::string_view local_peer, std::string_view operation,
                           std::string_view path, const Entity& token,
                           std::string_view handler_pattern) {
    const auto* grants = token_grants(token);
    if (!grants) return false;
    // canonicalize is TOTAL for the matchers and may answer the sentinel, which matches
    // no grant (§5.4) — so a malformed path falls through to DENY rather than being
    // matched against anything. matches_scope canonicalizes its `value` itself, and an
    // already-absolute path passes through unchanged; a reserved form answers nullopt
    // there, which is also a DENY.
    for (const auto& gbox : std::get<ecf::Array>(grants->as_variant())) {
        const EcfValue* g = &*gbox;
        if (!g->is<ecf::Map>()) continue;
        if (!matches_scope(local_peer, handler_pattern, parse_scope(grant_dim(g, "handlers")),
                           ScopeKind::Path)) {
            continue;
        }
        if (!matches_scope(local_peer, operation, parse_scope(grant_dim(g, "operations")),
                           ScopeKind::Id)) {
            continue;
        }
        if (!matches_scope(local_peer, path, parse_scope(grant_dim(g, "resources")),
                           ScopeKind::Path)) {
            continue;
        }
        return true;
    }
    return false;
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
        bool ok = matches_scope(local_peer, operation, parse_scope(grant_dim(&g, "operations")), ScopeKind::Id) &&
                  matches_scope(local_peer, handler_pattern, parse_scope(grant_dim(&g, "handlers")), ScopeKind::Path);
        if (ok) {
            const auto* peers_v = grant_dim(&g, "peers");
            if (peers_v) {
                ok = matches_scope(local_peer, target_peer, parse_scope(peers_v), ScopeKind::Id);
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
