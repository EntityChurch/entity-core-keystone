// entity_core/capability.hpp — the §5 capability system surface used by the dispatcher:
// pattern matching (§5.4), the §5.2 three-way request verdict, check-permission (§5.2),
// delegation-chain verification (§5.5) incl. genuine §3.6 multi-sig K-of-N at the root,
// attenuation (§5.6), the §PR-8 granter frame, and the §4.10(b) chain-depth pre-check.
//
// Idiom: free functions in entity_core::cap over borrowed EcfValue / Entity / Store /
// Envelope. Verdicts are the §5.10 Layer-1 ALLOW/DENY (determinism, N8); the dispatcher
// maps the trichotomy → 401 authn / 403 authz / 401 unresolvable / 400 chain_depth.
//
// SPDX-License-Identifier: Apache-2.0
#ifndef ENTITY_CORE_CAPABILITY_HPP
#define ENTITY_CORE_CAPABILITY_HPP

#include <cstdint>
#include <optional>
#include <string>

#include "entity_core/entity.hpp"
#include "entity_core/store.hpp"

namespace entity_core::cap {

// §5.2 three-way request verdict + the §5.5 unresolvable-grantee carve-out (→401) + the
// §4.10(b) over-deep chain carve-out (→400).
enum class ReqVerdict {
    Allow,
    AuthnFail,      // → 401 authentication_failed
    AuthzDeny,      // → 403 capability_denied
    ChainTooDeep,   // → 400 chain_depth_exceeded (§4.10b)
    Unresolvable,   // → 401 unresolvable_grantee
};

enum class Verdict { Allow, Deny };

// Wall-clock milliseconds (token created_at / temporal validity).
std::uint64_t now_ms();

// §1.4 / §5.4 path helpers.
bool starts_with(std::string_view prefix, std::string_view s);
// Resolve a peer-relative path to absolute /{local}/... form. nullopt on a reserved/
// ambiguous path (./ ../ */ prefix).
std::optional<std::string> canonicalize(std::string_view local_peer, std::string_view path);
std::string normalize_uri(std::string_view uri);   // entity://x → /x ; else unchanged
bool is_peer_id(std::string_view seg);
std::string extract_peer(std::string_view local_peer, std::string_view uri);

// §5.2 verify-request: the 3-way dispatch-time verdict over the inbound envelope.
ReqVerdict verify_request(const std::string& local_peer, const Store& store,
                          const Envelope& env);

// §5.2 check-permission: gate the wire request at the authz boundary.
Verdict check_permission(const std::string& local_peer, const std::string& granter_peer,
                         const Entity& exec, const Entity& token,
                         const std::string& handler_pattern);

// §PR-8: the granter peer_id for canonicalizing a cap's resource patterns (nullopt →
// caller falls back to local).
std::optional<std::string> resolve_granter_peer(const Envelope& env, const Store& store,
                                                const Entity& cap);

// §4.10(b) structural depth pre-check: true if the chain rooted at `cap` exceeds max depth
// (64), walking parents with NO signature work, BEFORE the authz walk. An unreachable
// parent is NOT a depth problem (returns false, stays 403).
bool chain_exceeds_depth(const Store& store, const Entity& cap, const Envelope& env);

// §5.6 attenuation subset check used by capability/delegate mint-bounding: child ⊆ parent.
bool grant_subset(const std::string& local_peer, const std::string& child_peer,
                  const std::string& parent_peer, const EcfValue& child_grant,
                  const EcfValue& parent_grant);

}  // namespace entity_core::cap

#endif  // ENTITY_CORE_CAPABILITY_HPP
