/*
 * capability.h — the §5 capability system surface used by the dispatcher.
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef EC_CAPABILITY_H
#define EC_CAPABILITY_H

#include "peer_internal.h"

/* §5.2 three-way request verdict + the §5.5 unresolvable-grantee carve-out (→401). */
typedef enum ec_req_verdict {
    EC_REQ_ALLOW = 0,
    EC_REQ_AUTHN_FAIL,      /* → 401 authentication_failed */
    EC_REQ_AUTHZ_DENY,      /* → 403 capability_denied */
    EC_REQ_CHAIN_TOO_DEEP,  /* → 400 chain_depth_exceeded (§4.10b) */
    EC_REQ_UNRESOLVABLE     /* → 401 unresolvable_grantee */
} ec_req_verdict;

typedef enum ec_verdict { EC_V_ALLOW = 0, EC_V_DENY } ec_verdict;

/* §1.4 / §5.4 path helpers. Returned strings are malloc'd (caller frees) unless noted. */
bool ec_startswith(const char *prefix, const char *s);
/* Resolve a peer-relative path to absolute /{local}/... form. *out malloc'd; on a
 * reserved/ambiguous path returns EC_ERR_BAD_INPUT. */
ec_status ec_canonicalize(const char *local_peer, const char *path, char **out);
/* entity://x → /x ; else unchanged. *out malloc'd. */
ec_status ec_normalize_uri(const char *uri, char **out);
bool ec_is_peer_id(const char *seg);
/* The peer named by the URI's first segment, or local. *out malloc'd. */
ec_status ec_extract_peer(const char *local_peer, const char *uri, char **out);

/* §5.2 verify-request: the 3-way dispatch-time verdict over the inbound envelope. */
ec_req_verdict ec_cap_verify_request(const char *local_peer, ec_store *store,
                                     const ec_envelope *env);

/* §5.2 check-permission: gate the wire request at the authz boundary. */
ec_verdict ec_cap_check_permission(const char *local_peer, const char *granter_peer,
                                   const ec_entity *exec, const ec_entity *token,
                                   const char *handler_pattern);

/* §5.6: the parent token's ABSOLUTE expires_at term for MIN_DEFINED, resolved from
 * the frame's included set or the store. False = the parent contributes no term. */
bool ec_cap_parent_expiry(const ec_envelope *env, ec_store *store,
                          const uint8_t *parent_hash, uint64_t *out);

/* §PR-8: the granter peer_id for canonicalizing a cap's resource patterns. *out
 * malloc'd or NULL (caller falls back to local). EC_OK even when *out==NULL. */
ec_status ec_cap_resolve_granter_peer(const ec_envelope *env, ec_store *store,
                                      const ec_entity *cap, char **out);

/* §4.10(b) structural depth pre-check: true if the chain rooted at `cap` exceeds the
 * max depth (64), walking parents with NO signature work, BEFORE the authz walk. An
 * unreachable parent is NOT a depth problem (returns false, stays 403). */
bool ec_cap_chain_exceeds_depth(ec_store *store, const ec_entity *cap,
                                const ec_envelope *env);

/* §5.6 attenuation subset check used by capability/delegate mint-bounding. The grant
 * args are the raw grant cbor-maps; returns true if `child` ⊆ `parent`. */
bool ec_cap_grant_subset(const char *local_peer, const char *child_peer,
                         const char *parent_peer,
                         const ec_value *child_grant, const ec_value *parent_grant);

/* §6.3 resource scope test for one grant's resources dimension. */
bool ec_cap_check_resource_scope(const char *local_peer, const char *granter_peer,
                                 const ec_value *resource_map, const ec_value *res_scope);

/* §5.2 effective targets (0.8.2.20/.21/.25 N11). `s` BORROWS into the exec's value
 * tree and `len` is the value-node byte length (not strlen — an embedded NUL is
 * invisible to the C-string view and §1.4 R1 forbids it). */
typedef struct ec_tgt { const char *s; size_t len; } ec_tgt;
typedef struct ec_effective {
    ec_tgt *items;       /* malloc'd array of borrowed targets; free with the helper */
    size_t len;          /* survivors after the CALLER's own resource.exclude */
    bool had_resource;   /* was a `resource` carrying a `targets` key present at all? */
} ec_effective;
ec_status ec_cap_effective_targets(const char *local_peer, const ec_entity *exec,
                                   ec_effective *out);
void ec_cap_effective_free(ec_effective *e);

/* §6.3's handler-level path check. THREE dimensions (handlers/operations/resources),
 * framed on the LOCAL peer — never the granter. See the definition. */
bool ec_cap_check_path_permission(const char *local_peer, const char *operation,
                                  const char *path, const ec_entity *token,
                                  const char *handler_pattern);

/* ── §1.4 PD-2: outbound sub-dispatch authorization ─────────────────────────── */

/* The §1.4 PEER-RELATIVE spelling of a uri (scheme + leading peer_id segment stripped,
 * and ONLY when that segment IS a peer_id). *out malloc'd. */
ec_status ec_cap_peer_relative_of(const char *uri, char **out);

/* Store key of a handler's OWN grant (§6.8), tolerant of an absolute or peer-relative
 * pattern. *out malloc'd. */
ec_status ec_cap_grant_path_for(const char *local_peer, const char *pattern, char **out);

/* §1.4's PD-2 gate — check_permission before a locally-originated sub-dispatch leaves the
 * peer. `cred == NULL` selects the ambient arm. See the definition. */
bool ec_cap_check_outbound_sub_dispatch(const char *local_peer, const char *target_peer,
                                        const char *handler_pattern, const char *operation,
                                        ec_store *store, const ec_entity *handler_grant,
                                        const ec_value *resource, const ec_entity *cred,
                                        const ec_envelope *env);

uint64_t ec_now_ms(void);

#endif /* EC_CAPABILITY_H */
