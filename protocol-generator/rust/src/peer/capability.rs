//! Capability system (L3) — the §5 verification core: pattern matching (§5.4),
//! request verification (§5.2 verify_request / check_permission), delegation-chain
//! verification (§5.5), attenuation (§5.6), delegation caveats (§5.7), revocation
//! (§5.1), and the genuine §3.6 K-of-N multi-signature root.
//!
//! Verdict is the §5.10 Layer-1 deterministic ALLOW/DENY; the dispatcher maps
//! DENY→403, with the §5.5 unresolvable-grantee carve-out surfaced as a distinct
//! verdict mapping to 401 (§5.2 / §4.6 / F20 authn/authz split), and the §4.10(b)
//! over-depth chain surfaced as `400 chain_depth_exceeded` (structural excess,
//! NOT 403 — checked BEFORE the per-link authz walk).

use super::identity;
use super::model::{self, hex, Entity, Envelope};
use super::store::Store;
use crate::value::{Key, Value};

/// §4.10(b) max capability-chain depth (recommended default 64).
pub const MAX_CHAIN_DEPTH: usize = 64;

/// Layer-1 deterministic verdict (§5.10).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
}

/// 3-way request verdict (§5.2 / §4.6 / F20): authn-class failure → 401,
/// authz-class deny → 403, chain-too-deep → 400, allow → dispatch. The
/// `UnresolvableGrantee` carve-out (§5.5) is surfaced separately → 401.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReqVerdict {
    Allow,
    AuthnFail,
    AuthzDeny,
    ChainTooDeep,
    UnresolvableGrantee,
}

// ── parse helpers ─────────────────────────────────────────────────────────────

#[derive(Default, Clone)]
pub(crate) struct Scope {
    pub(crate) incl: Vec<String>,
    pub(crate) excl: Vec<String>,
}

#[derive(Default, Clone)]
struct Grant {
    handlers: Scope,
    resources: Scope,
    operations: Scope,
    peers: Option<Scope>,
}

fn text_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|it| match it {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn parse_scope(c: &Value) -> Scope {
    Scope {
        incl: text_list(model::map_get(c, "include")),
        excl: text_list(model::map_get(c, "exclude")),
    }
}

fn parse_grant(c: &Value) -> Grant {
    let sc = |key: &str| match model::map_get(c, key) {
        Some(s) => parse_scope(s),
        None => Scope::default(),
    };
    Grant {
        handlers: sc("handlers"),
        resources: sc("resources"),
        operations: sc("operations"),
        peers: model::map_get(c, "peers").map(parse_scope),
    }
}

fn grants_of_token(token: &Entity) -> Vec<Grant> {
    match token.field("grants") {
        Some(Value::Array(arr)) => arr.iter().map(parse_grant).collect(),
        _ => Vec::new(),
    }
}

// ── §5.4 pattern matching ──────────────────────────────────────────────────────

const B58_ALPHABET: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

pub fn is_peer_id(seg: &str) -> bool {
    if seg.len() < 46 {
        return false;
    }
    seg.bytes().all(|c| B58_ALPHABET.contains(&c))
}

/// URI normalization (§1.4): strip the `entity://` scheme to absolute form.
pub fn normalize_uri(uri: &str) -> String {
    if let Some(rest) = uri.strip_prefix("entity://") {
        format!("/{rest}")
    } else {
        uri.to_string()
    }
}

/// The unmatchable value (0.8.2.20). Unreachable as a canonical path by
/// CONSTRUCTION: its first segment cannot be a peer_id, since [`is_peer_id`]
/// requires >= 46 Base58 characters and `-` is outside the Base58 alphabet.
pub const NEVER_MATCH: &str = "/never-match";

/// Resolve peer-relative paths to absolute `/{local}/...` form.
///
/// TOTAL (0.8.2.20): the return domain is "a canonical path OR [`NEVER_MATCH`]".
/// The two reserved arms were ABSENT here — `../x` came back as `/{local}/../x`,
/// which matched nothing, so a grant exclude carrying it carved out nothing and the
/// grant was silently wider than its author wrote (measured on the wire
/// 2026-09-14). A non-match is the desired outcome in an INCLUDE and the opposite
/// of it in an EXCLUDE; the sentinel is what lets the exclude-reading sites tell
/// the two positions apart.
pub fn canonicalize(local_peer: &str, path: &str) -> String {
    if path.starts_with("./") || path.starts_with("../") {
        return NEVER_MATCH.to_string(); // reserved: directory-relative (§1.4)
    }
    if path.starts_with("*/") {
        return NEVER_MATCH.to_string(); // ambiguous bare peer wildcard: use /*/rest
    }
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{local_peer}/{path}")
    }
}

/// AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is
/// fail-CLOSED in an include (covers nothing -> the grant grants nothing) and
/// fail-OPEN in an exclude (carves out nothing), so the reading is chosen where the
/// POSITION is known and [`matches_pattern`] stays uniform over its operands.
///
/// EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be
/// asked of every dimension, transcribing §5.2's loop before that loop grew its type
/// dispatch. NEVER_MATCH is a §5.4 PATH-canonicalization sentinel and has no meaning
/// on an id-scope dimension, whose patterns are literal identifiers that §5.2's own
/// id-scope arm forbids putting through the §5.4 transforms. Asking it outside the
/// type dispatch ran an id pattern through those transforms purely to classify it and
/// then DENIED THE WHOLE DIMENSION on a property unrelated to whether the exclude
/// carves anything out: an `operations` exclude of `*/apply` — an ordinary namespaced
/// operation name, a literal matching nothing under the id-scope grammar —
/// path-canonicalized to the sentinel and denied every operation. Over-denial, and
/// invisible on any well-formed grant.
fn exclude_is_unmatchable(frame: &str, excl: &[String]) -> bool {
    excl.iter().any(|p| canonicalize(frame, p) == NEVER_MATCH)
}

/// Both `path` and `pattern` MUST already be canonical (absolute).
pub fn matches_pattern(path: &str, pattern: &str) -> bool {
    // NEVER_MATCH never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
    // rule rather than a property of the string: the arm below returns true for a
    // bare "*", so safety must not rest on a value merely looking unmatchable.
    if path == NEVER_MATCH || pattern == NEVER_MATCH {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if let Some(remainder) = pattern.strip_prefix("/*/") {
        // /*/rest — skip the first path segment, then match the remainder.
        let after = match path.get(1..).and_then(|p| p.find('/')) {
            Some(i) => &path[1 + i + 1..],
            None => return false,
        };
        return matches_pattern(after, remainder);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        // trailing "/*" → prefix match (keep the slash)
        if prefix.ends_with('/') {
            return path.starts_with(prefix);
        }
    }
    path == pattern
}

fn covered(frame: &str, value: &str, pats: &[String]) -> bool {
    pats.iter()
        .any(|p| matches_pattern(value, &canonicalize(frame, p)))
}

/// Which §5.2 matcher a grant dimension uses (0.8.1, F40). No `Default` impl on
/// purpose — every call site names its dimension, so a new one cannot silently
/// inherit the wrong matcher, which is exactly the F40 defect.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ScopeKind {
    /// `operations`, `peers` — `system/capability/id-scope`.
    Id,
    /// `handlers`, `resources` — `system/capability/path-scope`.
    Path,
}

/// §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard
/// forms — bare `*` and a trailing `/*` segment-prefix. None of the §5.4 path
/// transforms apply, so a pattern carrying path syntax (`/*/get`) is matched as a
/// literal string: a non-match, never a fault.
pub fn matches_id_pattern(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if prefix.ends_with('/') {
            return value.starts_with(prefix);
        }
    }
    value == pattern
}

fn covered_id(value: &str, pats: &[String]) -> bool {
    pats.iter().any(|p| matches_id_pattern(value, p))
}

fn matches_scope(local_peer: &str, value: &str, s: &Scope, kind: ScopeKind) -> bool {
    // SCOPED TO PATH-SCOPE (0.8.2.24, N2/N3). §5.2's exclude loop tests the sentinel
    // INSIDE `if dimension_type == "system/capability/path-scope"`, and §5.4's rule is
    // likewise "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID ...
    // It does NOT reach `operations` or `peers` [MUST]". The two id-scope dimensions
    // reach the literal arm below unguarded, which is correct: under the id-scope
    // grammar every non-`*` pattern is a literal and a literal is never structurally
    // unmatchable, so there is nothing here for the sentinel to detect. (§5.4 says so
    // outright and leaves the id-scope form of the carves-out-nothing hazard
    // deliberately open rather than minting a second sentinel for it — so this is a
    // scope boundary, not an omission.)
    if kind == ScopeKind::Path && exclude_is_unmatchable(local_peer, &s.excl) {
        return false; // 0.8.2.21 — deny, do not carve out nothing
    }
    if kind == ScopeKind::Id {
        return covered_id(value, &s.incl) && !covered_id(value, &s.excl);
    }
    let cv = canonicalize(local_peer, value);
    if !covered(local_peer, &cv, &s.incl) {
        return false;
    }
    !covered(local_peer, &cv, &s.excl)
}

// ── §5.2 check_permission ──────────────────────────────────────────────────────

fn first_segment(uri: &str) -> &str {
    let u = uri.strip_prefix('/').unwrap_or(uri);
    match u.find('/') {
        Some(i) => &u[..i],
        None => u,
    }
}

pub fn extract_peer<'a>(local_peer: &'a str, uri: &'a str) -> &'a str {
    // strip the entity:// scheme (the trailing slash normalize adds is handled by
    // first_segment, which ignores a leading slash)
    let body = uri.strip_prefix("entity://").unwrap_or(uri);
    let first = first_segment(body);
    if is_peer_id(first) {
        first
    } else {
        local_peer
    }
}

fn check_resource_scope(local_peer: &str, granter_peer: &str, resource: &Value, s: &Scope) -> bool {
    let targets = text_list(model::map_get(resource, "targets"));
    let caller_excl = text_list(model::map_get(resource, "exclude"));
    if targets.is_empty() {
        return false;
    }
    // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
    // target: the coverage test below is correct in isolation and is simply never
    // reached on a sentinel, because matches_pattern answers false.
    if exclude_is_unmatchable(granter_peer, &s.excl) {
        return false;
    }
    for tgt in &targets {
        let ct = canonicalize(local_peer, tgt);
        if covered(local_peer, &ct, &caller_excl) {
            continue; // caller excluded (local frame)
        }
        if !covered(granter_peer, &ct, &s.incl) {
            return false; // not in grant include (granter frame)
        }
        if covered(granter_peer, &ct, &s.excl) {
            return false; // in grant exclude → deny
        }
    }
    true
}

/// check_permission gates the wire request at the dispatch authorization boundary
/// (§5.2 / §3.2.3). `granter_peer` is the §PR-8 canonicalization frame for the
/// cap's grant resource patterns; every other dimension stays on the local frame.
pub fn check_permission(
    local_peer: &str,
    granter_peer: &str,
    exec: &Entity,
    token: &Entity,
    handler_pattern: &str,
) -> Verdict {
    let operation = exec.text_field("operation").unwrap_or("");
    let uri = exec.text_field("uri").unwrap_or("");
    let target_peer = extract_peer(local_peer, uri);
    let resource = exec.field("resource");
    for g in grants_of_token(token) {
        if !matches_scope(local_peer, operation, &g.operations, ScopeKind::Id) {
            continue;
        }
        if !matches_scope(local_peer, handler_pattern, &g.handlers, ScopeKind::Path) {
            continue;
        }
        let default_peers = Scope {
            incl: vec![local_peer.to_string()],
            excl: vec![],
        };
        let peers = g.peers.as_ref().unwrap_or(&default_peers);
        if !matches_scope(local_peer, target_peer, peers, ScopeKind::Id) {
            continue;
        }
        let r_ok = match resource {
            Some(r) => check_resource_scope(local_peer, granter_peer, r, &g.resources),
            None => true,
        };
        if r_ok {
            return Verdict::Allow;
        }
    }
    Verdict::Deny
}

/// §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude` removes
/// entries from `resource.targets` BEFORE anything else looks at the request.
///
/// The survivors are returned in the caller's OWN SPELLING, not canonicalized — 0.8.2.21
/// is explicit that `effective_targets` yields raw survivors, and the distinction is
/// load-bearing because the value flows on to `Store::get_at`, which canonicalizes for
/// itself.
///
/// The second return says whether a `resource` was present AT ALL. An ABSENT resource and
/// a resource whose every target was excluded are different inputs to §3.3 — the first is
/// "no resource", the second is an empty effective list — and for a resource-OPTIONAL
/// operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with different answers, not
/// merely different inputs to one disposition.
///
/// THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES `[MUST]` (0.8.2.25, N11): *"where an
/// implementation projects `resource.targets` onto the effective set ahead of the handler,
/// that projection MUST NOT be lossy about its own emptiness — narrow when narrowing
/// leaves something, and retain the raw pair when narrowing would empty it."* A function
/// returning only a list cannot satisfy that: collapsing `[qA] exclude [qA]` to `[]`
/// deletes the two-empties discriminator before any handler can read it, and the handler's
/// refusal arm becomes dead code only a WIRE drive can detect.
///
/// *"Every seam that narrows is exempted alike, inbound-wire and in-process
/// sub-dispatch."* This peer has exactly ONE narrowing seam — this function, called by the
/// tree handler — and §6.5's dispatch chain does not project: `Peer::route` passes `exec`
/// through untouched and `check_permission` reads `resource` for itself. So there is no
/// second door to keep in step, and adding a projection at dispatch would create one.
///
/// A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**: `text_list` of a non-array yields an
/// empty survivor list rather than "absent", so `{"targets": 42}` answers the
/// present-but-empty disposition and never the wider absent-case one. That is N11's own
/// defect one field over, and it is the cell the two vanguards initially disagreed on.
pub fn effective_targets(local_peer: &str, exec: &Entity) -> (Vec<String>, bool) {
    let r = match exec.field("resource") {
        Some(v @ Value::Map(_)) => v,
        _ => return (Vec::new(), false),
    };
    if model::map_get(r, "targets").is_none() {
        return (Vec::new(), false);
    }
    let targets = text_list(model::map_get(r, "targets"));
    let caller_excl = text_list(model::map_get(r, "exclude"));
    let mut out = Vec::with_capacity(targets.len());
    for t in targets {
        let ct = canonicalize(local_peer, &t);
        // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's table
        // rules it separately from the grant arm): `canonicalize` answers NEVER_MATCH and
        // `matches_pattern` then answers false, so the target simply survives. That
        // asymmetry is 0.8.2.21's whole point and it is INHERITED here, never restated.
        if caller_excl
            .iter()
            .any(|x| matches_pattern(&ct, &canonicalize(local_peer, x)))
        {
            continue;
        }
        out.push(t);
    }
    (out, true)
}

/// H9 — the public path-permission predicate: is `operation` on `path`, served by the
/// handler at `handler_pattern`, permitted by some single grant in `token`?
///
/// **Resources match against the local peer with NO granter frame.** This is the §6.3
/// tree handler's defense-in-depth check and the one an extension whose target lives
/// in its params needs; it is deliberately not the dispatch-boundary check (which takes
/// the granter frame for resources, §PR-8) and not chain attenuation (a different
/// function again). Adding a frame here is the over-scoping defect this cohort has
/// recorded three times.
///
/// It answers about the token's grants only; the token's signature, chain, temporal
/// bounds and revocation are `verify_request`'s, and must already have held.
///
/// IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
/// subject is derived after dispatch, and the dispatch-level check can be made VACUOUS by
/// caller-controlled input: a caller who excludes the one target its capability does not
/// cover removes that target from `check_permission`'s view entirely, and a handler that
/// then acts on it has authorized nothing.
///
/// THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by
/// construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
/// step 3, before any handler runs), and §6.3's signature names only handlers, operations
/// and resources.
///
/// There is no caller-exclude set at this call site: the subject is a single concrete
/// path, and the caller's exclusions have already been applied in deriving it. Every grant
/// exclude covering the subject therefore denies — which `matches_scope` already
/// implements, including 0.8.2.21's sentinel rule, so this function is three calls to it
/// and nothing else. An empty `resources.include` is a legal grant shape (§5.2: handlers
/// that touch no tree paths) and DENIES every path here, which is what that note says it
/// should: `covered` over an empty include list is false.
pub fn check_path_permission(
    operation: &str,
    path: &str,
    token: &Entity,
    handler_pattern: &str,
    local_peer: &str,
) -> bool {
    // `canonicalize` is total and may answer NEVER_MATCH, which matches no grant (§5.4) —
    // so a malformed path falls through to DENY rather than being matched against anything.
    let cp = canonicalize(local_peer, path);
    grants_of_token(token).iter().any(|g| {
        matches_scope(local_peer, handler_pattern, &g.handlers, ScopeKind::Path)
            && matches_scope(local_peer, operation, &g.operations, ScopeKind::Id)
            && matches_scope(local_peer, &cp, &g.resources, ScopeKind::Path)
    })
}

// ── §5.5 / §5.6 chain verification + attenuation ───────────────────────────────

pub fn resolve(env: &Envelope, st: &Store, h: &[u8]) -> Option<Entity> {
    if let Some(e) = env.included_get(h) {
        return Some(e.clone());
    }
    st.get_by_hash(h)
}

pub fn find_signature(env: &Envelope, target: &[u8]) -> Option<Entity> {
    env.included.values().find_map(|e| {
        if e.typ == "system/signature" && e.bytes_field("target") == Some(target) {
            Some(e.clone())
        } else {
            None
        }
    })
}

fn link_granter_peer(env: &Envelope, st: &Store, local_peer: &str, cap: &Entity) -> Option<String> {
    // a multi-sig root (M3) has a map granter → local frame
    let gh = match cap.field("granter") {
        Some(Value::Bytes(b)) => b.clone(),
        Some(Value::Map(_)) => return Some(local_peer.to_string()),
        _ => return Some(local_peer.to_string()),
    };
    let g = resolve(env, st, &gh)?; // unresolvable granter → None (deny)
    let pk = g.bytes_field("public_key")?;
    Some(identity::peer_id_of_pubkey(pk))
}

/// §5.5a subset check: every child include must be covered by some parent include, and
/// every parent exclude must be inherited by some child exclude.
///
/// TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
/// §3.6's id-scope grammar binds the scope TYPE, not one function — *"An implementation
/// on the canonicalizing reading is non-conformant and MUST adopt the literal matcher"* —
/// so the rule F40 landed on `matches_scope` reaches here too, with delegation-chain
/// WIDENING named as the reason: on the canonicalizing reading `/tree/get` is covered by
/// `*` in one direction and `*/apply` is not, and a child grant can come out wider than
/// its parent. `lean`'s differential put it at 2 of 64 include pairs and 2 of 64 exclude
/// pairs, fail-closed, with a 16-pair control alphabet reporting 0 — which is why every
/// hand-tried example missed it.
///
/// `kind` has NO DEFAULT and is named at every call site, because a default is how the
/// next dimension inherits the wrong matcher silently — the original F40 defect.
/// `handlers`/`resources` -> path; `operations`/`peers` -> id. The per-link granter
/// frames are meaningless on the id arm (an id pattern is never canonicalized) and are
/// simply unread there rather than being a second parameter to get wrong.
fn scope_subset(
    child_peer: &str,
    parent_peer: &str,
    child: &Scope,
    parent: &Scope,
    kind: ScopeKind,
) -> bool {
    let frame = |peer: &str, p: &String| -> String {
        match kind {
            ScopeKind::Path => canonicalize(peer, p),
            ScopeKind::Id => p.clone(),
        }
    };
    let covers = |pattern_side: &str, value_side: &str| -> bool {
        match kind {
            ScopeKind::Path => matches_pattern(value_side, pattern_side),
            ScopeKind::Id => matches_id_pattern(value_side, pattern_side),
        }
    };
    for cp in &child.incl {
        let cc = frame(child_peer, cp);
        if !parent
            .incl
            .iter()
            .any(|pp| covers(&frame(parent_peer, pp), &cc))
        {
            return false;
        }
    }
    for pe in &parent.excl {
        let cpe = frame(parent_peer, pe);
        if !child
            .excl
            .iter()
            .any(|ce| covers(&frame(child_peer, ce), &cpe))
        {
            return false;
        }
    }
    true
}

fn grant_subset(
    local_peer: &str,
    child_peer: &str,
    parent_peer: &str,
    child: &Grant,
    parent: &Grant,
) -> bool {
    // The scope KIND is a property of the dimension, named here, never defaulted
    // (F50 / 0.8.2.16). Only the RESOURCES dimension takes the §5.5a per-link granter
    // frames; handlers stays local, and the two id dimensions do not canonicalize at all.
    if !scope_subset(
        local_peer,
        local_peer,
        &child.handlers,
        &parent.handlers,
        ScopeKind::Path,
    ) {
        return false;
    }
    if !scope_subset(
        local_peer,
        local_peer,
        &child.operations,
        &parent.operations,
        ScopeKind::Id,
    ) {
        return false;
    }
    if !scope_subset(
        child_peer,
        parent_peer,
        &child.resources,
        &parent.resources,
        ScopeKind::Path,
    ) {
        return false;
    }
    let default = Scope {
        incl: vec![local_peer.to_string()],
        excl: vec![],
    };
    let cp = child.peers.as_ref().unwrap_or(&default);
    let pp = parent.peers.as_ref().unwrap_or(&default);
    scope_subset(local_peer, local_peer, cp, pp, ScopeKind::Id)
}

fn is_attenuated(
    local_peer: &str,
    child_peer: &str,
    parent_peer: &str,
    child: &Entity,
    parent: &Entity,
) -> bool {
    let cg = grants_of_token(child);
    let pg = grants_of_token(parent);
    for c in &cg {
        if !pg
            .iter()
            .any(|p| grant_subset(local_peer, child_peer, parent_peer, c, p))
        {
            return false;
        }
    }
    let pe = parent.uint_field("expires_at");
    let ce = child.uint_field("expires_at");
    if pe.is_some() && ce.is_none() {
        return false; // child infinite, parent finite
    }
    if let (Some(p), Some(c)) = (pe, ce) {
        if c > p {
            return false;
        }
    }
    true
}

fn check_delegation_caveats(parent: &Entity, child: &Entity, depth: u64) -> bool {
    let caveats = match parent.field("delegation_caveats") {
        Some(c) => c,
        None => return true,
    };
    if let Some(Value::Bool(true)) = model::map_get(caveats, "no_delegation") {
        return false;
    }
    if let Some(Value::UInt(m)) = model::map_get(caveats, "max_delegation_depth") {
        if depth >= *m {
            return false;
        }
    }
    if let Some(Value::UInt(maxttl)) = model::map_get(caveats, "max_delegation_ttl") {
        match (
            child.uint_field("expires_at"),
            child.uint_field("created_at"),
        ) {
            (Some(e), Some(c)) => {
                if e.saturating_sub(c) > *maxttl {
                    return false;
                }
            }
            (None, _) => return false, // infinite child lifetime exceeds any finite limit
            _ => {}
        }
    }
    true
}

/// §6.2 CAP-6a (INGEST): every temporal field on a RECEIVED token must be either
/// ABSENT (legal — "no bound") or representable as `primitive/uint`. A bignum, a
/// negative integer, or anything else is **malformed**, and the verifier MUST refuse
/// it rather than treat the unrepresentable field as absent.
///
/// This is the reader-side half of CAP-6 and it is where this peer failed OPEN.
/// `uint_field` returns `None` BOTH for an absent field and for a present non-`UInt`
/// one, so `if let Some(ex) = cap.uint_field("expires_at")` silently SKIPPED the
/// expiry check on a token carrying `expires_at: -1` and honored it with 200 — an
/// immortal capability handed to whoever sent the malformed value.
///
/// MUST run BEFORE the range checks it protects, because the range checks are
/// exactly what the absent/unrepresentable ambiguity defeats.
pub(super) fn temporal_fields_representable(cap: &Entity) -> bool {
    for key in ["expires_at", "not_before", "created_at"] {
        match cap.field(key) {
            None | Some(Value::Null) => continue, // absent/null is legal — no bound
            Some(Value::UInt(_)) => continue,     // representable
            _ => return false,                    // negative, bignum, text, … → malformed
        }
    }
    true
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

enum ChainResult {
    Chain(Vec<Entity>),
    TooDeep,
    Unreachable,
}

fn collect_chain(env: &Envelope, st: &Store, cap: &Entity) -> ChainResult {
    let mut chain = Vec::new();
    let mut current = cap.clone();
    let mut depth = 0usize;
    loop {
        if depth > MAX_CHAIN_DEPTH {
            return ChainResult::TooDeep;
        }
        let parent_h = current.bytes_field("parent").map(|b| b.to_vec());
        chain.push(current);
        match parent_h {
            None => return ChainResult::Chain(chain),
            Some(ph) => match resolve(env, st, &ph) {
                Some(p) => current = p,
                None => return ChainResult::Unreachable,
            },
        }
        depth += 1;
    }
}

/// §4.10(b) structural pre-check: true iff the authority chain rooted at `cap`
/// exceeds [`MAX_CHAIN_DEPTH`]. Walks parent pointers without verifying signatures
/// — depth is a purely structural property, gated BEFORE the per-link authz walk
/// so an over-deep chain is reported as `400 chain_depth_exceeded` (structural
/// excess), distinct from `403 capability_denied`. An *unreachable* parent is NOT
/// a depth problem — it returns false here and is left for the authz walk to deny.
pub fn chain_exceeds_depth(env: &Envelope, st: &Store, cap: &Entity) -> bool {
    let mut current = cap.clone();
    let mut depth = 0usize;
    loop {
        if depth > MAX_CHAIN_DEPTH {
            return true;
        }
        let ph = match current.bytes_field("parent") {
            Some(p) => p.to_vec(),
            None => return false, // root within bound
        };
        match resolve(env, st, &ph) {
            Some(p) => current = p,
            None => return false, // unreachable — not a depth problem
        }
        depth += 1;
    }
}

// ── §3.6 M3 multi-signature granter ────────────────────────────────────────────
//
// The capability `granter` field is a UNION (§3.6): a single system/hash (bytes,
// single-sig) OR a {signers: [system/hash], threshold: uint} map (multi-sig,
// root-only). A multi-sig root is verified by verify_multisig_root — M3 structure
// first, then §5.5 M6 (local peer ∈ signers) + M4 K-of-N distinct-signer quorum.

struct MultiGranter {
    signers: Vec<Vec<u8>>,
    threshold: u64,
}

fn multi_granter_of_entity(cap: &Entity) -> Option<MultiGranter> {
    let g = cap.field("granter")?;
    match g {
        Value::Map(_) => {}
        _ => return None, // bytes (single-sig) or other → not multi-sig
    }
    let signers = match model::map_get(g, "signers") {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|it| match it {
                Value::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .collect(),
        _ => Vec::new(),
    };
    let threshold = match model::map_get(g, "threshold") {
        Some(Value::UInt(t)) => *t,
        _ => 0,
    };
    Some(MultiGranter { signers, threshold })
}

fn has_duplicate_signers(signers: &[Vec<u8>]) -> bool {
    for (i, s) in signers.iter().enumerate() {
        if signers[i + 1..].iter().any(|o| o == s) {
            return true;
        }
    }
    false
}

fn signer_peer_id(env: &Envelope, st: &Store, h: &[u8]) -> Option<String> {
    let p = resolve(env, st, h)?;
    let pk = p.bytes_field("public_key")?;
    Some(identity::peer_id_of_pubkey(pk))
}

/// verify_multisig_root (§3.6 M3 / §5.5 M4·M6). ALLOW only if the quorum is
/// well-formed AND a threshold of DISTINCT signers signed the cap's content hash.
/// Structural validation (M3) precedes signature counting (§3.6 precedence): a
/// malformed quorum is denied on its structure, not on its signatures.
fn verify_multisig_root(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    cap: &Entity,
    mg: &MultiGranter,
) -> Verdict {
    let n = mg.signers.len();
    // §3.6 M3 structure (BEFORE signatures): root-only; real quorum (n ≥ 2);
    // usable threshold (2 ≤ threshold ≤ n); distinct signers.
    if cap.bytes_field("parent").is_some() {
        return Verdict::Deny; // multi-sig is root-only
    }
    if n < 2 {
        return Verdict::Deny;
    }
    if mg.threshold < 2 || mg.threshold > n as u64 {
        return Verdict::Deny;
    }
    if has_duplicate_signers(&mg.signers) {
        return Verdict::Deny;
    }

    // §5.5 M6 root-at-local — the local peer MUST be a quorum member.
    let local_in_quorum = mg
        .signers
        .iter()
        .any(|s| signer_peer_id(env, st, s).as_deref() == Some(local_peer));
    if !local_in_quorum {
        return Verdict::Deny;
    }

    // temporal validity + grantee resolution (as for any root).
    // CAP-6a FIRST: an unrepresentable temporal field is malformed, and must not be
    // read as absent by the `uint_field` checks below (which cannot tell the two apart).
    if !temporal_fields_representable(cap) {
        return Verdict::Deny;
    }
    let t = now_ms();
    if let Some(nb) = cap.uint_field("not_before") {
        if t < nb {
            return Verdict::Deny;
        }
    }
    if let Some(ex) = cap.uint_field("expires_at") {
        if ex < t {
            return Verdict::Deny;
        }
    }
    let grantee = match cap.bytes_field("grantee") {
        Some(g) => g.to_vec(),
        None => return Verdict::Deny,
    };
    if resolve(env, st, &grantee).is_none() {
        return Verdict::Deny;
    }

    // §5.5 M4 K-of-N — count DISTINCT signers with a valid signature over the
    // cap's content hash; ≥ threshold ⇒ quorum. A duplicate signature from one
    // signer does NOT inflate the count.
    let mut valid: Vec<&Vec<u8>> = Vec::new();
    for s in &mg.signers {
        if valid.contains(&s) {
            continue;
        }
        let signer_peer = match resolve(env, st, s) {
            Some(p) => p,
            None => continue,
        };
        let signed = env.included.values().any(|sgn| {
            sgn.typ == "system/signature"
                && sgn.bytes_field("target") == Some(cap.hash.as_slice())
                && sgn.bytes_field("signer") == Some(s.as_slice())
                && identity::verify_signature(sgn, &signer_peer)
        });
        if signed {
            valid.push(s);
        }
    }
    if valid.len() as u64 >= mg.threshold {
        Verdict::Allow
    } else {
        Verdict::Deny
    }
}

/// verify_capability_chain (§5.5). A single-sig root roots at the local peer; a
/// §3.6 M3 multi-sig root (root-only) passes K-of-N quorum. Returns a verdict;
/// the `UnresolvableGrantee` carve-out is surfaced as `Err(())` → 401 by the
/// caller.
fn verify_capability_chain(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    capability: &Entity,
) -> Result<Verdict, ()> {
    verify_capability_chain_rooted_at(env, st, local_peer, local_peer, capability)
}

/// [`verify_capability_chain`] with the expected ROOT granter named separately from
/// the verifying peer.
///
/// §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is
/// minted by the TARGET peer, so root-trust is relaxed away from the local peer — and
/// every other clause (per-link signatures, grantee resolution, temporal validity,
/// attenuation, caveats) is unchanged. Parameterized rather than forked because a
/// second copy of a chain walk is a second copy that drifts.
///
/// A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When
/// `root_peer != local_peer` the quorum arm is REFUSED outright rather than verified:
/// *minted by the target* means the target SOLELY minted it, and a K-of-N root is a
/// GROUP's authority — its co-signers authorized it too. Verifying the quorum here and
/// accepting it would let any one signer's target confer the whole group's grant,
/// which is E3/F66's over-acceptance. §5.5's M6 also requires the LOCAL peer in the
/// signer set, so the quorum arm has no meaning in a foreign frame even on its own
/// terms.
fn verify_capability_chain_rooted_at(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    root_peer: &str,
    capability: &Entity,
) -> Result<Verdict, ()> {
    let chain = match collect_chain(env, st, capability) {
        ChainResult::Chain(c) => c,
        ChainResult::TooDeep | ChainResult::Unreachable => return Ok(Verdict::Deny),
    };
    let root = &chain[chain.len() - 1];
    // Root authority: a single-sig root must root at `root_peer`; a §3.6 M3 multi-sig
    // root (root-only) must pass K-of-N quorum validation, and only in the LOCAL frame.
    let root_ok = if let Some(mg) = multi_granter_of_entity(root) {
        root_peer == local_peer
            && verify_multisig_root(env, st, local_peer, root, &mg) == Verdict::Allow
    } else {
        match root.bytes_field("granter") {
            Some(gh) => match resolve(env, st, gh) {
                Some(g) => match g.bytes_field("public_key") {
                    Some(pk) => identity::peer_id_of_pubkey(pk) == root_peer,
                    None => false,
                },
                None => false,
            },
            None => false,
        }
    };
    if !root_ok {
        return Ok(Verdict::Deny);
    }

    let n = chain.len();
    let t = now_ms();
    for (i, current) in chain.iter().enumerate() {
        // §3.6 M3 multi-sig is root-only and fully verified above. A multi-sig
        // token anywhere but the chain root is rejected.
        if multi_granter_of_entity(current).is_some() {
            if i != n - 1 {
                return Ok(Verdict::Deny); // multi-sig off-root → deny
            }
            continue;
        }
        // signature: signer == granter, verify against granter identity.
        let gh = match current.bytes_field("granter") {
            Some(g) => g.to_vec(),
            None => return Ok(Verdict::Deny),
        };
        let sgn = match find_signature(env, &current.hash) {
            Some(s) => s,
            None => return Ok(Verdict::Deny),
        };
        let granter = match resolve(env, st, &gh) {
            Some(g) => g,
            None => return Ok(Verdict::Deny),
        };
        let signer_ok = sgn.bytes_field("signer") == Some(gh.as_slice());
        if !(signer_ok && identity::verify_signature(&sgn, &granter)) {
            return Ok(Verdict::Deny);
        }
        // grantee resolution → 401 carve-out.
        let grantee = match current.bytes_field("grantee") {
            Some(g) => g.to_vec(),
            None => return Err(()),
        };
        if resolve(env, st, &grantee).is_none() {
            return Err(());
        }
        // temporal validity. CAP-6a runs FIRST, for the same reason as the root path:
        // `uint_field` collapses "absent" and "present but not a uint", so an
        // unrepresentable expiry would otherwise skip the range check and fail OPEN.
        if !temporal_fields_representable(current) {
            return Ok(Verdict::Deny);
        }
        if let Some(nb) = current.uint_field("not_before") {
            if t < nb {
                return Ok(Verdict::Deny);
            }
        }
        if let Some(ex) = current.uint_field("expires_at") {
            if ex < t {
                return Ok(Verdict::Deny);
            }
        }
        // delegation link.
        if i < n - 1 {
            let parent = &chain[i + 1];
            let child_peer = match link_granter_peer(env, st, local_peer, current) {
                Some(p) => p,
                None => return Ok(Verdict::Deny),
            };
            let parent_peer = match link_granter_peer(env, st, local_peer, parent) {
                Some(p) => p,
                None => return Ok(Verdict::Deny),
            };
            let pg = parent.bytes_field("grantee");
            let cg = current.bytes_field("granter");
            let link_ok = pg.is_some()
                && cg.is_some()
                && pg == cg
                && is_attenuated(local_peer, &child_peer, &parent_peer, current, parent)
                && check_delegation_caveats(parent, current, i as u64);
            if !link_ok {
                return Ok(Verdict::Deny);
            }
        }
    }
    Ok(Verdict::Allow)
}

/// is_revoked (§5.1) — marker check at the revocations path; covers leaf + root.
fn is_revoked(env: &Envelope, st: &Store, local_peer: &str, capability: &Entity) -> bool {
    let root_hash = match collect_chain(env, st, capability) {
        ChainResult::Chain(c) => c[c.len() - 1].hash.clone(),
        _ => capability.hash.clone(),
    };
    let check = |h: &[u8]| {
        let path = format!("/{local_peer}/system/capability/revocations/{}", hex(h));
        st.get_at(&path).is_some()
    };
    check(&capability.hash) || check(&root_hash)
}

/// verify_request (§5.2) — 3-way authn/authz verdict (§4.6 / F20). The
/// §4.10(b) chain-depth pre-check runs before the authz walk.
pub fn verify_request(env: &Envelope, st: &Store, local_peer: &str) -> ReqVerdict {
    let exec = &env.root;
    // 1. content hash already validated on parse (envelope_of_cbor).
    // 2. signature / author — authentication class (§4.6 boundary → 401).
    let sgn = match find_signature(env, &exec.hash) {
        Some(s) => s,
        None => return ReqVerdict::AuthnFail,
    };
    let author_h = exec.bytes_field("author").map(|b| b.to_vec());
    let signer_ok = match (sgn.bytes_field("signer"), &author_h) {
        (Some(s), Some(a)) => s == a.as_slice(),
        _ => false,
    };
    if !signer_ok {
        return ReqVerdict::AuthnFail;
    }
    let author = match author_h.as_ref().and_then(|a| env.included_get(a)) {
        Some(a) => a.clone(),
        None => return ReqVerdict::AuthnFail,
    };
    if !identity::verify_signature(&sgn, &author) {
        return ReqVerdict::AuthnFail;
    }
    // 3. capability / chain — authorization class (→ 403).
    let cap_h = match exec.bytes_field("capability") {
        Some(c) => c.to_vec(),
        None => return ReqVerdict::AuthzDeny,
    };
    let capability = match env.included_get(&cap_h) {
        Some(c) => c.clone(),
        None => return ReqVerdict::AuthzDeny,
    };
    // §4.10(b): chain over max depth → 400 chain_depth_exceeded (structural
    // excess) BEFORE the per-link authz walk — distinct from 403.
    if chain_exceeds_depth(env, st, &capability) {
        return ReqVerdict::ChainTooDeep;
    }
    // chain first: a per-link unresolvable grantee (§5.5) → 401 takes precedence.
    let chain_verdict = match verify_capability_chain(env, st, local_peer, &capability) {
        Ok(v) => v,
        Err(()) => return ReqVerdict::UnresolvableGrantee,
    };
    if chain_verdict == Verdict::Deny {
        return ReqVerdict::AuthzDeny;
    }
    let grantee_ok = match (capability.bytes_field("grantee"), &author_h) {
        (Some(g), Some(a)) => g == a.as_slice(),
        _ => false,
    };
    if !grantee_ok {
        return ReqVerdict::AuthzDeny;
    }
    if is_revoked(env, st, local_peer, &capability) {
        return ReqVerdict::AuthzDeny;
    }
    ReqVerdict::Allow
}

/// Resolve the §PR-8 granter frame for a leaf cap at the dispatch site; falls
/// back to the local peer for an unresolvable/multisig granter.
pub fn granter_frame(env: &Envelope, st: &Store, local_peer: &str, cap: &Entity) -> String {
    match cap.field("granter") {
        Some(Value::Bytes(gh)) => match resolve(env, st, gh) {
            Some(g) => match g.bytes_field("public_key") {
                Some(pk) => identity::peer_id_of_pubkey(pk),
                None => local_peer.to_string(),
            },
            None => local_peer.to_string(),
        },
        _ => local_peer.to_string(),
    }
}

// ── §6.2 mint-time subset check (local frame) ──────────────────────────────────

/// §6.2 local-frame subset (child=parent=local) — the mint-time check used by the
/// capability handler. Each requested grant must be a subset of some grant the
/// caller's cap already carries.
pub fn requested_grants_within(
    local_peer: &str,
    req_grants: &[Value],
    caller_cap: &Entity,
) -> bool {
    let parent_grants = grants_of_token(caller_cap);
    for cg in req_grants {
        let c = parse_grant(cg);
        let matched = parent_grants
            .iter()
            .any(|pg| grant_subset(local_peer, local_peer, local_peer, &c, pg));
        if !matched {
            return false;
        }
    }
    true
}

// ── multi-sig granter descriptor builder (used by tests + handlers) ────────────

/// Build a `{signers, threshold}` multi-granter descriptor value (§3.6).
pub fn multi_granter_value(signers: &[Vec<u8>], threshold: u64) -> Value {
    Value::Map(vec![
        (
            Key::Text("signers".into()),
            Value::Array(signers.iter().map(|s| Value::Bytes(s.clone())).collect()),
        ),
        (Key::Text("threshold".into()), Value::UInt(threshold)),
    ])
}

#[cfg(test)]
mod tests;

/// `SDK-OPERATIONS` §11.3 SEC-3 — whether `identity_hash` appears as a GRANTER in the
/// authority chain of the capability whose content hash is `cap_hash` (in the chain, not
/// merely at its root — core §5.5), and that chain verifies for this peer. A handler that
/// embeds a caller-supplied capability in an entity it creates asks this before persisting.
///
/// `false` for a capability that cannot be resolved (from the envelope's `included` or the
/// store), whose chain is unreachable or too deep, or which does not verify.
pub fn identity_in_authority_chain(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    cap_hash: &[u8],
    identity_hash: &[u8],
) -> bool {
    let cap = match resolve(env, st, cap_hash) {
        Some(c) if c.typ == "system/capability/token" => c,
        _ => return false,
    };
    if !matches!(verify_capability_chain(env, st, local_peer, &cap), Ok(Verdict::Allow)) {
        return false;
    }
    match collect_chain(env, st, &cap) {
        ChainResult::Chain(links) => links
            .iter()
            .any(|l| l.bytes_field("granter") == Some(identity_hash)),
        _ => false,
    }
}

#[cfg(test)]
pub(crate) fn verify_capability_chain_for_test(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    capability: &Entity,
) -> Result<Verdict, ()> {
    verify_capability_chain(env, st, local_peer, capability)
}

// ── §1.4 PD-2: outbound sub-dispatch authorization ──────────────────────────

/// Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
///
/// §1.4 admits three spellings of one address — `system/tree`,
/// `/{peer}/system/tree` and `entity://{peer}/system/tree` — and §1.4's PD-2 block
/// requires Dimension 1's handler pattern to be the target uri's peer-relative path,
/// because a grant names HANDLERS and a handler pattern never carries a peer segment.
/// Matching a grant against the absolute or schemed form matches nothing, silently,
/// which reads at the wire as an authority refusal.
///
/// The first segment is dropped ONLY when it is a peer_id. A peer-relative
/// `system/protocol/connect` must not lose `system` — the standing defect on
/// `smalltalk` and `forth`, where an unconditional strip made every self-minted grant
/// unusable while the handshake stayed green.
pub(crate) fn peer_relative_of(uri: &str) -> String {
    let p = normalize_uri(uri);
    if !p.starts_with('/') {
        return p;
    }
    let segs: Vec<&str> = p[1..].split('/').collect();
    match segs.split_first() {
        Some((first, rest)) if is_peer_id(first) => rest.join("/"),
        _ => segs.join("/"),
    }
}

/// Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
/// tolerant of the pattern arriving absolute or peer-relative.
///
/// §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
/// the grant path is built from the PEER-RELATIVE one. The two are one segment apart
/// and concatenating the wrong one yields a doubled peer segment whose lookup misses —
/// which fails closed as "no handler grant" and is indistinguishable, at the wire,
/// from a genuine authority refusal.
pub(crate) fn grant_path_for(local_peer: &str, pattern: &str) -> String {
    let prefix = format!("/{local_peer}/");
    let rel = pattern.strip_prefix(&prefix).unwrap_or(pattern);
    format!("/{local_peer}/system/capability/grants/{rel}")
}

/// Verify a presented reentry credential against §1.4's clauses and, where they all
/// hold, answer the `peers` scope Dimension 4 relaxes to. `None` relaxes nothing.
///
/// Every clause is required and failing any relaxes nothing:
///
/// * the chain ROOT `granter` resolves to the TARGET peer, and is NOT a
///   multi-signature root — a K-of-N root is a GROUP's authority and never relaxes
///   Dimension 4 ([`verify_capability_chain_rooted_at`] refuses the quorum arm in a
///   foreign frame, which is where that rule lands);
/// * the LEAF `grantee` is the local peer;
/// * valid (per-link signatures, temporal, attenuation, caveats) and not revoked.
pub(crate) fn target_minted_peers_relaxation(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    target_peer: &str,
    cred: &Entity,
) -> Option<Scope> {
    // Nothing to relax — the default already covers this peer. Treating a
    // self-targeted credential as a relaxation would make the exemption reachable with
    // no foreign mint at all.
    if target_peer == local_peer {
        return None;
    }
    if !matches!(
        verify_capability_chain_rooted_at(env, st, local_peer, target_peer, cred),
        Ok(Verdict::Allow)
    ) {
        return None;
    }
    if is_revoked(env, st, local_peer, cred) {
        return None;
    }
    let grantee_is_local = cred
        .bytes_field("grantee")
        .and_then(|gh| resolve(env, st, gh))
        .and_then(|ge| ge.bytes_field("public_key").map(identity::peer_id_of_pubkey))
        .is_some_and(|pid| pid == local_peer);
    if !grantee_is_local {
        return None;
    }
    // The credential's own `peers` scope is what Dimension 4 relaxes TO. Absent means
    // the granter — the target peer — which is the ordinary reentry shape: "you may
    // dispatch back to me."
    grants_of_token(cred).into_iter().next().map(|g| {
        g.peers.unwrap_or(Scope {
            incl: vec![target_peer.to_string()],
            excl: vec![],
        })
    })
}

/// §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
/// LEAVES the peer, with all four dimensions applied.
///
/// ONE GATE AND ONE EXEMPTION, in §1.4's own words:
///
/// * the EXECUTING HANDLER'S GRANT decides all four dimensions (§6.8), evaluated in
///   the LOCAL frame, with Dimension 1's pattern the target uri's PEER-RELATIVE path;
/// * a valid capability MINTED BY THE TARGET PEER naming this peer as `grantee`
///   relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4, to the peers that capability
///   covers, evaluated in the TARGET's frame.
///
/// *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT
/// a grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
/// sub-dispatch is refused however good the credential is. That is the COMPOSE, and
/// the BYPASS it is distinguished from is a peer that treats the credential as a
/// standalone authorizer and steers past its own grant — §6.8's confused-deputy
/// substitution. Both obvious vectors agree under either reading (sources agree ->
/// allow, no source -> refuse), so the only input that separates them is a VALID
/// credential presented to a handler whose own grant does NOT cover the request, which
/// MUST refuse.
///
/// A credential failing any verification clause relaxes NOTHING and the handler grant
/// gates unrelaxed — it does not turn the verdict into an error.
///
/// `target_peer` is supplied by the caller rather than derived here: on the §6.11
/// reentry seam the uri may be PEER-RELATIVE and the destination is the connection's
/// remote, so `extract_peer(uri, local)` would answer the LOCAL peer and Dimension 4
/// would pass vacuously on the default `{include: [local]}` — the exemption would then
/// never be exercised and a bypass would read as a compose.
///
/// `cred = None` is the ambient arm: Dimension 4 is decided by the handler's grant
/// alone.
#[allow(clippy::too_many_arguments)]
pub(crate) fn check_outbound_sub_dispatch(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    target_peer: &str,
    handler_pattern: &str,
    operation: &str,
    handler_grant: &Entity,
    resource: &Value,
    cred: Option<&Entity>,
) -> bool {
    // Computed FIRST and consulted LAST, so no credential can stand in for 1-3.
    let relax_to =
        cred.and_then(|c| target_minted_peers_relaxation(env, st, local_peer, target_peer, c));
    grants_of_token(handler_grant).into_iter().any(|g| {
        matches_scope(local_peer, handler_pattern, &g.handlers, ScopeKind::Path)
            && matches_scope(local_peer, operation, &g.operations, ScopeKind::Id)
            && check_resource_scope(local_peer, local_peer, resource, &g.resources)
            // Dimension 4. §5.2's default for an absent `peers` scope is
            // {include: [local_peer_id]}, so a foreign target fails unless this grant
            // names it or a target-minted credential relaxes it.
            && {
                let peers = g.peers.clone().unwrap_or(Scope {
                    incl: vec![local_peer.to_string()],
                    excl: vec![],
                });
                matches_scope(local_peer, target_peer, &peers, ScopeKind::Id)
                    || relax_to
                        .as_ref()
                        .is_some_and(|r| matches_scope(local_peer, target_peer, r, ScopeKind::Id))
            }
    })
}
