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
struct Scope {
    incl: Vec<String>,
    excl: Vec<String>,
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

/// Resolve peer-relative paths to absolute `/{local}/...` form.
pub fn canonicalize(local_peer: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{local_peer}/{path}")
    }
}

/// Both `path` and `pattern` MUST already be canonical (absolute).
pub fn matches_pattern(path: &str, pattern: &str) -> bool {
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

fn matches_scope(local_peer: &str, value: &str, s: &Scope) -> bool {
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
        if !matches_scope(local_peer, operation, &g.operations) {
            continue;
        }
        if !matches_scope(local_peer, handler_pattern, &g.handlers) {
            continue;
        }
        let default_peers = Scope {
            incl: vec![local_peer.to_string()],
            excl: vec![],
        };
        let peers = g.peers.as_ref().unwrap_or(&default_peers);
        if !matches_scope(local_peer, target_peer, peers) {
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

fn scope_subset(child_peer: &str, parent_peer: &str, child: &Scope, parent: &Scope) -> bool {
    for cp in &child.incl {
        let cc = canonicalize(child_peer, cp);
        if !parent
            .incl
            .iter()
            .any(|pp| matches_pattern(&cc, &canonicalize(parent_peer, pp)))
        {
            return false;
        }
    }
    for pe in &parent.excl {
        let cpe = canonicalize(parent_peer, pe);
        if !child
            .excl
            .iter()
            .any(|ce| matches_pattern(&cpe, &canonicalize(child_peer, ce)))
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
    if !scope_subset(local_peer, local_peer, &child.handlers, &parent.handlers) {
        return false;
    }
    if !scope_subset(
        local_peer,
        local_peer,
        &child.operations,
        &parent.operations,
    ) {
        return false;
    }
    if !scope_subset(child_peer, parent_peer, &child.resources, &parent.resources) {
        return false;
    }
    let default = Scope {
        incl: vec![local_peer.to_string()],
        excl: vec![],
    };
    let cp = child.peers.as_ref().unwrap_or(&default);
    let pp = parent.peers.as_ref().unwrap_or(&default);
    scope_subset(local_peer, local_peer, cp, pp)
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
    let chain = match collect_chain(env, st, capability) {
        ChainResult::Chain(c) => c,
        ChainResult::TooDeep | ChainResult::Unreachable => return Ok(Verdict::Deny),
    };
    let root = &chain[chain.len() - 1];
    // Root authority: a single-sig root must root at the local peer; a §3.6 M3
    // multi-sig root (root-only) must pass K-of-N quorum validation.
    let root_ok = if let Some(mg) = multi_granter_of_entity(root) {
        verify_multisig_root(env, st, local_peer, root, &mg) == Verdict::Allow
    } else {
        match root.bytes_field("granter") {
            Some(gh) => match resolve(env, st, gh) {
                Some(g) => match g.bytes_field("public_key") {
                    Some(pk) => identity::peer_id_of_pubkey(pk) == local_peer,
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
        // temporal validity.
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

#[cfg(test)]
pub(crate) fn verify_capability_chain_for_test(
    env: &Envelope,
    st: &Store,
    local_peer: &str,
    capability: &Entity,
) -> Result<Verdict, ()> {
    verify_capability_chain(env, st, local_peer, capability)
}
