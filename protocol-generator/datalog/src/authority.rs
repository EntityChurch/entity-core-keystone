//! authority.rs — THE PROBE ARTIFACT. The §5/§6.6 authority interior authored as
//! genuine **bottom-up Datalog rules** (Ascent 0.8), foregrounded and legible — NOT
//! folded into a host call with the engine as decoration (the FLOW-DESIGN
//! wrapper-guard). This is Datalog's home turf: authorization/delegation IS a
//! trust-management logic (SecPAL, Binder, DKAL are Datalog dialects), so the §5.5
//! delegation-chain-as-recursive-rule is a natural fit.
//!
//! THE SEAM SPLIT (the probe's co-equal finding — see the profile
//! `[authority_interior_expressibility]` and SPEC-AMBIGUITY-LOG A-DL-010..014):
//!
//!   * The HOST (`dispatch.rs`) owns everything Datalog genuinely can't: it verifies
//!     signatures via the C-ABI and asserts `verified_root` / `verified_link` /
//!     `multisig_signer` FACTS; it decides the string-glob scope match and asserts
//!     `g_op` / `g_handler` / `g_peer` / `g_resource` per-grant coverage FACTS
//!     (A-DL-011); it reads the clock and asserts temporal validity into the root
//!     facts. Datalog never touches a key, a byte, or a clock.
//!   * The RULES below own the DECISION LOGIC: the recursive delegation closure
//!     (§5.5), the K-of-N counting aggregate (§3.6), the within-grant conjunction
//!     (§5.5a), the fail-closed verdict (§5.2 — absence of a derived `allow` IS
//!     denial), and the longest-prefix handler resolution (§6.6).
//!
//! Cap / signer / handler identifiers ride as **hex Strings** (readable IDs — the
//! opaque bytes stay host-side); paths + lengths are plain facts.

use ascent::aggregators::count;
use ascent::ascent;

// ─────────────────────────────────────────────────────────────────────────────
// PROGRAM 1 — the §5.2 / §5.5 / §5.5a / §3.6 AUTHORIZATION interior.
// ─────────────────────────────────────────────────────────────────────────────
ascent! {
    pub struct Authorizer;

    // ── EDB (host-established facts; the host does the crypto/glob/clock) ──────
    /// A single-sig token that is a verified ROOT at the local peer: signature over
    /// the token verified, granter == local peer, temporally valid, grantee
    /// resolvable. (Host asserts; §5.5 root authority.)
    relation verified_root(String);
    /// A verified DELEGATION link `(child, parent)`: child's signature verified,
    /// parent resolvable, attenuation (§5.6) + caveats (§5.7) hold, temporally
    /// valid. (Host asserts the link validity; the CLOSURE is the rule below.)
    relation verified_link(String, String);
    /// A structurally-valid §3.6 M3 multi-sig root: root-only, real quorum (n≥2),
    /// usable threshold, distinct signers, local peer ∈ quorum, temporally valid,
    /// grantee resolvable. (Host asserts M3 structure; the K-of-N count is the rule.)
    relation multisig_root(String);
    /// `threshold(cap, K)` — the multi-sig quorum size K. (Host.)
    relation threshold(String, u64);
    /// `multisig_signer(cap, signer)` — signer S is in the quorum AND produced a
    /// verified signature over `cap`. This is EDB and may carry a duplicated
    /// signature; distinctness is restored by the `distinct_signer` copy-rule below
    /// (A-DL-012: Ascent dedups DERIVED tuples, NOT pre-seeded EDB vectors — set
    /// semantics are a property of the fixpoint, not of externally-loaded facts).
    relation multisig_signer(String, String);

    /// The leaf capability the request presents (§5.2). (Host.)
    relation request_cap(String);
    /// `cap`'s grantee hash equals the request author (§5.2 grantee binding). (Host.)
    relation grantee_is_author(String);
    /// No revocation marker covers `cap` or its root (§5.1). (Host.)
    relation not_revoked(String);

    // Per-grant scope coverage (§5.5a). The host decides the string-glob match for
    // each dimension of grant #g of `cap` (incl. the "*"/"/*/*" dual form, A-DL-011)
    // and asserts these DECISION facts; the within-grant CONJUNCTION is the rule.
    /// grant #g exists on `cap`.
    relation scope_grant(String, u32);
    /// grant #g's operations cover the request operation.
    relation g_op(String, u32);
    /// grant #g's handlers cover the resolved handler pattern.
    relation g_handler(String, u32);
    /// grant #g's peers cover the target peer.
    relation g_peer(String, u32);
    /// grant #g's resources cover the request resource (or the request has none).
    relation g_resource(String, u32);

    // ── IDB (derived — the authored decision logic) ───────────────────────────
    /// A token that CONFERS authority: a verified root, or a verified delegation
    /// from a parent that itself confers. §5.5 transitive delegation closure,
    /// evaluated bottom-up to least fixpoint (the SecPAL/Binder shape).
    relation confers(String);
    /// The distinct signers of `cap` — a DERIVED copy of `multisig_signer` so the
    /// fixpoint's set semantics collapse duplicate signatures (A-DL-012).
    relation distinct_signer(String, String);
    /// §3.6 K-of-N quorum met: ≥ threshold DISTINCT verified signers.
    relation quorum_met(String);
    /// §5.5a some single grant covers ALL FOUR dimensions of the request.
    relation scope_ok(String);
    /// §5.2 verdict: the leaf cap authorizing the request. ABSENCE of any `allow`
    /// tuple IS denial (deductive fail-closed — no imperative if-ladder).
    relation allow(String);

    // §5.5 — the recursive delegation closure. THE canonical Datalog use case.
    confers(c) <-- verified_root(c);
    confers(c) <-- verified_link(c, p), confers(p);

    // §3.6 — restore distinctness in the rule layer, then count.
    distinct_signer(c, s) <-- multisig_signer(c, s);
    quorum_met(c) <--
        threshold(c, k),
        agg n = count() in distinct_signer(c, _),
        if (n as u64) >= *k;
    // A multi-sig root confers authority once its quorum is met.
    verified_root(c) <-- multisig_root(c), quorum_met(c);

    // §5.5a — a grant authorizes iff it covers every dimension (the within-grant
    // conjunction as a join; the host owns only the per-dimension glob decision).
    scope_ok(c) <--
        scope_grant(c, g),
        g_op(c, g),
        g_handler(c, g),
        g_peer(c, g),
        g_resource(c, g);

    // §5.2 — the fail-closed verdict as a DERIVED fact.
    allow(c) <--
        request_cap(c),
        confers(c),
        grantee_is_author(c),
        not_revoked(c),
        scope_ok(c);
}

// ─────────────────────────────────────────────────────────────────────────────
// PROGRAM 2 — §6.6 handler resolution as LONGEST-PREFIX-FIRST selection.
// The tree-walk expressed declaratively: `resolved` = a candidate handler prefix
// with no strictly-longer candidate (stratified negation) — NOT a hidden host loop.
// ─────────────────────────────────────────────────────────────────────────────
ascent! {
    pub struct Resolver;

    /// `candidate(pattern, len)` — `pattern` is a bound `system/handler` AND a path
    /// prefix of the request path; `len` = pattern length. (Host asserts membership;
    /// the SELECTION is the rule.)
    relation candidate(String, u32);
    /// some strictly-longer candidate exists (a lower stratum for the negation).
    relation longer_exists(String);
    /// the winning handler pattern (the longest matching prefix).
    relation resolved(String);

    longer_exists(p) <-- candidate(p, lp), candidate(_q, lq), if lq > lp;
    resolved(p) <-- candidate(p, _l), !longer_exists(p);
}

// ─────────────────────────────────────────────────────────────────────────────
// HOST-FACING WRAPPERS — the host fills these plain fact vectors (it did the
// crypto/glob/clock); the engine derives the verdict / resolution.
// ─────────────────────────────────────────────────────────────────────────────

/// Everything the host established about ONE request's authority (per-request EDB).
/// Each field maps 1:1 to an [`Authorizer`] relation. The Datalog layer is stateless
/// between requests (profile `[async]`): assert → fixpoint → read → drop.
#[derive(Default, Debug)]
pub struct AuthFacts {
    pub verified_root: Vec<String>,
    pub verified_link: Vec<(String, String)>,
    pub multisig_root: Vec<String>,
    pub threshold: Vec<(String, u64)>,
    pub multisig_signer: Vec<(String, String)>,
    pub request_cap: Vec<String>,
    pub grantee_is_author: Vec<String>,
    pub not_revoked: Vec<String>,
    pub scope_grant: Vec<(String, u32)>,
    pub g_op: Vec<(String, u32)>,
    pub g_handler: Vec<(String, u32)>,
    pub g_peer: Vec<(String, u32)>,
    pub g_resource: Vec<(String, u32)>,
}

/// Run the §5.2 authorization fixpoint. Returns `true` iff the engine DERIVES
/// `allow` — fail-closed: no derived `allow` IS denial (§5.2).
pub fn authorize(f: AuthFacts) -> bool {
    let mut prog = Authorizer {
        verified_root: f.verified_root.into_iter().map(|s| (s,)).collect(),
        verified_link: f.verified_link,
        multisig_root: f.multisig_root.into_iter().map(|s| (s,)).collect(),
        threshold: f.threshold,
        multisig_signer: f.multisig_signer,
        request_cap: f.request_cap.into_iter().map(|s| (s,)).collect(),
        grantee_is_author: f.grantee_is_author.into_iter().map(|s| (s,)).collect(),
        not_revoked: f.not_revoked.into_iter().map(|s| (s,)).collect(),
        scope_grant: f.scope_grant,
        g_op: f.g_op,
        g_handler: f.g_handler,
        g_peer: f.g_peer,
        g_resource: f.g_resource,
        ..Default::default()
    };
    prog.run();
    !prog.allow.is_empty()
}

/// §6.6 handler resolution: pick the longest handler-prefix of `request_path` from
/// the set of bound handler patterns, as a Datalog longest-prefix selection.
pub fn resolve_handler(handler_patterns: &[String], request_path: &str) -> Option<String> {
    let candidate: Vec<(String, u32)> = handler_patterns
        .iter()
        .filter(|p| is_path_prefix(p, request_path))
        .map(|p| (p.clone(), p.len() as u32))
        .collect();
    if candidate.is_empty() {
        return None;
    }
    let mut prog = Resolver {
        candidate,
        ..Default::default()
    };
    prog.run();
    prog.resolved.into_iter().map(|(p,)| p).next()
}

/// A handler `pattern` covers `path` iff it equals `path` or is a `/`-delimited
/// ancestor of it (the §6.6 backward tree-walk membership; the host decides
/// membership, the rule decides WHICH candidate wins).
fn is_path_prefix(pattern: &str, path: &str) -> bool {
    if pattern == path {
        return true;
    }
    if let Some(rest) = path.strip_prefix(pattern) {
        return rest.starts_with('/');
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base(cap: &str) -> AuthFacts {
        // A fully-covered request over `cap` EXCEPT the authority source, which each
        // test supplies. One grant (#0) covers all four scope dimensions.
        AuthFacts {
            request_cap: vec![cap.into()],
            grantee_is_author: vec![cap.into()],
            not_revoked: vec![cap.into()],
            scope_grant: vec![(cap.into(), 0)],
            g_op: vec![(cap.into(), 0)],
            g_handler: vec![(cap.into(), 0)],
            g_peer: vec![(cap.into(), 0)],
            g_resource: vec![(cap.into(), 0)],
            ..Default::default()
        }
    }

    #[test]
    fn single_sig_root_allows() {
        let mut f = base("cap0");
        f.verified_root = vec!["cap0".into()];
        assert!(authorize(f));
    }

    #[test]
    fn delegation_closure_depth_2_allows() {
        // cap0 <- cap1 <- cap2 (root); the leaf cap0 confers via the transitive
        // closure to the root. §5.5.
        let mut f = base("cap0");
        f.verified_root = vec!["cap2".into()];
        f.verified_link = vec![
            ("cap0".into(), "cap1".into()),
            ("cap1".into(), "cap2".into()),
        ];
        assert!(authorize(f));
    }

    #[test]
    fn broken_delegation_link_denies() {
        // cap1's parent link is missing → cap0 never reaches a root → fail-closed.
        let mut f = base("cap0");
        f.verified_root = vec!["cap2".into()];
        f.verified_link = vec![("cap0".into(), "cap1".into())]; // cap1 -> cap2 absent
        assert!(!authorize(f));
    }

    #[test]
    fn k_of_n_2_of_3_accept_path() {
        // THE mandatory accept-path test (A-DL-006): a 2-of-3 multisig root with two
        // distinct verified signers meets quorum → confers → allow.
        let mut f = base("mcap");
        f.multisig_root = vec!["mcap".into()];
        f.threshold = vec![("mcap".into(), 2)];
        f.multisig_signer = vec![
            ("mcap".into(), "signerA".into()),
            ("mcap".into(), "signerB".into()),
        ];
        assert!(authorize(f), "2-of-3 with 2 distinct signers must ALLOW");
    }

    #[test]
    fn k_of_n_below_threshold_denies() {
        let mut f = base("mcap");
        f.multisig_root = vec!["mcap".into()];
        f.threshold = vec![("mcap".into(), 2)];
        f.multisig_signer = vec![("mcap".into(), "signerA".into())]; // only 1
        assert!(!authorize(f));
    }

    #[test]
    fn k_of_n_duplicate_signer_does_not_inflate() {
        // A-DL-012: set semantics collapse a duplicated signature — 1 distinct
        // signer for a 2-of-3 stays below quorum (no host de-dup loop needed).
        let mut f = base("mcap");
        f.multisig_root = vec!["mcap".into()];
        f.threshold = vec![("mcap".into(), 2)];
        f.multisig_signer = vec![
            ("mcap".into(), "signerA".into()),
            ("mcap".into(), "signerA".into()), // duplicate
        ];
        assert!(!authorize(f), "duplicate signer must NOT reach quorum");
    }

    #[test]
    fn scope_conjunction_requires_all_four_in_one_grant() {
        // op covered by grant 0, handler by grant 1 — no SINGLE grant covers all
        // four → scope_ok never derives → deny (§5.5a within-grant conjunction).
        let mut f = base("cap0");
        f.verified_root = vec!["cap0".into()];
        f.scope_grant = vec![("cap0".into(), 0), ("cap0".into(), 1)];
        f.g_op = vec![("cap0".into(), 0)];
        f.g_handler = vec![("cap0".into(), 1)];
        f.g_peer = vec![("cap0".into(), 0), ("cap0".into(), 1)];
        f.g_resource = vec![("cap0".into(), 0), ("cap0".into(), 1)];
        assert!(!authorize(f));
    }

    #[test]
    fn revoked_denies() {
        let mut f = base("cap0");
        f.verified_root = vec!["cap0".into()];
        f.not_revoked = vec![]; // revoked
        assert!(!authorize(f));
    }

    #[test]
    fn longest_prefix_resolution() {
        let handlers = vec![
            "/peer/system".to_string(),
            "/peer/system/tree".to_string(),
            "/peer/system/tree/sub".to_string(),
        ];
        assert_eq!(
            resolve_handler(&handlers, "/peer/system/tree/leaf"),
            Some("/peer/system/tree".to_string())
        );
        assert_eq!(resolve_handler(&handlers, "/peer/other"), None);
    }
}
