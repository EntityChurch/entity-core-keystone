//! §3.6 multi-signature K-of-N — ACCEPT path + invariant deny flips.
//!
//! The validate-peer `multisig` category is rejection-heavy (malformed quorum →
//! 403), which a fail-closed peer passes vacuously. This is the direction the
//! oracle does NOT cover: a real 2-of-3 root (one signer = the local peer) with a
//! threshold of valid signatures over the cap's content_hash MUST be ALLOWed —
//! and each M3/M4/M6 invariant flip MUST deny. Plus a single-sig superset check.

use super::*;
use crate::peer::identity::Identity;
use crate::value::Value;

/// Build a `system/capability/token` with a multi-sig granter descriptor.
fn mk_multi_cap(
    grantee_hash: &[u8],
    signers: &[Vec<u8>],
    threshold: u64,
    parent: Option<&[u8]>,
) -> Entity {
    let mut pairs = vec![
        (
            Key::Text("granter".into()),
            multi_granter_value(signers, threshold),
        ),
        (
            Key::Text("grantee".into()),
            Value::Bytes(grantee_hash.to_vec()),
        ),
        (Key::Text("grants".into()), Value::Array(vec![])),
    ];
    if let Some(p) = parent {
        pairs.push((Key::Text("parent".into()), Value::Bytes(p.to_vec())));
    }
    Entity::make("system/capability/token", Value::Map(pairs))
}

/// Assemble an envelope from the cap + extra entities, run verify_capability_chain.
fn allows_multisig(local_peer: &str, cap: &Entity, extra: &[Entity]) -> Verdict {
    let st = Store::new();
    let mut included = vec![cap.clone()];
    included.extend_from_slice(extra);
    let env = Envelope::with_included(cap.clone(), included);
    verify_capability_chain_for_test(&env, &st, local_peer, cap).unwrap_or(Verdict::Deny)
}

#[test]
fn multisig_k_of_n_accept_and_deny_flips() {
    let id1 = Identity::of_seed([1u8; 32]);
    let id2 = Identity::of_seed([2u8; 32]);
    let id3 = Identity::of_seed([3u8; 32]);
    let local = id1.peer_id.clone();
    let signers = vec![
        id1.identity_hash.clone(),
        id2.identity_hash.clone(),
        id3.identity_hash.clone(),
    ];

    // valid 2-of-3, local in quorum, 2 valid sigs → Allow
    {
        let cap = mk_multi_cap(&id1.identity_hash, &signers, 2, None);
        let s1 = id1.sign_entity(&cap);
        let s2 = id2.sign_entity(&cap);
        let extra = vec![
            id1.peer_entity.clone(),
            id2.peer_entity.clone(),
            id3.peer_entity.clone(),
            s1,
            s2,
        ];
        assert_eq!(allows_multisig(&local, &cap, &extra), Verdict::Allow);
    }

    // only 1 valid sig (< threshold) → Deny (M4)
    {
        let cap = mk_multi_cap(&id1.identity_hash, &signers, 2, None);
        let s1 = id1.sign_entity(&cap);
        let extra = vec![
            id1.peer_entity.clone(),
            id2.peer_entity.clone(),
            id3.peer_entity.clone(),
            s1,
        ];
        assert_eq!(allows_multisig(&local, &cap, &extra), Verdict::Deny);
    }

    // duplicate signature from one signer does NOT inflate the count → Deny (M4)
    {
        let cap = mk_multi_cap(&id1.identity_hash, &signers, 2, None);
        let s1 = id1.sign_entity(&cap);
        let extra = vec![
            id1.peer_entity.clone(),
            id2.peer_entity.clone(),
            id3.peer_entity.clone(),
            s1.clone(),
            s1,
        ];
        assert_eq!(allows_multisig(&local, &cap, &extra), Verdict::Deny);
    }

    // local peer not among the signers → Deny (M6)
    {
        let two = vec![id2.identity_hash.clone(), id3.identity_hash.clone()];
        let cap = mk_multi_cap(&id1.identity_hash, &two, 2, None);
        let n2 = id2.sign_entity(&cap);
        let n3 = id3.sign_entity(&cap);
        let extra = vec![id2.peer_entity.clone(), id3.peer_entity.clone(), n2, n3];
        assert_eq!(allows_multisig(&local, &cap, &extra), Verdict::Deny);
    }

    // threshold = 1 (M3 structure) → Deny even with valid sigs (precedence)
    {
        let cap = mk_multi_cap(&id1.identity_hash, &signers, 1, None);
        let s1 = id1.sign_entity(&cap);
        let s2 = id2.sign_entity(&cap);
        let extra = vec![
            id1.peer_entity.clone(),
            id2.peer_entity.clone(),
            id3.peer_entity.clone(),
            s1,
            s2,
        ];
        assert_eq!(allows_multisig(&local, &cap, &extra), Verdict::Deny);
    }

    // duplicate signers (M3 structure) → Deny
    {
        let dup = vec![id1.identity_hash.clone(), id1.identity_hash.clone()];
        let cap = mk_multi_cap(&id1.identity_hash, &dup, 2, None);
        let s1 = id1.sign_entity(&cap);
        let extra = vec![id1.peer_entity.clone(), s1];
        assert_eq!(allows_multisig(&local, &cap, &extra), Verdict::Deny);
    }

    // multi-sig off-root → Deny (root-only): a multi-sig child of a multi-sig root.
    {
        let parent = mk_multi_cap(&id1.identity_hash, &signers, 2, None);
        let child = mk_multi_cap(&id1.identity_hash, &signers, 2, Some(&parent.hash));
        let ps1 = id1.sign_entity(&parent);
        let ps2 = id2.sign_entity(&parent);
        let cs1 = id1.sign_entity(&child);
        let cs2 = id2.sign_entity(&child);
        let extra = vec![
            id1.peer_entity.clone(),
            id2.peer_entity.clone(),
            id3.peer_entity.clone(),
            parent,
            ps1,
            ps2,
            cs1,
            cs2,
        ];
        assert_eq!(allows_multisig(&local, &child, &extra), Verdict::Deny);
    }
}

#[test]
fn single_sig_root_is_strict_superset() {
    let id1 = Identity::of_seed([1u8; 32]);
    let local = id1.peer_id.clone();
    let cap = Entity::make(
        "system/capability/token",
        Value::Map(vec![
            (
                Key::Text("granter".into()),
                Value::Bytes(id1.identity_hash.clone()),
            ),
            (
                Key::Text("grantee".into()),
                Value::Bytes(id1.identity_hash.clone()),
            ),
            (Key::Text("grants".into()), Value::Array(vec![])),
        ]),
    );
    let ss = id1.sign_entity(&cap);
    let extra = vec![id1.peer_entity.clone(), ss];
    assert_eq!(allows_multisig(&local, &cap, &extra), Verdict::Allow);
}

#[test]
fn pattern_matching_5_4() {
    assert!(matches_pattern("/p/system/tree", "*"));
    assert!(matches_pattern("/p/system/tree/x", "/p/system/tree/*"));
    assert!(matches_pattern("/p/a/b", "/*/a/b"));
    assert!(!matches_pattern("/p/a/b", "/p/a/c"));
}

#[test]
fn canonicalize_peer_relative() {
    assert_eq!(canonicalize("peerX", "system/tree"), "/peerX/system/tree");
    assert_eq!(
        canonicalize("peerX", "/peerX/system/tree"),
        "/peerX/system/tree"
    );
}

// ── §5.2 typed scope matching (0.8.1, F40) — ACCEPT path ──────────────────────
//
// The oracle carried no F40 vector when this was written, and a rejection-only probe
// would let a uniformly-canonicalizing peer pass anyway, so the accept direction is
// the peer's own to cover. Case ids mirror the cohort-shared set in
// `protocol-generator/shared/scope-matching/id-scope-vectors.json` — this crate is
// dep-minimized (no JSON parser), so the cases are transcribed rather than loaded;
// keep the ids greppable so drift against the shared file is findable.

const F40_LOCAL: &str = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA";
const F40_REMOTE: &str = "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB";

fn f40_scope(incl: &[&str], excl: &[&str]) -> Scope {
    Scope {
        incl: incl.iter().map(|s| s.to_string()).collect(),
        excl: excl.iter().map(|s| s.to_string()).collect(),
    }
}

#[test]
fn f40_id_scope_cases() {
    let qualified = format!("/{F40_LOCAL}/get");
    let peer_qualified = format!("/*/{F40_REMOTE}");
    // (case id, value, include, exclude, expect)
    let cases: &[(&str, &str, &[&str], &[&str], bool)] = &[
        ("id.exact.hit", "get", &["get"], &[], true),
        ("id.exact.miss", "put", &["get"], &[], false),
        ("id.star", "get", &["*"], &[], true),
        ("id.prefix.hit", "compute/apply", &["compute/*"], &[], true),
        ("id.prefix.miss", "computex/apply", &["compute/*"], &[], false),
        ("id.prefix.no_bare_parent", "compute", &["compute/*"], &[], false),
        ("id.pathform.universal_prefix", "get", &["/*/get"], &[], false),
        ("id.pathform.local_qualified", "get", &[&qualified], &[], false),
        ("id.pathform.absolute", "get", &["/get"], &[], false),
        ("id.peers.exact", F40_REMOTE, &[F40_REMOTE], &[], true),
        ("id.peers.star", F40_REMOTE, &["*"], &[], true),
        ("id.peers.other", F40_REMOTE, &[F40_LOCAL], &[], false),
        ("id.peers.pathform.all", F40_REMOTE, &["/*/*"], &[], false),
        ("id.peers.pathform.qualified", F40_REMOTE, &[&peer_qualified], &[], false),
        ("id.literal.pathform.self", "/*/get", &["/*/get"], &[], true),
        ("id.exclude.exact", "get", &["*"], &["get"], false),
        // The discriminator: DENIES on the pre-F40 canonicalizing reading, ALLOWS here.
        ("id.exclude.pathform", "get", &["*"], &["/*/get"], true),
        ("id.exclude.peers.pathform", F40_REMOTE, &["*"], &["/*/*"], true),
        ("id.exclude.prefix", "compute/apply", &["*"], &["compute/*"], false),
    ];
    for (id, value, incl, excl, expect) in cases {
        let got = matches_scope(F40_LOCAL, value, &f40_scope(incl, excl), ScopeKind::Id);
        assert_eq!(got, *expect, "{id}: expected {expect}, got {got}");
    }
}

#[test]
fn f40_path_scope_still_canonicalizes() {
    // The control half: without these, "the fix" would read as a blanket removal of
    // canonicalization rather than a split.
    let cases: &[(&str, &str, &[&str], &[&str], bool)] = &[
        ("path.relative.include", "system/tree", &["system/tree"], &[], true),
        ("path.universal.include", "system/tree", &["/*/system/tree"], &[], true),
        ("path.subtree.include", "system/type/a", &["system/type/*"], &[], true),
        ("path.exclude.universal", "system/tree", &["*"], &["/*/system/tree"], false),
    ];
    for (id, value, incl, excl, expect) in cases {
        let got = matches_scope(F40_LOCAL, value, &f40_scope(incl, excl), ScopeKind::Path);
        assert_eq!(got, *expect, "{id}: expected {expect}, got {got}");
    }
}

// ── 0.8.2.24 N2/N3 — the §5.4 sentinel is scoped to PATH-SCOPE ────────────────

/// *"A capability carrying an unmatchable PATH-SCOPE pattern is INVALID `[MUST]` … It
/// does NOT reach `operations` or `peers` `[MUST]`."* NEVER_MATCH is a §5.4
/// path-canonicalization sentinel; an id-scope pattern is a literal identifier that
/// §5.2's id-scope arm forbids putting through the §5.4 transforms at all.
///
/// The id-scope case cannot be passed by accident: `*/apply` is an ordinary namespaced
/// operation name that PATH-canonicalizes to the sentinel, so on the pre-.24 unscoped
/// reading it DENIED THE WHOLE DIMENSION — `get`, included by a bare `*`, came back false.
/// The path-scope cases are the other half and prove this is a scope SPLIT rather than a
/// removal: the sentinel's own arm still bites where the dimension is a path.
#[test]
fn sentinel_is_path_scope_only() {
    // id-scope: the sentinel MUST NOT be consulted.
    assert!(
        matches_scope(F40_LOCAL, "get", &f40_scope(&["*"], &["*/apply"]), ScopeKind::Id),
        "id-scope: a path-unmatchable exclude must not deny the dimension (0.8.2.24)"
    );
    // The same holds for `peers`, the other id-scope dimension.
    assert!(
        matches_scope(F40_LOCAL, F40_LOCAL, &f40_scope(&["*"], &["../nope"]), ScopeKind::Id),
        "id-scope peers: a path-unmatchable exclude must not deny the dimension (0.8.2.24)"
    );
    // path-scope: UNCHANGED. An unmatchable exclude still denies, because there it would
    // otherwise carve out nothing and leave the grant silently wider than its author
    // wrote (0.8.2.21).
    assert!(
        !matches_scope(F40_LOCAL, "system/tree", &f40_scope(&["*"], &["../nope"]), ScopeKind::Path),
        "path-scope: an unmatchable exclude must still deny (0.8.2.21)"
    );
    // And an ordinary path-scope exclude still carves out only its own target — the
    // sentinel arm must not have swallowed the ordinary case.
    assert!(
        matches_scope(
            F40_LOCAL,
            "system/tree",
            &f40_scope(&["*"], &["system/secret"]),
            ScopeKind::Path
        ),
        "path-scope: an ordinary exclude must not deny an unrelated value"
    );
}

// ── F50 / 0.8.2.16 — `scope_subset` is typed by scope kind ────────────────────

/// F50, ruled YES at 0.8.2.16: F40's id-scope typing reaches `scope_subset` too, with
/// delegation-chain WIDENING named as the reason. §3.6's grammar binds the scope TYPE, not
/// one function.
///
/// The two discriminating pairs are `entity-core-formalization`'s (K-7), which found them
/// by differential on `lean`: 2 of 64 include pairs and 2 of 64 exclude pairs disagree
/// between the two readings, fail-closed, and a 16-pair control alphabet reports 0 — which
/// is why every hand-tried example missed it. Under the canonicalizing reading a child
/// include of `/tree/get` reads as covered by a parent `*` (it canonicalizes to an
/// absolute path and `*` matches everything); under the LITERAL id-scope matcher
/// `matches_id_pattern("/tree/get", "*")` is ALSO true — so the pair that actually moves is
/// the EXCLUDE direction, where a parent exclude must be inherited by the child.
#[test]
fn scope_subset_is_typed_by_scope_kind() {
    let child = f40_scope(&["*"], &["*/apply"]);
    let parent = f40_scope(&["*"], &["*/apply"]);
    // ID: `*/apply` is a literal on both sides and inherits itself.
    assert!(
        scope_subset(F40_LOCAL, F40_LOCAL, &child, &parent, ScopeKind::Id),
        "id-scope: a literal parent exclude is inherited by the identical child exclude"
    );
    // PATH: the same pair canonicalizes to NEVER_MATCH on both sides, and NEVER_MATCH
    // matches nothing in EITHER operand (§5.4) — so the parent exclude is NOT inherited
    // and the subset check fails closed. Same input, opposite answer: the two matchers
    // are genuinely different and the kind is what selects between them.
    assert!(
        !scope_subset(F40_LOCAL, F40_LOCAL, &child, &parent, ScopeKind::Path),
        "path-scope: an unmatchable pattern is not inherited by itself (§5.4)"
    );

    // The include direction, where the canonicalizing reading over-accepts a child
    // pattern that is a LITERAL non-match under the id grammar.
    let narrow = f40_scope(&["compute/apply"], &[]);
    let wide = f40_scope(&["compute/*"], &[]);
    assert!(
        scope_subset(F40_LOCAL, F40_LOCAL, &narrow, &wide, ScopeKind::Id),
        "id-scope: a segment-prefix parent include covers a concrete child include"
    );
    //
    // THE PREDICTION THIS TEST WAS FIRST WRITTEN WITH WAS WRONG AND RUNNING IT IS WHAT
    // SAID SO: the pair was `child ["/*/get"] ⊆ parent ["get"]`, predicted to be a subset
    // on the PATH arm. It is not — the child's `/*/get` is already absolute so it
    // canonicalizes to itself, the parent's `get` canonicalizes to `/{local}/get`, and
    // `matches_pattern("/*/get", "/{local}/get")` falls through to string equality. The
    // discriminating pair runs the other way round, and it is recorded here rather than
    // quietly replaced: a control whose arm you have not RUN is a prediction, not a
    // measurement.
    let child_bare = f40_scope(&["get"], &[]);
    let parent_pathform = f40_scope(&["/*/get"], &[]);
    assert!(
        !scope_subset(F40_LOCAL, F40_LOCAL, &child_bare, &parent_pathform, ScopeKind::Id),
        "id-scope: `/*/get` is a LITERAL parent include and does not cover the bare `get`"
    );
    // The control, on the PATH arm, where the same pair IS a subset: `get` canonicalizes
    // to `/{local}/get`, the parent's `/*/get` is a peer wildcard, and the match holds.
    // This is the answer the untyped function gave on BOTH dimensions — over-accepting on
    // the id one, which is the chain-widening F50 names.
    assert!(
        scope_subset(F40_LOCAL, F40_LOCAL, &child_bare, &parent_pathform, ScopeKind::Path),
        "path-scope control: the same pair IS a subset once both sides canonicalize"
    );
}

// ── 0.8.2.20/.21/.24/.25 — effective_targets ──────────────────────────────────

fn exec_with_resource(resource: Option<Value>) -> Entity {
    let mut pairs = vec![
        (Key::Text("request_id".into()), Value::Text("t1".into())),
        (Key::Text("uri".into()), Value::Text("system/tree".into())),
        (Key::Text("operation".into()), Value::Text("get".into())),
    ];
    if let Some(r) = resource {
        pairs.push((Key::Text("resource".into()), r));
    }
    Entity::make("system/protocol/execute", Value::Map(pairs))
}

fn resource_value(targets: Option<Value>, exclude: Option<&[&str]>) -> Value {
    let mut pairs = vec![];
    if let Some(t) = targets {
        pairs.push((Key::Text("targets".into()), t));
    }
    if let Some(x) = exclude {
        pairs.push((
            Key::Text("exclude".into()),
            Value::Array(x.iter().map(|s| Value::Text(s.to_string())).collect()),
        ));
    }
    Value::Map(pairs)
}

fn text_array(items: &[&str]) -> Value {
    Value::Array(items.iter().map(|s| Value::Text(s.to_string())).collect())
}

#[test]
fn effective_targets_narrows_and_keeps_the_two_empties_apart() {
    let local = F40_LOCAL;

    // ABSENT resource: no narrowing happened and nothing was asked for.
    let (eff, present) = effective_targets(local, &exec_with_resource(None));
    assert!(!present, "absent resource must report ABSENT");
    assert!(eff.is_empty());

    // PRESENT with a surviving target — returned in the CALLER'S OWN SPELLING, not
    // canonicalized (0.8.2.21: effective_targets yields RAW survivors).
    let (eff, present) = effective_targets(
        local,
        &exec_with_resource(Some(resource_value(Some(text_array(&["app/a"])), None))),
    );
    assert!(present);
    assert_eq!(eff, vec!["app/a".to_string()], "survivors keep the caller's spelling");

    // PRESENT and SELF-EXCLUDED: the effective list is EMPTY and the resource is still
    // PRESENT. This is the discriminator N11 makes a MUST — a function returning only a
    // list collapses it, and the handler's refusal arm becomes dead code.
    let (eff, present) = effective_targets(
        local,
        &exec_with_resource(Some(resource_value(
            Some(text_array(&["app/a"])),
            Some(&["app/a"]),
        ))),
    );
    assert!(present, "a self-excluded resource is PRESENT, not absent");
    assert!(eff.is_empty());

    // The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules the
    // caller arm separately from the grant arm): `../nope` canonicalizes to NEVER_MATCH,
    // matches_pattern then answers false, and the target simply survives.
    let (eff, present) = effective_targets(
        local,
        &exec_with_resource(Some(resource_value(
            Some(text_array(&["app/a"])),
            Some(&["../nope"]),
        ))),
    );
    assert!(present);
    assert_eq!(eff, vec!["app/a".to_string()], "an unmatchable caller exclude carves out nothing");

    // A `resource` map with NO `targets` key is ABSENT.
    let (eff, present) = effective_targets(
        local,
        &exec_with_resource(Some(resource_value(None, Some(&["app/a"])))),
    );
    assert!(!present, "a resource carrying no `targets` key reports ABSENT");
    assert!(eff.is_empty());

    // A PRESENT-BUT-ILL-TYPED `targets` is PRESENT with an EMPTY survivor list, never
    // absent. Collapsing the two is N11's own defect one field over, and it is the cell
    // the two vanguard peers initially disagreed on: reporting ABSENT here serves the
    // wider absent-case answer to a request that named a resource.
    let (eff, present) = effective_targets(
        local,
        &exec_with_resource(Some(resource_value(Some(Value::UInt(42)), None))),
    );
    assert!(present, "an ill-typed `targets` is PRESENT");
    assert!(eff.is_empty());

    // More than one survivor — the arithmetic the §3.3 ladder reads.
    let (eff, present) = effective_targets(
        local,
        &exec_with_resource(Some(resource_value(
            Some(text_array(&["app/a", "app/b"])),
            Some(&["app/a"]),
        ))),
    );
    assert!(present);
    assert_eq!(eff, vec!["app/b".to_string()], "the survivor is SELECTED, never targets[0]");
}
