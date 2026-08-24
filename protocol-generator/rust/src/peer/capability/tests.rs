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
