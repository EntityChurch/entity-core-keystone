"""§3.6 K-of-N multi-sig accept-path unit test.

The oracle's multisig validate-peer category is REJECTION-heavy, so the ACCEPT
path needs the peer's own positive test.  This builds a genuine 2-of-3 multi-sig
root capability — granter = a {signers, threshold} multi-granter — signs it with
2 of the 3 constituent signers (one of which is the LOCAL peer, M6), and asserts
verify_capability_chain returns ALLOW.  It then flips each of M3 / M4 / M6 and
asserts each flip DENIES, and confirms the single-sig path is a strict superset.
"""

from __future__ import annotations

from entity_core.peer.capability import (
    ALLOW,
    AUTHZ_DENY,
    verify_capability_chain,
)
from entity_core.peer.identity import Identity
from entity_core.peer.model import Entity, Included
from entity_core.peer.store import Store


def _seed(b: int) -> bytes:
    return bytes([b] * 32)


def _grant_all() -> list:
    return [{
        "handlers": {"include": ["*"]},
        "resources": {"include": ["*"]},
        "operations": {"include": ["*"]},
    }]


def _multi_root_cap(signer_ids: list[Identity], threshold: int, grantee_hash: bytes) -> Entity:
    """A root cap whose granter is a {signers, threshold} multi-granter."""
    granter = {
        "signers": [bytes(s.identity_hash) for s in signer_ids],
        "threshold": threshold,
    }
    return Entity.make("system/capability/token", {
        "granter": granter,
        "grantee": bytes(grantee_hash),
        "grants": _grant_all(),
        "created_at": 1_000,
    })


def _build(local: Identity, signers: list[Identity], threshold: int,
           sign_with: list[Identity], grantee: Identity):
    """Build (store, included) for a multi-sig root cap signed by `sign_with`."""
    store = Store()
    inc = Included()
    # the cap's signer/grantee identities must resolve.
    for ident in {id(s): s for s in signers + [grantee]}.values():
        inc.add(ident.peer_entity)
    cap = _multi_root_cap(signers, threshold, grantee.identity_hash)
    inc.add(cap)
    # each signer signs the cap (detached system/signature, signer = its id hash).
    for s in sign_with:
        inc.add(s.sign_entity(cap))
    return store, inc, cap


def test_multisig_2of3_accepted():
    # local peer is one of the 3 signers (M6); 2 of 3 sign (M4 threshold met).
    local = Identity.of_seed(_seed(0x01))
    s2 = Identity.of_seed(_seed(0x02))
    s3 = Identity.of_seed(_seed(0x03))
    grantee = Identity.of_seed(_seed(0x04))
    signers = [local, s2, s3]

    store, inc, cap = _build(local, signers, 2, [local, s2], grantee)
    verdict = verify_capability_chain(local.peer_id, store, cap, inc)
    assert verdict == ALLOW, f"2-of-3 multi-sig should ALLOW, got {verdict}"


def test_multisig_m4_threshold_not_met_denies():
    # only 1 of 3 signs -> below threshold 2 -> DENY.
    local = Identity.of_seed(_seed(0x01))
    s2 = Identity.of_seed(_seed(0x02))
    s3 = Identity.of_seed(_seed(0x03))
    grantee = Identity.of_seed(_seed(0x04))
    signers = [local, s2, s3]

    store, inc, cap = _build(local, signers, 2, [local], grantee)
    assert verify_capability_chain(local.peer_id, store, cap, inc) == AUTHZ_DENY, \
        "M4: 1 valid sig < threshold 2 must DENY"


def test_multisig_m6_local_not_in_signers_denies():
    # local peer is NOT among the signers -> M6 fails -> DENY (even with K sigs).
    local = Identity.of_seed(_seed(0x09))
    s1 = Identity.of_seed(_seed(0x01))
    s2 = Identity.of_seed(_seed(0x02))
    s3 = Identity.of_seed(_seed(0x03))
    grantee = Identity.of_seed(_seed(0x04))
    signers = [s1, s2, s3]  # local absent

    store, inc, cap = _build(local, signers, 2, [s1, s2], grantee)
    assert verify_capability_chain(local.peer_id, store, cap, inc) == AUTHZ_DENY, \
        "M6: local peer not in signers must DENY"


def test_multisig_m3_threshold_one_denies():
    # threshold 1 is invalid for a multi-granter (K must be in [2, N]) -> DENY.
    local = Identity.of_seed(_seed(0x01))
    s2 = Identity.of_seed(_seed(0x02))
    grantee = Identity.of_seed(_seed(0x04))
    signers = [local, s2]

    store, inc, cap = _build(local, signers, 1, [local, s2], grantee)
    assert verify_capability_chain(local.peer_id, store, cap, inc) == AUTHZ_DENY, \
        "M3: threshold < 2 must DENY"


def test_multisig_m3_single_signer_denies():
    # len(signers) == 1 is invalid for a multi-granter (use single-sig) -> DENY.
    local = Identity.of_seed(_seed(0x01))
    grantee = Identity.of_seed(_seed(0x04))
    signers = [local]

    store, inc, cap = _build(local, signers, 2, [local], grantee)
    assert verify_capability_chain(local.peer_id, store, cap, inc) == AUTHZ_DENY, \
        "M3: len(signers) < 2 must DENY"


def test_multisig_m3_duplicate_signers_denies():
    local = Identity.of_seed(_seed(0x01))
    s2 = Identity.of_seed(_seed(0x02))
    grantee = Identity.of_seed(_seed(0x04))
    # duplicate the local signer -> M3 dup-signer violation.
    signers = [local, local, s2]

    store, inc, cap = _build(local, signers, 2, [local, s2], grantee)
    assert verify_capability_chain(local.peer_id, store, cap, inc) == AUTHZ_DENY, \
        "M3: duplicate signers must DENY"


def test_single_sig_strict_superset_still_allows():
    # the single-sig path (granter = a hash) must still verify identically.
    local = Identity.of_seed(_seed(0x01))
    grantee = Identity.of_seed(_seed(0x04))
    store = Store()
    inc = Included()
    inc.add(local.peer_entity)
    inc.add(grantee.peer_entity)
    cap = Entity.make("system/capability/token", {
        "granter": bytes(local.identity_hash),
        "grantee": bytes(grantee.identity_hash),
        "grants": _grant_all(),
        "created_at": 1_000,
    })
    inc.add(cap)
    inc.add(local.sign_entity(cap))
    assert verify_capability_chain(local.peer_id, store, cap, inc) == ALLOW, \
        "single-sig root must ALLOW (strict superset)"
