"""§1.4 PD-2: the outbound sub-dispatch gate.

WHY THESE CASES AND NOT THE TWO OBVIOUS ONES.  §1.4 says outright that a check set
MUST discriminate a COMPOSE from a BYPASS, and that the two obvious vectors — both
sources agree -> allow, no source at all -> refuse — are exactly the two that pass a
peer whose credential path bypasses the handler's grant.  So the load-bearing case here
is ``presented_credential_out_of_handler_grant``: a VALID target-minted credential
presented for an operation the handler's own grant does NOT cover, which MUST refuse.

⛔ AND THE MULTI-SIGNATURE CASE EXISTS BECAUSE THE WIRE CHECK DOES NOT MEASURE THE RULE.
``dispatch_outbound_multisig_root_refused`` PASSES on this peer with the §1.4
foreign-frame guard PLANTED OUT — measured, the plant runs green — because the oracle's
K-of-2 root is co-signed by the target and a third party and NOT by the local peer, so
§5.5's **M6** (the local peer MUST be a validated quorum member) refuses it first, for a
reason that has nothing to do with §1.4.  A credential the local peer IS a member of,
minted at the target, is the discriminating input, and nothing on the wire drives it.
That is what this test is for: without it the rule is unmeasured on this peer, and the
green wire row would read as evidence for it.
"""

from __future__ import annotations

import pytest

from entity_core.peer.capability import (
    ALLOW,
    Scope,
    check_outbound_sub_dispatch,
    grant_path_for,
    peer_relative_of,
    verify_capability_chain_rooted_at,
)
from entity_core.peer.model import Entity, Included
from entity_core.peer.peer import Peer
from entity_core.peer.wire import resource_target

ECHO = "system/validate/echo"
DISPATCH = "system/validate/dispatch-outbound"


def _seed(b: int) -> bytes:
    return bytes([b] * 32)


@pytest.fixture()
def peers():
    return Peer(_seed(1), conformance=True), Peer(_seed(2), conformance=True)


def _mint_cred(target: Peer, grantee_hash: bytes, handlers, ops):
    """Mint, AT ``target``, a credential naming ``grantee_hash`` and covering ``ops``."""
    grants = [{
        "handlers": {"include": handlers},
        "operations": {"include": ops},
        "resources": {"include": ["*"]},
    }]
    cred, sig = target.mint_token(grantee_hash, grants, None)
    inc = Included()
    for e in (target.identity.peer_entity, sig):
        inc.add(e)
    return cred, inc


def test_peer_relative_of_all_three_spellings():
    """§1.4's three spellings of one address, onto the one form a grant can match.

    The validator sends the SCHEMED ABSOLUTE form.  The last two cases are the standing
    defect from ``smalltalk`` and ``forth``: an UNCONDITIONAL first-segment strip turns
    ``system/protocol/connect`` into ``protocol/connect``, which made every self-minted
    grant unusable while the handshake stayed green.
    """
    local = "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"
    remote = "2K8mc32Lv3cJdniUfdAVv69DkqHqTzwq6GyHtroBX6ogUF"
    cases = [
        ("system/validate/echo", "system/validate/echo"),
        ("/" + remote + "/system/validate/echo", "system/validate/echo"),
        ("entity://" + remote + "/system/validate/echo", "system/validate/echo"),
        ("entity://" + local + "/system/validate/echo", "system/validate/echo"),
        # `system` is NOT a peer_id and MUST survive.
        ("system/protocol/connect", "system/protocol/connect"),
        ("/system/protocol/connect", "system/protocol/connect"),
    ]
    for uri, want in cases:
        assert peer_relative_of(local, uri) == want, uri


def test_grant_path_resolves_from_either_pattern_form(peers):
    local, _ = peers
    assert local.store.get_at(grant_path_for(local.local_peer, DISPATCH)) is not None
    absolute = "/" + local.local_peer + "/" + DISPATCH
    assert local.store.get_at(grant_path_for(local.local_peer, absolute)) is not None


def test_handler_grant_is_narrow(peers):
    """A WIDE grant here makes every case below pass for the wrong reason.

    GUIDE-CONFORMANCE §7a.1 makes narrowness a scaffold-contract requirement precisely
    because consulting a wide grant and skipping it agree on every input.
    """
    local, _ = peers
    g = local.store.get_at(grant_path_for(local.local_peer, DISPATCH))
    from entity_core.peer.capability import _grants_of_token

    recs = _grants_of_token(g)
    assert len(recs) == 1
    for s in (recs[0].handlers.incl, recs[0].operations.incl, recs[0].resources.incl):
        assert "*" not in s, f"wildcard in the dispatch-outbound own grant: {s}"


@pytest.mark.parametrize(
    "case,operation,cover,want,why",
    [
        ("presented_credential_in_handler_grant", "echo", [ECHO], True,
         "the compose: handler grant covers echo, credential relaxes Dimension 4"),
        ("presented_credential_out_of_handler_grant", "reentry-oos-probe", ["*"], False,
         "THE discriminating vector (§1.4): a valid target-minted credential for an "
         "operation the handler's OWN grant does not cover MUST refuse"),
    ],
)
def test_outbound_gate_presented(peers, case, operation, cover, want, why):
    local, remote = peers
    own = local.store.get_at(grant_path_for(local.local_peer, DISPATCH))
    ops = ["echo"] if cover == [ECHO] else ["*"]
    cred, inc = _mint_cred(remote, local.identity.identity_hash, cover, ops)
    got = check_outbound_sub_dispatch(
        local.local_peer, remote.local_peer, ECHO, operation, local.store, own,
        resource_target("system/handler/" + ECHO), cred, inc,
    )
    assert got is want, why


def test_outbound_gate_ambient_is_refused(peers):
    """The ambient arm: Dimension 4 is decided by the handler grant alone, whose absent
    ``peers`` scope defaults to ``{include: [local]}``, so a foreign target fails."""
    local, remote = peers
    own = local.store.get_at(grant_path_for(local.local_peer, DISPATCH))
    assert not check_outbound_sub_dispatch(
        local.local_peer, remote.local_peer, ECHO, "echo", local.store, own,
        resource_target("system/handler/" + ECHO), None, Included(),
    )


def test_outbound_gate_unverifiable_credential_relaxes_nothing(peers):
    """A credential that fails verification relaxes NOTHING and the handler grant gates
    unrelaxed — it does not become an error and it does not become a pass."""
    local, remote = peers
    own = local.store.get_at(grant_path_for(local.local_peer, DISPATCH))
    cred, _ = _mint_cred(remote, local.identity.identity_hash, [ECHO], ["echo"])
    assert not check_outbound_sub_dispatch(
        local.local_peer, remote.local_peer, ECHO, "echo", local.store, own,
        resource_target("system/handler/" + ECHO), cred, Included(),  # empty bundle
    )


def test_multisig_root_never_relaxes_dimension_4(peers):
    """E3/F66 — and the ONLY measurement of this rule on this peer.

    A K-of-N root is a GROUP's authority, so it is not *minted BY the target peer* and
    never relaxes Dimension 4 (§1.4, 0.8.2.19) — even when the quorum is well-formed and
    WOULD verify locally.  Accepting it would let any one signer's target confer the
    whole group's grant.

    ⚠ THE QUORUM MUST INCLUDE THE LOCAL PEER AND MUST OTHERWISE VERIFY.  With signers
    {remote, third}, §5.5's M6 refuses the root for a reason unrelated to §1.4 and this
    case goes green with the guard planted out — an inert control that reads exactly like
    a passing one.  That is measured, not hypothetical: it is why the wire check does not
    measure this rule either.
    """
    local, remote = peers
    own = local.store.get_at(grant_path_for(local.local_peer, DISPATCH))
    resource = resource_target("system/handler/" + ECHO)

    # Control: the same request with a SINGLE-signature root from the same target MUST
    # be allowed.  Without it, a peer refusing every credential form passes for a reason
    # that has nothing to do with §1.4 — fail-closed by absence (§2.4b).
    cred_single, inc_single = _mint_cred(remote, local.identity.identity_hash, [ECHO], ["echo"])
    assert check_outbound_sub_dispatch(
        local.local_peer, remote.local_peer, ECHO, "echo", local.store, own,
        resource, cred_single, inc_single,
    ), "single-signature control refused — the multi-sig case would measure nothing"

    # The variable is the GRANTER FORM and nothing else.
    grants = [{
        "handlers": {"include": [ECHO]},
        "operations": {"include": ["echo"]},
        "resources": {"include": ["*"]},
    }]
    cred_multi = Entity.make("system/capability/token", {
        "granter": {
            "signers": [bytes(local.identity.identity_hash), bytes(remote.identity.identity_hash)],
            "threshold": 2,
        },
        "grantee": bytes(local.identity.identity_hash),
        "grants": grants,
        "created_at": 1_000,
    })
    inc_multi = Included()
    for e in (
        local.identity.peer_entity,
        remote.identity.peer_entity,
        local.identity.sign_entity(cred_multi),
        remote.identity.sign_entity(cred_multi),
    ):
        inc_multi.add(e)

    # Antecedent control: the quorum DOES verify in the local frame.  If this fails the
    # case below refuses structurally and measures nothing.
    assert verify_capability_chain_rooted_at(
        local.local_peer, local.local_peer, local.store, cred_multi, inc_multi
    ) == ALLOW, "the quorum does not verify even locally — this case cannot discriminate"

    assert not check_outbound_sub_dispatch(
        local.local_peer, remote.local_peer, ECHO, "echo", local.store, own,
        resource, cred_multi, inc_multi,
    ), ("a K-of-2 multi-signature root relaxed Dimension 4 — §1.4: a multi-signature root "
        "NEVER relaxes it, because *minted by the target* means the target SOLELY minted it")


def test_credential_peers_scope_absent_relaxes_to_the_target(peers):
    """An absent ``peers`` scope on the credential relaxes to the GRANTER — the target —
    which is the ordinary reentry shape: *you may dispatch back to me*."""
    local, remote = peers
    from entity_core.peer.capability import target_minted_peers_relaxation

    cred, inc = _mint_cred(remote, local.identity.identity_hash, [ECHO], ["echo"])
    s = target_minted_peers_relaxation(local.local_peer, remote.local_peer, local.store, cred, inc)
    assert isinstance(s, Scope)
    assert s.incl == [remote.local_peer]
