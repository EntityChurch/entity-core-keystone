"""§3.3/§5.2 `effective_targets` — the TWO-EMPTIES DISCRIMINATOR (N7/N10/N11, 0.8.2.25).

N11 makes the discriminator a ``[MUST]``: *"where an implementation projects
``resource.targets`` onto the effective set ahead of the handler, that projection MUST
NOT be lossy about its own emptiness — narrow when narrowing leaves something, and
retain the raw pair when narrowing would empty it."*  This peer carries the
discriminator as ``list | None`` rather than as a second return value; the property is
the same and the spelling is the substrate's.

The cell this file exists for is `{"targets": <not an array>}`: it is PRESENT, and
reporting it as absent hands `get` the ROOT LISTING for a request that named
something — the wider-than-the-request answer §3.3 forbids.  It is also where the two
0.8.2.25 vanguards disagreed: `go`'s `textElems` of a non-array yields an empty
effective list, python's `isinstance(..., list)` guard yielded "absent".
"""

from __future__ import annotations

from entity_core.peer.handlers import _effective_targets
from entity_core.peer.wire import make_execute
from entity_core.peer.model import Entity

LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"


def _exec(resource) -> Entity:
    return make_execute("r1", "system/tree", "get", Entity.make("primitive/any", {}),
                        resource=resource)


def test_absent_resource_is_none() -> None:
    """No `resource` field at all, and a `resource` that is not a map: ABSENT."""
    assert _effective_targets(LOCAL, _exec(None)) is None
    assert _effective_targets(LOCAL, _exec(42)) is None


def test_targets_key_absent_is_reported_absent_and_that_is_the_open_question() -> None:
    """PINS THE SHIPPED ANSWER TO AN OPEN QUESTION rather than endorsing it.

    A `resource` MAP carrying no `targets` key is reported ABSENT by both 0.8.2.25
    vanguards, so `get` serves it the root listing.  §3.2 says ``targets`` *"MUST
    contain at least one entry"*, which makes the shape MALFORMED rather than absent —
    and N10's point is that a PRESENT ``resource`` must not be served the wider
    absent-case answer.  Nothing in the 778-check set drives it and no disposition is
    pinned, so the behaviour is held rather than changed; this case exists so that
    changing it is a DECISION and not a drift.

    It is also the discriminator the first plant pass was missing: without it the
    "collapse the two empties" mutation ran GREEN, because nothing else here reaches
    this branch at all.
    """
    assert _effective_targets(LOCAL, _exec({})) is None
    assert _effective_targets(LOCAL, _exec({"exclude": ["a"]})) is None


def test_present_but_empty_is_a_list_not_none() -> None:
    """The discriminator, in the direction N11 protects: `[qA] exclude [qA]` narrows to
    nothing and MUST NOT come back looking like an absent resource."""
    assert _effective_targets(LOCAL, _exec({"targets": ["a"], "exclude": ["a"]})) == []
    assert _effective_targets(LOCAL, _exec({"targets": []})) == []


def test_ill_typed_targets_is_present_not_absent() -> None:
    """`{"targets": 42}` is a PRESENT resource.  Reporting it absent gives `get` the
    root listing for a request that named something — and it is the cell on which the
    two vanguards diverged."""
    assert _effective_targets(LOCAL, _exec({"targets": 42})) == []
    assert _effective_targets(LOCAL, _exec({"targets": "a"})) == []


def test_survivors_keep_the_callers_own_spelling() -> None:
    """0.8.2.21: `effective_targets` yields RAW survivors, not canonical forms — the
    value flows on to the store lookup, which canonicalizes for itself."""
    eff = _effective_targets(LOCAL, _exec({"targets": ["app/x", "app/y"], "exclude": ["app/y"]}))
    assert eff == ["app/x"], "raw survivor, not /{local}/app/x"


def test_caller_exclude_is_fail_open_on_an_unmatchable_pattern() -> None:
    """§5.4 rules the caller-exclude arm separately from the GRANT arm: `canon` answers
    the sentinel, `matches_pattern` answers False, and the target simply SURVIVES.  The
    matchable control beside it is what says the exclude works at all — without it a
    peer that ignored `exclude` entirely would pass this."""
    assert _effective_targets(LOCAL, _exec({"targets": ["app/x"], "exclude": ["../nope"]})) \
        == ["app/x"]
    assert _effective_targets(LOCAL, _exec({"targets": ["app/x"], "exclude": ["app/x"]})) == []
