"""§5.2 typed scope matching (0.8.1, F40) — accept-path unit test.

The oracle carried no F40 vector when this was written, and a rejection-only probe
would let a uniformly-canonicalizing peer pass anyway, so the accept direction is the
peer's own to cover.  Drives the REAL ``_matches_scope`` against the cohort-shared
case set in ``protocol-generator/shared/scope-matching/id-scope-vectors.json``.

The load-bearing case is ``id.exclude.pathform``: an ``exclude`` written in path form
inside an ``operations`` scope DENIES on the pre-F40 canonicalizing reading and ALLOWS
on the conformant one, so it cannot be passed by accident.
"""

from __future__ import annotations

import json
import pathlib

from entity_core.peer.capability import Scope, _matches_scope

LOCAL = "12D3KooWLocalPeerIdExampleAAAAAAAAAAAAAAAAAAAA"
REMOTE = "12D3KooWRemotePeerIdExampleBBBBBBBBBBBBBBBBBBB"

_VECTORS = (
    pathlib.Path(__file__).resolve().parents[3]
    / "shared" / "scope-matching" / "id-scope-vectors.json"
)

_KIND = {"id-scope": "id", "path-scope": "path"}


def _sub(s: str) -> str:
    return s.replace("{local}", LOCAL).replace("{remote}", REMOTE)


def test_f40_typed_scope_matching() -> None:
    doc = json.loads(_VECTORS.read_text())
    failures = []
    for case in doc["cases"]:
        scope = Scope(
            [_sub(p) for p in case["include"]],
            [_sub(p) for p in case.get("exclude") or []],
        )
        got = _matches_scope(LOCAL, _sub(case["value"]), scope, _KIND[case["scope_type"]])
        if got != case["expect"]:
            failures.append(f"{case['id']}: expected {case['expect']}, got {got}")
    assert not failures, "F40 scope-typing divergence:\n  " + "\n  ".join(failures)


def test_f40_exclude_inversion_is_the_discriminator() -> None:
    """Stated inline as well as via the fixture — this is the case a canonicalizing
    peer gets wrong, and the reason the fixture is not merely decorative."""
    ops = Scope(["*"], ["/*/get"])
    assert _matches_scope(LOCAL, "get", ops, "id") is True

    # ... while the same shape on a path dimension MUST still canonicalize and bite.
    handlers = Scope(["*"], ["/*/system/tree"])
    assert _matches_scope(LOCAL, "system/tree", handlers, "path") is False


def test_f40_id_scope_wildcards_survive() -> None:
    """Bootstrap depends on these: the seed policy grants operations ``["*"]``."""
    assert _matches_scope(LOCAL, "get", Scope(["*"], []), "id") is True
    assert _matches_scope(LOCAL, "compute/apply", Scope(["compute/*"], []), "id") is True
    assert _matches_scope(LOCAL, "compute", Scope(["compute/*"], []), "id") is False
