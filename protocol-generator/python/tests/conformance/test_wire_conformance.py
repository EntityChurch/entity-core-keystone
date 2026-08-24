"""pytest entry point for the ECF wire-conformance gate.

Drives ``tests/conformance/harness.py`` against the normative cross-blessed
corpus and asserts 71/71 PASS, 0 FAIL. Each vector is also reported as its
own parametrized case so a failure names the exact vector id.
"""

from __future__ import annotations

import pytest

from tests.conformance.harness import DEFAULT_CORPUS, run

_REPORT = run(DEFAULT_CORPUS)


def test_no_failures():
    failures = [v["id"] for v in _REPORT["vectors"] if not v["pass"]]
    assert not failures, f"wire-conformance failures: {failures}"


def test_full_corpus_count():
    # The finalized F29/F30 corpus holds 71 testable vectors: 66 encode_equal
    # (incl. the F29 nested.5/nested.6 array-of-maps head-boundary pair) + 5
    # decode_reject (the F30-regenerated tag_reject battery). All must run and
    # pass (S7 lower bar).
    assert _REPORT["total"] == 71, f"expected 71 vectors, ran {_REPORT['total']}"
    assert _REPORT["fail"] == 0


@pytest.mark.parametrize(
    "vec",
    _REPORT["vectors"],
    ids=[v["id"] for v in _REPORT["vectors"]],
)
def test_vector(vec):
    assert vec["pass"], vec["detail"]
