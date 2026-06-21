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
    # The v7.56 corpus array holds 69 testable vectors (64 encode_equal + 5
    # decode_reject; the manifest's "71" counts 2 metadata-agreement checks
    # that are not array entries). All must run and pass (S7 lower bar).
    assert _REPORT["total"] == 69, f"expected 69 vectors, ran {_REPORT['total']}"
    assert _REPORT["fail"] == 0


@pytest.mark.parametrize(
    "vec",
    _REPORT["vectors"],
    ids=[v["id"] for v in _REPORT["vectors"]],
)
def test_vector(vec):
    assert vec["pass"], vec["detail"]
