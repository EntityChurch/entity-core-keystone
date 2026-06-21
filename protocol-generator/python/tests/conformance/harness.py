"""ECF wire-conformance harness — the S2 conformance gate for the Python peer.

Loads the normative cross-blessed corpus
(``protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor``)
through the peer's OWN ECF decoder (a decoder bug surfaces here first, per
Appendix E §E.3 step 1), then for each vector branches on ``kind``:

  * ``encode_equal`` — run ``input`` through the peer's construction for the
    vector's category and assert the bytes are byte-identical to the vector's
    ``canonical`` field.
  * ``decode_reject`` — feed ``canonical`` (non-canonical wire bytes) to the
    peer's strict ECF decoder; pass iff it rejects.

Category dispatch mirrors the Go oracle (``entity-core-go`` @ 33f35fd,
``cmd/internal/wire-conformance/emit.go`` :: ``encodeVector``) EXACTLY — this
is a clean-room BYTE-validation against the oracle's construction (we read its
construction contract, not to copy code, but because the cross-blessed
``canonical`` bytes ARE the contract):

  * ``content_hash.*`` — ``varint(format_code) || SHA256(ECF({type, data}))``
    (``format_code`` defaults to 0; an override key exercises multi-byte varint)
  * ``peer_id.*``      — ``ECF(Base58(varint(kt) || varint(ht) || digest))``
    (the canonical bytes are the ECF text-string of the Base58 string)
  * ``signature.*``    — Ed25519 sign over ``ECF(entity)`` (deterministic seed)
  * ``envelope.*``     — canonical ECF re-encode of the envelope value tree
  * everything else    — Class A canonical ECF re-encode of ``input``

Run as a script (``python -m tests.conformance.harness [corpus.cbor]``) to
get a JSON+text report on stdout; importable for the pytest suite.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path
from typing import Any

from entity_core import _base58, _cbor
from entity_core._cbor import ByteKey
from entity_core._varint import encode_varint
from entity_core.signature import sign_ed25519

CORPUS_VERSION = "v1"
SPEC_VERSION = "1.5"
IMPL = "core-python"

# Default corpus location relative to the repo root (this file lives at
# protocol-generator/python/tests/conformance/harness.py).
_REPO_ROOT = Path(__file__).resolve().parents[4]
DEFAULT_CORPUS = (
    _REPO_ROOT
    / "protocol-generator"
    / "shared"
    / "test-vectors"
    / "v0.8.0"
    / "conformance-vectors-v1.cbor"
)


def _as_str(v: Any) -> str:
    if isinstance(v, str):
        return v
    raise TypeError(f"expected text string, got {type(v).__name__}")


def _as_int(v: Any) -> int:
    if isinstance(v, bool) or not isinstance(v, int):
        raise TypeError(f"expected int, got {type(v).__name__}")
    return v


def _as_bytes(v: Any) -> bytes:
    if isinstance(v, (bytes, bytearray, ByteKey)):
        return bytes(v)
    raise TypeError(f"expected byte string, got {type(v).__name__}")


# ── Category constructions (byte-for-byte mirror of the Go oracle) ────────────
def _emit_content_hash(inp: dict) -> bytes:
    typ = _as_str(inp["type"])
    data = inp["data"]
    format_code = _as_int(inp["format_code"]) if "format_code" in inp else 0
    if format_code < 0:
        raise ValueError("content_hash format_code must be >= 0")
    encoded = _cbor.encode({"type": typ, "data": data})
    digest = hashlib.sha256(encoded).digest()
    return encode_varint(format_code) + digest


def _emit_peer_id(inp: dict) -> bytes:
    kt = _as_int(inp["key_type"])
    ht = _as_int(inp["hash_type"])
    digest = _as_bytes(inp["digest"])
    if kt < 0 or ht < 0:
        raise ValueError("peer_id codes must be >= 0")
    raw = encode_varint(kt) + encode_varint(ht) + digest
    b58 = _base58.b58encode(raw)
    # Canonical = ECF text-string encoding of the Base58 string.
    return _cbor.encode(b58)


def _emit_signature(inp: dict) -> bytes:
    seed = _as_bytes(inp["seed"])
    entity = inp["entity"]
    entity_bytes = _cbor.encode(entity)
    return sign_ed25519(seed, entity_bytes)


def _emit_envelope(inp: dict) -> bytes:
    return _cbor.encode(inp)


def _emit_class_a(inp: Any) -> bytes:
    return _cbor.encode(inp)


def emit_vector(vector_id: str, inp: Any) -> bytes:
    if vector_id.startswith("content_hash."):
        return _emit_content_hash(inp)
    if vector_id.startswith("peer_id."):
        return _emit_peer_id(inp)
    if vector_id.startswith("signature."):
        return _emit_signature(inp)
    if vector_id.startswith("envelope."):
        return _emit_envelope(inp)
    return _emit_class_a(inp)


# ── Runner ────────────────────────────────────────────────────────────────────
def run(corpus_path: Path | str = DEFAULT_CORPUS) -> dict:
    """Run the full corpus; return a structured result dict."""
    corpus_bytes = Path(corpus_path).read_bytes()
    # Step 1 (Appendix E §E.3): load the corpus through the peer's OWN decoder.
    vectors = _cbor.decode(corpus_bytes)
    if not isinstance(vectors, list):
        raise TypeError("corpus root must be a CBOR array of vector maps")

    results: list[dict] = []
    n_pass = n_fail = 0
    per_category: dict[str, dict[str, int]] = {}

    for vec in vectors:
        vid = _as_str(vec["id"])
        kind = _as_str(vec["kind"])
        canonical = _as_bytes(vec["canonical"])
        category = vid.split(".", 1)[0]
        cat = per_category.setdefault(category, {"pass": 0, "fail": 0})

        ok = False
        detail = ""
        if kind == "encode_equal":
            try:
                produced = emit_vector(vid, vec["input"])
                ok = produced == canonical
                if not ok:
                    detail = (
                        f"got {produced.hex()} want {canonical.hex()}"
                    )
            except Exception as e:  # noqa: BLE001 — report, don't crash the run
                detail = f"emit raised: {type(e).__name__}: {e}"
        elif kind == "decode_reject":
            try:
                _cbor.decode(canonical)
                detail = "decoder ACCEPTED bytes that MUST be rejected"
            except _cbor.NonCanonicalEcfError as e:
                ok = True
                detail = f"rejected: non_canonical_ecf ({e})"
            except _cbor.TruncatedError as e:
                ok = True
                detail = f"rejected: truncated ({e})"
        else:
            detail = f"unknown kind: {kind!r}"

        results.append(
            {"id": vid, "kind": kind, "pass": ok, "detail": detail}
        )
        if ok:
            n_pass += 1
            cat["pass"] += 1
        else:
            n_fail += 1
            cat["fail"] += 1

    return {
        "impl": IMPL,
        "corpus_version": CORPUS_VERSION,
        "spec_version": SPEC_VERSION,
        "total": len(vectors),
        "pass": n_pass,
        "fail": n_fail,
        "categories": per_category,
        "vectors": results,
    }


def main(argv: list[str]) -> int:
    corpus = Path(argv[1]) if len(argv) > 1 else DEFAULT_CORPUS
    report = run(corpus)
    failures = [v for v in report["vectors"] if not v["pass"]]
    print(
        f"wire-conformance ({report['impl']}, corpus {report['corpus_version']}, "
        f"spec {report['spec_version']}): "
        f"{report['pass']}/{report['total']} PASS, {report['fail']} FAIL"
    )
    cats = ", ".join(
        f"{k} {v['pass']}/{v['pass'] + v['fail']}"
        for k, v in sorted(report["categories"].items())
    )
    print(f"  categories: {cats}")
    for f in failures:
        print(f"  FAIL {f['id']} ({f['kind']}): {f['detail']}")
    print("---JSON---")
    print(json.dumps(report, indent=2))
    return 1 if report["fail"] else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
