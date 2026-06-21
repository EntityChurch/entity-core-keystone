# Phase S2 — Python peer — Codec layer — Summary

**Peer:** `entity-core-protocol-python` (CPython) — clean-room clone of the hand-
written sibling `entity-core-py`. **Branch:** `lang/python` (worktree).
**Phase:** S2 (codec). **Spec authority:** `spec-data/v7.75`
(`ENTITY-CBOR-ENCODING.md` v1.5 + `ENTITY-NATIVE-TYPE-SYSTEM.md` 4.2.1).
**Codec strategy:** `native` (hand-rolled ECF + `cryptography` native-full-agility).

## Exit criteria — met

- [x] **Wire-conformance 69/69 PASS, 0 FAIL** against the cross-blessed v1 corpus
      (`shared/test-vectors/v7.56/conformance-vectors-v1.cbor`). S7 lower bar met.
- [x] **Three-way byte-identity** Python == corpus == Go oracle (`entity-core-go`
      `wire-conformance` @ **`e8524ed`**), 0 mismatches. Oracle vendored into a temp
      dir OUTSIDE `entity-core-go`; go tree clean before+after.
- [x] **Ed448 byte-pin** verified against the v7.71 agility corpus (`KEY-TYPE-ED448-1`):
      pubkey + 114-byte signature + peer_id all byte-match → native-full-agility
      (A-PY-002 closed, no FFI).
- [x] `pyproject.toml` (hatchling, src-layout) + **hash-pinned lockfile**
      (`requirements.txt`, `--require-hashes`: cryptography 48.0.0 + cffi 2.0.0 +
      pycparser 3.0, all-platform sha256) + fedora:43 **base digest** pinned in the
      Containerfile.
- [x] Container builds clean; build-time Ed25519+Ed448 sign/verify/tamper assertion
      passes (image `localhost/entity-core-keystone/python-toolchain:latest`).
- [x] `status/PHASE-S2.md` (this file) + `status/CONFORMANCE-REPORT.{md,json}` +
      `SPEC-AMBIGUITY-LOG.md` updated (A-PY-008 new; A-PY-002/003 resolved).

## What was built (`src/entity_core/`)

| Module | Surface | Notes |
|---|---|---|
| `_cbor.py` | `encode` / `decode` / `ByteKey` | Hand-rolled canonical ECF; shortest int/float head, length-then-lex map order, strict decode (tag-6 recursive reject, indefinite-length reject, non-minimal reject, dup/misordered key reject). (pre-existing; verified) |
| `_varint.py` | `encode_varint` / `decode_varint` | LEB128 (§1.5/§7.3); owns non-minimal rejection. (pre-existing) |
| `_base58.py` | `b58encode` / `b58decode` | Bitcoin alphabet, leading-zero convention. (pre-existing) |
| `content_hash.py` | `content_hash` | `varint(format_code) ‖ SHA256(ECF({type,data}))`. (pre-existing) |
| `errors.py` | `EntityCoreError` tree | Exception hierarchy. (pre-existing) |
| **`peer_id.py`** | `format_peer_id` / `parse_peer_id` / `PeerIdParts` | **NEW.** `Base58(varint(kt) ‖ varint(ht) ‖ digest)` + inverse; round-trip surface. |
| **`signature.py`** | `sign_ed25519/ed448`, `verify_*`, `*_public_key`, `sign_entity` / `verify_entity` | **NEW.** `cryptography` raw-key Ed25519 + Ed448; sign over canonical `ECF(entity)`. |
| **`__init__.py`** | public re-exports + `__version__` | **NEW.** Stable `import entity_core` surface. |

Test surface: `tests/conformance/harness.py` (loads corpus through the peer's own
decoder, dispatches by category exactly like the Go oracle, byte-compares) +
`tests/conformance/test_wire_conformance.py` (pytest, 71 passed).

## Key S2 confirmations / resolutions

- **A-PY-001** (hand-roll CBOR) — vindicated: the hand-rolled ECF reproduces all 64
  `encode_equal` vectors byte-exactly and rejects all 5 `decode_reject`, byte-
  identical to the Go reference. No library swap warranted.
- **A-PY-002 / A-PY-003** — RESOLVED (see ambiguity log): Ed448 native byte-verified;
  Ed25519/Ed448 raw-key API spelling confirmed in-container.
- **A-PY-008** — NEW: fedora:43 ships **CPython 3.14.5** at S2 build (not 3.13.x);
  accepted (conformance-neutral, distro-channel relaxation), Containerfile assert
  widened to 3.13.x∨3.14.x. The realized python pin is 3.14.5; the digest-pinned
  fedora:43 base makes it reproducible.

## Supply-chain lock-step

- **Runtime dep tree pinned by hash** (`requirements.txt`, `--require-hashes`):
  `cryptography==48.0.0` (newest clearing the S11 ≥30-day floor) + transitive
  `cffi==2.0.0` + `pycparser==3.0`, all published sha256 digests for every platform.
- **Base image digest pinned:**
  `registry.fedoraproject.org/fedora@sha256:4df057b0002143b48074d763237e1bb1eeae7b65aede070dda7a893e3f46f491`.
- The image install step now runs `pip install --require-hashes -r requirements.txt`.

## Anything blocking S3 (peer) — NONE

The codec + crypto + identity surface is complete and conformant. Open items for S3
(not blockers):

1. **Peer machinery** — transport (length-prefixed framing §5.1), thread-per-
   connection loop, `Lock`-guarded store, `Condition` §6.11 demux, dispatch, multisig
   accept-path + unit test, seed-policy bootstrap (all PLANNED in profile `[bootstrap]`).
2. **`host.py`** — the `python -m entity_core.host` S4 oracle-driver entry point
   (validate-peer / live conformance) is not yet written (S4 surface).
3. **Profile note** — `[deps].python` still reads `3.13.14` (S1 intent); the realized
   pin is 3.14.5 (A-PY-008). Left as-is for the S1 audit trail; the Containerfile is
   the source of truth for the realized toolchain.
