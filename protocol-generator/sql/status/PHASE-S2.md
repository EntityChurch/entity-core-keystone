# Phase S2 — SQL peer codec/crypto seam (delegated FFI-C host)

**The declarative-query / authority-as-query probe · exploratory ‡ (probe) tier ·
seam-hybrid · S2 completed 2026-07-16**

S2 builds the **codec/crypto seam** of the C host — the "byte-pump + FFI seam"
lower half. Everything the SQL substrate genuinely cannot do (canonical CBOR bytes,
content_hash, peer-id, Ed25519/SHA) is **delegated to `libentitycore_codec` across
the C-ABI** (profile `[codec].strategy = "ffi-c-host"`), exposed as clean C
functions the S3 authority layer + the SQLite app-defined functions will call.
**Not in this phase:** sockets, §1.6 framing, §6.5 dispatch, the §4 handshake state
machine, any authority-interior SQL — those are S3.

## Honest framing (ADR-0012)

**Not independent convergence.** The codec/crypto is `libentitycore_codec` (shared
C-ABI lineage), so this byte-identity pass is **cohort-consistent, not independent**.
The seam does no canonical CBOR or crypto of its own — it moves bytes/handles across
the C-ABI. Stated plainly in the harness banner (it prints `ec_impl_info()`).

## The S2 gate — GREEN

Real container build + real vector run, inside the capped
`entity-core-keystone/sqlite-toolchain:latest` image, `--network=none`,
`$PODMAN_RUN_CAPS` (`./run-s2.sh`):

```
== ECF wire-conformance: 71/71 PASS, 0 FAIL ==
== TOTAL: 79 pass, 0 fail ==
A-SQL-001 RESOLVED: provenance label reads spec-data v7.71, but every v0.8.0
corpus vector is byte-identical — the label lag is cosmetic, wire-confirmed.
```

- **71/71** ECF wire-conformance vectors byte-identical against
  `protocol-generator/shared/test-vectors/ecf-conformance/conformance-vectors.cbor`
  (66 `encode_equal` + 5 `decode_reject`). Corpus SHA-256
  `9695b1f1…f7c6dc` (MANIFEST-pinned).
- **+8 self-tests** (79 total): N1–N4 targeted, an Ed25519 RFC-8032 KAT, and the
  crypto-callable-FROM-SQL KAT (3 checks). See CONFORMANCE-REPORT.md for the split.

**Differential per category** (each delegated primitive byte-compared vs the
vector's `canonical`):

| Category | Count | Delegated primitive |
|---|---|---|
| float / int / map_keys / length / primitive / nested / envelope | 56 | `ec_encode_bare_value` (F6 decode+re-encode; identity for canonical input — exercises the decoder AND the canonical encoder) |
| content_hash | 4 | `ec_content_hash_with_format` (3 byte-match at format 0x00; `content_hash.4` format 128 = correct-unsupported, A-SQL-005) |
| peer_id | 3 | `ec_peerid_format` → CBOR-text (incl. `peer_id.3` key_type 128 multi-byte varint, byte-matched) |
| signature | 3 | `ec_ed25519_sign(seed, ECF({type,data}))` |
| decode_reject | 5 | `ec_encode_bare_value` MUST fail (§3.2 recursive tag scan, N2) |

## N1–N4 (the pinned codec bug-classes) — covered

- **N1** LEB128 format-code framing: `ec_hash_format_code_encode(128)` → `0x80 0x01`
  (self-test), plus `peer_id.3`/`content_hash.4` drive the multi-byte varint path.
- **N2** recursive major-type-6 tag reject: all 5 `tag_reject.*` (incl. `.4`
  top-level `d9d9f7`, `.5` deep-nested in an included entity) + a bare-tag self-test.
  The delegated decoder runs the real scanner; the seam only forwards the verdict.
- **N3** empty-map `0xA0`: `length.2` identity + `content_hash.1` over `{data:{}}`
  (the empty-params boundary) + a `0xA0`-identity self-test.
- **N4** entity fidelity (forward original bytes, never re-serialize):
  `ec_decode_entity` returns the exact original byte span; the self-test asserts
  `orig == input` byte-identical over `nested.3`. The seam never re-encodes an entity.

## The tight-seam move — crypto callable FROM SQL (proven at S2)

`ec_seam_register_sql_functions()` registers three SQLite application-defined
functions backed by the C-ABI, so the §5.2 verdict query calls them inline:

- `sha256(blob) → blob(32)` — S1 GO-gate KAT re-proven (`sha256("abc")`).
- `content_hash(text type, blob data) → blob(33)` — `SELECT hex(content_hash(
  'system/empty', x'a0'))` == `content_hash.1` canonical `005f3139…0ca396b`.
- `ed25519_verify(blob pub, blob msg, blob sig) → 1/0` — sign in C, verify FROM
  SQL → 1; tampered sig → 0.

This narrows the crypto seam to the primitive and keeps the §5.2 verify *sequencing*
authorable in SQL (S3). The three functions are the exact rungs the SQL verdict
ladder will call.

## A-SQL-001 — RESOLVED (byte-identity, not assumption)

The delegated codec's `ec_impl_info()` still reads `spec-data v7.71`, but every one
of the 71 v0.8.0 vectors is byte-identical → the V7→V8 core wire is **wire-confirmed
byte-unchanged**, and the label is a cosmetic build-metadata lag. Closed; see the
ambiguity log.

## New findings this phase

- **A-SQL-005** (NOTE, resolved): the delegated `content_hash` supports format
  0x00/0x01 only, so `content_hash.4` (format 128) is correctly reported
  *unsupported* rather than emitted as wrong bytes — the vector's own allowed branch.
- **A-SQL-006** (FINDING): the FFI-C impl's **bundled header** baked into the image
  (`/opt/codec/include/entitycore_codec.h`) lags the canonical C-ABI spec header —
  it omits `ec_ed25519_seed_to_pubkey` though the `.so` exports it. S2 builds against
  the canonical spec header (`ffi-generator/c-abi/spec/`, the authority) instead.
  Cosmetic ffi-generator re-sync; not arch/spec.

## Files written this phase

- `protocol-generator/sql/src/host/ec_seam.h` — the seam API (declarations).
- `protocol-generator/sql/src/host/ec_seam.c` — thin ec_* wrappers + the two-call
  OUT_OF_SPACE sizing + the SQLite app-defined crypto-function registration.
- `protocol-generator/sql/src/test/codec_test.c` — the wire-conformance differential
  harness (minimal fixture CBOR reader + N1–N4 + Ed25519 KAT + crypto-from-SQL KAT).
- `protocol-generator/sql/Makefile` — the codec-seam build + `check` gate.
- `protocol-generator/sql/run-s2.sh` — container-bound, capped, offline gate runner.
- `protocol-generator/sql/status/PHASE-S2.md` — this file.
- `protocol-generator/sql/status/CONFORMANCE-REPORT.md` — the S2 gate summary.
- `protocol-generator/sql/status/SPEC-AMBIGUITY-LOG.md` — A-SQL-001 resolved;
  A-SQL-005 + A-SQL-006 added.

## Phase exit criteria — MET

- [x] Codec/crypto seam authored, delegated to `libentitycore_codec` via the C-ABI.
- [x] Wire-conformance gate GREEN: `71/71 PASS` byte-identical, in-container,
  capped, `--network=none`.
- [x] N1–N4 each covered by a vector and/or a targeted self-test.
- [x] Crypto callable FROM SQL proven at the seam layer (sha256/content_hash/
  ed25519_verify app-defined functions).
- [x] A-SQL-001 resolved by byte-identity; ambiguity log has no blocking items.

## Handoff to S3 (authority interior)

Author the §5/§6.6 authority interior as legible SQL over grant/token/handler
tables (the wrapper-guard: `verify_ladder.sql` CASE ladder calling `ed25519_verify()`
/`content_hash()` inline; `chain_walk.sql` `WITH RECURSIVE`; `resolve.sql`
`ORDER BY length(pattern) DESC LIMIT 1`; `k_of_n.sql` `GROUP BY … HAVING count(
DISTINCT signer) >= :threshold`). Build the host imperative shell on this seam:
sockets + §1.6 framing + frame-cap + the §6.5 dispatch scaffold + the §4 handshake
state machine. Fill in `[authority_interior_expressibility]` (hypothesis → outcome
→ finding) per element — the seam-split (A-SQL-003) is the probe's central
deliverable. Mandatory at S3/S4: the genuine 2-of-3 multisig **accept-path** test
(A-SQL-004) the rejection-only oracle can't cover. Rebuild the oracle binaries from
`entity-core-go` HEAD (`CGO_ENABLED=0 GOWORK=off`) before S4.
