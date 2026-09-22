# Crypto-Agility Conformance Vectors

**Version**: 1.0
**Status**: Active

Phase 1 (allocation + machinery) and Phase 2 (cross-key / cross-hash matrix) are byte-pinned cross-impl in `agility-vectors.diag`, with the seed convention in `SEEDS.md` (this directory). Phase 3a/3b stay deferred. The sibling `agility-vectors.cbor` is the deterministic ECF-canonical encoding produced from `.diag` by any conformant encoder; bytes MUST match the inline canonical (`h'...'`) values in `.diag`.

Spec homes: §1.2 (`content_hash_format` seed table), §1.5 (`key_type` seed table).

---

## Vector inventory

### Phase 1 — allocation + machinery (LANDED cross-impl: Go × Rust × Python byte-equal)

| Vector | Validates | key_type / hash_format |
|---|---|---|
| `KEY-TYPE-ED448-1` | `system/peer({public_key, key_type="ed448"})` → canonical `(0x02, 0x01)` peer_id; `content_hash` byte-equal cross-impl; sign/verify round-trip on a fixed seed | Ed448 `0x02` / SHA-256-form |
| `HASH-FORMAT-SHA-384-1` | `content_hash` under `content_hash_format=0x01` byte-equal cross-impl for a canonical fixture entity; store + retrieve round-trip | Ed25519 `0x01` / SHA-384 `0x01` |
| `VARINT-MULTIBYTE-1` | Impl decodes a `system/hash` with a multi-byte LEB128 format code (fixture uses `0x80`, first two-byte encoding) and rejects with `unsupported_content_hash_format` (`0x80` unallocated). Confirms the multi-byte decode path exists. | n/a |
| `VARINT-RESERVED-FF-1` | Impl rejects constructing a `system/peer` with `key_type` value 255 (`0xFF 0x01`) and a `system/hash` with format-code value 255 | n/a |
| `FORMAT-CODE-INTERPRETATION-1` | (renamed from v7.66 `PREFIX-DISPATCH-1`; semantics unchanged) impl receiving a `content_hash` with an unsupported format code returns `unsupported_content_hash_format` | n/a |

### Phase 2 — cross-key / cross-hash matrix, classical (LANDED cross-impl; 11/11 mixed-key pairs convergence-flat)

| Vector | Peer A | Peer B | Cap chain depth |
|---|---|---|---|
| `MATRIX-M2` | Ed448 / SHA-256 | Ed25519 / SHA-256 | ≥ 1 |
| `MATRIX-M3` | Ed25519 / SHA-384 | Ed25519 / SHA-256 | ≥ 1 |
| `MATRIX-M6` | Ed448 / SHA-384 | Ed25519 / SHA-256 | ≥ 1 |

Each matrix vector exercises: handshake (`hello` + `authenticate`, signature scheme + peer_id canonicalization per allocation) → tree-get on a small entity (content-store dispatch by format code) → cap grant A→B (mixed-`key_type` cap-pattern peer references) → cap use B→A (sig verification + cap-chain walk + format-code freeze).

### Phase 3a — DEFERRED to W2 backlog (BLAKE3 family)

| Vector | Notes |
|---|---|
| `HASH-FORMAT-BLAKE3-1` | `content_hash` under `content_hash_format=0x03` (BLAKE3-256) |
| `MATRIX-M5` | Ed25519/BLAKE3 ↔ Ed25519/SHA-256; format-code freeze across chain links |

### Phase 3b — DEFERRED to W2 backlog (ML-DSA-65 / PQ)

| Vector | Notes |
|---|---|
| `KEY-TYPE-ML-DSA-65-1` | `key_type="ml-dsa-65"`; canonical `(0x03, 0x01)`; sign/verify round-trip on a fixed seed |
| `MATRIX-M4` | ML-DSA-65/SHA-256 ↔ Ed25519/SHA-256; **cap chain depth ≥ 3** (PQ size accumulation) |
| `MATRIX-M7` | ML-DSA-65/BLAKE3 ↔ Ed25519/SHA-256; **cap chain depth ≥ 3** (combined PQ size + non-SHA-2) |
| `MATRIX-M8` | ML-DSA-65/SHA-384 ↔ Ed448/BLAKE3; single-permutation regression check (does NOT replace a fuzz-over-pairs harness — descoped) |

---

## Fixture byte status

**Phase 1 — LOCKED.** All five Phase-1 vectors are byte-pinned in `agility-vectors.diag` with the seed convention in `SEEDS.md` §1, byte-equal cross-impl. Per the corpus-authoring discipline, pinned bytes derive from the spec algorithm (§§1.2/1.3/1.5); the inline canonical values in `.diag` are the lock.

**Phase 2 — LOCKED.** The three matrix vectors (`MATRIX-M2`, `MATRIX-M3`, `MATRIX-M6`) are byte-pinned in `agility-vectors.diag` from a cross-impl round-trip. All 7 gates per matrix vector are byte-equal across implementations: pubkeys + peer_ids + home content_hashes + cap-data CBOR + active cap content_hash + signature. Convention pinned during the round-trip: an unconstrained capability scope dimension encodes as `{include: []}` (`0x80`), not `{include: null}` (`0xf6`) — both halves are already bound by ENTITY-CBOR-ENCODING §232 + §3.6 `list-of(pattern)` typing.

**Build-artifact `.cbor`.** The `.cbor` is regenerated from the `.diag` by a canonical ECF encoder (definite-length, minimal integer encoding, length-then-lexicographic map keys per ENTITY-CBOR-ENCODING §4.1). **sha256 = `b5484e84dd2cddfa7d3cc8a041deba92cb29615aedb2180e31d8b6910ac5b648`** (10874 B). Corpus discipline: a byte gate MUST decode the `.cbor` and assert structural invariants (seed/pubkey field widths against the spec, no placeholder strings in `expected_*` fields), not only compare the file sha — and a second gate MUST assert that the `.diag` still *produces* the `.cbor`, which comparing the artifact to itself never does.

`CHANGELOG.md` in this directory records every change that moved the artifact, and is the corpus's history — the filename does not carry a version.

**Phase 3a/3b — DEFERRED.** BLAKE3 + ML-DSA-65 seeds not pinned (Phase 3 deferred).

Pinned seeds (cross-reference for impl authoring):
- **Ed448** — 57-byte secret seed (RFC 8032), byte `0x42` × 57 for `KEY-TYPE-ED448-1` / `MATRIX-M2`-A; `0x46` × 57 for `MATRIX-M6`-A. Library expansion (SHAKE256) happens inside the signing library; no pre-expansion.
- **Ed25519** — 32-byte secret seed (RFC 8032), `0x43` × 32 for `MATRIX-M2`-B; `0x44`/`0x45` for `MATRIX-M3` A/B; `0x47` × 32 for `MATRIX-M6`-B.
- **SHA-384** — re-hash of the `AGILITY-ENTITY-1` fixture (`system/peer({pub=0xAA×64, key_type='experimental-test'})`) under `content_hash_format=0x01`. Same source entity as the inherited SHA-256 corpus pin.
- **ML-DSA-65 / BLAKE3** — to be pinned at Phase-3b/3a pickup.
