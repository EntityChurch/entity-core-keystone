# test-vectors v0.8.0 — Vendor Manifest

**Spec version:** Entity Core Protocol **0.8.0** (V8). ECF corpus per `ENTITY-CBOR-ENCODING.md` v1.5 — wire-format byte-stable; agility corpus per §1.2/§1.5 seed tables.
**Vendor type:** byte-identical copies of architecture-repo canonical fixtures. Keystone does **not** author canonical bytes (S5). CI hash-checks against the tables below.
**Single retained snapshot:** the earlier point-in-time corpus dirs (byte-identical ECF set) were retired at the V8 cutover; this `v0.8.0/` is the one live corpus. *Agility Phase-1* closed since first vendor; *Phase-2* was vacuously "locked" over TBD placeholders until **F16** (see the agility-corpus block below) forced the regen — Phase-2 is now byte-real and closes on the §3.2 decode-and-validate run.

## Two corpora in this directory

### 1. ECF codec corpus

The lower-bar codec conformance set. **Wire-format byte-stable** — the ECF corpus has not changed across spec revisions.

| File | Role | SHA-256 |
|---|---|---|
| `conformance-vectors-v1.cbor` | Normative ECF corpus (64 encode + 5 reject + 2 meta = 71 vectors). | `41d68d2d717f84e195d46ec002fce6b8729742026256e72dc7a3a8b6c0c6a052` |
| `conformance-vectors-v1.diag` | Human source-of-truth (CBOR diagnostic notation). | `987672147c90e252fdee51334fe1faa60baff453c2743d44724b29cb671e25fe` |

Source: arch `specs/test-vectors/ecf-conformance/`, commit `23db2546`. C# / Rust-FFI / C-FFI all 69/69 — **carries forward unchanged.**

### 2. Crypto-agility corpus (vendored from arch, byte-pinned)

The agility conformance set. Locked 3-way (Go × Rust × Python byte-equal) across two phases.

| File | Role | SHA-256 |
|---|---|---|
| `agility-vectors-v1.cbor` | Normative agility corpus (Phase 1 + Phase 2). **Cohort lock.** | `8e7c5232f64bee83d628679f930c771e4e49f2f1e37d19e41e0d7838e31f982e` |
| `agility-vectors-v1.diag` | Human source-of-truth + per-vector byte pins. | `6d423cc6fe83bae099ce0172a360ca7d10ff2faf7d1f4d19894d0ffb26b877ae` |
| `agility-SEEDS.md` | Seed-construction reference (Ed448 `0x42×57`, Ed25519 `0x43/0x44/0x45/0x47×32`, Ed448 `0x46×57`). | (informative; see file) |

Source: arch `specs/test-vectors/crypto-agility/` (de-versioned corpus; arch and this vendor copy unified).

> **F16 re-vendor.** The `.cbor` previously vendored here was **byte-defective** — internally inconsistent with its own `.diag`: 58-byte Ed448 seeds (RFC = 57), a 63-byte experimental pubkey (should be 64), and all 12 Phase-2 `expected_*` fields still `"TBD-COHORT-ROUND-TRIP"` text placeholders. Keystone caught it during FFI agility bring-up by **decoding the artifact** (not trusting the cohort's sha-lock); escalated as `SPEC-FINDINGS-LOG.md` **F16**. Architecture regenerated the `.cbor` from the (always-correct) `.diag`; **no crypto pin changed** — only input-side widths and Phase-2 field types. The `.diag` pins here were since re-stamped to strip provenance dates (vector data unchanged).

**Agility vector inventory (8 vectors):**

*Phase 1 — allocation + machinery (5):*
| Vector | Validates |
|---|---|
| `KEY-TYPE-ED448-1` | `system/peer(key_type="ed448")` → canonical `(0x02,0x01)` peer_id; content_hash byte-equal; sign/verify on fixed seed `0x42×57`. |
| `HASH-FORMAT-SHA-384-1` | v7.66 `AGILITY-ENTITY-1` entity re-hashed under `content_hash_format=0x01`; wire content_hash `01` + SHA-384 digest. |
| `VARINT-MULTIBYTE-1` | Multi-byte LEB128 format-code (`0x80 01` = 128) decode path → rejects `unsupported_content_hash_format`. |
| `VARINT-RESERVED-FF-1` | Rejects `key_type`/format-code value 255. |
| `FORMAT-CODE-INTERPRETATION-1` | Unsupported format code → `unsupported_content_hash_format` (renamed from v7.66 `PREFIX-DISPATCH-1`). |

*Phase 2 — cross-key/cross-hash matrix, classical (3):* each exercises all 7 gates (pubkeys, peer_ids, home content_hashes, cap CBOR, active cap content_hash, signature, `.cbor` sha256).
| Vector | Peer A | Peer B |
|---|---|---|
| `MATRIX-M2` | Ed448/SHA-256 (`0x42×57`) | Ed25519/SHA-256 (`0x43×32`) |
| `MATRIX-M3` | Ed25519/SHA-384 (`0x44×32`) | Ed25519/SHA-256 (`0x45×32`) |
| `MATRIX-M6` | Ed448/SHA-384 (`0x46×57`) | Ed25519/SHA-256 (`0x47×32`) |

*Phase 3a (BLAKE3) + 3b (ML-DSA-65) — DEFERRED per v7.67 §13.7; allocations stand, not yet byte-pinned.*

## AUTHZ-* matrix — NOT byte-fixtures; assertion vectors

The 7 `AUTHZ-*` vectors are defined in arch `guides/GUIDE-CONFORMANCE.md` §9 `(k)–(q)` — they assert **(status, code)** pairs on authorization-denial paths, validated by `validate-peer`, not byte-pinned codec vectors. Not vendored as fixtures here (no canonical bytes to pin); they are a **validate-peer obligation** for the C# peer:

| Vector | Status | Code |
|---|---|---|
| `AUTHZ-DELEGATE-GRANT-1` | 403 | `capability_denied` |
| `AUTHZ-DENY-DEFAULT-1` | 403 | `capability_denied` |
| `AUTHZ-SCOPE-EXCEEDS-1` | 403 | `scope_exceeds_authority` |
| `AUTHZ-GRANTEE-1` | 401 | `unresolvable_grantee` (the single §5.2 401 carve-out) |
| `AUTHZ-REVOKED-1` | 401 | `capability_revoked` |
| `AUTHZ-NO-CATCHALL-1` | 403 | `capability_denied` (regression pin — MUST NOT emit `verification_failed`) |
| `AUTHZ-EXPIRED-1` | 403 | `capability_denied` (expiry surfaces as default, not a separate code) |

These are the operative answer to S4 F4/A1. The C# peer's authz DENY paths must conform to this matrix at S4 re-run.

## The latent-bug lesson (carry into FFI + C# work)

Phase 2 caught a Go bug: `[]string(nil)` → CBOR `null` via fxamacker default, where spec-canonical is `{include: []}` → `0x80`. It stayed latent because handshake caps are self-signed and verified against received bytes — nothing re-encodes a cap cross-impl until the byte-pin round-trip forces independent re-derivation. **Class:** idiomatic-language serializer defaults silently overriding spec-canonical encoding. **Every impl (FFI Rust/C, C#) must be checked for the same class** — empty list vs null, omitted vs present-empty, map-key ordering defaults. The byte gate is the only thing that catches it.

## Discipline

- Vendored from arch canonical. The `.cbor` corpora are byte-identical to arch; the `.diag` human-source copies had provenance dates stripped here and were re-pinned (vector data unchanged — see the F16 note).
- Single retained snapshot. The earlier point-in-time corpus dirs (byte-identical ECF set) were retired at the V8 cutover; this `v0.8.0/` snapshot is the one live corpus.
