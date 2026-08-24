# test-vectors v0.8.0 — Vendor Manifest

**Spec version:** Entity Core Protocol **0.8.0** (V8). ECF corpus per `ENTITY-CBOR-ENCODING.md` v1.5 — wire-format byte-stable; agility corpus per §1.2/§1.5 seed tables.
**Vendor type:** byte-identical copies of architecture-repo canonical fixtures. Keystone does **not** author canonical bytes (S5). CI hash-checks against the tables below.
**Single retained snapshot:** the earlier point-in-time corpus dirs (byte-identical ECF set) were retired at the V8 cutover; this `v0.8.0/` is the one live corpus. *Agility Phase-1* closed since first vendor; *Phase-2* was vacuously "locked" over TBD placeholders until **F16** (see the agility-corpus block below) forced the regen — Phase-2 is now byte-real and closes on the §3.2 decode-and-validate run.

## Two corpora in this directory

### 1. ECF codec corpus

The lower-bar codec conformance set. **F29/F30 re-vendor (2026-07-12):** the prior corpus was **69 vectors** (64 `encode_equal` + 5 `decode_reject`); this snapshot is the finalized **71** — F29 added `nested.5`/`nested.6` (array-of-maps text-head boundary), F30 regenerated `tag_reject.1/.2/.3/.5` to be truly canonical-except-the-tag (the old bytes had `type` before `data`, so they rejected on trailing-data instead of the §6.3 tag scanner — a vacuous pass). See the re-vendor note below.

| File | Role | SHA-256 |
|---|---|---|
| `conformance-vectors-v1.cbor` | Normative ECF corpus (66 `encode_equal` + 5 `decode_reject` = **71 vectors**). | `9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc` |
| `conformance-vectors-v1.diag` | Human source-of-truth (CBOR diagnostic notation). | `71015b729b205f39e29750e632a136844fe7da3f9e37800e870d14bf87086544` |

Source: arch `entity-core-protocol` `specs/test-vectors/ecf-conformance/`, commit **`be54baf`** (`fix(corpus): close F30 tag_reject + F29 array-of-maps head-boundary gaps`). Three-way byte-equality (Go × Rust × Python) → 71/71 PASS.

> **F29/F30 re-vendor (2026-07-12).** Supersedes the prior `41d68d2d…` (`.cbor`) / `987672147c90…` (`.diag`) 69-vector corpus. That corpus's table row here had been pre-stamped "71" while its own `.diag` carried only 69 vectors — the discrepancy this re-vendor reconciles. The new `.cbor` is **byte-identical to arch**; the `.diag` is copied **byte-identical** as well (unlike the agility `.diag`, this file carries no provenance-date lines to strip — its only dates are the `2026-06-06T12:00:00Z` datetime literals *inside* `tag_reject` vector data, which are canonical vector content). Verified per the F16 lesson by **decoding the `.cbor` artifact** and cross-checking all 71 ids + canonical byte values against the `.diag` (zero mismatches, no placeholder text), plus the F29 byte pins: `nested.5` = `82a1616b7818`+24×`61`+`a1616b781e`+30×`62`, `nested.6` = `81a1616b790100`+256×`63`.

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
