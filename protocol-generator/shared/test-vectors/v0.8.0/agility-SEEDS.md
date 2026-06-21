# Crypto-Agility Conformance Corpus — Seed Pins

**Version**: 1.0
**Status**: Active
**Source**: §1.2 (`content_hash_format` seed table) + §1.5 (`key_type` seed table) + §1.3 (ECF canonical encoding) + §4.5/§4.5a (negotiated format semantics) + §1.2/§1.2a (home format vs active format).

Phase 1 values are byte-equal cross-impl; Phase 2 uses the pinned-seed scheme in §2.

This document is the SINGLE SOURCE OF TRUTH for the crypto-agility corpus seeds. The sibling `agility-vectors-v1.diag` carries the same values inline per the ECF-corpus convention; if anything diverges, `agility-SEEDS.md` wins and `.diag` is corrected.

---

## §1 Phase 1 — byte-pinned (cross-impl validated)

### §1.1 Ed448 fixture — `KEY-TYPE-ED448-1`

| Pin | Value |
|---|---|
| Secret seed | 57 bytes, every byte `0x42`. Hex: `42` × 57. |
| Library call | `cloudflare/circl/sign/ed448::NewKeyFromSeed(seed)` (Go reference); equivalent direct-seed APIs in Rust + Python. **No pre-expansion**: the 57 bytes are passed verbatim to the library; the RFC 8032 SHAKE256 expansion happens inside. |
| Fixture sign-message | ASCII, 45 bytes, no trailing newline: `v7.67 Phase 1 cohort cross-impl Ed448 fixture`. Hex: `76372e3637205068617365203120636f686f72742063726f73732d696d706c2045643434382066697874757265`. |
| `public_key` (57 B) | `2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00` |
| Canonical `(key_type, hash_type)` | `(0x02, 0x01)` SHA-256-form per §1.5 size-cutoff rule (Ed448 pubkey > 32 bytes → not identity-multihash). |
| `peer_id` (Base58) | `3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4` |
| `signature` over the fixture message (114 B) | `0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b19ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4d2a0c8304d67e6f20e814b90411049b33400` |

**Derived `system/peer` entity (ECF-canonical CBOR)**:

| Field | Value |
|---|---|
| `entity.Type` | `system/peer` |
| `entity.Data` raw CBOR (data map, ECF-deterministic field order `key_type` then `public_key`) | `a2686b65795f747970656565643434386a7075626c69635f6b657958392601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00` |
| `content_hash` (33 B wire = `0x00` SHA-256 format byte + 32 B digest) | `002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748` |

### §1.2 SHA-384 fixture — `HASH-FORMAT-SHA-384-1`

This vector **inherits the v7.66 `AGILITY-ENTITY-1` corpus fixture**; it is *not* a fresh seed. The fixture entity is re-hashed under `content_hash_format = 0x01` (SHA-384) to validate that the same canonical entity bytes produce the spec-required digest under a second hash family.

| Pin | Value |
|---|---|
| Fixture entity | `system/peer({ public_key: 0xAA × 64, key_type: "experimental-test" })` (the v7.66-allocated `0xFE` test-only stub; substrate floor forces SHA-256-form / `hash_type=0x01` regardless of content_hash_format). |
| Public-key seed | 64 bytes, every byte `0xAA`. |
| ECF-encoded `{data, type}` input length | 128 bytes |
| SHA-256 content_hash (33 B wire, inherited v7.66 `AGILITY-ENTITY-1` pin) | `003d0c34b508c5bf9eca5f086f09aac10f44bd43fca1a091b6aa55a096ca8fcd45` |
| SHA-384 digest (48 B raw) | `2e64bbde3c494cf7cd4fb53ae3bf6420ec6d9bfa686348729eaa687e421c01c059c1ed5775824bcffc50df0f3eef5a69` |
| SHA-384 content_hash (49 B wire = `0x01` format byte + 48 B digest) | `012e64bbde3c494cf7cd4fb53ae3bf6420ec6d9bfa686348729eaa687e421c01c059c1ed5775824bcffc50df0f3eef5a69` |
| Display | `ecfv1-sha384:2e64bbde…3eef5a69` |

### §1.3 Varint probes — `VARINT-MULTIBYTE-1` / `VARINT-RESERVED-FF-1` / `FORMAT-CODE-INTERPRETATION-1`

These are **probe vectors** — they pin REJECTION behavior, not byte outputs. No keypair or message seeds required.

| Vector | Probe input | Expected behavior |
|---|---|---|
| `VARINT-MULTIBYTE-1` | `system/hash` with format-code bytes `80 01` (LEB128 of integer 128; multi-byte decode path) | Impl decodes the varint; resolves to integer 128; integer 128 is not in §1.2 seed table → surface `unsupported_content_hash_format` error. **Pins that the multi-byte LEB128 decoder exists and the unsupported-code error fires from it (not from a single-byte short-circuit).** |
| `VARINT-RESERVED-FF-1` | (a) `system/peer` mint with `key_type` integer 255 (varint `FF 01`). (b) `system/hash` with format-code integer 255. | Both refused. 255 is reserved per §1.5 / §1.2. |
| `FORMAT-CODE-INTERPRETATION-1` | `system/hash` with an unallocated format-code byte (e.g. `0x42`). Renamed from v7.66 `PREFIX-DISPATCH-1`; semantics unchanged. | Surface `unsupported_content_hash_format`. Pins that an unknown code is an INTERPRETATION error (not a routing dispatch issue) — §1.2 reframe per v7.68. |

---

## §2 Phase 2 — matrix vector seed convention

Matrix vectors `MATRIX-M2`, `MATRIX-M3`, `MATRIX-M6` exercise the cross-key / cross-hash agility surface end-to-end: handshake → tree-get → cap grant A→B → cap use B→A. The earlier Phase-2 cross-impl pass used **ephemeral keypairs** (process-start `crypto/rand`); seeds were never pinned. To make Phase 2 a byte-pinned corpus item rather than only a wire-flow assertion, the corpus uses the seed scheme below, with three clarifications that nail down cross-format semantics the bare scheme leaves implicit.

### §2.1 Per-peer keypair seeds (ratified from Go §3.1 Table)

| Matrix vector | Peer A keypair seed | Peer B keypair seed |
|---|---|---|
| `MATRIX-M2` | Ed448 from seed `0x42` × 57 (same as Phase-1 `KEY-TYPE-ED448-1` — intentionally reuses the Phase-1 Ed448 identity) | Ed25519 from seed `0x43` × 32 |
| `MATRIX-M3` | Ed25519 from seed `0x44` × 32 — peer home `content_hash_format = 0x01` | Ed25519 from seed `0x45` × 32 — peer home `content_hash_format = 0x00` |
| `MATRIX-M6` | Ed448 from seed `0x46` × 57 — peer home `content_hash_format = 0x01` | Ed25519 from seed `0x47` × 32 — peer home `content_hash_format = 0x00` |

Each seed is the RFC 8032 secret-seed input: 32 bytes for Ed25519, 57 bytes for Ed448, every byte the indicated value.

### §2.2 Active format — arch clarification #1 (negotiation outcome pinned)

Per §4.5/§4.5a (v7.69), the connection's *active* `content_hash_format` is determined by single-active-value first-match from the initiator's preference list. **The matrix vectors fix the initiator and the active format as follows**, so all three impls converge:

| Matrix vector | Initiator | A `hash_formats` (preference order) | B `hash_formats` | Active format |
|---|---|---|---|---|
| `MATRIX-M2` | A | `[0x00]` | `[0x00]` | `0x00` (SHA-256) |
| `MATRIX-M3` | A | `[0x01, 0x00]` (initiator prefers home, falls back to standard) | `[0x00]` | `0x00` (SHA-256) — first-match is B's only supported format |
| `MATRIX-M6` | A | `[0x01, 0x00]` | `[0x00]` | `0x00` (SHA-256) |

**Net**: in all three matrix vectors the connection's active format is SHA-256, and cap-token entities carry SHA-256 content_hashes. Mixed-home (M3/M6) is the experimental annex per v7.70 §1.2a; the corpus pins the standard-compliance fallback path (active = SHA-256) because that is what a conformant peer MUST handle, not the experimental cross-format-on-wire reading.

### §2.3 Cap-token payload (ratified from Go §3.1)

Each matrix vector exercises a single root cap grant A→B with the payload below. Fixed-zero timestamps make the cap-token entity's content_hash deterministic from the seed inputs alone.

```
CapabilityTokenData {
  grantee:    content_hash(B's system/peer)           // see §2.4 below
  granter:    SingleSig {
                hash: content_hash(A's system/peer)   // see §2.4 below
              }
  grants:     [
                GrantEntry {
                  resources: CapabilityScope {
                    include: ["system/validate/matrix/*"]
                  }
                }
              ]
  parent:     null     // root cap
  created_at: 0        // fixed; deterministic content_hash
  expires_at: 0        // 0 = no expiry (the matrix vectors don't exercise expiry)
}
```

**Notes**:
- `grantee` is the wire content_hash of B's `system/peer` entity. Per v7.69 §1.8, references to identities use the identity's home-format content_hash (NOT re-derived under the active format).
- `granter.hash` is the wire content_hash of A's `system/peer` entity, under A's home format.
- The cap-token entity ITSELF has a content_hash under the active format (SHA-256 in all three matrix vectors per §2.2).
- `expires_at: 0` is the matrix-vector convention for "no expiry"; impls that gate on `expires_at <= now()` MUST treat 0 as "infinite past" only for the impl-defined sentinel, not for these corpus vectors. The `AUTHZ-EXPIRED-1` vector in GUIDE-CONFORMANCE §9 (v7.71) covers the expiry behavior separately.

### §2.4 Identity references — arch clarification #2 (home-format pin)

For M3 and M6, Peer A's home format is SHA-384 and Peer B's is SHA-256. The cap-token references each peer by THAT peer's home-format content_hash:

- `grantee` (refers to B): SHA-256 content_hash of B's `system/peer` entity.
- `granter.hash` (refers to A): SHA-384 content_hash of A's `system/peer` entity (for M3/M6); SHA-256 for M2.

The cap-token entity itself is authored under the active format (SHA-256 — see §2.2), so the wire cap-token content_hash is SHA-256-form even when it references a SHA-384 identity. **This is the v7.69/v7.70 invariant**: content travels in active format, references to identities use the identity's home format.

### §2.5 Signature target — arch clarification #3 (RFC 8032 deterministic)

Per §5.2 cap-chain verification, A signs the root-cap content_hash. Concretely:

```
signature = ed_sign(
  secret_key = A's_keypair,      // from §2.1 seed
  message    = content_hash(root_cap)   // the cap-token entity's wire content_hash, see §2.3
)
```

`message` is the full wire content_hash (algorithm byte + digest), 33 bytes for SHA-256-form. Both Ed25519 and Ed448 sign deterministically per RFC 8032, so the signature bytes are byte-equal across any conformant library given the same seed + message.

### §2.6 Expected byte pin shape

For each matrix vector, the corpus pins the tuple:

```
{
  "id": "matrix.M2",  // or M3 / M6
  "peer_a_pubkey":   hex,
  "peer_a_peer_id":  Base58,
  "peer_a_content_hash":  hex (home-format),
  "peer_b_pubkey":   hex,
  "peer_b_peer_id":  Base58,
  "peer_b_content_hash":  hex (home-format),
  "root_cap_cbor":          hex (cap-token entity {type, data} CBOR, active format),
  "root_cap_content_hash":  hex (active format = SHA-256),
  "root_cap_signature":     hex (A's signature over root_cap_content_hash)
}
```

Implementations run M2/M3/M6 with the §2.1 seeds substituted for ephemeral keys and confirm these tuples are byte-equal to the §2.1+§2.3+§2.5 derivation; the pins are folded into `agility-vectors-v1.diag` Phase-2 vector entries.

---

## §3 Deferred (not pinned)

| Phase | Vector(s) | Status |
|---|---|---|
| **3a** | `HASH-FORMAT-BLAKE3-1`, `MATRIX-M5` | Deferred (Phase 3). No seeds. |
| **3b** | `KEY-TYPE-ML-DSA-65-1`, `MATRIX-M4`, `MATRIX-M7`, `MATRIX-M8` | Deferred (Phase 3). No seeds. |

When PQ pickup happens (post-release, on external signal), seeds get pinned then. The §2 scheme is the model — pick a seed-byte offset, document the per-peer home format, fix the active format outcome, list the cap-token payload with zeroed timestamps, and run the cross-impl round-trip.

---

## §4 Corpus encoding (`.cbor` build artifact)

The sibling `agility-vectors-v1.cbor` is the deterministic ECF-canonical encoding of `agility-vectors-v1.diag` per ENTITY-CBOR-ENCODING.md v1.5 Appendix E (same procedure as `ecf-conformance/`). Build step:

```
# Produced from the .diag by a conformant ECF encoder. Bytes MUST match the
# inline canonical: h'...' values in the .diag.
```

Architecture does NOT bless a specific encoder binary; the `.diag` is the spec-derived ground truth and the `.cbor` is its deterministic build output. Any conformant ECF encoder (Go `ecf.Encode`, Rust `ecf::encode`, Python `entity_core_codec.encode_ecf`) MUST produce byte-identical output. The Phase-1 entity bytes inlined in §§1.1–1.2 above are the lock against which the encoder is regression-checked.

---

*The §2.2/§2.4/§2.5 clarifications nail down cross-format semantics (initiator + `hash_formats` list → active format; home-format identity reference vs active-format content; RFC 8032 deterministic signature target). The `AUTHZ-*` matrix lives in `GUIDE-CONFORMANCE.md` §9, not this file — codes are domain-scoped per §3.3 + GUIDE-EXTENSION-DEVELOPMENT.*
