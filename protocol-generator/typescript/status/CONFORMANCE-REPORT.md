> **v7.75 re-run (oracle `entity-core-go @ 62044c5`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 291 pass · 196 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-typescript — Conformance Report

Two gates (S7): the **lower bar** (codec byte-identical vs the C-ABI reference,
`wire-conformance`) and the **higher bar** (full peer under `validate-peer
--profile core`). Both green.

---

## S4 — live peer · `validate-peer --profile core` → **PASS**

**Oracle:** `entity-core-go` HEAD `cb54f5b` (the v7.72 §9.0 core-profile head, post
F21/F22 oracle fixes). **Spec-data:** v7.72. **Peer:** `node dist/test/host.js
--port 7777 --debug-open-grants`, run in the `node24` container, sealed offline
(`--network=none`); the Go oracle is a fedora:43 ELF binary that runs in the same
container, so oracle and peer share one loopback.

```
Summary: 552 total, 269 passed, 194 warned, 0 failed, 89 skipped (elapsed 1.241s)
         89 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out
Result: PASS (with warnings)
```

**Zero failures, zero code fixes.** This is the *identical* scoreboard the C#
reference peer (peer #1) reached — 552 / 269P / 194W / 0F / 89skip — landed here on
the **first** validate-peer run. The peer was a faithful port of peer #1 (already at
the core verdict) and the A-006 type registry was byte-identical going in, so a
first-run PASS is the expected convergence outcome (S8), independently corroborated
three ways: JSON `failed: 0`, the matching numbers, and origination's outbound leg
passing against a live Go reference peer.

| Category | P / total | Notes |
|---|---|---|
| connectivity | 22/22 | incl. F12 nonce-echo PoP (ported from peer #1) |
| encoding | 6/6 | codec holds on the wire |
| type_system | 108 / 302 | 194 warn = non-§9.5-floor types (matched-if-present, non-blocking); **0 core fail** |
| handlers | 25/57 | 32 skip = extension handler ops (§9.0 carve-out) |
| capability | 12/12 | request / configure / revoke / is_revoked |
| tree_operations | 25/56 | 31 skip = EXTENSION-TREE §9 ops |
| security | 22/23 | 1 skip = extension scope |
| multisig | 10/10 | §3.6 / §5.5 multi-granter |
| universal_address_space | 8/8 | §1.4 foreign-namespace addressing |
| peer_canonicalization | 7/7 | §3.6 v7.65 patterns |
| format_agility | 10/10 | §4.7 unsupported_key_type at hello |
| crypto_agility | 4/4 | §1.5 key-type / §1.2 hash-format seam |
| negotiation | 4/4 | §4.5 hello advertisements |
| authz | 6/8 | 2 skip = ROLE §5.5 extension (delegate/revoked) |

**Warns (194, all type_system):** the matched-if-present non-floor type vocabulary —
non-blocking by §9.5 design. **Skips (89, all auto-allowlisted):** §9.0 extension
carve-outs — extension handler ops (32), EXTENSION-TREE §9 ops (31), ROLE authz (2),
and whole extension categories (1 each: subscriptions, continuations, revision,
auto_version, clock, history, query, local_files, compute, entity_native,
origination, attestation, quorum, identity, role, behavioral_*, durability, type,
content, serving_mode, transport_family, session).

**A-006 precursor (type-registry byte-diff):** `test/type-registry.test.ts` renders
all 53 core types and diffs `content_hash` against the Go-rendered
`type-registry-vectors-v1.cbor` → **53/53 byte-identical, first run.** Full
`node:test` suite **55/55** (54 from S3 + A-006), no regression.

**`origination` (A-009 finding):** auto-allowlisted as *outside* `--profile core`
(v7.72 §9.0 "extension-only"). Exercised under the full profile with the Go
`entity-peer` as `-reference-peer`: `reference_connect` + `reference_ready` **pass**
(outbound dispatch works); the 3 fails are ASYNC §1 + NETWORK §10 extension
over-demand. The lifecycle doc's "required for v0.1 / extension-free" row for
origination is stale vs v7.72 §9.0 → escalated to research/arch.

**Reproduce:** `podman run --rm --network=none -v "$PWD":/work:Z -v kc-npm:/npm-cache
entity-core-keystone/node24:latest sh /work/protocol-generator/typescript/run-s4.sh`
Raw JSON: `status/CONFORMANCE-REPORT.json`.

---

## S2 — codec layer · `wire-conformance` → **PASS** (69/69)
**Phase:** S2 (codec layer)
**Strategy:** native — hand-rolled canonical CBOR (zero runtime deps) + `@noble/curves` 2.2.0 (Ed25519) + `@noble/hashes` 2.2.0 (SHA-256)
**Corpus:** `protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`
(SHA `41d68d2d…`, the vendored arch-canonical fixture, ECF v1.5 / V7 7.72 — codec corpus byte-identical 7.71→7.72)
**Result:** ✅ **69/69 PASS — byte-identical** (S7 lower bar met)

```
category        pass total
--------------------------
float            14   14  ok
int              14   14  ok
map_keys          6    6  ok
length            8    8  ok
primitive         6    6  ok
nested            4    4  ok
tag_reject        5    5  ok
content_hash      4    4  ok
peer_id           3    3  ok
signature         3    3  ok
envelope          2    2  ok
--------------------------
TOTAL            69   69
# RESULT: PASS (69/69)
```

(64 `encode_equal` + 5 `decode_reject` = 69 wire vectors, matching the
rust-ffi / c-ffi / C# 69/69 baseline exactly. The "71" in the corpus MANIFEST
adds 2 non-vector metadata-agreement checks.)

## How to reproduce

```sh
# Phase 1 — populate the npm cache ONCE (network on, per lockfile change):
podman run --rm -v "$PWD":/work:Z -v kc-npm:/npm-cache \
  entity-core-keystone/node24:latest \
  sh -c 'cd /work/protocol-generator/typescript && npm ci'

# Phase 2 — build + conformance SEALED OFFLINE (--network=none):
podman run --rm --network=none -v "$PWD":/work:Z -v kc-npm:/npm-cache \
  entity-core-keystone/node24:latest sh -c '
    cd /work/protocol-generator/typescript &&
    npm ci --offline && npx tsc -p tsconfig.json &&
    node dist/test/run-conformance.js'        # prints the table, exit code = gate

# full node:test suite (corpus gate + F7 boundaries + units + cborg cross-check):
    ... node --test "dist/test/**/*.test.js"   # 54 tests, all green
```

## What each category proves (and the load-bearing risks it closed)

- **float (14/14)** — the hand-rolled shortest-float pass (eval R1). f16/f32/f64
  boundary selection by exact round-trip + Rule 4a specials (NaN `f97e00`, ±Inf,
  ±0). Pure-JS half-precision (no `Float16Array` dep). The single biggest
  native-codec risk; matches the W2-battery large-f16 cases (32768.0 `f97800`,
  65504.0 `f97bff`, 65503.0 → f32). Decode-side enforces minimality (R3): a float
  whose value re-encodes shorter is rejected `non_canonical`.
- **int (14/14)** — minimal-length argument at every boundary incl. max i64.
  **`bigint` end-to-end** (R1) — the full u64 range, no `number`/2⁵³ truncation.
- **map_keys (6/6)** — length-then-lexicographic ordering (RFC 8949 §4.2.1)
  byte-for-byte, incl. the length-boundary (23 vs 24) and mixed byte/text keys.
- **length (8/8)** — definite-length only, all container kinds, boundaries.
- **primitive (6/6)** — `f4`/`f5`/`f6` single-byte forms; null/bool in maps.
- **nested (4/4)** — deep nesting + the entity `{type,data}` + hash-keyed
  `included` shapes.
- **tag_reject (5/5)** — N2: recursive tag rejection at any depth (eval R4), incl.
  tag-0/1/37/55799 and the deep tag nested inside an `included` entity.
- **content_hash (4/4)** — `LEB128(format_code) ‖ SHA256(ECF({data,type}))`; the
  N3 empty-data boundary (`content_hash.1` → `005f3139…`); N1 multi-byte varint
  prefix (`format_code=128` → `8001`); N4 verbatim `data` splice (no
  decode→re-encode on the hash path — the `preEncoded` value node).
- **peer_id (3/3)** — `Base58(LEB128(key_type) ‖ LEB128(hash_type) ‖ digest)`;
  N1 multi-byte varint (`key_type=128`). Hand-rolled Base58.
- **signature (3/3)** — deterministic Ed25519 (RFC 8032) over canonical-ECF
  entities; `@noble/curves` produces signatures **byte-identical** to the
  Go/Rust/Py/C#-blessed seeds. Cross-confirms the canonical encoder feeding sign.
- **envelope (2/2)** — `{root, included}` carrier; map-key sort under the envelope
  shape; hash-keyed included map.

## Supplementary suites (beyond the corpus gate)

- **F7 boundary vectors (authored here — the oracle can't see them).** Encode +
  strict round-trip at `2⁵³−1, 2⁵³, 2⁶³−1, 2⁶³, 2⁶⁴−1` and the negative analogs.
  `2⁶³` (`1b8000000000000000`) is the critical case: one past i64::MAX, where a
  signed-64 codec sign-flips. TS is the peer most exposed to this gap (R1). See
  `test/f7-vectors.test.ts`; escalated as F7 (add the corpus probes).
- **cborg cross-check (the A-005 spike).** An independent encoder (the
  profile-named library) corroborates the hand-rolled output on map-sort,
  minimal-int, the full `bigint`/u64 range (incl. 2⁶³), strings, bytes, and
  non-integral floats — a 5th ECF producer agreeing with the cross-blessed
  corpus. It diverges only where JS `number` structurally erases int-vs-float
  (`cborg.encode(1.0)` → integer `01`), which is exactly why the value model
  carries an explicit float node and the core is hand-rolled. See A-005.
- **Codec units** — LEB128 (N1, incl. `128`→`8001` + u64 overflow reject), Base58
  round-trips, float specials, tag/indefinite/undefined/non-minimal/duplicate-key
  rejections.

## Cross-impl convergence (S8)

This is the **fourth** independent codec to hit 69/69 on this fixture — joining
`entity-core-codec-ffi-rust`, `entity-core-codec-ffi-c`, and the C# peer. Four
hand-independent implementations (hand-rolled-TS+@noble vs `System.Formats.Cbor`+NSec
vs ciborium+dalek vs hand-rolled-C+libsodium) converging to the byte is exactly
what S8 promises. **And TS is the first peer with no native sibling reference** —
pure spec → peer in an ecosystem with no prior Entity Core impl. The spec carried
everything (S8 validated). The native path needs no FFI fallback for any primitive.

## Gate status

- **S7 lower bar (codec byte-identical to fixture):** ✅ met (69/69).
- **S7 higher bar (`validate-peer` live categories):** not in scope for S2 —
  belongs to S3 (peer) + S4 (conformance).
