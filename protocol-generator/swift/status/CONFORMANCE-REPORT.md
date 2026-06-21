> **v7.75 re-run (oracle `entity-core-go @ 62044c5`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 290 pass · 197 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-swift — Conformance Report

Two gates (S7): the **lower bar** (codec byte-identical to the cross-blessed ECF
fixture, `wire-conformance`) and the **higher bar** (full peer under
`validate-peer --profile core`). **Both green** — the higher bar (S4) below, the
lower bar (S2) further down.

---

## S4 — peer · `validate-peer --profile core` → **PASS, 0 fail**

**Result: 573 total · 288 pass · 196 warn · 0 fail · 89 skip.** Machine-verified
`summary.failed == 0` (`status/CONFORMANCE-REPORT.json`). Same fixed point the
C#/TS/OCaml/Zig/Elixir/Common-Lisp cohort converged to — reached **spec-first** (peer
behavior derived from spec-data/v7.74; the cohort consulted only for the cross-blessed
structural 53-type floor enumeration + the §7a/§7b contract shape, never protocol semantics).

**Oracle:** Go `validate-peer` from `entity-core-go` HEAD `749e57e` (the post-§7b-matrix-fix
build), vendored at `output/s4-oracles/validate-peer`; Go reference peer at
`output/s4-oracles/entity-peer` (same build, §10.2). Gate symbols verified present before use.
**Harness:** `run-s4.sh` runs peer + Go ELF oracle together inside `swift-toolchain:latest`,
sealed offline (`--network=none`), one shared loopback; host `--debug-open-grants --validate`;
`--profile core` is the gate.

### Scoreboard (per category)

| Category | Pass | Warn | Fail | Skip | Total |
|---|---|---|---|---|---|
| connectivity | 22 | 0 | 0 | 0 | 22 |
| encoding | 6 | 0 | 0 | 0 | 6 |
| **type_system** | **108** | 194 | **0** | 0 | 302 |
| handlers | 35 | 0 | 0 | 32 | 67 |
| capability | 12 | 0 | 0 | 0 | 12 |
| tree_operations | 24 | 1 | 0 | 31 | 56 |
| security | 28 | 0 | 0 | 1 | 29 |
| multisig | 10 | 0 | 0 | 0 | 10 |
| concurrency (§7b) | 5 | 0 | 0 | 0 | 5 |
| universal_address_space | 8 | 0 | 0 | 0 | 8 |
| peer_canonicalization | 7 | 0 | 0 | 0 | 7 |
| format_agility | 10 | 0 | 0 | 0 | 10 |
| crypto_agility | 4 | 0 | 0 | 0 | 4 |
| negotiation | 4 | 0 | 0 | 0 | 4 |
| authz | 5 | 1 | 0 | 2 | 8 |
| *(19 extension-only categories)* | 0 | 0 | 0 | 1 each | — |

**Summary: 573 total, 288 passed, 196 warned, 0 failed, 89 skipped → PASS.** The 196 warns are
the non-§9.5-floor type vocabulary (matched-if-present — `compute/*`, `content/*`, `subscription/*`,
… that a *core* peer does not publish) + the AUTHZ-SCOPE-EXCEEDS code-preference warn. The 89 skips
are the §9.0 extension-category auto-allowlist carve-outs (exempt from the FAIL gate).

### §10.1 core-register gate — **10/10 PASS** (in `handlers`)

`core_register_body_binding`, `core_register_op_status`, `core_register_op_result`,
`core_register_manifest_at_path`, `core_register_handler_at_path`, `core_register_grant_at_path`,
**`core_register_grant_signature_at_invariant_path`** (§3.4 grant-sig at `system/signature/{grant_hash}`,
enforced both ways — presence + `sig.target == grant.content_hash`), **`validate_echo_dispatch`**
(the §7a A-011 closure), `core_register_unregister_status`, `core_register_unregister_signature_removed`
(unregister symmetry — the five writes reversed).

### §10.2 origination-core — **3/3 PASS** (`run-origination-core.sh`)

`reference_connect`, `reference_ready`, **`dispatch_outbound_reentry`** — the last over **real
two-peer TCP**: the validator mints a reentry cap, EXECUTEs `system/validate/dispatch-outbound` on the
Swift target, and the target ORIGINATES one outbound EXECUTE back to the **validator-as-B over the same
inbound connection** (§6.11 reentry, NOT a fresh dial). Wire-proves the `Transport.swift`
Connection-actor reader-demux + the §6.13b `makeOutbound`/`originate` seam from the actor idiom.

### §7b concurrency gate — **5/5 PASS** (3.0s)

`t1_1_concurrent_demux`, `t1_2_concurrent_reentry`, `t1_3_no_head_of_line`, `t2_1_sustained_load`,
`t2_2_connection_churn` — all green. The **`Store` actor** makes the store-race a compile error, not
a runtime crash. Two real fixes this phase: the t1_2 value-passthrough contract + the t2_2
dedicated-OS-thread-for-blocking-I/O (PHASE-S4.md). `TCP_NODELAY` set on every socket.

### type_system 53-type byte-diff — **53/53 byte-identical** (A-SW-009 RESOLVED)

The full §9.5 core type floor renders **byte-identical** to the Go reference vectors — offline
(`TypeRegistryTests`, `swift test`) AND live (type_system 108/108). Rendered **from the in-code
FSpec/TypeDef declaration through the byte-green S2 codec** (the render-from-model cross-peer ruling),
not by ingesting reference bytes. 53/53 on the first run.

### Honest skips

- **89 auto-allowlisted §9.0 extension-category skips** (subscriptions, continuations, revision,
  history, query, local_files, compute, entity_native, origination, attestation, quorum, identity,
  role, durability, content, serving_mode, transport_family, session, …) — a core peer does not
  implement these; exempt from the FAIL gate by the profile carve-out.
- **2 authz skips** — `authz_delegate_grant_1` (targets `system/role` ext; core 404s before PR-8.2)
  and `authz_revoked_1` (ROLE §5.5 401 cascade carve-out; the core surface answers
  `authz_revoked_core_1`, which **PASSes**). **1 security + 32 handler + 31 tree_operations skips** —
  EXTENSION-TREE §9 ops + extension handler vocab.

**Regression held:** `swift test` 27/27 (S2 corpus 69/69 + 25 selftests + the new A-SW-009 byte-diff);
`swift run smoke` 11/11. **S4 PASS.**

---

## S2 — codec · ECF wire-conformance → **69/69 PASS, byte-identical**

**Corpus:** `protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor`
(SHA-256 `41d68d2d…c0c6a052`, the v1 corpus 3-way-locked by Go/Rust/Py; valid at
v7.74 — ECF is byte-stable across the v7.71→v7.74 line). The harness verifies the
corpus SHA-256 in-test before trusting it (decodes it with our own decoder per
Appendix E §E.3), then runs all 69 vectors.

**Strategy:** `native` — hand-rolled canonical ECF (zero CBOR dependency) +
swift-crypto (Ed25519 / SHA-256). **Container:**
`entity-core-keystone/swift-toolchain:latest` (Swift 6.2-RELEASE), run offline
(`--network=none`) after the one-time dependency resolve.

```
-- conformance by category --
  content_hash   4/4
  envelope       2/2
  float          14/14
  int            14/14
  length         8/8
  map_keys       6/6
  nested         4/4
  peer_id        3/3
  primitive      6/6
  signature      3/3
  tag_reject     5/5
TOTAL: 69 passed, 0 failed (of 69)
```

| Category | P / Total | Coverage |
|---|---|---|
| float | 14 / 14 | Rule 4 shortest-form ladder (f16↔f32↔f64 boundaries) + Rule 4a specials (NaN, ±Inf, ±0). Includes the f16/f32 boundary trio (65503→f32, 65504→f16, 100000→f32) and 1.1→f64. |
| int | 14 / 14 | Major-type-0/1 minimization at every boundary, incl. `2^63-1` (max signed i64) — full UInt64 carrier, no Int64 clamp. |
| map_keys | 6 / 6 | Length-then-lexicographic key sort **over encoded UTF-8 key bytes** (A-SW-002); pure-text, pure-byte, mixed, length-23/24 boundary, identical-prefix. |
| length | 8 / 8 | Definite-length only; empty array/map/text/bytes; array/bytes/text at 23/24 boundaries. |
| primitive | 6 / 6 | bool / null single-byte forms; mixed-primitive maps; empty string + empty bytes. |
| nested | 4 / 4 | 2/3-level map nesting; `{type,data}` entity carrier; hash-keyed `included` map. |
| tag_reject | 5 / 5 | §6.3 / N2 — bare tag 0/1/37; tag 55799 wire frame; **tag nested in `included` entity data** (deep recursive reject). |
| content_hash | 4 / 4 | `varint(format_code) ‖ SHA256(ECF{type,data})`; empty-data boundary (F5-resolved `005f3139…`); multi-field sort; **synthetic format_code 128** (multi-byte varint prefix, N1). |
| peer_id | 3 / 3 | `Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)`; all-zero + ascending digest; **synthetic key_type 128** (multi-byte varint). |
| signature | 3 / 3 | Deterministic Ed25519 (RFC 8032) over the ECF preimage of `{type,data}` (corpus convention — see A-SW-007); 3 fixed seeds. |
| envelope | 2 / 2 | `system/envelope/v1` carrier (root + included); empty-included + one hash-keyed signature entity. |

### Codec-logic fixes: **ZERO**

The codec passed **66/69 on the first run**; the only post-first-run change was a
**test-harness** correction — the `signature` category signs over the ECF preimage
of `{type,data}` (the cross-peer corpus convention, established at corpus-v1 by the
FFI/oracle cohort), not over the 33-byte content_hash that §7.3 NORMATIVE names.
That is a harness-understanding fix, **not a codec bug** (see A-SW-007). Every
encoder/decoder byte-path — float ladder, integer minimization, map-key sort,
tag-reject, content-hash, peer-id, envelope — was byte-identical on first
execution. Matches the 6-for-6 prior-peer pattern (no codec-logic fixes).

The S2-entry **spike** (map_keys + float vectors through a minimal hand-rolled
encoder, run before the full build) passed **20/20** — the float ladder and
length-then-lex map-key sort were proven byte-identical up front, confirming the
`native` strategy (no `ffi` fallback needed).

---

## Selftests (uncovered-range, beyond the 69) → **25/25 PASS**

Conformance-green ≠ bug-free. Coverage for ranges the corpus doesn't hit:

- **Full unsigned 64-bit:** `2^64-1` → `1bffffffffffffffff`; `2^63` (just past
  `Int64.max`); nint min `-2^64` → `3bffffffffffffffff`. Proves UInt64 carrier,
  not Int64 (the integer-width trap).
- **Base58:** decode∘encode round-trip incl. leading-zero preservation (`00 00 05`
  → `11…`); invalid-char rejection.
- **Ed25519:** determinism (same input→same sig), verify, message-tamper +
  signature-tamper reject, bad-seed throw.
- **Recursive tag rejection (N2):** bare tag; tag nested in array; tag in map
  value; tag at depth 3 (array>array>array>tag).
- **Duplicate-key rejection** on both decode and encode; **empty containers** →
  `a0`/`80`/`60`/`40` (N3); indefinite-length reject; non-minimal-int reject;
  trailing-bytes reject.
- **Varint multi-byte (N1):** `128`→`80 01`, `300`→`ac 02`, decode round-trip.
- **PeerID round-trip** incl. multi-byte key_type (1, 128, 300).
- **decode∘encode == identity** over the whole corpus.
- **A-SW-002 String discipline:** `"café"` text head = `0x65` (5 UTF-8 bytes), not
  `0x64` (4 graphemes); map-key sort `"Z"`(1B) before `"aa"`(2B) by length-first.

---

## N1–N4 invariant coverage

| Invariant | Where enforced | Covering test |
|---|---|---|
| **N1** varint LEB128 (not fixed byte) | `Varint.swift`; routed through `ContentHash`/`PeerID` framing | `content_hash.4` + `peer_id.3` (synthetic 128); `testVarintMultiByte` |
| **N2** recursive major-type-6 tag reject | `CBOR.Decoder.decodeItem` major 6 → throw, at any depth | `tag_reject.1–5`; `testTagNestedIn*` / `testDeeplyNestedTagRejected` |
| **N3** empty-params/empty-map = `0xA0` | `CBOR.encodeMap` 0 pairs | `length.2`; `testEmptyContainersCanonical`; `content_hash.1` floor |
| **N4** entity byte-fidelity (forward originals) | `DecodedEntity.originalBytes` retains exact wire bytes | `Entity.swift` decode surface (peer-side forward exercised at S3) |

---

## Reproduce

```bash
podman run --rm -v "$PWD:/work:Z" -w /work/protocol-generator/swift \
  entity-core-keystone/swift-toolchain:latest swift test
```

Offline build (after one-time resolve, `Package.resolved` committed):

```bash
podman run --rm --network=none -v "$PWD:/work:Z" -w /work/protocol-generator/swift \
  entity-core-keystone/swift-toolchain:latest swift build -c release
```
