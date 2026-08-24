# entity-core-protocol-crystal — Conformance Report

Two gates: the **lower bar** (codec byte-identical to the cross-blessed fixture,
`wire-conformance` — S2) and the **higher bar** (full live peer under
`validate-peer --profile core` — S4). Both GREEN.

---

## S4 — live peer · `validate-peer --profile core` → **PASS**

**Verdict: 292·0F @ `cc1970f` — P292 / W294 / F0 / S96** (`--profile core`).

**Oracle:** `entity-core-go` `validate-peer` @ `cc1970f`
(`cc1970f448e01b0eea8d8032e076f50b571359ed`, core_gate_fingerprint
`8261a033…f745`). **Spec-data:** v0.8.0 (V8). **Peer:** `bin/entity-core-peer
--port 7777 --name conformance --debug-open-grants --validate`, run in
`entity-core-keystone/crystal-toolchain:latest`, sealed offline
(`--network=none`) — oracle + peer share one loopback.

```
Summary: 682 total, 292 passed, 294 warned, 0 failed, 96 skipped (elapsed ~21.5s)
         96 skip(s) auto-allowlisted by V7 v7.72 §9.0 profile carve-out — exempt from the FAIL gate
Result: PASS (with warnings)
```

Every core-profile category is 0-FAIL — full table + the single S4 bug fixed
(`core_tree_path_flex_1` NUL-byte reject) + the accept-path units in
`status/PHASE-S4.md`. Highlights: multisig 11/0 incl. the LIVE
`valid_2of3_peer_signed_accepted` accept probe (not vacuous); concurrency 5/5;
resource_bounds 413 + 400-chain-depth PASS; type_system 108-pass over the 53-type
floor (render-from-shapes, byte-identical to the Go drift target).

Spec suite (S3/S4 accept-path + S2): **97 examples, 0 failures**.

Reproduce:
```
. tools/podman-caps.sh
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
  entity-core-keystone/crystal-toolchain:latest \
  sh /work/protocol-generator/crystal/run-s4.sh -profile core -json-out /tmp/report.json
```

---

## S2 — codec · `wire-conformance` → **PASS**

**Verdict: 71·0F @ `be54baf` — P71 / W0 / F0 / S0** (`--profile core`, wire-conformance corpus).

| Field | Value |
|---|---|
| Peer | `entity-core-protocol-crystal` |
| Phase | S2 (CODEC layer) |
| Spec | v0.8.0 (V8) |
| Corpus | `shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor` |
| Corpus SHA-256 | `9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc` (matches MANIFEST pin) |
| Oracle commit | `be54baf` (arch `entity-core-protocol`, F29/F30 corpus) |
| Vectors | 71 (66 `encode_equal` + 5 `decode_reject`) |
| Toolchain | Crystal 1.20.2 / LLVM 20.1.8 / libsodium 1.0.18 |
| Container | `entity-core-keystone/crystal-toolchain:latest`, `--network=none` (sealed offline) |
| Gate | `crystal spec` → **89 examples, 0 failures, 0 errors, 0 pending** |

## Per-category breakdown (71/71)

| Category | Kind | Pass | Fail |
|---|---|---|---|
| `float` | encode_equal | 14 | 0 |
| `int` | encode_equal | 14 | 0 |
| `map_keys` | encode_equal | 6 | 0 |
| `length` | encode_equal | 8 | 0 |
| `primitive` | encode_equal | 6 | 0 |
| `nested` | encode_equal | 6 | 0 |
| `content_hash` | encode_equal | 4 | 0 |
| `peer_id` | encode_equal | 3 | 0 |
| `signature` | encode_equal | 3 | 0 |
| `envelope` | encode_equal | 2 | 0 |
| `tag_reject` | decode_reject | 5 | 0 |
| **Total** | | **71** | **0** |

The corpus is decoded by **this peer's own decoder** (a decoder bug is itself a
conformance failure, §E.3) before any vector runs — the decode of the 71-vector
array is itself exercised.

## Extra units (beyond the corpus)

- **Fixed-width uint64 head-form self-test** (`spec/codec_spec.cr`): `2^63`
  (`1b8000000000000000`), `2^64-1` (`1bffffffffffffffff`), `2^63-1` from a native
  `Int64`, and the `-2^64` min-nint (`3bffffffffffffffff`) all carry the correct
  9-byte head via the `EcInt(major, arg : UInt64)` model. This is the profile's
  `native_fixed_width_int` trap: Crystal ints are machine ints, so a uint in
  `[2^63, 2^64-1]` does NOT fit `Int64` — the Ruby peer's `native_bignum` does not
  hold here. Round-trip through decode preserves the full-range value.
- **Ed25519 sign→verify accept path** (`spec/signature_spec.cr`) via the direct
  in-process libsodium C binding (`lib LibSodium` + `crypto_sign_seed_keypair` /
  `crypto_sign_detached` / `crypto_sign_verify_detached`): pubkey derivation (32 B),
  `sign`→`verify` returns **true**, the `signature.1` byte-pin matches, and both a
  tampered-sig and wrong-message case return **false**. The corpus `signature`
  category is an encode-side byte-pin only; this adds the accept/reject direction
  the oracle cannot cover (the "conformance-green can be vacuous" lesson).
- **Decode-reject units** (`spec/codec_spec.cr`): bare tag, non-minimal int arg,
  indefinite-length array, duplicate map key, trailing bytes.

## Reproduce

```
./protocol-generator/crystal/run-s2.sh      # sealed-offline; gate = `crystal spec`
```

## Honesty framing (ADR-0012)

This is **corroboration / generator-robustness** work — the spec-discovery well is
dry on the current wire surface. A green verdict here is **cohort-consistent, not
independent convergence**: this peer passes one author's 3-way (Go × Rust × Python)
cross-blessed corpus. It corroborates that the generator lands the canonical ECF
codec on a COMPILED, statically-typed, fixed-width-integer, libsodium-backed
substrate whose idiom seams deliberately differ from the Ruby peer; it does NOT add
an independent producer of the canonical bytes. Every published number above is
oracle-pinned (`71·0F @ be54baf`) and reproducible.

## Robustness (S4 stress — post graceful-shutdown fix)

The `--profile core` gate was re-verified **20/20 crash-free** under repeated concurrent
load after the graceful-shutdown fix (A-CRY-011). An earlier intermittent
`Thread#execution_context cannot be nil` (~1/15 runs — Crystal 1.20's preview
Execution-Contexts scheduler interrupted by the harness's unhandled `SIGTERM`) is
eliminated by trapping `SIGTERM`/`SIGINT` → `server.close` → clean exit, plus a graceful
`run-s4.sh` reap. `292·0F @ cc1970f`, 0 crashes / 20 consecutive full runs (independently
re-verified).
