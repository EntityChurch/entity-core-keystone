> **v7.75 re-run (oracle `entity-core-go @ 62044c5`).**
> `validate-peer --profile core` → **PASS, 0 FAIL** · **576 total · 291 pass · 196 warn · 0 FAIL · 89 skip.**
> New v7.75 categories scored GREEN: **`resource_bounds`** r1 `413 payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN (SHOULD, external-admission carve-out); **`concurrency`** 5/5 PASS.
> The only net-new peer change this cycle: an explicit §4.10(b) max-chain-depth (64) pre-check that surfaces **400 `chain_depth_exceeded`** for an over-deep chain BEFORE the per-link authz walk — distinct from the prior 403 `capability_denied` (arch v7.75 ruling: structural excess ≠ authz denial). The numbers below this line predate the v7.75 re-vendor and are retained for history.

---

# entity-core-protocol-ocaml — Conformance Report (S2 codec)

**Corpus:** `conformance-vectors-v1` (v7.71;
sha256 `41d68d2d…6a052`) · **Result: 69 / 69 PASS, 0 FAIL** · **First run, 0 fixes.**

Run in-container, sealed offline:

```
podman run --rm --network=none -v $PWD:/work:Z -w /work/protocol-generator/ocaml \
  entity-core-keystone/ocaml-toolchain:latest sh -c \
  'eval $(opam env --switch=ec-ocaml) && dune build && \
   dune exec test/conformance.exe -- \
     /work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor'
```

## Scoreboard (byte-identity vs the cross-blessed fixture)

| Category | Pass | Kind |
|---|---|---|
| float        | 14/14 | encode_equal (f16/f32/f64 minimisation + R4a specials) |
| int          | 14/14 | encode_equal (uint/nint minimisation to 2^63-1) |
| map_keys     |  6/6  | encode_equal (length-then-lex on encoded key bytes) |
| length       |  8/8  | encode_equal (definite-length only) |
| primitive    |  6/6  | encode_equal (bool/null/empty) |
| nested       |  4/4  | encode_equal (entity + envelope-included shapes) |
| tag_reject   |  5/5  | decode_reject (recursive major-type-6 rejection, N2) |
| content_hash |  4/4  | encode_equal (varint(fc) ‖ SHA256(ECF); multi-byte fc) |
| peer_id      |  3/3  | encode_equal (Base58(varint‖varint‖digest); multi-byte key_type) |
| signature    |  3/3  | encode_equal (deterministic Ed25519 over canonical ECF) |
| envelope     |  2/2  | encode_equal (root + hash-keyed included map) |
| **TOTAL**    | **69/69** | |

## Codec invariants (N1–N4) — enforced + covered

- **N1 (LEB128 varints):** `src/varint.ml`; format-code/key-type/hash-type routed
  through it. Multi-byte path proven by `content_hash.4` (fc 128) + `peer_id.3`
  (key_type 128) + a selftest round-trip.
- **N2 (tag rejection):** decoder raises `Cbor.Decode_error` on any major-type-6
  item at any depth; `tag_reject.1–5` (incl. nested-in-included + bare 55799) pass.
- **N3 (empty-params 0xA0):** `length.2` (`{}` → `a0`) + `content_hash.1`
  (empty-data entity → `005f3139…396b`) pass.
- **N4 (entity fidelity):** decoder is structural; the harness re-encodes decoded
  inputs and gets byte-identical output (lossless round-trip). Original-byte
  forwarding is wired explicitly at S3 (peer surface).

## Uncovered-range self-tests (codec-review heuristic) — `test/selftest.ml`, all PASS
- uint64 = 2^64-1 and 2^63 (above i64-max — the OCaml int63 hazard, A-OC-001): encode
  + round-trip correct.
- nint64 min (-2^64): `3bffffffffffffffff`.
- peer-id format→parse round-trip (incl. multi-byte key_type); base58
  decode∘encode with leading-zero preservation.
- Ed25519 sign/verify + tamper-reject; bare-tag rejection.

## Notes
- **Native codec, no FFI.** No `dlopen`/C-ABI boundary to exercise (the
  codec-review-heuristic's FFI caveat is N/A for a native peer).
- **Ed448 not covered** — agility higher-bar only; native gap A-OC-002. The 69-vector
  ECF floor (Ed25519) is complete. The agility corpus (`agility-vectors-v1`) is NOT
  yet run; it requires Ed448 + SHA-384 matrix and is gated on A-OC-002's resolution.
- **S7 lower bar: MET.** Codec byte-identical to the corpus → unblocks shared-data-
  library consumers. Higher bar (validate-peer) is S3/S4, next session.

---

## S4 — Live-peer conformance (`validate-peer --profile core`)

**Scope:** v7.73 §PR-8 + Amendment-1 closeout · **Oracle:**
`output/s4-oracles/validate-peer` rebuilt from `entity-core-go` HEAD with the V1/V2 +
Amendment-1 (V1′) vectors compiled in · **Result: 558 total · 274 pass · 195 warn ·
0 FAIL · 89 skip → PASS** (machine-verified `summary.failed == 0`;
`status/CONFORMANCE-REPORT.json`, artifact `output/s4-oracles/ocaml-amend1-postfix.json`).

The higher S7 bar is met. Same fixed-point as C# (#1, 558/275/194/0/89) and TS (#2,
558/275/194/0/89), reached spec-first. Per-category: connectivity 22/22 · encoding 6/6 ·
type_system 108P/194W · handlers 25/25 (32 skip) · capability 12/12 · tree_operations
24P/1W (31 skip) · security 28/28 (1 skip) · multisig 10/10 · universal_address_space
8/8 · peer_canonicalization 7/7 · format_agility 10/10 · crypto_agility 4/4 ·
negotiation 4/4 · authz 6/6 (2 skip). The only non-pass-vs-peers delta is the same
non-critical `tree_operations.cleanup` warn the cohort carries. See `PHASE-S4.md` for
the 190→0 grind.

### v7.73 closeout deltas (both surfaces, dispatch + chain-walk)

The first S4 green (552/268, old vendored oracle) predated the V1/V2 cross-peer vectors.
On oracle rebuild the cohort's convergent §PR-8 gap surfaced and was closed on both
authorization surfaces:

- **§PR-8 dispatch boundary (V2(a)).** A cap's grant resource patterns now canonicalize
  against the **granter's** `peer_id`, resolved once at the dispatch site (`peer.ml`);
  request target + caller-exclude stay local (§5.4). `authz` cross-peer bare-`*` cap
  200→403. Reported to architecture in the v7.73 keystone-closeout handoff.
- **Amendment-1 chain attenuation (V1′ triple).** Per-link granter frame in the
  chain-walk subset-check (`capability.ml`); `authz_attenuation_foreign_granter_{1,deep,
  wildcard_leaf}` 200→403, shipped the preferred **hard-fail on unresolvable granter**.
  Reported to architecture in the v7.73 Amendment-1 (V1′) keystone handoff.

Both fixes are rust-kernel-shaped and convergent across C#/TS/OCaml (no keystone-template
divergence). Handler-internal re-check + operations/peers/attenuation beyond the chain
remain local — the v7.74 follow-on per §3.2.3, vector-gated.
