# c-abi conformance harness

The shared harness that proves any conforming `libentitycore_codec.*` against the contract (spec §10).

## What it does

1. `dlopen`s a target `libentitycore_codec.{so,dylib,dll}` — **impl-agnostic**: it loads whichever implementation you point it at by the symbol table alone (spec §2.1).
2. Runs the test-vector corpus from `protocol-generator/shared/test-vectors/v0.8.0/` through every §4 export (encode, content_hash, decode incl. N4 original bytes, peer-id round-trip, Ed25519, SHA-256, envelope verify).
3. Cross-checks every output against the **Go / Rust / Python reference impls** → byte-identical or fail.

## The differential matrix

With both FFI impls present, conformance is a **5-way agreement**:

```
Go ── Rust ── Python ── rust-ffi ── c-ffi      (encode/hash output, per vector)
```

- pairwise disagreement → localizes the bug to one impl
- one impl alone disagrees → that impl is wrong (S5: fix the code, not the test)
- the *references* split → the **spec** is ambiguous → log to S3 (`SPEC-AMBIGUITY-LOG.md`) + escalate to arch

No green differential → no publish (S7).

## Invariant vectors (must be present)

N1 synthetic ≥`0x80` varint · N2 `tag_reject` · N3 `0xA0` empty-map · N4 original-byte fidelity · float specials (`F9 7E00`/`8000`/`7C00`/`FC00`, `32768.0`→`F9 7800`, `65504.0`→`F9 7BFF`) · `map_keys` length-then-lex ordering. See `research/diagnostics/conformance-invariants.md` + spec §3, §10.

## Source of truth

Reference corpus generated from `entity-core-go/core/ecf/ecf.go` until the spec's Appendix E fixture is committed (finding F1).

## Status

⏳ **impl-agnostic `dlopen` harness: not-started** (this dir). Step 10 (corpus) is done — vendored at `test-vectors/v0.8.0/`.

A **first-pass rust-native harness** already runs: `entity-core-codec-ffi-rust/src/bin/conformance_harness.rs`, which links the rust crate directly (rlib) and diffs against the vendored fixture — **69/69 byte-identical**. It is not impl-agnostic (can't load the C impl), and it links `api::encode_value` directly because of **finding F6**: the fixture's Class-A vectors encode *bare* values, but the C-ABI's only encode entry is entity-shaped (`ec_encode_ecf`). Resolve F6 (`SPEC-FINDINGS-LOG.md`) before building the `dlopen` 5-way version here — likely a `conformance-hooks` feature exposing a bare-encode test symbol.
