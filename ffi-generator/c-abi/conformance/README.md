# c-abi conformance harness

The shared harness that proves any conforming `libentitycore_codec.*` against the contract (spec §10).

## What it does

1. `dlopen`s a target `libentitycore_codec.{so,dylib,dll}` — **impl-agnostic**: it loads whichever implementation you point it at by the symbol table alone (spec §2.1).
2. Runs the test-vector corpus from `protocol-generator/shared/test-vectors/ecf-conformance/` through every §4 export (encode, content_hash, decode incl. N4 original bytes, peer-id round-trip, Ed25519, SHA-256, envelope verify).
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

⏳ **impl-agnostic `dlopen` harness: not-started** (this dir). Step 10 (corpus) is done — vendored at `test-vectors/ecf-conformance/`.

**Corrected 2026-09-04.** This paragraph used to describe a "first-pass rust-native harness" at `entity-core-codec-ffi-rust/src/bin/conformance_harness.rs` scoring **69/69** against the vendored fixture. **That file has never existed in this repository** — `git log` finds no commit that added or removed it, the crate declares no `[[bin]]`, and the documented command exits `No such file or directory`. The number was not reproducible from a clone and is withdrawn.

The consequence is the one worth carrying: **the Rust impl has no independent corpus harness.** Its only verification is `abi_differential.c` below, which is a *mutual* check against the C impl — a defect the two shared would pass it. The C impl alone is graded against architecture's fixture (71/71). Closing this means driving the corpus **through the ABI**, so one harness can grade either impl against the fixture rather than against its sibling; that is owed and not done.

**Finding F6 is closed** — `ec_encode_bare_value` (C-ABI v1.1, "test-only, not a protocol surface") makes the bare canonical encoder reachable across the ABI, and the differential drives it directly over a Class-A battery.
