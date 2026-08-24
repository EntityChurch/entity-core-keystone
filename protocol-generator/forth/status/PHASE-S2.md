# entity-core-protocol-forth — Phase S2 summary (COMPLETE)

**Phase:** S2 (codec layer)
**Date:** 2026-07-11
**Container:** `entity-core-keystone/forth-toolchain:latest` (gforth 0.7.3, fedora:43)
**Status:** COMPLETE — full pinned-corpus gate **69/69 (0 fail, 0 skip)** + the uint64
boundary self-test + the crypto accept-path test, all green, container-bound + offline
(`--network=none`). Reproduce: `./run-s2.sh`. Report: `status/CONFORMANCE-REPORT.md`.

The stack-machine / typeless probe (A-FT-000) is validated: a recursive canonical-CBOR
codec + base58/varint/peer_id reproduce ECF byte-identically on a substrate with no records,
no typed values, and no named locals by idiom. No spec defect surfaced (corroboration, as
expected on the saturated wire surface); the payoff is generator robustness down to a
typeless stack machine, plus two banked Forth-substrate gotchas.

## Done

- **`src/buf.fs`** — the foundation: a bump-allocated **arena** (a HERE-style byte builder;
  `b,`/`bytes,`/`>be`) that both the decoded tagged-value (TV) model and the encoded wire
  output are built into, handing back `(c-addr u)` spans; a **separate reentrant scratch
  stack** for the map-sort bookkeeping (so nested maps don't clobber a parent's arrays);
  the private THROW-code leaf-kind table (base −25000, A-FT error model).
- **`src/varint.fs`** — LEB128 (N1): `varint-encode`/`varint-decode` primitives + a
  buffer-targeting `varint-to` (for the peer_id prefix, off-arena). Non-minimal + truncated
  rejected.
- **`src/base58.fs`** — Bitcoin-alphabet base58 by **byte-array long division** (the digest
  is >64 bits, so it can't go through one cell — divide/multiply the big-endian byte array
  with a byte-wide carry; the fixed-width-cell discipline applied to a >64-bit quantity).
- **`src/cbor.fs`** — the canonical CBOR (ECF) codec, the stack-machine probe. Encode: minimal
  int heads (mt0/mt1 magnitude as an UNSIGNED cell — A-FT-001), length-then-lex map-key sort
  on **encoded** key bytes, the shortest-float ladder f16→f32→f64 (f32/f64 from native IEEE
  bits, f16 leg hand-rolled), canonical NaN/±Inf/±0. Decode: minimal-head re-validate,
  recursive **major-type-6 tag reject** (N2), shortest-float re-validate, full-consume, map
  key-order check. TV rep is an explicitly-tagged byte record (A-FT-003 — a cell has no type).
- **`src/tv.fs`** — TV navigation (map-get by text key, array-elem, unwrap) for the harness +
  the S3 peer.
- **`src/peer-id.fs`** — §1.5 canonical form: `Base58(varint(kt) ‖ varint(ht) ‖ digest)`.
- **`src/ffi/crypto.fs`** — the libcc `c-library` binding of libentitycore_codec's
  `ec_sha256/384` + `ec_ed25519_{seed_to_pubkey,sign,verify}` — a genuine in-process libffi
  call (A-FT-005, the KEY differentiator vs Rexx). `src/hash.fs` — content_hash construction.
- **`src/entity-core.fs`** — the umbrella loader (the S3 peer require's it).
- **`test/conformance.fs`** (the 69-vector harness), **`test/crypto-accept.fs`** (the crypto
  ACCEPT path the rejection-only oracle can't cover), **`test/int-boundary.fs`** (the
  [2^63, 2^64-1] self-test), `Makefile`, `run-s2.sh`.

## Findings / decisions (S2)

- **A-FT-002 (native float bits) — CONFIRMED, and it holds.** All 14 float vectors green.
  f32/f64 encode reads real `SF!`/`DF!` bits; the f16 leg + shortest-form ladder are exact
  bit arithmetic on those bits. Much less hand-roll than Rexx's decimal float; no spec
  finding — the shortest-form determinism survives cleanly.
- **A-FT-005 (in-process libcc FFI) — CONFIRMED against the REAL lib.** The `ec_*` symbols
  of libentitycore_codec bind and call in-process; content_hash (incl. `.4`) + signature +
  the sign→verify accept path all pass. No subprocess. The banked cache gotcha
  (`~/.gforth/libcc-named` keyed by c-library name) is handled by clearing it before each run
  (`CLEAR_CACHE` in the Makefile / `rm -rf` in run-s2.sh).
- **A-FT-010 (NEW, banked) — the `>r`/`?do`/`r@` return-stack collision.** A `?do…loop`
  pushes its loop-control parameters onto the **return stack**, so an `r@` inside the loop
  reads the loop index, NOT a value you `>r`'d before the loop. The first `tv-node-len` /
  `enc-map` drafts used that pattern and read garbage addresses. Fixed by carrying the state
  in **locals** (`{ }`) and using `recurse` for self-reference — the idiomatic fix, and it
  keeps the recursive codec readable. Durable Forth lesson.
- **A-FT-011 (NEW, banked) — `1 0 ?do` wraps on empty containers.** gforth's counted `?do`
  with start > limit (e.g. the insertion sort's `n 1 ?do` when n = 0 for `{}`) does NOT run
  zero times — it counts up and wraps 2^64. Guard any counted loop whose start can exceed its
  limit (`n 2 >= if … then` around the sort). The empty-map `A0` (N3) is the trigger.

## The stack-machine idiom verdict (A-FT-000 — the probe's payoff)

**Verdict: the recursive canonical codec reads as NATIVE Forth, not translated.** Two idioms
carried it:
1. **An arena / HERE-style byte builder returning `(c-addr u)` spans.** Because a Forth
   "value" is just a byte span, both the decoded model (the tagged-value record) and the
   encoded wire are *the same kind of thing* — bytes appended to a bump allocator — and the
   recursion composes on the data stack passing `(addr u)` pairs. This is exactly how a
   Forth programmer builds a serializer; there is no impedance mismatch with the
   language-agnostic phase prompt's "recursive encoder over a value model."
2. **Locals as a scoped escape hatch, per A-FT-009.** Where a word's live stack effect would
   exceed ~3–4 items (the map encode's four parallel sort arrays; `@be`'s addr/off/width;
   the float legs' sign/exp/mant), a `{ … }` locals frame reads far better than deep
   `dup`/`roll`/`pick`. Idiomatic modern gforth uses locals freely; leaning on them at those
   seams kept the code from becoming stack choreography.

Where the substrate DID bite was **not** the paradigm mismatch the probe hypothesized
(awkward stack gymnastics) but two **return-stack / counted-loop hazards** (A-FT-010/011) —
Forth-specific footguns, not a generator-robustness gap. Once those were understood, the
recursive encoder/decoder + the map-sort + the base58 long-division all expressed cleanly.
**Generator-robustness conclusion: the pipeline reaches down to a typeless stack machine;
the phase prompts' "value model + recursion" framing did not assume named-variable/typed-
record structure the generator had to work around.** The probe closes as corroboration.

## Exit criteria — MET

Full-corpus 69/69 green (byte-identical encode + decode + hash); the uint64 boundary
self-test + crypto accept-path green; N1–N4 each covered; codec loads cleanly under gforth;
no blocking ambiguity items. **Next: S3** — the live networked peer (single-thread select
loop over `unix/socket.fs`; the in-process crypto binding carries in directly — Rexx's whole
FIFO/co-process transport pain does not arise, A-FT-005/008).
