# Evaluation — `entity-core-codec-ffi-rust`

**Author:** operator (FFI review pass)
**Purpose:** Ground the library/stack choices for the Rust implementation of the codec C-ABI (`ffi-generator/c-abi/spec/`) with an audit trail, before writing the crate. Supply-chain pin discipline: only depend on releases that have passed the ≥30-day cool-down.

## Headline decision: hand-write the ECF encoder; use a CBOR crate only as a decode tokenizer

No Rust CBOR crate gives ECF's canonical guarantees, and the serde-driven ones (`ciborium`, `cbor4ii`, deprecated `serde_cbor`) actively fight all four of ours — they own float minimization, canonicalize/interpret tags, and return *values* not original byte slices. So:

- **Encode:** hand-written. The ECF surface (ints, byte/text strings, arrays, maps, the four floats, bool/null) is a few hundred lines of straight major-type emission. Total control over float16 minimization and CTAP2 key sorting (encode each key to a scratch buffer, sort by `(len, bytes)`, concat). Easier to audit than bending a library to canonical rules. Satisfies spec §3 ("CBOR lib for primitives only; canonicality is ours").
- **Decode:** `minicbor` as a **tokenizer/validator only** — its `Decoder`/`Tokenizer` exposes major-type inspection and borrowed `&[u8]` slices, exactly what tag-rejection (N2) and raw-byte fidelity (N4) need. We walk the structure to *validate* (reject any major-type-6, check minimal encoding/ordering) and hand back the **original input slice unchanged** — never a re-encode. minicbor does not force tag interpretation.

(Zero-CBOR-dep is also viable — hand-roll the decoder too — but minicbor's tokenizer saves real work on the decode walk with no canonical-correctness risk since we never trust it to *produce* output.)

## Recommended stack + pins

| Purpose | Crate | Pin | Released | License | Notes |
|---|---|---|---|---|---|
| CBOR decode tokenizer/primitives | `minicbor` | **2.2.1** | — | BlueOak-1.0.0 | The 2.2.2 point release is still inside the 30-day cool-down → pin 2.2.1. Decode-side only; encoder hand-written. |
| Ed25519 keygen/sign/verify | `ed25519-dalek` | **2.2.0** | — | BSD-3 | Stable line; **avoid 3.0 (rc-only)**. `sign`/`verify` on arbitrary bytes (we sign the 33-byte hash; PureEdDSA, not Ed25519ph). |
| (transitive) curve | `curve25519-dalek` | **≥ 4.1.3** | — | BSD-3 | Floor for RUSTSEC-2024-0344 (Scalar sub timing). Enforce in CI/deny.toml. |
| RNG for keygen | `rand_core` | **0.6.4** | — | MIT/Apache | Must match dalek 2.x (`rand_core 0.6`, **not** 0.9). Use `OsRng`, **not** `ThreadRng` (RUSTSEC-2026-0097). |
| SHA-256 | `sha2` | **0.10.9** | — | MIT/Apache | Stay on 0.10 line; **0.11.0 is breaking + too new**. No open advisories. |
| Base58 (Bitcoin) | `bs58` | **0.5.1** | — | MIT/Apache | Bitcoin alphabet is the default. |
| float16 | `half` | **2.4.x** | 2024 | MIT/Apache | For shortest-float; also pulled transitively by minicbor. |
| Header check (build tool) | `cbindgen` | **0.29.2** | — | MPL-2.0 | **CI diff-check only** — generate, diff against the committed canonical `entitycore_codec.h`, fail on drift. Not linked → MPL doesn't touch the Apache-2.0 output. |

All satisfy the ≥30-day supply-chain cool-down and are license-compatible with Apache-2.0 output. (BlueOak-1.0.0 is OSI-approved permissive with a patent grant — note it in the license audit so it isn't flagged spuriously.)

## Risks / gotchas (carry into implementation)

- **R1 — Don't trust any CBOR crate for canonicality.** Hand-write encode; minicbor reads/validates only; always return original input bytes on decode (N4). Single most important decision.
- **R2 — ed25519-dalek 3.0 is rc-only; the rand_core trap.** Pin 2.2.0; use `rand_core 0.6` + `OsRng`. Mismatched RNG traits (0.6 vs 0.9) is the #1 integration failure. Avoid `ThreadRng`.
- **R3 — curve25519-dalek ≥ 4.1.3** (RUSTSEC-2024-0344) — enforce a floor.
- **R4 — sha2 0.11 is brand-new + breaking** — stay on 0.10.9; revisit later.
- **R5 — glibc symbol floor.** A glibc `cdylib` won't load on Linux older than the build host's glibc. Build the shipped `.so` on an **old-glibc base** (manylinux-style) for "drop it in, no dep hunt." `x86_64-unknown-linux-musl` can make a fully-static `.so` (no libc) but musl cdylib is rough + slower allocator — offer only if a consumer needs zero-libc. Pin an older container base for the release build (still S1/S11).
- **R6 — never let a panic cross the FFI boundary.** `catch_unwind` in every exported fn → convert to `int32_t` error code; do **not** abort the host process. `panic = "abort"` is simpler but kills the consumer. Don't rely on `extern "C-unwind"`.
- **R7 — symbol hygiene + memory contract.** `[lib] crate-type = ["cdylib","staticlib"]`; export only `#[no_mangle] pub extern "C"` symbols (version script / hidden visibility) so Rust/std symbols don't collide with the host; never hand C a Rust-allocated pointer to `free()` — pair every alloc with a freeing entry point; all FFI types `#[repr(C)]`.
- **R8 — aarch64-apple-darwin needs a macOS runner** — can't fully produce the Mach-O `.dylib` from a Linux container without the Apple SDK. linux x86_64/aarch64 cross-build cleanly (watch the glibc floor).

## Cross-reference

Spec: `ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` (§3 canonical obligations, §5 memory rules, §7 static output, §8 pins). Sibling impl: `research/evaluations/ffi-c.md`. Invariants: `research/diagnostics/conformance-invariants.md` (N1–N4).
