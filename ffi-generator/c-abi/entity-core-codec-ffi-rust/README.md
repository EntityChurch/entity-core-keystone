# entity-core-codec-ffi-rust

A **conforming implementation** of the Entity Codec C-ABI (`../spec/ENTITY-CODEC-C-ABI-V1.md`), in Rust.

Named as a future standalone repo (S10) — it lifts out of the keystone tree cleanly if/when extraction is warranted.

## Conforms to

`../spec/ENTITY-CODEC-C-ABI-V1.md` (ABI 1.0) over `spec-data/v0.8.0`. Ships the spec's `entitycore_codec.h` unchanged. Builds `libentitycore_codec.{so,dylib,dll}` + static lib — **same artifact name** as the C impl (interchangeable; provenance via `ec_impl_info()`).

## Stack (decided — see `research/evaluations/ffi-rust.md`)

- **CBOR: hand-write the ECF encoder; `minicbor` 2.2.1 as a decode tokenizer only.** No CBOR crate is trusted for canonicality — sort, shortest-float, tag-reject, and raw-byte fidelity are enforced in this crate (spec §3). minicbor reads/validates; encode is ours.
- **Ed25519:** `ed25519-dalek` 2.2.0 (NOT 3.0 rc) + `rand_core` 0.6.4 (`OsRng`, not `ThreadRng`); transitive `curve25519-dalek` ≥ 4.1.3.
- **SHA-256:** `sha2` 0.10.9 (stay off the new/breaking 0.11).
- **Base58:** `bs58` 0.5.1 (Bitcoin alphabet default).
- **float16:** `half` 2.4.x.
- **Header:** `cbindgen` 0.29.2 as a **CI diff-check** against the canonical `../spec/entitycore_codec.h` — not the source of truth.

All pins ≥ 30 days old (re-check at impl time, S11). `crate-type = ["cdylib","staticlib"]`, statically self-contained (spec §7). **catch_unwind at every FFI boundary** → int error code, never abort the host. Build the shipped `.so` on an old-glibc base; macOS arm64 needs a macOS runner.

## Build + run the harness (container, from repo root)

```
# 1. build the pinned cargo image (once)
podman build --memory=4g --memory-swap=4g -t entity-core-keystone/cargo:latest -f containers/cargo/Containerfile containers/cargo
podman volume create kc-cargo            # persistent crate cache across runs

# 2. compile: libentitycore_codec.{so,a} + the conformance-harness bin
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm -v "$PWD":/work:Z -v kc-cargo:/cargo entity-core-keystone/cargo:latest \
  sh -c "cd /work/ffi-generator/c-abi/entity-core-codec-ffi-rust && cargo build --release"

# 3. gate it — see "How this impl is verified" below for what this does and does not cover
./ffi-generator/c-abi/run-ffi-gate.sh
```

Artifacts land in `target/release/` (gitignored): `libentitycore_codec.so` (deps
statically linked — `ldd` shows only libc/libgcc_s/ld-linux, satisfying §7) + `.a`.

**The build needs the network.** There is no vendored crate closure: `cargo build --offline`
fails to resolve, and the `kc-cargo` volume above is host-local — warmed by hand on one
machine, empty on a fresh one. `Cargo.lock` is committed and `--locked` is honored, so a
networked build is reproducible; an air-gapped one is not possible today. This is tracked
backlog, not a property of the design.

## How this impl is verified — and what that does NOT cover

**Measured 2026-09-04, through `ffi-generator/c-abi/run-ffi-gate.sh`:**

- **Cross-impl differential vs the C impl: 101/101 probes PASS** through a real `dlopen`
  boundary (`../conformance/abi_differential.c`), covering **19 of the 27 spec-declared
  symbols**. The gate now prints that 19/27 next to the probe count, because a probe count
  is not a symbol count and for a long time nothing said which was which.
- **Exports 26 of 27 spec-declared symbols.** The one absent is `ec_entity_original_bytes`,
  which spec §4.1 declares **OPTIONAL** ("MAY be provided") — so this is conformant. It is
  still worth knowing: both impls ship the same soname and artifact name and are advertised
  as drop-in interchangeable, so a consumer that links the C impl and swaps this one in gets
  an unresolved symbol. The differential reports the asymmetry rather than failing on it. No
  peer in the tree calls it.
- **No leak on the per-request path.** ASan/LSan over the exported ABI only, valid and
  malformed input: **0 bytes/pass over 18 000 measured passes**, against a control tree that
  measures 5 552 bytes/pass on the same instrument.

**What is NOT covered, stated rather than implied.** This crate has **no independent
conformance harness in this tree** — no `[[bin]]`, no `tests/`, and `src/bin` has never
existed in git history. Its correctness rests entirely on agreeing with the C impl, which is
a *mutual* check: a defect both impls shared would pass it. The C impl is separately graded
against architecture's vendored ECF corpus (71/71); this one is not.

> An earlier version of this file documented `./target/release/conformance_harness` and a
> **"69/69 byte-identical to the vendored fixture"** result. That binary is not in this
> repository and the command cannot run, so the number was not reproducible from a clone.
> It has been withdrawn rather than restated. The owed fix is to drive the corpus *through
> the ABI*, so one harness can grade either impl against architecture's fixture instead of
> against its sibling.

### Implementation notes

- **Decoder is hand-rolled** (`src/decode.rs`); `ffi-rust.md`'s decided stack wires `minicbor`
  2.2.1 as a tokenizer/validator only. The hand-written *encoder* — the load-bearing decision
  — is final.
- **Nothing is stubbed.** An earlier revision of this file listed `ec_ed25519_keygen`,
  `ec_envelope_verify_root_hash`, `ec_envelope_find_signature_for` as returning
  `EC_INTERNAL_ERROR` and the arena trio as "not yet defined". All are implemented; the first
  three are driven by the differential.
- **Finding F6 is closed** — `ec_encode_bare_value` makes the bare encoder core reachable
  across the ABI, and the differential drives it directly.

See `../status/DESIGN-NOTES-FROM-REVIEW.md` for the N1–N4 design-time notes.
