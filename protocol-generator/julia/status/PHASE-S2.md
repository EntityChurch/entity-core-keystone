# entity-core-protocol-julia — Phase S2 (Codec) Summary

**Peer** (Julia, Tier-3 corroboration / generator-robustness — multiple-dispatch codec,
native UInt64+BigInt, UTF-8-native strings) ·
**Status: COMPLETE — 71/71 wire-conformance, first conformance run, 0 codec fixes.**

## Container (the deferred S1 build)

`containers/julia-toolchain/Containerfile` built clean:
```
. tools/podman-caps.sh
podman build $PODMAN_BUILD_CAPS -t entity-core-keystone/julia-toolchain:latest \
  -f containers/julia-toolchain/Containerfile .
```
- **A-JULIA-001 closed:** the S1 `JULIA_SHA256` fail-closed sentinel was filled with the real
  digest `723e878c642220cc0251a0e13758c059a389cadc7f01376feaf1ea7388fe8f9c` for
  `julia-1.11.5-linux-x86_64.tar.gz`, verified against the official
  `julialang-s3.julialang.org/bin/checksums/julia-1.11.5.sha256`. Build verifies the tarball
  cryptographically (fails closed on mismatch); `julia --version` → 1.11.5. Runs
  `--network=none` thereafter (stdlib + system libsodium only, zero registered packages).

## What was built (`src/`, module `EntityCore`)

| Module | Responsibility |
|---|---|
| `cbor.jl` | Canonical ECF encode/decode via **multiple dispatch** on the value type; f16/f32/f64 shortest-float ladder (native `Float16`); length-then-lex map ordering on encoded key bytes; recursive major-type-6 tag rejection (N2); full `UInt64`/`nint` range with BigInt fold; `CborMap` ordered-pair model |
| `varint.jl` | LEB128 encode/decode (N1) — multi-byte path proven by content_hash.4 + peer_id.3 |
| `base58.jl` | Bitcoin-alphabet encode+decode over **BigInt** long division; leading-zero preserving |
| `contenthash.jl` | `content_hash = varint(fc) ‖ SHA(ECF{type,data})`; SHA-256 floor + SHA-384 (agility) via the `SHA` **stdlib** |
| `peerid.jl` | `Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)` + parse round-trip |
| `sign.jl` | Deterministic Ed25519 sign/verify/pub via **system libsodium `ccall`** (`crypto_sign_seed_keypair`/`_detached`/`_verify_detached`) |
| `EntityCore.jl` | Umbrella module (includes + re-exports) |
| `test/harness.jl` | Shared corpus runner (`run_conformance`) |
| `test/conformance.jl` | The S2 gate CLI (loads fixture with the hand-rolled decoder, byte-checks every vector, exits nonzero on any FAIL) |
| `test/runtests.jl` | Test-stdlib suite: N1–N3 + A-JULIA-006/007/008 self-tests + the corpus |

**Stdlib + system-libsodium only, zero registered packages.** Error model = exceptions
(`EntityCoreError <: Exception` leaves: `NonCanonicalECF`/`TruncatedInput`/`TagRejected`/…),
per profile `[error_model]`.

## Conformance

**71 / 71 byte-identical** against `conformance-vectors.cbor` (sha256 `9695b1f1…c6dc`,
66 `encode_equal` + 5 `decode_reject`), **first run, zero codec-logic fixes.** Same converged
scoreboard as the native cohort (C#/TS/OCaml/Zig …) — spec-first. Full tally +
reproduction in `CONFORMANCE-REPORT.md` / `.json`.

The S1 handoff quoted the gate as 69/69 (the pre-F29/F30 corpus); the live corpus is the
finalized **71** (F29 `nested.5/.6`, F30 `tag_reject.1/.2/.3/.5`). Ran the current 71 — all pass,
including the two F29 array-of-maps text-head-boundary vectors and the four F30
canonical-except-the-tag rejection vectors (the §6.3 tag scanner is what rejects them, not
trailing-data — exactly what F30 was regenerated to gate).

## Idiom-axis confirmations (the Julia-novel seams)

- **Multiple-dispatch codec (A-JULIA-006):** `encode!` dispatches on value type with no
  shimmer — `Vector{UInt8}`→mt2 vs `String`→mt3, `Bool` (≺ `Integer`, more-specific method)→mt7
  vs `Integer`→mt0/1, `Vector{Any}`→mt4. Confirmed by self-test + the full corpus.
- **Fixed-width UInt64 head-form self-test (A-JULIA-008) — MANDATORY:** PASS across
  `{2^63, 2^64-2, 2^64-1}` and nint-min `-2^64` (`3bffffffffffffffff`). The negative fold uses
  `-1 - big(n)` narrowed to `UInt64`, so the classic silent int64 overflow at the boundary is
  structurally impossible. `BigInt` carries reconstructed values; the wire stays on `UInt64`.
- **UTF-8-native byte-length strings (A-JULIA-007):** mt3 length via `length(codeunits(s))`, so
  a 2-byte-UTF-8 char encodes with a byte-length prefix (Tcl char-vs-byte trap avoided by
  construction).
- **Ed25519 via libsodium `ccall` (A-JULIA-003):** deterministic RFC-8032 signatures match the
  corpus byte-exactly (3/3), sign→verify→tamper-reject + determinism self-tests pass. Native
  audited-lib tier, not the keystone C-ABI; floor peer self-contained.

## Ambiguity log

No blocking codec items. One new tooling note **A-JULIA-009** (`Pkg.test()` git-clones the
General registry → fails under `--network=none` even for a stdlib-only package; run
`julia --project=. test/*.jl` directly — the offline-correct form, wrapped by
`run-conformance.sh`). S1 confirm-at-phase items A-JULIA-001/002/003/006/007/008 all CLOSED /
CONFIRMED.

## Exit criteria

All 71 vectors PASS · 62/62 self-tests PASS (offline) · module loads + precompiles clean under
Julia 1.11.5 · container reproducible + offline · ambiguity log has no blocking codec items.
**S2 PASS.**

## Not in this phase (S3+)

- Peer machinery (connection, dispatch, capability, store, processor) on the single-threaded
  Task scheduler (§7b structural store-safety, A-JULIA-005); the `bin/peer.jl` executable
  `validate-peer` drives.
- Agility corpus (Ed448 + SHA-384 matrix) — Ed448 is the opt-in hybrid-FFI sub-package over the
  C-ABI (`ec_ed448_*`, A-JULIA-004); the SHA-384 leg is already wired in `contenthash.jl`.
