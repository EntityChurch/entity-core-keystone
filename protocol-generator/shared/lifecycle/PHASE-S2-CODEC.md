# Phase S2 — Codec layer

> Loaded by `/entity-rosetta <lang> --phase codec` or as second phase of full `/entity-rosetta <lang>`.

## Objective

Build the codec layer of `entity-core-protocol-<lang>`: ECF encode/decode, content_hash, peer-id parse/format, Ed25519 sign/verify, signature/envelope verify. Per the profile's `codec_strategy`:
- `native`: implement using the language's CBOR + Ed25519 libraries
- `ffi`: implement as a thin shim around the codec C-ABI (`libentitycore_codec`, from either `entity-core-codec-ffi-{rust,c}`) via the language's FFI primitive; declarations from `ffi-generator/c-abi/spec/entitycore_codec.h`
- `interop`: implement as a thin wrapper around a sibling-runtime native codec (e.g. Clojure → Java codec)

If a `native` strategy proves non-viable here — the canonical layer can't be made byte-identical, or a library actively blocks it — don't grind against it. Fall back to `ffi`, note it as a finding, and re-run. The profile's strategy is a starting bet, not a contract.

## Inputs

- `protocol-generator/shared/spec-data/<version>/` — entity shapes, hash construction, varint encoding, peer-id grammar
- `protocol-generator/shared/test-vectors/<version>/` — round-trip fixtures (canonical CBOR bytes; decoded form; expected hash)
- `ffi-generator/c-abi/entity-core-codec-ffi-rust/output/libentitycore_codec.{so,dll,dylib}` — a conforming codec C-ABI impl for byte-identity cross-check (any conforming impl works; spec at `ffi-generator/c-abi/spec/`)
- `protocol-generator/<lang>/profile.toml` — what to use, how to package
- `protocol-generator/<lang>/templates/` — language scaffolds

## The byte-identity rule

Your codec output MUST be byte-identical to the test-vector corpus (and to any conforming codec C-ABI impl, `libentitycore_codec`) for every test vector. If you disagree on bytes, **you are wrong** — fix the generated code. Common causes:
- Map-key ordering (RFC 8949 §4.2.3 canonical: sort by encoded-length then lexicographic)
- Integer minimal encoding (don't use 2-byte encoding for values that fit in 1)
- Negative integer encoding (major type 1, value = -1 - n)
- Float canonicalization (shortest preserving value)
- Optional field absent vs null vs zero (V7 §1.3 — absent ≠ null ≠ zero on the wire)
- Varint format codes (V7 §1.5 / §7.3; multikey leb128)

## Pinned conformance invariants (read before building)

The codec-side bug classes that bit all three reference impls — `research/diagnostics/conformance-invariants.md` **N1–N3**: route all format-code/key-type/hash-type framing through real **LEB128 varint primitives**, not fixed bytes (N1); run an **explicit recursive major-type-6 tag scanner** on decode and reject (N2, do not trust library defaults); pin empty-params/empty-map as the single byte **`0xA0`** (N3). **N4** (entity fidelity — forward original bytes, never re-serialize) shapes the decode surface; see `ffi-generator/c-abi/spec/ENTITY-CODEC-C-ABI-V1.md` §3.4 + `ffi-generator/c-abi/status/DESIGN-NOTES-FROM-REVIEW.md`. Each of N1–N3 MUST have a covering test-vector.

## Conformance gate

Phase exits when `wire-conformance` runs green:

```bash
# Resource caps are mandatory: source tools/podman-caps.sh, pass $PODMAN_RUN_CAPS
# on every podman run so a runaway can't take the host down (RESOURCE-CAPS standard).
. "$(cd "$(dirname "$0")/../.." && pwd)/tools/podman-caps.sh"
podman run $PODMAN_RUN_CAPS --rm -v $PWD:/work entity-core-keystone/<lang-toolchain>:latest \
    wire-conformance run /work/protocol-generator/<lang>/src/ \
    --vectors /work/protocol-generator/shared/test-vectors/v0.8.0/
```

Output must report all vectors as `PASS` (encode + decode + hash). Any `FAIL` blocks phase exit.

## What you write

- `protocol-generator/<lang>/src/codec/` (or per-profile module layout) — encode, decode, hash, peer-id, sign, verify
- `protocol-generator/<lang>/src/<test-module>/codec_test.<ext>` — unit tests calling your codec against test-vectors
- `protocol-generator/<lang>/status/CONFORMANCE-REPORT.md` — wire-conformance output summary
- `protocol-generator/<lang>/status/SPEC-AMBIGUITY-LOG.md` — any new entries
- `protocol-generator/<lang>/status/PHASE-S2.md` — phase summary

## What you do NOT do

- Patch test vectors to make your codec pass
- Skip canonical-mode handling because the library makes it inconvenient
- Implement TREE / CONTENT / IDENTITY / any extension type's encoding rules — codec only covers core types (`Entity`, `system/hash`, `system/peer`, `system/signature`, `system/capability/token` shape, envelopes, protocol messages)

## Phase exit criteria

All test vectors pass; conformance report green; ambiguity log has no blocking items; codec module compiles cleanly under the profile's compiler/linter settings.
