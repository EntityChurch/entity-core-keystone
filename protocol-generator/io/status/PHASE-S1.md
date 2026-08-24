# entity-core-protocol-io — Phase S1 summary (COMPLETE)

**Phase:** S1 (profile research + authoring + toolchain)
**Date:** 2026-07-15
**Status:** ✅ COMPLETE — profile authored, container built with the GO-gate
self-test green, no blocking ambiguity.

## Inputs

- The S1 feasibility gate had already PASSED (2026-07-15 session, committed
  `3faf205`): live in-container probes proved headless `io -e`, the manual
  Socket-addon build, and a byte-identical coroutine TCP echo incl 0x00/0xFF.
  Full evidence: `research/evaluations/oz-io-viability.md` §S1. This phase
  *encoded* that evidence; it did not re-decide feasibility.
- Build plan: `docs/status/HANDOFF-2026-07-15-oz-io-s1-go.md`.

## Outputs

- `containers/io-toolchain/Containerfile` + `IoSocketInit.c` +
  `gogate-selftest.sh` — the pinned recipe:
  - Io core from the permanently frozen native tag `2026.04.20-native-final`
    (tarball SHA-256 `08184259…`, fail-closed), CMake with the gcc-15 dialect
    flags (`-std=gnu11 -Wno-incompatible-pointer-types
    -Wno-implicit-function-declaration -Wno-int-conversion`).
  - **New finding vs the S1 notes:** the GitHub tag tarball ships the
    `deps/parson` git submodule EMPTY (the S1 probe cloned recursively). The
    Containerfile fetches the exact submodule commit `4f3eaa68…` (SHA-pinned)
    and drops it in place — without it the iovm CMake targets have no sources.
  - Socket addon hand-built from `IoLanguage/Socket @ e348c23` (SHA-pinned
    tarball) + the hand-written `IoSocketInit.c` (all ten `Io<Name>_proto`
    registrations), `gcc -shared … -include assert.h -levent`, installed at
    `/root/.eerie/base/addons/Socket/{_build/dll/libIoSocket.so, io/, protos,
    depends}`.
  - Build-time GO-gate: headless eval + Server/Socket coroutine echo,
    byte-identical incl 0x00/0xFF — the image does not build if the gate fails.
    (First iteration used a non-canonical async idiom and failed honestly; the
    documented `@handleSocketFromServer` pattern passes.)
  - libevent + libsodium(-static) + cmake staged for the S2 codec builds.
- `protocol-generator/io/profile.toml` — complete, no TBDs blocking S2.
- `protocol-generator/io/arch/PROFILE-RATIONALE.md`.
- `protocol-generator/io/status/SPEC-AMBIGUITY-LOG.md` — A-IO-001…A-IO-012
  authored at S1/S2-design time; none blocking.

## Key decisions (detail in PROFILE-RATIONALE.md)

1. **Native line, not the WASM port** (settled in the handoff; recorded).
2. **ffi-addon-hybrid codec:** canonical CBOR + crypto/hash/peer-id in the
   EntityCodec C addon over `libentitycore_codec`; ALL protocol logic in Io.
3. **Explicit value model** (EcMap/EcBytes/EcBig/EcFloat/EcNull ↔ CBOR) — the
   double-trap and byte-vs-text answers (A-IO-001).
4. **Coroutine concurrency contract:** coroutine-per-request, per-connection
   request_id demux, per-connection writer FIFO (A-IO-002), structural §4.8
   store safety, half-close design rule.

## Exit criteria — MET

Profile fields all populated; container exists and self-tests; ambiguity log has
no blocking-severity items. → S2 (EntityCodec addon + 71-vector corpus gate).
