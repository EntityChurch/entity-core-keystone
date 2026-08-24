# PHASE-S1 — entity-core-protocol-asm-x86_64

**Phase:** S1 (profile research + authoring). **Substrate probe** — the extreme end of the
substrate axis (bare-metal, no-runtime, no-stdlib, syscall-level). Not a language-idiom
probe; expected spec-discovery yield is low, the payoff is generator-robustness +
substrate-dynamics research (ADR-0012: cohort-consistent corroboration, not independent
convergence).

## Deliverables (this phase)

- `profile.toml` — complete, no `TBD`.
- `arch/PROFILE-RATIONALE.md` — per-choice rationale.
- `arch/WIRE-SURFACE-REFERENCE.md` — byte-level implementation scaffold (interop-context
  cross-check from the Zig sibling; spec-anchored) for S3.
- `status/SPEC-AMBIGUITY-LOG.md` — A-ASM-001..004.
- `containers/asm-x86_64-toolchain/Containerfile` — binutils + gcc(link driver) + the
  prebuilt `libentitycore_codec.{so,a}` + headers.

## Decisions (→ ambiguity log)

| Axis | Decision |
|---|---|
| Codec strategy | **FFI (Level 1)** — entire codec + crypto via `libentitycore_codec` (C-ABI 1.1) |
| Assembler | **GAS / AT&T** (binutils, zero new dep) — A-ASM-001 |
| Link | **`cc` driver + `-no-pie`**, dynamic against the codec `.so`; asm `main` (not `_start`) — A-ASM-001 |
| Transport | **raw `syscall`s** (socket/bind/listen/accept4/read/write/setsockopt) — the substrate point |
| Concurrency | **single-threaded epoll** event loop, `TCP_NODELAY` — A-ASM-003 |
| Error model | **errno** (register status + branch), mapped to §5.2a/§6.12 at dispatch |
| Memory | static `.bss` + bump-over-`mmap` + FFI'd `ec_arena_t` |
| Agility | Ed448/SHA-384 **deferred** (not in the core floor) — A-ASM-002 |

## Key finding — A-ASM-004 (scope)

"FFI the whole codec" does **not** eliminate hand-written CBOR. The C-ABI decomposes
*entities*, not the *envelope* map nor the EXECUTE/RESPONSE *data* map — both are bare
canonical-CBOR maps the peer's model layer owns. Level-1 therefore includes a minimal
hand-rolled canonical-CBOR map reader+writer for that layer; the hard canonical bits
(shortest-float, tag-reject, key-sort) stay behind the FFI. This is the honest Level-1
hand-roll surface: transport + envelope/data-map CBOR + dispatch + store + capability walk +
§9.1 floor + identity + CLI.

## Exit criteria

- [x] `profile.toml` complete (no `TBD`).
- [x] `arch/PROFILE-RATIONALE.md` written.
- [x] `status/SPEC-AMBIGUITY-LOG.md` initialized (no blocking items).
- [x] Container specified + **built** (`containers/asm-x86_64-toolchain/Containerfile`).
- [x] **FFI bridge de-risked** — hand-written GAS `main` → dynamically-linked
      `libentitycore_codec.so` → `ec_sha256("abc")` byte-exact vs the RFC 6234 KAT, output
      via a raw `write` syscall, exit 0. Deterministic across repeat runs; a negative
      control (flipped KAT byte) correctly reports FAIL/exit 1 (the compare is not vacuous).
      `ldd` chain: `libentitycore_codec.so → libc → ld-linux`; sole unresolved import
      `ec_sha256`, resolved from the codec `.so`. FFI provenance `ec_impl_info()` =
      `c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 / libsodium 1.0.22`. Source:
      `src/ffi_smoke.s`; run `make ffi-smoke`. The three mechanics (SysV call ABI +
      dynamic link + raw syscall) all confirmed — the one genuinely novel unknown is
      retired; S2/S3 are now "assemble the known logic".

## Next

De-risk the asm→C-ABI bridge (a minimal asm program calling `ec_sha256` on a known input,
verified byte-for-byte against a KAT) BEFORE the full S2/S3 build — the one genuinely novel
mechanical unknown. Then S2 (corpus through the FFI'd codec, 71/71) → S3 (peer machinery) →
S4 (`validate-peer --profile core` = 0-FAIL).
