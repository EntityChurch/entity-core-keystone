# PHASE-S3 — entity-core-protocol-asm-arm64 (green)

The first **ISA port** off `protocol-generator/asm-x86_64` (the Level-1 FFI-all template).
Transport + the envelope/data-map CBOR + the entire dispatch/authority interior are
hand-written **aarch64** assembly (GAS, native ARM syntax); entity codec + Ed25519/SHA +
peer-id are **FFI** via `libentitycore_codec` (cross-built for aarch64). The peer runs under
`qemu-aarch64-static`; the Go `validate-peer` oracle runs natively beside it, one loopback,
`--network=none`.

## Result — `--profile core` = Result: PASS (0 fail)

Reproducible full `--profile core` at oracle **`cc1970f`**, deterministic (clean rebuild):
**682 total · 583 pass · 3 warn · 0 fail · 96 skip (~16.4 s) — Result: PASS.** All 96 skips are
auto-allowlisted by the V7 §9.0 profile carve-out; **zero skips count as FAIL**. This is
**byte-identical to the x86-64 sibling's verdict** (583P/3W/0F/96S, same 3 WARNs:
`tree_operations.cleanup` "non-critical", `resource_bounds.r3_connection_flood` matches the
reference's WARN, `authz.authz_scope_exceeds_1` "spec-defensible"). Handoff sub-targets all
met: **§7a `validate_echo_dispatch` PASS**, **concurrency 5/5** (incl. the flagged
`t2_2_connection_churn`), `type_system` 400/400, `connectivity` 22/22, genuine §5.5 multisig
accept (`valid_2of3_peer_signed_accepted`).

**Honesty framing (ADR-0012).** This is **corroboration, not independent convergence**: the
arm64 peer shares the x86-64 peer's generation lineage (a mechanical ISA transliteration) and
FFIs the *same* codec `.so`. The session's real signal is the **substrate mechanics**
(FFI×ISA cross-libsodium, `fork`→`clone`, qemu fidelity under §6.11 churn) — see
`status/PHASE-S1.md` — plus one durable **porting-discipline finding** (A-ARM64-003 below).
Oracle-pinned `--profile core`, FFI-hybrid codec/crypto — not full-profile, cohort-pinned to
one author's vectors.

## What the port entailed

- **Data (~310 lines) transferred verbatim** — the two `.rodata` atom blocks + two `.bss`
  `.lcomm` blocks are arch-neutral; only `@function`→`%function` and comment-char adjustments.
- **~6200 instruction lines transliterated** across all 75 functions by the codified
  x86-64→aarch64 register/ABI/syscall map (`src/macros.s`): args `rdi..r9`→`x0..x5`, ret
  `rax`→`x0`, callee-saved `rbx rbp r12-r15`→`x19-x24` with the **CBOR writer cursor
  r15→x24 globally**, syscall nr in x8 + `svc #0` (no r10-for-arg4 divergence),
  `bswap`→`rev`/`rev16`, and the aarch64 logical-immediate workaround (`mov` scratch then
  register-form `orr`). `push/pop` of callee-saved regs → proper 16-aligned `stp/ldp` frames;
  values that must survive a `bl` are promoted to x19–x28 (a real judgment step, not a rename
  — x86 leaves some live values in volatile regs that aarch64 `memeq` would clobber).
- **The port confirms the ISA-MAP Axis-A thesis end-to-end**: with the codec/crypto/peer-id
  behind the FFI, the peer's protocol interior is a **mechanical register/syscall swap** — no
  protocol-logic change on any of the 75 functions. (`status/PHASE-S1.md` proved it on the 4
  shell modules; dispatch.s — the 6414-line control-flow core — was "more of the same".)

## The one bug the port surfaced (A-ARM64-003)

A **cross-boundary ABI drift**: the store helpers `canon_path`/`store_get`/`path_valid` take
their path **length in x3** (x86 `rcx`), but `store_delete` takes it in **x1** (x86 `rsi`) and
`cas_check` in x2 — the arg register is per-function, not uniform. Three call sites passed the
length in the wrong register (x2), so those calls canonicalized with a garbage length →
store-key miss. Symptom: a **revoked capability was accepted (200)** (`is_revoked`'s
canon/get missed the revocation marker → `capability.revoked_cap_denied_on_use` +
`authz.authz_revoked_core_1` FAIL) and **unregister didn't delete the signature entity**
(`store_delete`'s canon missed → `handlers.core_register_unregister_signature_removed` FAIL +
the `tree_operations.cleanup` WARN). Fixed by passing the length in the register each helper
actually reads. See A-ARM64-003 in `SPEC-AMBIGUITY-LOG.md` — a porting-discipline lesson, not
a spec defect.

## Reproduce

```
podman run --memory=4g --memory-swap=4g --pids-limit=4096 --cpus=4 --rm --network=none \
  -v "$PWD":/work:Z localhost/entity-core-keystone/asm-arm64-toolchain:latest \
  sh /work/protocol-generator/asm-arm64/run-s4.sh
```
(from the repo root; `make host` cross-builds the codec `.so` + assembles/links the aarch64
peer, run-s4 provisions the identity, boots under qemu, points the native oracle at it.)
Report JSON: `status/CONFORMANCE-REPORT.json`.
