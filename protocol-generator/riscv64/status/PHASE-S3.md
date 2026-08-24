# PHASE-S3 — entity-core-protocol-riscv64 (green)

The **third ISA** of the hand-authored assembly peer (after x86-64 and aarch64), ported off
`protocol-generator/asm-arm64` (the generic-syscall-table sibling). Transport + the
envelope/data-map CBOR + the entire dispatch/authority interior are hand-written **riscv64**
assembly (GAS, RV64GC); entity codec + Ed25519/SHA + peer-id are **FFI** via
`libentitycore_codec` (cross-built for riscv64 against a Debian trixie sysroot). The peer runs
under `qemu-riscv64-static`; the Go `validate-peer` oracle runs natively beside it, one
loopback, `--network=none`.

## Result — `--profile core` = Result: PASS (0 fail)

Reproducible full `--profile core` at oracle **`cc1970f`**:
**682 total · 583 pass · 3 warn · 0 fail · 96 skip (~13.1 s) — Result: PASS.** All 96 skips are
auto-allowlisted by the V7 §9.0 profile carve-out; **zero skips count as FAIL**. This is
**byte-identical to the x86-64 and aarch64 siblings' verdict** (583P/3W/0F/96S, same 3 WARNs:
`resource_bounds` r3 matches the reference's WARN, `authz.authz_scope_exceeds_1`
"spec-defensible", and the `tree_operations.cleanup` "non-critical"). Sub-targets all met:
**§7a `validate_echo_dispatch` PASS**, **concurrency 5/5** (incl. `t2_2_connection_churn` — the
clone/wait4/accept4 churn is faithful under qemu-riscv64), **security 28/29**, genuine §5.5
multisig **11/11** accept (`valid_2of3_peer_signed_accepted`), `universal_address_space` 8/8,
`peer_canonicalization` 7/7, `format_agility` 10/10, `crypto_agility` 4/4, `negotiation` 4/4.

**Honesty framing (ADR-0012).** This is **corroboration, not independent convergence**: the
riscv64 peer shares the x86-64/arm64 generation lineage (a mechanical ISA transliteration) and
FFIs the *same* codec `.so`. A cohort of transliterations passing one author's vectors is
cohort-consistent, not independent. Oracle-pinned `--profile core`, FFI-hybrid codec/crypto —
not full-profile. The session's real signal is the **toolchain finding** (riscv64 has a clean
first-class-distro FFI path — the "BLOCKED" call was Fedora-secondary-arch-specific; A-RISCV-002)
plus the **bijection-vs-seam observation** (A-RISCV-004).

## What the port entailed

- **Data (~310 lines) transferred verbatim** — the two `.rodata` atom blocks + two `.bss`
  `.lcomm` blocks are arch-neutral; only `//`→`#` comment conversion and `%function`→`@function`.
  `typestore.s` (arch-neutral generated data) is byte-identical, copied wholesale.
- **~5900 instruction lines transliterated** across all 75 functions by the codified
  aarch64→riscv64 register/ABI/syscall map (`src/macros.s`), via a **9-way parallel fan-out**
  along function boundaries. args `x0-x5`→`a0-a5`, ret `x0`→`a0`, callee-saved `x19-x28`→`s1-s10`
  with the **CBOR writer cursor x24→s6 globally**, syscall nr in a7 + `ecall`. Two riscv wrinkles:
  hand-rolled `bswap*` (no base-ISA byte-swap; A-RISCV-001) and the flag-less fused compare-branch
  (every `cmp`+`b.cc` repeats operands).
- **The port confirms the ISA-MAP Axis-A thesis a third time**: with the codec/crypto/peer-id
  behind the FFI, the protocol interior is a mechanical register/syscall swap — no protocol-logic
  change on any of the 75 functions.

## The seam that DIDN'T bite (A-RISCV-004)

arm64's port surfaced A-ARM64-003: the store helpers use a **per-function** length register, and
three x86→arm64 call sites passed it in the wrong register (garbage canonicalization → a revoked
cap accepted, an unregister that didn't delete). That was a symptom of x86→arm64 **register
pressure** — x86 has fewer registers, so the map is not a bijection and some live values land in
different places. **arm64→riscv64 IS a clean bijection** (both have ample registers + the same arg
model), so applying the fixed map preserves every callee's per-function arg register automatically
— even across a 9-way fan-out where no agent saw another slice. The riscv64 peer landed
**0-FAIL on the first full run**, with no seam-bug debugging pass. This is the durable lesson: the
fan-out risk is proportional to how far the map is from a bijection, and same-register-class ISA
ports (arm64↔riscv64) are near-free where cross-class ports (x86↔arm64) need the oracle to catch
the seam.

## Reproduce

```
podman run --memory=4g --memory-swap=4g --pids-limit=4096 --cpus=4 --rm --network=none \
  -v "$PWD":/work:Z localhost/entity-core-keystone/riscv64-toolchain:latest \
  sh /work/protocol-generator/riscv64/run-s4.sh
```
(from the repo root; `make host` cross-builds the codec `.so` + assembles/links the riscv64 peer,
run-s4 provisions the identity, boots under qemu, points the native oracle at it.)
Report JSON: `status/CONFORMANCE-REPORT.json`.
