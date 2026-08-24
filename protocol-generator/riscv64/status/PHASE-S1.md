# riscv64 — Phase S1 / port progress

Third ISA of the hand-authored assembly peer, ported off `protocol-generator/asm-arm64` (the
generic-syscall-table sibling — NOT asm-x86_64), per
`docs/status/HANDOFF-2026-07-15-asm-L2-COMPLETE-l3-deferred.md` §5. Risk-first ordering
(step-0 toolchain gate FIRST, exactly where the earlier "BLOCKED" finding surfaced).

## Done + verified (all under `qemu-riscv64-static`, sealed `--network=none`)

| Piece | State | Evidence |
|---|---|---|
| **step-0 toolchain gate** | ✅ | fedora:43 cross binutils/gcc + `qemu-user-static-riscv` install; Debian trixie riscv64 sysroot assembled from `.debs`; trivial dynamic main runs under qemu (exit 42); libsodium `sha256("abc")` byte-exact — the retired "BLOCKED" finding (A-RISCV-002) |
| `containers/riscv64-toolchain` | ✅ | cross tools + qemu + Debian riscv64 glibc+libsodium sysroot (merged-usr symlinks; `-B`/`-I` for the multiarch dir) |
| Codec `.so` cross-build (FFI×ISA) | ✅ | RISC-V riscv64, **27 `ec_*` exports**, self-contained (static libsodium); **71/71 conformance vectors PASS** under qemu |
| `ffi_smoke.s` | ✅ | `ec_sha256("abc")` byte-exact vs RFC6234 KAT through the LP64D call |
| `macros.s` | ✅ assembles | the aarch64→riscv64 register/ABI/syscall convention + `bswap16/32/64` (A-RISCV-001) |
| `cbor.s` | ✅ assembles | reader + writer prims; exports read_head/skip_value/map_find/get_text/memeq/w_* |
| `host.s` | ✅ assembles | boot + clone-per-conn accept loop + helpers; exports g_seed/g_pubkey/g_peerid/… |
| `typestore.s` | ✅ assembles | **byte-identical** to x86-64/arm64 (arch-neutral generated data — copied verbatim) |
| **`dispatch.s`** | ✅ ported | 75 functions / ~5900 instr lines transliterated (9-way parallel fan-out); assembles clean (6704 lines) |
| link + `run-s4` green gate | ✅ **PASS** | `--profile core` **682·0F** (583P/3W/0F/96S) @ `cc1970f`, byte-identical to x86-64/arm64 — see `PHASE-S3.md` |
| status docs / matrix row | ✅ done | `PHASE-S3.md`, `SPEC-AMBIGUITY-LOG.md` (A-RISCV-001..004), CONFORMANCE-MATRIX row |

## Findings that retire the earlier "riscv BLOCKED" call

- **riscv64 was never really blocked — it was Fedora-secondary-arch-specific.** Fedora ships no
  `sysroot-riscv64-fc43-glibc` and `dnf download --forcearch riscv64` 404s (no mirror metalink).
  But **Debian trixie ships riscv64 as a first-class release architecture** — an official signed
  distro port. The glibc + libsodium sysroot is assembled from Debian trixie riscv64 `.debs`
  (fetched from deb.debian.org, resolved via the signed Packages index, extracted with ar+tar —
  **no foreign-arch code executed at build, no host binfmt/qemu needed**). This is the one
  "first-class riscv64 distro" deviation from the fedora:43 sysroot; cross tools, qemu, and the
  Go oracle all stay native fedora:43 x86-64. (A-RISCV-002.)
- **No base-ISA byte-swap on RV64GC.** aarch64 `rev`/`rev16` has no base-RV64 equivalent (byte-
  reverse is the `Zbb` extension's `rev8`). Rather than depend on Zbb, the CBOR head byteswap is
  **hand-rolled** in `macros.s` as `bswap16/32/64` (shifts+ands+ors; `bswap`+LE-store == BE-store,
  preserved). Base `rv64gc`, no extension dependency, guaranteed qemu support. (A-RISCV-001.)
- **libsodium is 1.0.18 on Debian trixie vs 1.0.22 on fedora x86/arm64** — the codec uses only the
  long-stable C-ABI (Ed25519, SHA-256/512, generichash), so the differential + full conformance
  are byte-identical regardless. (A-RISCV-003.)

## Porting convention (codified in macros.s)

aarch64 (AAPCS64) → riscv64 (LP64D), a **clean bijection**: args `x0-x5`→`a0-a5`, ret `x0`→`a0`,
callee-saved `x19-x28`→`s1-s10` (**CBOR writer cursor x24→s6 globally**), syscall nr in a7 +
`ecall` (same generic-table numbers). `adr_l`(adrp+lo12)→`lla`(auipc+addi); `cbz/cbnz`→
`beqz/bnez`; **no condition flags** → every `cmp`+`b.cc` becomes a fused compare-branch repeating
operands (`b.lo/hs`→`bltu/bgeu`, `b.lt/ge`→`blt/bge`, imm→`li` into a temp); `tbnz x,#63`→`bltz`;
`rev`/`rev16`→`bswap*`; `stp/ldp`→`addi sp`+individual `sd/ld`; indexed/post-index addressing →
explicit address add.

## dispatch.s port method (9-way parallel fan-out)

The 75-function / ~5900-instruction-line `dispatch.s` was split at function boundaries into 9
contiguous slices (A..I), each translated by an independent agent handed the codified convention
+ the two bilingual worked examples (`cbor.s`/`host.s` in both ISAs) + the register-map table,
each **self-assembling its fragment in-container** before integration, then concatenated in the
source's section order (head · rodata1 · bss1 · text1 · rodata2 · bss2 · text2 · GNU-stack). The
arch-neutral data sections (~310 lines) transferred verbatim (only `//`→`#` comment conversion +
`%function`→`@function`). **All 9 fragments integrated and the full peer passed `--profile core`
0-FAIL on the FIRST full run** — see A-RISCV-004: the A-ARM64-003 inter-function seam bug did not
recur, because unlike x86→arm64 (register-pressure divergence) the arm64→riscv64 map is bijective,
so every callee's per-function arg register is preserved automatically.
