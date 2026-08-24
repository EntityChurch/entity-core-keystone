# SPEC-AMBIGUITY-LOG — entity-core-protocol-riscv64

Decisions/findings surfaced building the riscv64 assembly peer — the **third ISA** (ported off
`asm-arm64`). `A-RISCV-*` entries are peer-local; the shared `A-ASM-*` protocol findings
(envelope-CBOR boundary, fork-per-conn head-of-line, per-fork `.bss` store, multisig M3, §7a
one-socket reentry, …) are **inherited unchanged** from
`../asm-x86_64/status/SPEC-AMBIGUITY-LOG.md`, and the arm64 generic-table findings
(`A-ARM64-001` fork→clone, `A-ARM64-003` per-function store-helper arg register) carry over from
`../asm-arm64/status/SPEC-AMBIGUITY-LOG.md` — the port changes the *machine*, not the *protocol*.
Only the riscv64-specific substrate/porting entries live here. Severity: `decision` / `info` /
`blocking`.

| ID | Sev | Phase | Title |
|---|---|---|---|
| A-RISCV-001 | decision | S1 | No base-ISA byte-swap on RV64GC (no Zbb `rev8`) → hand-rolled `bswap16/32/64` macros |
| A-RISCV-002 | decision | S1 | riscv64 is a Fedora *secondary* arch (no forcearch/sysroot) → glibc+libsodium sysroot from Debian trixie's first-class riscv64 port (retires the "BLOCKED" finding) |
| A-RISCV-003 | info | S1 | Debian libsodium 1.0.18 vs fedora 1.0.22 — same stable C-ABI; differential + conformance byte-identical |
| A-RISCV-004 | info | S3 | The A-ARM64-003 inter-function seam bug did NOT recur — arm64→riscv64 is a clean bijection, so per-function arg registers are preserved automatically |

---

## A-RISCV-001 — Hand-rolled byte-swap (decision, S1)

**Decision.** The CBOR head codec emits big-endian integer arguments; aarch64 does this with
`rev`/`rev16`. **Base RV64GC has no byte-reverse** — it lives in the `Zbb` bit-manipulation
extension (`rev8`). Rather than target `rv64gc_zbb` (an extension dependency on both the assembler
and qemu), the byteswap is **hand-rolled** in `src/macros.s` as `bswap16/32/64` (shifts + ands +
ors). The reader loads big-endian wire bytes with `ld`/`lwu` then `bswap`s to host; the writer
`bswap`s then stores little-endian — `bswap`+LE-store == BE-store, so the wire bytes are identical
to the sibling ISAs. Internal scratch is `t5`/`t6` only, verified never held live across a
byteswap call site. Base `rv64gc`, no extension, guaranteed qemu support. Non-blocking.

## A-RISCV-002 — Debian sysroot for the FFI×ISA cost (decision, S1) — retires "riscv BLOCKED"

**Decision/finding.** An earlier session logged riscv64·L1 as BLOCKED: Fedora ships no
`sysroot-riscv64-fc43-glibc`, and `dnf download --forcearch riscv64` 404s (riscv64 is a Fedora
*secondary* arch, not in the mirror metalink), so the arm64-style forcearch path (A-ARM64-002) does
not exist. That block was **Fedora-specific**, not a riscv64 property: **Debian trixie ships riscv64
as a first-class release architecture** — an official signed distro port, same trust class as
Fedora x86_64. The container assembles the glibc + libsodium sysroot from Debian trixie riscv64
`.debs`, fetched from the official deb.debian.org mirror, resolved via the signed Packages index,
extracted with `ar`+`tar`. **No foreign-arch code is executed at build time and no host
binfmt/qemu registration is needed** — the peer runs under `qemu-riscv64-static` invoked explicitly
inside the fedora:43 container (as arm64 does), and the Go oracle stays native x86-64. Two sysroot
mechanics (both baked into the Containerfile + `riscv64-cross-toolchain.cmake`): Debian trixie is
**merged-usr** (one `lib`→`usr/lib` symlink resolves the libc.so linker-script's absolute refs +
the DT_INTERP loader path), and **multiarch** (fedora's non-multiarch cross-gcc needs explicit
`-I…/usr/include/riscv64-linux-gnu` for `bits/` headers + `-B…/usr/lib/riscv64-linux-gnu` for
startfiles). Verified end-to-end: 71/71 wire vectors + `ec_sha256` KAT green under qemu.
Non-blocking.

## A-RISCV-003 — Debian libsodium version (info, S1)

**Finding.** Debian trixie ships libsodium **1.0.18**; fedora (x86-64/arm64) ships **1.0.22**. The
codec (`entity-core-codec-ffi-c`) uses only the long-stable libsodium C-ABI — Ed25519 sign/verify,
SHA-256/512, generichash — all present well before 1.0.18. The 71-vector differential and the full
`--profile core` conformance are byte-identical across all three ISAs regardless of the libsodium
minor. Recorded for provenance; no action. Non-blocking.

## A-RISCV-004 — The seam that didn't bite (info, S3)

**Finding (porting discipline — the mirror image of A-ARM64-003).** arm64's port surfaced a
cross-function ABI drift: the store helpers take their path length in a **per-function** register
(x3 for `canon_path`/`store_get`/`path_valid`, x1 for `store_delete`, x2 for `cas_check`), and
three x86→arm64 call sites passed it in the wrong register → garbage canonicalization → a **revoked
capability accepted (200)** and an **unregister that didn't delete the signature entity**. Those
were symptoms of x86→arm64 **register pressure**: x86-64 has fewer GPRs, so the x86→arm64 map is
*not* a bijection — some values live in different register classes and a mechanical rename can
misplace them.

**arm64→riscv64 IS a clean bijection** (both ISAs have ample registers + the same arg-passing
model), so applying the fixed map (`x0-x5`→`a0-a5`, `x19-x28`→`s1-s10`, cursor `x24`→`s6`)
preserves **every callee's per-function arg register automatically** — the caller and callee each
rename the same source register to the same target register, so the seam is closed by
construction. Concretely: the riscv64 peer was ported by a **9-way parallel fan-out** where no
agent saw any other slice, yet it landed **0-FAIL on the first full conformance run** — no
seam-bug debugging pass, unlike arm64's 3 initial FAILs. **Lesson:** the fan-out/transliteration
risk is proportional to how far the register map is from a bijection. Same-register-class ISA ports
(arm64↔riscv64) are near-free; cross-class ports (x86↔arm64) need the oracle to catch the seam and
warrant an explicit per-call-site arg-register audit. Non-blocking.
