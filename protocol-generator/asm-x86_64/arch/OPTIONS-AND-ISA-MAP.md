# Options & ISA Map — the design space for hand-authored assembly peers

Exploration output (session 2026-07-13). Maps the option space for implementing the
protocol in hand-authored assembly, so the roadmap picks **non-redundant** build points
(each teaching something the others don't) rather than grinding one track by reflex. The
x86-64 peer (S1 + FFI bridge proven, committed `1ca7877`) is the template; this doc is its
family design map. All syscall numbers + calling conventions below are **verified from the
fedora:43 kernel headers** (`asm/unistd_64.h`, `asm-generic/unistd.h`) in-container, not
from memory.

## The four independent axes

An asm peer is a point in a 4-axis space. The axes are orthogonal — you can move on one
without the others — so the interesting question is *which combinations teach something new*.

| Axis | Values | What it stresses |
|---|---|---|
| **A. ISA** | x86-64 · ARM64 (AArch64) · RISC-V (RV64) | register file, calling convention, syscall ABI, toolchain/qemu |
| **B. Hand-roll level** | L1 FFI-all · L2 asm-codec + FFI-crypto · L3 pure (asm codec + crypto) | how much of the byte/crypto work is native vs borrowed |
| **C. Link / startup** | cc-driver + `main` · freestanding `_start` · dynamic vs static | runtime dependency surface (libc? loader?) |
| **D. Concurrency** | single-thread epoll · `clone` threads + futex | the §4.8/§6.11 concurrency mapping |

The **protocol logic is invariant across all of them** — wire bytes, dispatch structure,
CBOR map shapes, capability walk, the §9.1 floor. Only the *mechanical shell* changes. That
is the whole thesis of the asm family: it isolates "what is protocol" from "what is machine."

---

## Axis A — ISA porting map (x86-64 → ARM64 → RISC-V)

The single most important empirical finding: **ARM64 and RISC-V both use the kernel's
"generic" syscall table** (`asm-generic/unistd.h`) and both put the syscall number in a
*high* register distinct from arg0, while **x86-64 uses its own legacy table**. So arm64 and
riscv are far more similar *to each other* than either is to x86-64 — a port from arm64 to
riscv is nearly a register-rename; a port from x86-64 to either is a table swap.

### Calling convention (SysV / AAPCS64 / RISC-V) — verified

| | x86-64 (SysV AMD64) | ARM64 (AAPCS64) | RISC-V (RV64) |
|---|---|---|---|
| Call args | `rdi rsi rdx rcx r8 r9` | `x0 x1 x2 x3 x4 x5 x6 x7` | `a0 a1 a2 a3 a4 a5 a6 a7` |
| Call return | `rax` | `x0` | `a0` (`a1` hi) |
| Callee-saved | `rbx rbp r12–r15` | `x19–x28` (`x29` FP, `x30` LR) | `s0–s11` (`s0`=FP, `ra`, `sp`) |
| Stack align at `call` | 16-byte | 16-byte | 16-byte |
| `(ptr,len)` pair | 2 regs | 2 regs | 2 regs |

### Syscall ABI — verified

| | x86-64 | ARM64 | RISC-V |
|---|---|---|---|
| Trap instruction | `syscall` | `svc #0` | `ecall` |
| Syscall number in | `rax` | `x8` | `a7` |
| Syscall args | `rdi rsi rdx r10 r8 r9` | `x0 x1 x2 x3 x4 x5` | `a0 a1 a2 a3 a4 a5` |
| Return | `rax` (−errno on fail) | `x0` | `a0` |
| Clobbers | `rcx r11` | (none beyond args) | (none beyond args) |

**Key ergonomic difference:** on x86-64 the syscall arg registers *differ* from the call arg
registers (`rcx`→`r10` for arg4) — a classic bug source. On arm64/riscv the syscall args are
the **same** registers as the first 6 call args (`x0–x5` / `a0–a5`) — simpler and less
error-prone. So the arm64/riscv shell is arguably *cleaner* asm than x86-64's.

### Syscall numbers the peer needs — verified from headers

| syscall | x86-64 | generic (arm64 & riscv) |
|---|---|---|
| read | 0 | 63 |
| write | 1 | 64 |
| close | 3 | 57 |
| openat | 257 | 56 |
| socket | 41 | 198 |
| bind | 49 | 200 |
| listen | 50 | 201 |
| accept4 | 288 | 242 |
| setsockopt | 54 | 208 |
| epoll_create1 | 291 | 20 |
| epoll_ctl | 233 | 21 |
| epoll_wait | 232 | **— (absent)** |
| epoll_pwait | 281 | 22 |
| mmap | 9 | 222 |
| clone | 56 | 220 |
| exit_group | 231 | 94 |

**Two portability gotchas (verified):**
1. The generic table (arm64/riscv) has **no `epoll_wait`** — only `epoll_pwait` (22). The
   port must call `epoll_pwait` with a NULL sigmask (a 6th arg) instead of `epoll_wait`.
   x86-64 has both, so writing x86-64 against `epoll_pwait` from the start makes the shell
   portable for free.
2. The generic table has **no bare `open`** (openat-only). x86-64 has `open` (2); the
   keypair read should use `openat(AT_FDCWD, …)` on x86-64 too, for a portable shell.

Writing the x86-64 template *pre-adapted to the generic conventions* (openat, epoll_pwait)
makes the arm64/riscv port a mechanical register+number substitution.

### Toolchain / execution reality

- **x86-64**: native on the dev host + fedora container. `as`/`cc`/`ld` from stock binutils.
  No emulation. (This is why it's the template — tightest debug loop.)
- **ARM64 / RISC-V**: do **not** run natively on the x86-64 host. Need either a cross
  binutils (`binutils-aarch64-linux-gnu` / `-riscv64-linux-gnu`) + `qemu-user` to run, or a
  foreign-arch container via qemu binfmt. GAS handles all three targets (it's the same
  assembler family; only the target syntax/mnemonics differ — ARM/RISC-V GAS is native
  syntax, not AT&T). Slower loop; land x86-64 green *first*, then port.

### ⚠ The FFI × ISA interaction — the load-bearing finding

`libentitycore_codec.so` is prebuilt **x86-64 only**. A Level-1 (FFI-all) arm64 or riscv
peer therefore needs the **codec rebuilt for that arch** — cross-compiling the C impl
*and its libsodium dependency*, or building it under qemu-user. So the FFI-hybrid level
that makes x86-64 *easy* makes the ISA port *heavier*: it drags a per-arch C + libsodium +
qemu toolchain along.

This inverts intuition and shapes the roadmap: **a pure-asm codec (Level 2/3) is more
portable across ISAs than the FFI-hybrid**, because pure asm has *no* foreign-arch library
dependency — only the register file changes. Axes B and A are coupled: if the goal is
"the protocol on three ISAs", pushing toward Level 2/3 pays for itself; if the goal is
"the protocol on the bare machine, fastest", Level-1 x86-64 wins. Pick per intent.

---

## Axis B — hand-roll level

| Level | Hand-rolled in asm | FFI'd | Cost | What it teaches |
|---|---|---|---|---|
| **L1** (current) | transport, envelope/data-map CBOR, dispatch, store, capability walk, §9.1 floor, identity, CLI | **entire** entity codec + Ed25519 + SHA-256 + base58 + peer-id | lowest | protocol control-flow on bare metal; the A-ASM-004 envelope-CBOR surface |
| **L2** | + the canonical **entity ECF codec** (varint, shortest-float f16 ladder, length-then-lex key sort, recursive tag-reject, base58) | Ed25519 only (field arithmetic) | high | canonical-CBOR byte-work in asm — the codec conformance floor becomes native |
| **L3** (pure) — **DEFERRED indefinitely (2026-07-15)** | + **SHA-256 + Ed25519** (RFC 8032 field arithmetic) | nothing | very high | a fully self-contained peer, zero external deps — but per-ISA (doesn't aid ports), high-risk crypto, ~zero discovery value; crypto stays linked-compiled. See matrix point 5. |

Note A-ASM-004: even L1 is not "zero CBOR" — the envelope/data maps are always
hand-rolled. L2's added surface is the *entity* codec (the hard canonical layer). L3 adds
the crypto field arithmetic (the highest-risk asm — constant-time discipline matters if it
were production; for conformance it's correctness-only).

**Where the research signal is:** L1 answers "does the control-flow map onto asm?" (mostly
yes, expected). L2 answers "can the canonical-CBOR invariants (N1–N4) be expressed in asm
and stay byte-exact?" — genuinely more interesting, and the natural cross-check against the
FFI'd codec (differential: hand-rolled asm vs `libentitycore_codec` on the 71-vector
corpus). L3 is a portability/purity artifact more than a discovery one.

---

## Axis C — link / startup

| Option | Entry | libc | Notes |
|---|---|---|---|
| **cc-driver + `main`** (current) | `main` | loaded + initialized by crt0/`__libc_start_main` | robust; the codec `.so` needs libc anyway, so this costs nothing at L1. `-no-pie`. |
| **freestanding `_start`** | `_start` | none (or manual init) | only coherent with L3 (pure) — at L1/L2 the codec `.so` still drags libc, so a bare `_start` must hand-init libc's TLS/errno (fragile, zero benefit). Pair `_start` with L3 static, or not at all. |
| **static vs dynamic** | — | — | dynamic (`-lentitycore_codec` + rpath) = simpler iteration; static (`.a`) = self-contained ELF, the shippable form. Both build the same peer. |

**Coupling:** freestanding `_start` only makes sense at L3 (pure, static). At L1/L2 it's a
trap. So "`_start` purity" is not an independent option — it's the tail of the L3 track.

---

## Axis D — concurrency

| Option | Mechanism | Cost | Chosen? |
|---|---|---|---|
| **single-thread epoll** | `epoll_pwait` readiness loop over non-blocking fds; §6.11 demux by `request_id` in one thread | low | **yes** (A-ASM-003) — interleaved progress satisfies `--profile core`; no thread-stack/futex hand-management |
| **`clone` threads + futex** | one thread per connection, futex mutex on the shared store | high | no — materially harder in asm for no core-profile benefit; revisit only if a multi-peer origination probe needs true parallelism |

Orthogonal to A/B/C. The epoll choice ports across ISAs unchanged (same generic
`epoll_*` numbers on arm64/riscv, modulo `epoll_pwait`).

---

## The build-point matrix — what's worth building

Not all 3×3×3×2 points are distinct research. The non-redundant sequence:

1. **x86-64 · L1 · cc+main · epoll** — *in progress.* The template. Answers "protocol
   control-flow on bare metal." Land green first (S2→S4).
2. **x86-64 · L2 · cc+main · epoll** — the highest-signal *next* asm point: canonical-CBOR
   byte-work in asm, differentially cross-checked against the FFI'd codec. Retires the
   "asm can't do canonical CBOR" question.
3. **ARM64 · L1 · cc+main · epoll** — first ISA port. Proves the shell is register-file-swap
   + generic-table. *Requires the codec built for arm64* (the FFI×ISA cost) — or defer to a
   pure track to avoid it.
4. **RISC-V · L1 · cc+main** — ~~nearly free after arm64 (shared generic table)~~
   ~~BLOCKED (2026-07-15) → move to L3~~ ~~UNBLOCKED (2026-07-15, corrected)~~ **✅ LANDED GREEN
   (2026-07-16, `protocol-generator/riscv64/`): `--profile core` = 682·0F (Result: PASS),
   583P/3W/0F/96S @ `cc1970f`, byte-identical to x86-64/arm64.** The block was a Fedora-only
   packaging gap, not a riscv problem: riscv64 is a Fedora *secondary* arch (no prebuilt glibc
   sysroot, `forcearch riscv64` 404s), but **Debian trixie ships riscv64 as a first-class release
   architecture**. The **actual landed path was even cleaner than the predicted
   `--platform linux/riscv64 debian:trixie` full-container route**: base the toolchain container on
   `fedora:43` (cross binutils/gcc + `qemu-user-static-riscv`, as arm64), and assemble the
   glibc+libsodium sysroot from Debian trixie riscv64 **`.debs`** (fetched from deb.debian.org,
   resolved via the signed Packages index, extracted with `ar`+`tar`). That needs **no host
   binfmt/qemu registration and executes no foreign-arch code at build time** — the peer runs under
   `qemu-riscv64-static` invoked explicitly and the Go oracle stays native x86-64 (the arm64 model,
   sysroot-source swapped). No crypto, no L3 dependency. Findings: A-RISCV-002 (Debian sysroot,
   retires "BLOCKED"), A-RISCV-001 (hand-rolled bswap — no base-ISA `rev8`), A-RISCV-004 (the
   arm64→riscv64 map is a clean **bijection**, so the A-ARM64-003 inter-function seam bug did NOT
   recur — 0-FAIL first run across a 9-way parallel fan-out; fan-out risk ∝ distance from a
   bijection). Detail: `protocol-generator/riscv64/status/` +
   `docs/status/HANDOFF-2026-07-16-riscv-l1-GREEN.md`.
5. **x86-64 · L3 · `_start` · static · epoll** — the purity capstone. **DEFERRED (2026-07-15,
   user decision) — likely indefinitely.** Rationale: (a) **it does not serve riscv** — the
   headline justification ("L3 enables cheap riscv") was *backwards*: hand-written asm crypto is
   **per-ISA**, so it would have to be re-authored for riscv, the *least* portable option; riscv
   is unblocked at L1 (point 4) with zero hand-crypto. (b) **Crypto is the boundary the
   methodology deliberately does not hand-author** — AGENTS: *"crypto … stays owned by KATs …"*;
   Ed25519 field arithmetic (mod 2²⁵⁵−19: carry propagation, constant-time) is exactly the
   high-blast-radius code a single bug ruins. (c) **~Zero discovery value** — L2 already retired
   the "can asm express canonical CBOR byte-exact" question; L3 is a purity artifact, not a
   finding. **Crypto stays linked-compiled (the existing FFI codec / a self-contained ref lib
   for foreign arches), never hand-written.** Revisit only as a deliberate bare-metal exercise
   for a genuinely bespoke architecture with no C toolchain — not on the current roadmap.

Everything else (e.g. clone-threads, freestanding `_start` at L1) is a redundant or
incoherent point — noted here so the roadmap doesn't wander into it.

## Recommended roadmap

**Status (2026-07-15): the asm probe's discovery arc is complete.** Points 1, 2, 3 are DONE
(x86-64 L1 green 682·0F; x86-64 L2 native codec green, `signature`-construction finding A-ASM-018
harvested; arm64 L1 green, byte-identical). L2 answered the real discovery bet ("can asm express
canonical-CBOR N1–N4 byte-exact?" → yes). Per AGENTS' own doctrine — *"a peer novel only off-wire
adds generator robustness, not new findings … the spec-discovery well is dry"* — everything
remaining on this substrate is **corroboration, not discovery**.

- **Done:** points 1 (x86 L1), 2 (x86 L2), 3 (arm64 L1). The x86 shell was written pre-adapted to
  generic conventions (`openat`, `epoll_pwait`), so the arm64 port was a register-file swap as
  predicted.
- **L3 (point 5): DEFERRED indefinitely** (see point 5) — no discovery value, high risk,
  crypto stays linked-compiled. Not a hand-write-crypto project.
- **RISC-V L1 (point 4): the one remaining *optional* item** — a portfolio/robustness "third ISA"
  point, not new signal. Achievable in ~hours via a first-class-riscv64 distro under
  `qemu-riscv64-static` (or full-system QEMU) — **no crypto, no L3**. Pick it up only if the
  third-ISA breadth is wanted for its own sake.
- **Steady state:** re-run the asm cohort (x86 + arm64, + riscv if built) against each spec
  amendment — the ecosystem's stated steady-state value, not adding levels or ISAs.
- **WASM/WASI** is a *different* substrate axis (sandboxed, capability-based, linear-memory)
  and a separate track — **now COMPLETE (2026-07-15):** three peers landed green — `wasm-wat`
  (hand-authored WAT), `rust-wasm` (Rust→`wasm32-wasip1`, WasmEdge/JIT), and `rust-wasm-wasmtime`
  (the SAME module under wasmtime **AOT**, compile-once-run-native). Note the correction to the
  plan above: the AOT peer targets **`wasm32-wasip1`, not wasip2** — `wasmtime compile` is
  WASI-version-agnostic, so wasip1 gives a controlled comparison + a distro-pure toolchain
  (fedora ships no wasip2 std); a **host-preopened listener** (`-S tcplisten`) + standard wasip1
  `sock_accept` replaced the presumed wasi-sockets/preview2 shim. See
  `protocol-generator/shared/evaluations/wasm-codegen-comparison.md` +
  `docs/status/HANDOFF-2026-07-15-wasmtime-aot-green-wasm-branch-complete.md`. wasip2 is a
  deferred forward-ABI probe.

## Honesty framing (ADR-0012)

Every point above is expected to land `--profile core` 0-FAIL as **corroboration** — the
wire-touching axes are saturated by the 30-peer cohort; the asm family's value is
generator-robustness + substrate-dynamics (how the protocol maps onto the bare machine and
across ISAs), not independent convergence. State this in each peer's status.
