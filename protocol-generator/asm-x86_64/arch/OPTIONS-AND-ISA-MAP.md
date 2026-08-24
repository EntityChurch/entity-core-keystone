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
| **L3** (pure) | + **SHA-256 + Ed25519** (RFC 8032 field arithmetic) | nothing | very high | a fully self-contained peer, zero external deps — max portability, max effort |

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
4. **RISC-V · L1 · cc+main · epoll** — nearly free after arm64 (shared generic table); proves
   the port is now a rename. Corroboration.
5. **x86-64 · L3 · `_start` · static · epoll** — the purity capstone: zero-dependency,
   self-contained ELF. Also the *enabler* for cheap arm64/riscv ports (no foreign libsodium).

Everything else (e.g. clone-threads, freestanding `_start` at L1) is a redundant or
incoherent point — noted here so the roadmap doesn't wander into it.

## Recommended roadmap

- **Now:** finish point 1 (x86-64 L1 green: S2 self-check → S3 peer → S4 `--profile core`
  0-FAIL). Write the x86-64 shell *pre-adapted* to generic conventions (`openat`,
  `epoll_pwait`) so ports are mechanical.
- **Then, by signal:** point 2 (L2 asm codec, the real discovery bet) **or** point 3
  (arm64 port, the reach bet). If reach is the goal, seriously weigh jumping to the L3/pure
  track to sidestep per-arch codec builds — the FFI×ISA finding says pure is *more* portable.
- **Corroboration:** riscv after arm64 (shared table → cheap).
- **WASM/WASI** is a *different* substrate axis (sandboxed, capability-based, linear-memory)
  and a separate track — compile the green Rust peer to `wasm32-wasip2` under wasmtime; not
  an asm-family point. (See `docs/status/HANDOFF-2026-07-13-asm-wasm-next.md`.)

## Honesty framing (ADR-0012)

Every point above is expected to land `--profile core` 0-FAIL as **corroboration** — the
wire-touching axes are saturated by the 30-peer cohort; the asm family's value is
generator-robustness + substrate-dynamics (how the protocol maps onto the bare machine and
across ISAs), not independent convergence. State this in each peer's status.
