# SPEC-AMBIGUITY-LOG — entity-core-protocol-asm-arm64

Decisions/findings surfaced building the aarch64 assembly peer — the **first ISA port** off
`asm-x86_64`. `A-ARM64-*` entries are peer-local; the shared `A-ASM-*` protocol findings
(envelope-CBOR boundary, fork-per-conn head-of-line, per-fork `.bss` store, multisig M3,
§7a one-socket reentry, …) are **inherited unchanged** from
`../asm-x86_64/status/SPEC-AMBIGUITY-LOG.md` — the port changes the *machine*, not the
*protocol*, so none of them re-open. Only the aarch64-specific substrate/porting entries live
here. Severity: `decision` / `info` / `blocking`.

| ID | Sev | Phase | Title |
|---|---|---|---|
| A-ARM64-001 | info | S1 | No `fork` in the aarch64 generic syscall table → `clone(SIGCHLD,0,0,0,0)` |
| A-ARM64-002 | decision | S1 | Cross libsodium is unpackaged → `dnf download --forcearch` into the cross sysroot; sysroot is the `aarch64-redhat-linux` triple + needs `/lib /lib64` usrmerge symlinks for qemu |
| A-ARM64-003 | info | S3 | Store-helper length-argument register is **per-function** (x3 for canon_path/store_get/path_valid, x1 for store_delete, x2 for cas_check) — a uniform "len→x2" porting assumption silently mis-canonicalizes |

---

## A-ARM64-001 — `fork` → `clone(SIGCHLD)` (finding, S1)

**Finding.** The x86-64 peer's `host.s` uses `fork(2)` per accepted connection (A-ASM-003's
shipped model). The **aarch64 generic syscall table has no `fork`** — `__NR_fork` is undefined
(header-verified); the fork-equivalent is `clone(2)` with flags `SIGCHLD` and null
stack/ptid/ctid/tls: `clone(SIGCHLD, 0, 0, 0, 0)`. `wait4`/`accept4` are present and
unchanged. Handled in `host.s`; `dispatch.s` itself issues no `fork`. qemu-user emulates the
clone/wait4/accept4 churn faithfully at ~4000 conn/s (8000/8000 fork-churn probe, 0 errors —
`status/PHASE-S1.md`). Non-blocking.

## A-ARM64-002 — Cross-toolchain libsodium + sysroot shape (decision, S1)

**Decision/finding.** Fedora ships libsodium for x86_64/i686 only — there is no packaged
aarch64 build for the codec `.so` to link. Resolved by `dnf download --forcearch aarch64` and
unpacking into the cross sysroot. Two sysroot gotchas, both baked into the Containerfile +
Makefile: (a) the cross sysroot ships under the **`aarch64-redhat-linux`** triple
(`/usr/aarch64-redhat-linux/sys-root/fc43`), **not** the driver's default `aarch64-linux-gnu`
sysroot — the link needs an explicit `--sysroot`; (b) it lacks the `/lib` `/lib64` usrmerge
symlinks the qemu-user guest loader needs, so those are added. Non-blocking.

## A-ARM64-003 — Store-helper length-argument register is per-function (finding, S3)

**Finding (porting discipline — the one bug this ISA port surfaced).** When the codec/crypto
is behind the FFI, transliterating the protocol interior is mechanical *within* a function,
but the **cross-function ABI** must be honored exactly — and the store helpers do **not** use
a uniform length register. Their x86-64 SysV signatures map to different aarch64 arg registers:

| helper | x86-64 args | aarch64 length reg |
|---|---|---|
| `canon_path` / `store_get` / `path_valid` | `rsi`=ptr, `rcx`=len | **x3** |
| `store_delete` | `rdi`=ptr, `rsi`=len | **x1** |
| `cas_check` | `rdi`=map, `rsi`=ptr, `rdx`=len | **x2** |
| `pcat` (returns) | → `rax`=ptr, `rdx`=len | returns len in **x2** |

A natural but wrong porting assumption — "a length always folds to x2" (true for `read_head`/
`get_text`/`pcat` *returns*, and for `memeq`'s standardized len arg) — put the length in x2 at
three `canon_path`/`store_get` **call** sites (in `is_revoked` and `store_delete`/
`serve_tree_listing`). Those calls then canonicalized with a garbage length → wrong store key
→ silent lookup miss. It assembled clean and passed 580/583 checks; the only symptoms were two
authority FAILs (a **revoked cap accepted 200**) and one handler FAIL (**unregister left the
signature entity**) — exactly the paths whose store key is computed via those helpers. Fix:
pass the length in the register each helper reads.

**Lesson (carried to the next ISA port / any parallel transliteration).** The intra-function
translation is safe to fan out; the **inter-function ABI is the seam that bites**. A helper's
arg-register map is part of its contract and is *not* uniform across helpers — verify each
call site against the callee's actual signature, not a global "len lives in xN" heuristic. A
per-fragment assemble catches syntax but **not** a wrong-but-valid register; only the
conformance oracle does, and only on the specific path that helper gates. Non-blocking.
