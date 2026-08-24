# asm-arm64 — Phase S1 / port progress

First ISA port off `protocol-generator/asm-x86_64` (the Level-1 FFI-all template), per
`docs/status/HANDOFF-2026-07-15-arm64-l1-next.md`. Risk-first ordering.

## Done + verified (all under `qemu-aarch64-static`, sealed `--network=none`)

| Piece | State | Evidence |
|---|---|---|
| `containers/asm-arm64-toolchain` | ✅ | cross binutils/gcc + aarch64 glibc sysroot + qemu-user + aarch64 libsodium (forcearch) |
| Codec `.so` cross-build (FFI×ISA) | ✅ | ARM aarch64, 27 `ec_*` exports, self-contained; **71/71 conformance vectors PASS** under qemu |
| `ffi_smoke.s` | ✅ | `ec_sha256("abc")` byte-exact vs RFC6234 KAT through the AAPCS64 call |
| qemu fork-fidelity probe | ✅ | clone(SIGCHLD)+wait4+accept4 churn **8000/8000, 0 errors**, no zombie/pid exhaustion |
| `macros.s` | ✅ assembles | the x86-64→aarch64 register/ABI/syscall convention (below) |
| `cbor.s` | ✅ assembles | reader + writer prims; exports read_head/skip_value/map_find/get_text/memeq/w_* |
| `host.s` | ✅ assembles | boot + clone-per-conn accept loop + helpers; exports g_seed/g_pubkey/g_peerid/… |
| `typestore.s` | ✅ assembles | regenerated from blobs; **byte-identical** to x86-64 (arch-neutral data) |
| **`dispatch.s`** | ✅ ported | 75 functions / ~6200 instr lines transliterated; assembles clean |
| link + `run-s4` green gate | ✅ **PASS** | `--profile core` **682·0F** (583P/3W/0F/96S) @ `cc1970f`, byte-identical to x86-64 — see `PHASE-S3.md` |
| status docs / matrix row / takeaways | ✅ done | `PHASE-S3.md`, `SPEC-AMBIGUITY-LOG.md` (A-ARM64-001/002/003), CONFORMANCE-MATRIX row |

## Findings that correct/extend the kickoff handoff

- **Cross libsodium is NOT packaged** (fedora ships it x86_64/i686 only). Solved by
  `dnf download --forcearch aarch64` + unpack into the cross sysroot. The sysroot itself ships
  under the `aarch64-redhat-linux` triple (not the driver's default `aarch64-linux-gnu`) and lacks
  the `/lib /lib64` usrmerge symlinks qemu-user needs for the guest loader — both handled in the
  Containerfile.
- **The real peer is `clone(SIGCHLD)`-per-connection, NOT the epoll single-thread the ISA-MAP's
  Axis D describes** (host.s uses `fork`; A-ASM-003). And the generic table has **no `fork`**
  (`__NR_fork` undefined) → the port must use `clone(SIGCHLD,0,0,0,0)` (A-ARM64-001). qemu emulates
  it faithfully at ~4000 conn/s — ample for validate-peer's churn probes.

## Porting convention (codified in macros.s)

x86-64 (SysV) → aarch64 (AAPCS64): args `rdi rsi rdx rcx r8 r9`→`x0 x1 x2 x3 x4 x5`; ret `rax`→`x0`;
callee-saved `rbx rbp r12-r15`→`x19-x24` (**CBOR writer cursor r15→x24 globally**); syscall nr in
x8, `svc #0`, args x0-x5 (**no r10-for-arg4 divergence** — a genuine simplification vs x86-64).
`lea sym(%rip)`→`adr_l` (adrp + :lo12:); `test;jz`→`cbz`; `cmp;jcc`→`cmp;b.cc`. Watch aarch64
logical-immediate encodability (e.g. `0x19`/`0xa0` are not valid ORR imms → mov-scratch-then-orr).

## dispatch.s port plan

Same mechanical translation, applied to the 75 functions. Structure (from the x86-64 source):
- **Core loop:** `peer_bootstrap`, `conn_serve`, `read_full`, `dispatch` (operation router),
  `op_is_known`, `send_error`.
- **Handlers:** hello (`build_hello_response`, `check_hello_negotiation`), `build_authenticate_response`,
  `build_echo_response`, tree get/put (`serve_tree_get`/`serve_tree_put` + store_get/put/canon/cas),
  capability (`build_request_response`/`mint_finish`, delegate/configure/revoke), handler
  register/unregister, `serve_dispatch_outbound`/`handle_dispatch_response` (§7a), listing + sort.
- **Authz interior:** `verify_get_auth`/`verify_multisig_granter`/`verify_get_cap`/`verify_get_scope`,
  grant/scope/resource matching (`grant_covers`/`grants_attenuated`/`resource_matches`/…).
- **Data/bss:** a second `.rodata`/`.bss` block near the file tail defines the `va_*` op strings,
  `ta_*`/`ka_*` type/key atoms, `ec_*` error codes, and the store/listing/multisig scratch buffers —
  all arch-neutral (`.asciz`/`.lcomm`), transfer directly.

No new wire axes here — every op routes through the same FFI codec + hand-rolled envelope CBOR that
are already proven on aarch64. The port is expected to land `--profile core` 0-FAIL as
**corroboration** (ADR-0012): the signal was the substrate mechanics (FFI×ISA, fork→clone, qemu
fidelity), already captured above.
