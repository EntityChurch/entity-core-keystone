# macros.s — shared constants + syscall/FFI helper macros for the riscv64 asm peer.
# GAS riscv64 (RV64GC). Included (`.include "macros.s"`, -Isrc) by every module.
# Ported from asm-arm64/src/macros.s (the THIRD ISA; off arm64, NOT x86-64 — arm64 and
# riscv64 share the kernel's *generic* syscall table, so arm64 pre-adapted every quirk).
#
# ============================ PORTING CONVENTION ============================
# The whole asm family isolates "what is protocol" (invariant) from "what is machine".
# This is the aarch64 → riscv64 register/ABI map, applied CONSISTENTLY across every module
# so the ported functions interoperate. (See asm-x86_64/arch/OPTIONS-AND-ISA-MAP.md, Axis A,
# and docs/status/HANDOFF-2026-07-15-riscv-l1-next.md for the worked table.)
#
#   aarch64 (AAPCS64)     riscv64 (RV64 LP64D)   role
#   x0 x1 x2 x3 x4 x5     a0 a1 a2 a3 a4 a5       call args (line up → no arg shuffle at a call)
#   x6                    a6                      7th call arg (only ec_peerid_format uses it)
#   x0                    a0 (a1 hi)              return value
#   x8                    a7                      syscall number (a7 is arg8 too, but no syscall
#                                                 here takes >6 args, so a7 is free for the nr)
#   x9  x10 x11 x12 x13   t0 t1 t2 t3 t4          volatile scratch (xN → t(N-9))
#   x14 x15               t5 t6                   volatile scratch AND bswap-macro internals —
#                                                 verified non-overlapping (no bswap site holds
#                                                 x14/x15 live; no x14/x15 site does a bswap)
#   x19 x20 x21 x22 x23   s1 s2 s3 s4 s5          callee-saved (xN → s(N-18))
#     x24 (CBOR cursor)   s6                      the CBOR WRITER CURSOR, GLOBALLY (cbor.s w_* +
#                                                 dispatch builders all assume s6)
#   x25 x26 x27 x28       s7 s8 s9 s10            callee-saved (s11 free)
#   x29(fp) x30(lr) sp    s0(fp) ra sp            frame ptr / link / stack
#   xzr / wzr             zero                    the zero register (x0)
#
#   memory:   ldrb w,[x]  → lbu t,0(a)  ;  strb w,[x]  → sb t,0(a)
#             ldrh/strh   → lhu/sh      ;  ldr w,[x] (zero-ext) → lwu ;  ldr x → ld ; str x → sd
#             POST-INDEX  ldrb w,[x],#1 has NO riscv form → `lbu t,0(a); addi a,a,1`
#   address:  adr_l r,sym → `lla r, sym` (auipc+addi, PC-relative; -no-pie safe)
#   branch:   cbz/cbnz    → beqz/bnez  ;  cmp+b.cc → FUSED compare-branch (repeat operands, no
#             flags): b.eq/ne → beq/bne ; b.lo/hs (unsigned) → bltu/bgeu ; b.lt/ge (signed) →
#             blt/bge ; b.hi/ls (unsigned) → bgtu/bleu. cmp against an immediate → `li tX,imm`
#             first (there is no cmp-with-imm; there is no condition-flags register to reuse, so
#             every flag-reuse site becomes N compare-branches). tbnz x,#63,L (sign/neg test) →
#             `bltz a,L`.
#   byteswap: rev/rev16   → `bswap32/bswap64/bswap16` macros below (RV64GC base — no Zbb rev8;
#             hand-rolled for portability, A-RISCV-001). rev+LE-store == BE-store, preserved.
#   syscall:  nr in a7, args a0-a5, trap `ecall`. Same generic table numbers as aarch64.
#   NB: the generic table has NO `fork` — host.s uses `clone(SIGCHLD)` (inherited A-ARM64-001).
# ===========================================================================

	# -- syscall numbers (generic table, asm-generic/unistd.h — IDENTICAL to aarch64) --
	.equ SYS_read,          63
	.equ SYS_write,         64
	.equ SYS_close,         57
	.equ SYS_openat,        56
	.equ SYS_socket,        198
	.equ SYS_bind,          200
	.equ SYS_listen,        201
	.equ SYS_setsockopt,    208
	.equ SYS_accept4,       242
	.equ SYS_clone,         220        # fork replacement: clone(SIGCHLD,0,0,0,0)
	.equ SYS_wait4,         260
	.equ SYS_fcntl,         25
	.equ SYS_mmap,          222
	.equ SYS_exit,          93
	.equ SYS_exit_group,    94
	.equ SYS_clock_gettime, 113
	.equ SYS_getrandom,     278
	.equ SYS_epoll_create1, 20
	.equ SYS_epoll_ctl,     21
	.equ SYS_epoll_pwait,   22
	.equ CLOCK_REALTIME,    0
	.equ WNOHANG,           1
	.equ SIGCHLD,           17         # clone flags for a fork-equivalent child

	# -- fs / fd --
	.equ AT_FDCWD,        -100
	.equ O_RDONLY,        0
	.equ STDOUT,          1
	.equ STDERR,          2

	# -- socket --
	.equ AF_INET,         2
	.equ SOCK_STREAM,     1
	.equ SOCK_NONBLOCK,   0x800
	.equ SOL_SOCKET,      1
	.equ SO_REUSEADDR,    2
	.equ IPPROTO_TCP,     6
	.equ TCP_NODELAY,     1

	# -- epoll --
	.equ EPOLLIN,         0x001
	.equ EPOLL_CTL_ADD,   1
	.equ EPOLL_CTL_DEL,   2

	# -- mmap --
	.equ PROT_RW,         3          # PROT_READ|PROT_WRITE
	.equ MAP_ANON_PRIV,   0x22       # MAP_PRIVATE|MAP_ANONYMOUS

	# -- C-ABI status --
	.equ EC_OK,           0

	# -- protocol sizes --
	.equ HASH_LEN,        33         # content_hash = varint(0x00) || 32-byte digest
	.equ SEED_LEN,        32
	.equ PUBKEY_LEN,      32
	.equ SIG_LEN,         64
	.equ MAX_FRAME,       0x1000000   # 16 MiB (§1.6)

# ksys nr — set a7=nr and trap. Args must already be in a0-a5; result in a0.
.macro ksys, nr
	li   a7, \nr
	ecall
.endm

# adr_l reg, sym — materialize the address of `sym` into `reg` (PC-relative, -no-pie).
# The riscv64 equivalent of aarch64 `adr_l` (adrp+:lo12:) / x86 `lea sym(%rip)`. `lla` always
# expands to auipc+addi (position-independent within ±2 GiB), so it is model-agnostic.
.macro adr_l, reg, sym
	lla  \reg, \sym
.endm

# bswapN rd, rs — byte-reverse the low N bits of rs into rd (rd==rs allowed). Internal scratch
# is t5/t6 ONLY (see the map above — verified free at every call site). rev+LE-store == BE-store,
# so these reproduce aarch64 `rev16`/`rev`(w)/`rev`(x) exactly. RV64GC base (no Zbb). A-RISCV-001.
#
# bswap16: rd = (rs[7:0] << 8) | rs[15:8]
.macro bswap16, rd, rs
	srli t6, \rs, 8
	andi t6, t6, 0xff
	andi \rd, \rs, 0xff
	slli \rd, \rd, 8
	or   \rd, \rd, t6
.endm
# bswap32: rd = v0<<24 | v1<<16 | v2<<8 | v3   (vk = byte k of rs, v0=LSB). LE-store ⇒ BE bytes.
.macro bswap32, rd, rs
	andi t5, \rs, 0xff        # v0
	slli t6, t5, 24
	srli t5, \rs, 8
	andi t5, t5, 0xff         # v1
	slli t5, t5, 16
	or   t6, t6, t5
	srli t5, \rs, 16
	andi t5, t5, 0xff         # v2
	slli t5, t5, 8
	or   t6, t6, t5
	srli t5, \rs, 24
	andi t5, t5, 0xff         # v3
	or   t6, t6, t5
	mv   \rd, t6
.endm
# bswap64: rd = v0<<56 | v1<<48 | ... | v6<<8 | v7   (vk = byte k of rs, v0=LSB).
.macro bswap64, rd, rs
	andi t5, \rs, 0xff        # v0
	slli t6, t5, 56
	srli t5, \rs, 8
	andi t5, t5, 0xff         # v1
	slli t5, t5, 48
	or   t6, t6, t5
	srli t5, \rs, 16
	andi t5, t5, 0xff         # v2
	slli t5, t5, 40
	or   t6, t6, t5
	srli t5, \rs, 24
	andi t5, t5, 0xff         # v3
	slli t5, t5, 32
	or   t6, t6, t5
	srli t5, \rs, 32
	andi t5, t5, 0xff         # v4
	slli t5, t5, 24
	or   t6, t6, t5
	srli t5, \rs, 40
	andi t5, t5, 0xff         # v5
	slli t5, t5, 16
	or   t6, t6, t5
	srli t5, \rs, 48
	andi t5, t5, 0xff         # v6
	slli t5, t5, 8
	or   t6, t6, t5
	srli t5, \rs, 56
	andi t5, t5, 0xff         # v7
	or   t6, t6, t5
	mv   \rd, t6
.endm
