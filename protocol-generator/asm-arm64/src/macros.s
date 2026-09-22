// macros.s — shared constants + syscall/FFI helper macros for the aarch64 asm peer.
// GAS aarch64 (native ARM syntax). Included (`.include "macros.s"`, -Isrc) by every module.
// Ported from asm-x86_64/src/macros.s.
//
// ============================ PORTING CONVENTION ============================
// The whole asm family isolates "what is protocol" (invariant) from "what is machine".
// This is the x86-64 → aarch64 register/ABI map, applied CONSISTENTLY across every module
// so the ported functions interoperate. (See asm-x86_64/arch/OPTIONS-AND-ISA-MAP.md, Axis A.)
//
//   x86-64 (SysV)          aarch64 (AAPCS64)     role
//   rdi rsi rdx rcx r8 r9  x0 x1 x2 x3 x4 x5     call args (line up → no arg shuffle at `bl`)
//   rax                    x0                    return value
//   rbx rbp r12 r13 r14 r15  x19 x20 x21 x22 x23 x24   callee-saved
//     └─ the CBOR WRITER CURSOR (x86 r15) → x24 globally (cbor.s w_* + dispatch builders)
//   rcx/rdx/rsi/r8..r11    x2/x3/x4/x9..x15      volatile scratch
//
//   memory:   mov (%r),%r → ldr/ldrb ;  mov %r,(%r) → str/strb
//   address:  lea sym(%rip),%r → `adr_l %r, sym` (adrp + :lo12:) ;  lea disp(%rb,%ri) → add
//   branch:   test r,r; jz → cbz ;  cmp; jcc → cmp; b.cc
//   syscall:  nr in x8, args x0-x5, trap `svc #0`. UNLIKE x86 there is NO r10-for-arg4
//             divergence — the 4th syscall arg stays in x3 (same as the 4th call arg).
//   NB: the generic table has NO `fork` — host.s uses `clone(SIGCHLD)` (A-ARM64-001).
// ===========================================================================

	// -- syscall numbers (aarch64 generic table, asm-generic/unistd.h) --
	.equ SYS_read,          63
	.equ SYS_write,         64
	.equ SYS_close,         57
	.equ SYS_openat,        56
	.equ SYS_socket,        198
	.equ SYS_bind,          200
	.equ SYS_listen,        201
	.equ SYS_setsockopt,    208
	.equ SYS_accept4,       242
	.equ SYS_clone,         220        // fork replacement: clone(SIGCHLD,0,0,0,0)
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
	.equ SIGCHLD,           17         // clone flags for a fork-equivalent child

	// -- fs / fd --
	.equ AT_FDCWD,        -100
	.equ O_RDONLY,        0
	.equ STDOUT,          1
	.equ STDERR,          2

	// -- socket --
	.equ AF_INET,         2
	.equ SOCK_STREAM,     1
	.equ SOCK_NONBLOCK,   0x800
	.equ SOL_SOCKET,      1
	.equ SO_REUSEADDR,    2
	.equ SO_RCVTIMEO,     20         // SO_RCVTIMEO_OLD — struct timeval optval
	.equ SO_SNDTIMEO,     21         // SO_SNDTIMEO_OLD — struct timeval optval
	.equ IPPROTO_TCP,     6
	.equ TCP_NODELAY,     1

	// -- §4.10(c) connection admission (SHOULD; spec allows refusal BY CLOSE) --
	// Bound on simultaneously-live connection children. The parent counts clones and
	// reaps; over the bound it closes the accepted fd immediately rather than cloning.
	// Chosen against the substrate, not the check: each child COWs a 16 MiB b_req plus
	// its seeded store, so an unbounded clone-per-connection peer converts a connection
	// flood into a memory-cap event and stops serving — which is the MUST half of
	// §4.10 ("rejection is clean, not collapse") failing, not the SHOULD half.
	.equ MAX_CONNS,       64

	// -- epoll --
	.equ EPOLLIN,         0x001
	.equ EPOLL_CTL_ADD,   1
	.equ EPOLL_CTL_DEL,   2

	// -- mmap --
	.equ PROT_RW,         3          // PROT_READ|PROT_WRITE
	.equ MAP_ANON_PRIV,   0x22       // MAP_PRIVATE|MAP_ANONYMOUS

	// -- C-ABI status --
	.equ EC_OK,           0

	// -- protocol sizes --
	.equ HASH_LEN,        33         // content_hash = varint(0x00) || 32-byte digest
	.equ SEED_LEN,        32
	.equ PUBKEY_LEN,      32
	.equ SIG_LEN,         64
	.equ MAX_FRAME,       0x1000000   // 16 MiB (§1.6)

// ksys nr — set x8=nr and trap. Args must already be in x0-x5; result in x0.
.macro ksys, nr
	mov  x8, #\nr
	svc  #0
.endm

// adr_l reg, sym — materialize the address of `sym` into `reg` (PC-relative, -no-pie).
// The aarch64 equivalent of `lea sym(%rip), reg`.
.macro adr_l, reg, sym
	adrp \reg, \sym
	add  \reg, \reg, :lo12:\sym
.endm
