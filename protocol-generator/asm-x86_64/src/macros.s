# macros.s — shared constants + syscall/FFI helper macros for the asm peer.
# GAS / AT&T. Included (`.include "macros.s"`, -Isrc) by every module.
#
# Syscall numbers are the x86-64 (legacy) table, but we deliberately use the
# generic-table-friendly variants (openat, epoll_pwait, accept4) so the eventual
# arm64/riscv ports are a mechanical number swap — see arch/OPTIONS-AND-ISA-MAP.md.

	# -- syscall numbers (x86-64) --
	.equ SYS_read,        0
	.equ SYS_write,       1
	.equ SYS_close,       3
	.equ SYS_mmap,        9
	.equ SYS_socket,      41
	.equ SYS_bind,        49
	.equ SYS_listen,      50
	.equ SYS_setsockopt,  54
	.equ SYS_exit,        60
	.equ SYS_fork,        57
	.equ SYS_wait4,       61
	.equ WNOHANG,         1
	.equ SYS_fcntl,       72
	.equ SYS_exit_group,  231
	.equ SYS_openat,      257
	.equ SYS_accept4,     288
	.equ SYS_epoll_wait,  232
	.equ SYS_epoll_ctl,   233
	.equ SYS_epoll_create1, 291
	.equ SYS_clock_gettime, 228
	.equ SYS_getrandom,   318
	.equ CLOCK_REALTIME,  0

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

# ksys nr — set rax=nr and issue a syscall. Args must already be in the syscall
# registers (rdi,rsi,rdx,r10,r8,r9); result in rax. NOTE: the macro must NOT be
# named `SYSCALL` — GAS matches macro names against the `syscall` instruction
# case-insensitively, so a macro body's `syscall` would re-invoke the macro with
# no argument. `ksys` sidesteps the collision.
.macro ksys nr
	mov  $\nr, %eax
	syscall
.endm
