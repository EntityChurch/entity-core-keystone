# host.s — entity-core-protocol-asm-x86_64 entry + boot path.
# GAS/AT&T. Entry is `main` (cc-driver startup; libc initialized — A-ASM-001).
#
# Boot: parse CLI → load identity (PEM keypair → 32-byte seed → FFI pubkey → peer_id)
#       → socket/bind/listen → print LISTENING → accept loop.
# Transport is raw syscalls. Codec/crypto/peer-id are FFI (libentitycore_codec).

	.include "macros.s"

# ---- FFI imports (libentitycore_codec) ----
	.extern ec_ed25519_seed_to_pubkey
	.extern ec_peerid_format
# ---- module imports ----
	.extern conn_serve                     # dispatch.s: handle one accepted connection (rdi=connfd)
	.extern peer_bootstrap                 # dispatch.s: build store + identity-derived state

	.section .rodata
s_home_key:   .asciz "HOME="
s_default_home: .asciz "/root"
s_pathmid:    .asciz "/.entity/peers/"
s_pathend:    .asciz "/keypair"
s_arg_port:   .asciz "--port"
s_arg_name:   .asciz "--name"
s_arg_val:    .asciz "--validate"
s_arg_open:   .asciz "--debug-open-grants"
s_default_name: .asciz "conformance"
s_listen_pre: .ascii "LISTENING 127.0.0.1:"
	.equ s_listen_pre_len, . - s_listen_pre
s_pid_eq:     .ascii " peer_id="
	.equ s_pid_eq_len, . - s_pid_eq
s_og_eq:      .ascii " open_grants="
	.equ s_og_eq_len, . - s_og_eq
s_val_eq:     .ascii " validate="
	.equ s_val_eq_len, . - s_val_eq
s_true:       .ascii "true"
	.equ s_true_len, . - s_true
s_false:      .ascii "false"
	.equ s_false_len, . - s_false
s_err_open:   .asciz "FATAL: cannot open keypair\n"
s_err_b64:    .asciz "FATAL: keypair seed not 32 bytes\n"
s_err_sock:   .asciz "FATAL: socket/bind/listen failed\n"

	.bss
	.lcomm g_name_ptr, 8
	.lcomm g_port_ascii, 8
	.lcomm g_port_ascii_len, 8
	.lcomm g_port_num, 8            # host-order u16 in low bytes
	.lcomm g_validate, 8           # 0/1
	.globl g_opengrants
	.lcomm g_opengrants, 8         # 0/1
	.lcomm g_listenfd, 8
	.lcomm g_envp, 8
	.globl g_seed
	.globl g_pubkey
	.globl g_peerid
	.globl g_peerid_len
	.lcomm g_seed, 64
	.lcomm g_pubkey, 64
	.lcomm g_peerid, 128
	.lcomm g_peerid_len, 8
	.lcomm b_path, 512
	.lcomm b_file, 4096
	.lcomm b_b64, 512
	.lcomm b_sockaddr, 16
	.lcomm b_line, 512

	.text
	.globl main
	.type main, @function
# main(int argc=%rdi, char** argv=%rsi, char** envp=%rdx)
main:
	push %rbx
	push %rbp
	push %r12
	push %r13
	push %r14
	push %r15
	sub  $8, %rsp                    # align to 16

	mov  %rdi, %r12                  # r12 = argc
	mov  %rsi, %r13                  # r13 = argv
	mov  %rdx, %rax
	mov  %rax, g_envp(%rip)

	# defaults
	lea  s_default_name(%rip), %rax
	mov  %rax, g_name_ptr(%rip)
	movq $0, g_validate(%rip)
	movq $0, g_opengrants(%rip)
	movq $0, g_port_num(%rip)

	# -- parse argv[1..] --
	mov  $1, %ebx                    # i = 1
.Largloop:
	cmp  %r12, %rbx
	jge  .Largdone
	mov  (%r13,%rbx,8), %r14         # r14 = argv[i]
	# --port ?
	mov  %r14, %rdi
	lea  s_arg_port(%rip), %rsi
	call streq
	test %eax, %eax
	jz   .Lnot_port
	inc  %rbx
	cmp  %r12, %rbx
	jge  .Largdone
	mov  (%r13,%rbx,8), %rax
	mov  %rax, g_port_ascii(%rip)
	mov  %rax, %rdi
	call strlen
	mov  %rax, g_port_ascii_len(%rip)
	mov  g_port_ascii(%rip), %rdi
	call parse_u16
	mov  %rax, g_port_num(%rip)
	jmp  .Larg_next
.Lnot_port:
	mov  %r14, %rdi
	lea  s_arg_name(%rip), %rsi
	call streq
	test %eax, %eax
	jz   .Lnot_name
	inc  %rbx
	cmp  %r12, %rbx
	jge  .Largdone
	mov  (%r13,%rbx,8), %rax
	mov  %rax, g_name_ptr(%rip)
	jmp  .Larg_next
.Lnot_name:
	mov  %r14, %rdi
	lea  s_arg_val(%rip), %rsi
	call streq
	test %eax, %eax
	jz   .Lnot_val
	movq $1, g_validate(%rip)
	jmp  .Larg_next
.Lnot_val:
	mov  %r14, %rdi
	lea  s_arg_open(%rip), %rsi
	call streq
	test %eax, %eax
	jz   .Larg_next
	movq $1, g_opengrants(%rip)
.Larg_next:
	inc  %rbx
	jmp  .Largloop
.Largdone:

	# -- build keypair path: HOME + "/.entity/peers/" + NAME + "/keypair" --
	call find_home                   # -> rax = HOME ptr
	lea  b_path(%rip), %r15          # r15 = cursor
	mov  %rax, %rdi
	mov  %r15, %rsi
	call strcpy_ret                  # copy HOME, rax=new cursor
	mov  %rax, %r15
	lea  s_pathmid(%rip), %rdi
	mov  %r15, %rsi
	call strcpy_ret
	mov  %rax, %r15
	mov  g_name_ptr(%rip), %rdi
	mov  %r15, %rsi
	call strcpy_ret
	mov  %rax, %r15
	lea  s_pathend(%rip), %rdi
	mov  %r15, %rsi
	call strcpy_ret
	movb $0, (%rax)                  # NUL-terminate path

	# -- openat(AT_FDCWD, path, O_RDONLY) --
	mov  $AT_FDCWD, %edi
	lea  b_path(%rip), %rsi
	xor  %edx, %edx                  # O_RDONLY
	xor  %r10d, %r10d
	ksys SYS_openat
	test %rax, %rax
	js   .Lfatal_open
	mov  %rax, %r14                  # r14 = fd
	# read(fd, b_file, 4096)
	mov  %r14, %rdi
	lea  b_file(%rip), %rsi
	mov  $4096, %edx
	ksys SYS_read
	mov  %rax, %r15                  # r15 = filelen
	test %rax, %rax
	jle  .Lfatal_open
	mov  %r14, %rdi
	ksys SYS_close

	# -- extract base64 body, decode -> g_seed --
	lea  b_file(%rip), %rdi
	mov  %r15, %rsi
	lea  b_b64(%rip), %rdx
	call extract_b64                 # rax = b64 len
	lea  b_b64(%rip), %rdi
	mov  %rax, %rsi
	lea  g_seed(%rip), %rdx
	call b64_decode                  # rax = out len
	cmp  $SEED_LEN, %rax
	jne  .Lfatal_b64

	# -- FFI: seed -> pubkey --
	lea  g_seed(%rip), %rdi
	lea  g_pubkey(%rip), %rsi
	call ec_ed25519_seed_to_pubkey
	test %eax, %eax
	jnz  .Lfatal_b64
	# -- FFI: peer_id = base58(varint(1)||varint(0)||pubkey) --
	mov  $1, %edi                    # key_type = ed25519
	xor  %esi, %esi                  # hash_type = 0 (identity)
	lea  g_pubkey(%rip), %rdx
	mov  $PUBKEY_LEN, %rcx
	lea  g_peerid(%rip), %r8
	mov  $128, %r9
	# 7th arg (out_len) goes on the stack at [rsp] at the call, rsp 16-aligned.
	sub  $16, %rsp                    # reserve 16 (arg7 + 8 pad) to keep alignment
	lea  g_peerid_len(%rip), %rax
	mov  %rax, (%rsp)                 # arg7 at [rsp]
	call ec_peerid_format
	add  $16, %rsp
	test %eax, %eax
	jnz  .Lfatal_b64

	# -- peer_bootstrap (store + identity-derived state) --
	call peer_bootstrap

	# -- socket(AF_INET, SOCK_STREAM, 0) --
	mov  $AF_INET, %edi
	mov  $SOCK_STREAM, %esi
	xor  %edx, %edx
	ksys SYS_socket
	test %rax, %rax
	js   .Lfatal_sock
	mov  %rax, %r14                  # r14 = listenfd
	mov  %rax, g_listenfd(%rip)

	# setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &1, 4)
	mov  %r14, %rdi
	mov  $SOL_SOCKET, %esi
	mov  $SO_REUSEADDR, %edx
	lea  .Lone(%rip), %r10
	mov  $4, %r8d
	ksys SYS_setsockopt

	# build sockaddr_in
	lea  b_sockaddr(%rip), %rdi
	movw $AF_INET, (%rdi)            # sin_family
	mov  g_port_num(%rip), %eax
	rol  $8, %ax                     # host -> network (BE) 16-bit
	movw %ax, 2(%rdi)               # sin_port
	movl $0x0100007f, 4(%rdi)      # 127.0.0.1 (network order bytes 7f 00 00 01)
	movq $0, 8(%rdi)

	# bind(fd, &sockaddr, 16)
	mov  %r14, %rdi
	lea  b_sockaddr(%rip), %rsi
	mov  $16, %edx
	ksys SYS_bind
	test %rax, %rax
	js   .Lfatal_sock
	# listen(fd, 128)
	mov  %r14, %rdi
	mov  $128, %esi
	ksys SYS_listen
	test %rax, %rax
	js   .Lfatal_sock

	# -- TCP_NODELAY on the listen fd is inherited by accepted conns? No — set per-conn.
	call print_listening

	# -- accept loop: fork per connection --
	# The single-threaded blocking model head-of-line-blocks under validate-peer,
	# which opens concurrent/lingering connections (e.g. handshake_replay_cross_
	# connection). fork-per-connection removes the blocking; it unblocks the
	# STATELESS categories (connect/negotiation/handshake). STATEFUL categories
	# (tree put→get across connections) need a shared store — a later epoll or
	# MAP_SHARED refit (A-ASM-003, staged).
.Laccept:
	# Drain ALL exited children (non-blocking) so zombies never accumulate — a single reap
	# per accept lags behind a burst of short-lived connections and eventually exhausts the
	# pid limit, at which point fork() fails and connections are dropped (broken pipe). Loop
	# until wait4 reports no more reapable children (rax <= 0).
.Lreap:
	mov  $-1, %edi
	xor  %esi, %esi                  # status = NULL
	mov  $WNOHANG, %edx
	xor  %r10d, %r10d
	ksys SYS_wait4
	test %rax, %rax
	jg   .Lreap                      # reaped one (pid>0) → keep draining
	mov  g_listenfd(%rip), %rdi
	xor  %esi, %esi                  # addr = NULL
	xor  %edx, %edx                  # addrlen = NULL
	xor  %r10d, %r10d                # flags = 0
	ksys SYS_accept4
	test %rax, %rax
	js   .Laccept                    # EINTR/again → retry
	mov  %rax, %r14                  # connfd (callee-saved across fork)
	ksys SYS_fork
	test %rax, %rax
	js   .Lserve_inline              # fork FAILED (resource pressure) → serve in-process
	jnz  .Lparent                    # parent: pid>0
	# --- child ---
	mov  %r14, %rdi                  # connfd
	mov  $IPPROTO_TCP, %esi
	mov  $TCP_NODELAY, %edx
	lea  .Lone(%rip), %r10
	mov  $4, %r8d
	ksys SYS_setsockopt
	mov  %r14, %rdi
	call conn_serve                  # handles + closes the connection
	xor  %edi, %edi
	ksys SYS_exit_group              # child exits
.Lserve_inline:
	# Fork failed — rather than drop the connection (a broken pipe the peer must never cause),
	# handle it inline in the parent. This briefly reintroduces head-of-line blocking, but
	# only under genuine fork exhaustion, and keeps the peer answering every connection.
	mov  %r14, %rdi
	mov  $IPPROTO_TCP, %esi
	mov  $TCP_NODELAY, %edx
	lea  .Lone(%rip), %r10
	mov  $4, %r8d
	ksys SYS_setsockopt
	mov  %r14, %rdi
	call conn_serve
	mov  %r14, %rdi
	ksys SYS_close
	jmp  .Laccept
.Lparent:
	mov  %r14, %rdi                  # close our copy of connfd
	ksys SYS_close
	jmp  .Laccept

.Lfatal_open:
	lea  s_err_open(%rip), %rdi
	jmp  .Lfatal
.Lfatal_b64:
	lea  s_err_b64(%rip), %rdi
	jmp  .Lfatal
.Lfatal_sock:
	lea  s_err_sock(%rip), %rdi
.Lfatal:
	call fputs_stderr
	mov  $1, %edi
	ksys SYS_exit_group

	.section .rodata
.Lone:	.long 1

# =====================================================================
# print_listening — writes the LISTENING readiness line to stdout.
#   LISTENING 127.0.0.1:PORT peer_id=PID open_grants=B validate=B\n
# =====================================================================
	.text
	.type print_listening, @function
print_listening:
	push %rbx
	lea  b_line(%rip), %rbx          # cursor
	# "LISTENING 127.0.0.1:"
	lea  s_listen_pre(%rip), %rsi
	mov  $s_listen_pre_len, %rdx
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	# PORT (ascii from argv)
	mov  g_port_ascii(%rip), %rsi
	mov  g_port_ascii_len(%rip), %rdx
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	# " peer_id="
	lea  s_pid_eq(%rip), %rsi
	mov  $s_pid_eq_len, %rdx
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	# PID
	lea  g_peerid(%rip), %rsi
	mov  g_peerid_len(%rip), %rdx
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	# " open_grants="
	lea  s_og_eq(%rip), %rsi
	mov  $s_og_eq_len, %rdx
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	mov  g_opengrants(%rip), %rdi
	call bool_str                    # rsi=ptr, rdx=len
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	# " validate="
	lea  s_val_eq(%rip), %rsi
	mov  $s_val_eq_len, %rdx
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	mov  g_validate(%rip), %rdi
	call bool_str
	mov  %rbx, %rdi
	call mcpy
	mov  %rax, %rbx
	movb $10, (%rbx)                 # '\n'
	inc  %rbx
	# write_all(1, b_line, rbx - b_line)
	lea  b_line(%rip), %rsi
	mov  %rbx, %rdx
	sub  %rsi, %rdx
	mov  $STDOUT, %edi
	call write_all
	pop  %rbx
	ret

# bool_str(rdi=0/1) -> rsi=ptr, rdx=len
	.type bool_str, @function
bool_str:
	test %rdi, %rdi
	jz   .Lbs_false
	lea  s_true(%rip), %rsi
	mov  $s_true_len, %rdx
	ret
.Lbs_false:
	lea  s_false(%rip), %rsi
	mov  $s_false_len, %rdx
	ret

# =====================================================================
# find_home() -> rax = ptr to HOME value (or "/root"). Scans envp for "HOME=".
# =====================================================================
	.type find_home, @function
find_home:
	mov  g_envp(%rip), %r8           # r8 = envp
.Lfh_loop:
	mov  (%r8), %rdi                 # env string
	test %rdi, %rdi
	jz   .Lfh_default
	# compare prefix "HOME="
	lea  s_home_key(%rip), %rsi
	mov  %rdi, %r9
	call strprefix                   # rax=1 if r9 starts with HOME=
	test %eax, %eax
	jnz  .Lfh_found
	add  $8, %r8
	jmp  .Lfh_loop
.Lfh_found:
	mov  (%r8), %rax
	add  $5, %rax                    # skip "HOME="
	ret
.Lfh_default:
	lea  s_default_home(%rip), %rax
	ret

# strprefix(rdi=str(unused), rsi=prefix, r9=str) -> rax=1 if str starts with prefix
	.type strprefix, @function
strprefix:
	mov  %r9, %rcx
.Lsp_loop:
	mov  (%rsi), %al
	test %al, %al
	jz   .Lsp_yes                    # prefix exhausted → match
	mov  (%rcx), %dl
	cmp  %al, %dl
	jne  .Lsp_no
	inc  %rsi
	inc  %rcx
	jmp  .Lsp_loop
.Lsp_yes:
	mov  $1, %eax
	ret
.Lsp_no:
	xor  %eax, %eax
	ret

# =====================================================================
# String / IO helpers (shared)
# =====================================================================
# strlen(rdi) -> rax
	.globl strlen
	.type strlen, @function
strlen:
	xor  %rax, %rax
.Lsl:	cmpb $0, (%rdi,%rax)
	je   .Lsl_done
	inc  %rax
	jmp  .Lsl
.Lsl_done:
	ret

# streq(rdi,rsi) -> rax=1 if equal null-terminated strings
	.globl streq
	.type streq, @function
streq:
.Lse:	mov  (%rdi), %al
	mov  (%rsi), %dl
	cmp  %al, %dl
	jne  .Lse_no
	test %al, %al
	jz   .Lse_yes
	inc  %rdi
	inc  %rsi
	jmp  .Lse
.Lse_yes:
	mov  $1, %eax
	ret
.Lse_no:
	xor  %eax, %eax
	ret

# strcpy_ret(rdi=src null-term, rsi=dst) -> rax = dst cursor after copy (no NUL)
	.type strcpy_ret, @function
strcpy_ret:
.Lsc:	mov  (%rdi), %al
	test %al, %al
	jz   .Lsc_done
	mov  %al, (%rsi)
	inc  %rdi
	inc  %rsi
	jmp  .Lsc
.Lsc_done:
	mov  %rsi, %rax
	ret

# mcpy(rdi=dst, rsi=src, rdx=len) -> rax = dst+len   (memcpy returning end cursor)
	.globl mcpy
	.type mcpy, @function
mcpy:
	xor  %rcx, %rcx
.Lmc:	cmp  %rdx, %rcx
	jge  .Lmc_done
	mov  (%rsi,%rcx), %al
	mov  %al, (%rdi,%rcx)
	inc  %rcx
	jmp  .Lmc
.Lmc_done:
	lea  (%rdi,%rdx), %rax
	ret

# write_all(rdi=fd, rsi=buf, rdx=len) — loops until all written
	.globl write_all
	.type write_all, @function
write_all:
	push %r12
	push %r13
	push %r14
	mov  %rdi, %r12                  # fd
	mov  %rsi, %r13                  # buf
	mov  %rdx, %r14                  # remaining
.Lwa:	test %r14, %r14
	jz   .Lwa_done
	mov  %r12, %rdi
	mov  %r13, %rsi
	mov  %r14, %rdx
	ksys SYS_write
	test %rax, %rax
	jle  .Lwa_done                   # error/EOF → stop
	add  %rax, %r13
	sub  %rax, %r14
	jmp  .Lwa
.Lwa_done:
	pop  %r14
	pop  %r13
	pop  %r12
	ret

# fputs_stderr(rdi=asciz) — write a C string to stderr
	.type fputs_stderr, @function
fputs_stderr:
	push %rdi
	call strlen
	mov  %rax, %rdx
	pop  %rsi
	mov  $STDERR, %edi
	call write_all
	ret

# parse_u16(rdi=asciz decimal) -> rax = value
	.type parse_u16, @function
parse_u16:
	xor  %rax, %rax
.Lpu:	movzbl (%rdi), %ecx
	test %cl, %cl
	jz   .Lpu_done
	cmp  $'0', %cl
	jb   .Lpu_done
	cmp  $'9', %cl
	ja   .Lpu_done
	imul $10, %rax
	sub  $'0', %ecx
	add  %rcx, %rax
	inc  %rdi
	jmp  .Lpu
.Lpu_done:
	ret

# extract_b64(rdi=filebuf, rsi=filelen, rdx=dst) -> rax = dst length.
# Skips whole lines beginning with '-'; copies base64 chars from other lines.
	.type extract_b64, @function
extract_b64:
	push %rbx
	mov  %rdi, %r8                   # p
	lea  (%rdi,%rsi), %r9            # end
	mov  %rdx, %r10                  # out cursor
	mov  %rdx, %r11                  # out start
.Lxb_line:
	cmp  %r9, %r8
	jae  .Lxb_done
	# peek first char of line
	movzbl (%r8), %ebx
	cmp  $'-', %bl
	jne  .Lxb_copy
	# skip line (to after '\n')
.Lxb_skip:
	cmp  %r9, %r8
	jae  .Lxb_done
	movzbl (%r8), %ebx
	inc  %r8
	cmp  $10, %bl
	jne  .Lxb_skip
	jmp  .Lxb_line
.Lxb_copy:
	cmp  %r9, %r8
	jae  .Lxb_done
	movzbl (%r8), %ebx
	inc  %r8
	cmp  $10, %bl
	je   .Lxb_line
	cmp  $13, %bl
	je   .Lxb_copy                   # skip CR
	mov  %bl, (%r10)
	inc  %r10
	jmp  .Lxb_copy
.Lxb_done:
	mov  %r10, %rax
	sub  %r11, %rax
	pop  %rbx
	ret

# b64_decode(rdi=src, rsi=srclen, rdx=dst) -> rax = out length. Standard alphabet.
	.type b64_decode, @function
b64_decode:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %r12                  # src
	mov  %rsi, %r13                  # srclen
	mov  %rdx, %r14                  # dst
	xor  %r15, %r15                  # i (src index)
	xor  %rbx, %rbx                  # o (out index)
.Lbd_loop:
	# need 4 input chars
	mov  %r13, %rax
	sub  %r15, %rax
	cmp  $4, %rax
	jl   .Lbd_done
	# decode 4 sextets
	movzbl (%r12,%r15), %edi
	call b64_val
	mov  %al, %r8b                   # c0 (0..63)
	movzbl 1(%r12,%r15), %edi
	call b64_val
	mov  %al, %r9b                   # c1
	movzbl 2(%r12,%r15), %edi
	call b64_val
	mov  %al, %r10b                  # c2 (0..63 or 0xFF for '=')
	movzbl 3(%r12,%r15), %edi
	call b64_val
	mov  %al, %r11b                  # c3
	add  $4, %r15
	# byte0 = c0<<2 | c1>>4
	movzbl %r8b, %eax
	shl    $2, %eax
	movzbl %r9b, %ecx
	shr    $4, %ecx
	or     %ecx, %eax
	mov    %al, (%r14,%rbx)
	inc    %rbx
	# if c2 == pad, stop
	cmp    $0xFF, %r10b
	je     .Lbd_done
	# byte1 = c1<<4 | c2>>2
	movzbl %r9b, %eax
	shl    $4, %eax
	movzbl %r10b, %ecx
	shr    $2, %ecx
	or     %ecx, %eax
	mov    %al, (%r14,%rbx)
	inc    %rbx
	# if c3 == pad, stop
	cmp    $0xFF, %r11b
	je     .Lbd_done
	# byte2 = c2<<6 | c3
	movzbl %r10b, %eax
	shl    $6, %eax
	movzbl %r11b, %ecx
	or     %ecx, %eax
	mov    %al, (%r14,%rbx)
	inc    %rbx
	jmp    .Lbd_loop
.Lbd_done:
	mov  %rbx, %rax
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

# b64_val(dil=char) -> al = 6-bit value, or 0xFF for '=' / invalid
	.type b64_val, @function
b64_val:
	movzbl %dil, %eax
	cmp  $'A', %al
	jb   .Lbv_1
	cmp  $'Z', %al
	ja   .Lbv_1
	sub  $'A', %al                   # 0..25
	ret
.Lbv_1:
	cmp  $'a', %al
	jb   .Lbv_2
	cmp  $'z', %al
	ja   .Lbv_2
	sub  $'a', %al
	add  $26, %al                    # 26..51
	ret
.Lbv_2:
	cmp  $'0', %al
	jb   .Lbv_3
	cmp  $'9', %al
	ja   .Lbv_3
	sub  $'0', %al
	add  $52, %al                    # 52..61
	ret
.Lbv_3:
	cmp  $'+', %al
	jne  .Lbv_4
	mov  $62, %al
	ret
.Lbv_4:
	cmp  $'/', %al
	jne  .Lbv_pad
	mov  $63, %al
	ret
.Lbv_pad:
	mov  $0xFF, %al                  # '=' or anything else
	ret

	.section .note.GNU-stack,"",@progbits
