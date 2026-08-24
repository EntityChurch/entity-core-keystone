# host.s — entity-core-protocol-riscv64 entry + boot path. Ported from asm-arm64/src/host.s.
# GAS riscv64 (RV64GC). Entry is `main` (cc-driver startup; libc initialized).
#
# Boot: parse CLI → load identity (PEM keypair → 32-byte seed → FFI pubkey → peer_id)
#       → socket/bind/listen → print LISTENING → accept loop.
# Transport is raw syscalls. Codec/crypto/peer-id are FFI (libentitycore_codec).
#
# Concurrency: clone(SIGCHLD)-per-connection. The generic syscall table has NO fork
# (__NR_fork undefined) — the x86-64 peer's `fork` becomes `clone(SIGCHLD,0,0,0,0)`,
# which with a NULL child stack is fork-equivalent (COW). See A-ARM64-001 (inherited).
#
# Register/ABI map: see macros.s. Notable riscv idioms used here:
#   tbnz x,#63,L (neg/error test)  → bltz a,L
#   cmp x,#0; b.gt/b.le            → bgtz/blez a,L
#   ldr xd,[xbase,xidx,lsl #3]     → slli t,idx,3; add t,base,t; ld xd,0(t)
#   host->net 16-bit (rev16)       → bswap16
#   movk-built 0x0100007f          → li t,0x0100007f (LE store ⇒ 7f 00 00 01 = 127.0.0.1)

	.include "macros.s"

# ---- FFI imports (libentitycore_codec) ----
	.extern ec_ed25519_seed_to_pubkey
	.extern ec_peerid_format
# ---- module imports ----
	.extern conn_serve                     # dispatch.s: handle one accepted connection (a0=connfd)
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
	.set s_listen_pre_len, . - s_listen_pre
s_pid_eq:     .ascii " peer_id="
	.set s_pid_eq_len, . - s_pid_eq
s_og_eq:      .ascii " open_grants="
	.set s_og_eq_len, . - s_og_eq
s_val_eq:     .ascii " validate="
	.set s_val_eq_len, . - s_val_eq
s_true:       .ascii "true"
	.set s_true_len, . - s_true
s_false:      .ascii "false"
	.set s_false_len, . - s_false
s_err_open:   .asciz "FATAL: cannot open keypair\n"
s_err_b64:    .asciz "FATAL: keypair seed not 32 bytes\n"
s_err_sock:   .asciz "FATAL: socket/bind/listen failed\n"
.Lone:        .long 1

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
# main(a0=argc, a1=argv, a2=envp)
main:
	addi sp, sp, -96
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	sd   s6, 56(sp)
	sd   s7, 64(sp)
	mv   s0, sp

	mv   s3, a0                     # argc
	mv   s4, a1                     # argv
	lla  t0, g_envp
	sd   a2, 0(t0)

	# defaults
	lla  t0, s_default_name
	lla  t1, g_name_ptr
	sd   t0, 0(t1)
	lla  t0, g_validate
	sd   zero, 0(t0)
	lla  t0, g_opengrants
	sd   zero, 0(t0)
	lla  t0, g_port_num
	sd   zero, 0(t0)

	# -- parse argv[1..] --
	li   s1, 1                      # i = 1
.Largloop:
	bge  s1, s3, .Largdone
	slli t0, s1, 3
	add  t0, s4, t0
	ld   s5, 0(t0)                  # argv[i]
	# --port ?
	mv   a0, s5
	lla  a1, s_arg_port
	call streq
	beqz a0, .Lnot_port
	addi s1, s1, 1
	bge  s1, s3, .Largdone
	slli t0, s1, 3
	add  t0, s4, t0
	ld   t0, 0(t0)                  # argv[i] (the port value string)
	lla  t1, g_port_ascii
	sd   t0, 0(t1)
	mv   a0, t0
	call strlen
	lla  t1, g_port_ascii_len
	sd   a0, 0(t1)
	lla  t0, g_port_ascii
	ld   a0, 0(t0)
	call parse_u16
	lla  t0, g_port_num
	sd   a0, 0(t0)
	j    .Larg_next
.Lnot_port:
	mv   a0, s5
	lla  a1, s_arg_name
	call streq
	beqz a0, .Lnot_name
	addi s1, s1, 1
	bge  s1, s3, .Largdone
	slli t0, s1, 3
	add  t0, s4, t0
	ld   t0, 0(t0)
	lla  t1, g_name_ptr
	sd   t0, 0(t1)
	j    .Larg_next
.Lnot_name:
	mv   a0, s5
	lla  a1, s_arg_val
	call streq
	beqz a0, .Lnot_val
	li   t0, 1
	lla  t1, g_validate
	sd   t0, 0(t1)
	j    .Larg_next
.Lnot_val:
	mv   a0, s5
	lla  a1, s_arg_open
	call streq
	beqz a0, .Larg_next
	li   t0, 1
	lla  t1, g_opengrants
	sd   t0, 0(t1)
.Larg_next:
	addi s1, s1, 1
	j    .Largloop
.Largdone:

	# -- build keypair path: HOME + "/.entity/peers/" + NAME + "/keypair" --
	call find_home                  # a0 = HOME ptr
	lla  a1, b_path
	call strcpy_ret                 # a0 = cursor after HOME
	mv   s7, a0
	lla  a0, s_pathmid
	mv   a1, s7
	call strcpy_ret
	mv   s7, a0
	lla  t0, g_name_ptr
	ld   a0, 0(t0)
	mv   a1, s7
	call strcpy_ret
	mv   s7, a0
	lla  a0, s_pathend
	mv   a1, s7
	call strcpy_ret
	sb   zero, 0(a0)                # NUL-terminate path (a0 = final cursor)

	# -- openat(AT_FDCWD, path, O_RDONLY) --
	li   a0, AT_FDCWD
	lla  a1, b_path
	li   a2, 0                      # O_RDONLY
	li   a3, 0
	ksys SYS_openat
	bltz a0, .Lfatal_open
	mv   s5, a0                     # fd
	# read(fd, b_file, 4096)
	mv   a0, s5
	lla  a1, b_file
	li   a2, 4096
	ksys SYS_read
	mv   s7, a0                     # filelen
	blez a0, .Lfatal_open
	mv   a0, s5
	ksys SYS_close

	# -- extract base64 body, decode -> g_seed --
	lla  a0, b_file
	mv   a1, s7
	lla  a2, b_b64
	call extract_b64                # a0 = b64 len
	mv   a1, a0                     # len
	lla  a0, b_b64
	lla  a2, g_seed
	call b64_decode                 # a0 = out len
	li   t0, SEED_LEN
	bne  a0, t0, .Lfatal_b64

	# -- FFI: seed -> pubkey --
	lla  a0, g_seed
	lla  a1, g_pubkey
	call ec_ed25519_seed_to_pubkey
	bnez a0, .Lfatal_b64
	# -- FFI: peer_id = base58(varint(1)||varint(0)||pubkey) --
	# ec_peerid_format(key_type, hash_type, digest, digest_len, out, out_cap, out_len).
	# 7 args → a0..a6 (all in registers on LP64D; no stack arg).
	li   a0, 1                      # key_type = ed25519
	li   a1, 0                      # hash_type = 0 (identity)
	lla  a2, g_pubkey
	li   a3, PUBKEY_LEN
	lla  a4, g_peerid
	li   a5, 128
	lla  a6, g_peerid_len
	call ec_peerid_format
	bnez a0, .Lfatal_b64

	# -- peer_bootstrap (store + identity-derived state) --
	call peer_bootstrap

	# -- socket(AF_INET, SOCK_STREAM, 0) --
	li   a0, AF_INET
	li   a1, SOCK_STREAM
	li   a2, 0
	ksys SYS_socket
	bltz a0, .Lfatal_sock
	mv   s5, a0                     # listenfd
	lla  t0, g_listenfd
	sd   a0, 0(t0)

	# setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &1, 4)
	mv   a0, s5
	li   a1, SOL_SOCKET
	li   a2, SO_REUSEADDR
	lla  a3, .Lone
	li   a4, 4
	ksys SYS_setsockopt

	# build sockaddr_in
	lla  t0, b_sockaddr
	li   t1, AF_INET
	sh   t1, 0(t0)                  # sin_family
	lla  t2, g_port_num
	lwu  t1, 0(t2)
	bswap16 t1, t1                  # host -> network (BE) 16-bit
	sh   t1, 2(t0)                  # sin_port
	li   t1, 0x0100007f            # 127.0.0.1 (LE store -> bytes 7f 00 00 01)
	sw   t1, 4(t0)                  # sin_addr
	sd   zero, 8(t0)

	# bind(fd, &sockaddr, 16)
	mv   a0, s5
	lla  a1, b_sockaddr
	li   a2, 16
	ksys SYS_bind
	bltz a0, .Lfatal_sock
	# listen(fd, 128)
	mv   a0, s5
	li   a1, 128
	ksys SYS_listen
	bltz a0, .Lfatal_sock

	call print_listening

	# -- accept loop: clone(SIGCHLD) per connection --
	# Mirrors the x86-64 fork-per-connection model (A-ASM-003): drains all exited children
	# (wait4 WNOHANG) so zombies never accumulate, accepts, clones a worker per connection,
	# serves inline on clone failure (never drops a connection).
.Laccept:
.Lreap:
	li   a0, -1
	li   a1, 0                      # status = NULL
	li   a2, WNOHANG
	li   a3, 0
	ksys SYS_wait4
	bgtz a0, .Lreap                 # reaped one (pid>0) → keep draining
	lla  t0, g_listenfd
	ld   a0, 0(t0)
	li   a1, 0                      # addr = NULL
	li   a2, 0                      # addrlen = NULL
	li   a3, 0                      # flags = 0
	ksys SYS_accept4
	bltz a0, .Laccept               # EINTR/again → retry
	mv   s5, a0                     # connfd (callee-saved across clone)
	# clone(SIGCHLD, 0, 0, 0, 0) == fork
	li   a0, SIGCHLD
	li   a1, 0
	li   a2, 0
	li   a3, 0
	li   a4, 0
	ksys SYS_clone
	bltz a0, .Lserve_inline         # clone FAILED (resource pressure) → serve in-process
	bnez a0, .Lparent               # parent: pid>0
	# --- child ---
	mv   a0, s5                     # connfd
	li   a1, IPPROTO_TCP
	li   a2, TCP_NODELAY
	lla  a3, .Lone
	li   a4, 4
	ksys SYS_setsockopt
	mv   a0, s5
	call conn_serve                 # handles + closes the connection
	li   a0, 0
	ksys SYS_exit_group             # child exits
.Lserve_inline:
	# clone failed — handle inline in the parent (brief head-of-line blocking under genuine
	# clone exhaustion) so every connection is still answered.
	mv   a0, s5
	li   a1, IPPROTO_TCP
	li   a2, TCP_NODELAY
	lla  a3, .Lone
	li   a4, 4
	ksys SYS_setsockopt
	mv   a0, s5
	call conn_serve
	mv   a0, s5
	ksys SYS_close
	j    .Laccept
.Lparent:
	mv   a0, s5                     # close our copy of connfd
	ksys SYS_close
	j    .Laccept

.Lfatal_open:
	lla  a0, s_err_open
	j    .Lfatal
.Lfatal_b64:
	lla  a0, s_err_b64
	j    .Lfatal
.Lfatal_sock:
	lla  a0, s_err_sock
.Lfatal:
	call fputs_stderr
	li   a0, 1
	ksys SYS_exit_group

# =====================================================================
# print_listening — writes the LISTENING readiness line to stdout.
#   LISTENING 127.0.0.1:PORT peer_id=PID open_grants=B validate=B\n
# =====================================================================
	.type print_listening, @function
print_listening:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	lla  s1, b_line                 # cursor
	# "LISTENING 127.0.0.1:"
	mv   a0, s1
	lla  a1, s_listen_pre
	li   a2, s_listen_pre_len
	call mcpy
	mv   s1, a0
	# PORT (ascii from argv)
	mv   a0, s1
	lla  t0, g_port_ascii
	ld   a1, 0(t0)
	lla  t0, g_port_ascii_len
	ld   a2, 0(t0)
	call mcpy
	mv   s1, a0
	# " peer_id="
	mv   a0, s1
	lla  a1, s_pid_eq
	li   a2, s_pid_eq_len
	call mcpy
	mv   s1, a0
	# PID
	mv   a0, s1
	lla  a1, g_peerid
	lla  t0, g_peerid_len
	ld   a2, 0(t0)
	call mcpy
	mv   s1, a0
	# " open_grants="
	mv   a0, s1
	lla  a1, s_og_eq
	li   a2, s_og_eq_len
	call mcpy
	mv   s1, a0
	lla  t0, g_opengrants
	ld   a0, 0(t0)
	call bool_str                   # a1=ptr, a2=len
	mv   a0, s1
	call mcpy
	mv   s1, a0
	# " validate="
	mv   a0, s1
	lla  a1, s_val_eq
	li   a2, s_val_eq_len
	call mcpy
	mv   s1, a0
	lla  t0, g_validate
	ld   a0, 0(t0)
	call bool_str
	mv   a0, s1
	call mcpy
	mv   s1, a0
	li   t0, 10                     # '\n'
	sb   t0, 0(s1)
	addi s1, s1, 1
	# write_all(1, b_line, s1 - b_line)
	lla  a1, b_line
	sub  a2, s1, a1
	li   a0, STDOUT
	call write_all
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# bool_str(a0=0/1) -> a1=ptr, a2=len
	.type bool_str, @function
bool_str:
	beqz a0, .Lbs_false
	lla  a1, s_true
	li   a2, s_true_len
	ret
.Lbs_false:
	lla  a1, s_false
	li   a2, s_false_len
	ret

# =====================================================================
# find_home() -> a0 = ptr to HOME value (or "/root"). Scans envp for "HOME=".
# =====================================================================
	.type find_home, @function
find_home:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	lla  t0, g_envp
	ld   s1, 0(t0)                  # envp (callee-saved across strprefix)
.Lfh_loop:
	ld   a0, 0(s1)                  # env string
	beqz a0, .Lfh_default
	lla  a1, s_home_key
	call strprefix                  # a0=1 if str starts with "HOME="
	bnez a0, .Lfh_found
	addi s1, s1, 8
	j    .Lfh_loop
.Lfh_found:
	ld   a0, 0(s1)
	addi a0, a0, 5                  # skip "HOME="
	j    .Lfh_ret
.Lfh_default:
	lla  a0, s_default_home
.Lfh_ret:
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# strprefix(a0=str, a1=prefix) -> a0=1 if str starts with prefix
	.type strprefix, @function
strprefix:
.Lsp_loop:
	lbu  t0, 0(a1)                  # prefix char
	beqz t0, .Lsp_yes               # prefix exhausted → match
	lbu  t1, 0(a0)                  # str char
	bne  t0, t1, .Lsp_no
	addi a0, a0, 1
	addi a1, a1, 1
	j    .Lsp_loop
.Lsp_yes:
	li   a0, 1
	ret
.Lsp_no:
	li   a0, 0
	ret

# =====================================================================
# String / IO helpers (shared)
# =====================================================================
# strlen(a0) -> a0
	.globl strlen
	.type strlen, @function
strlen:
	li   t0, 0
.Lsl:
	add  t2, a0, t0
	lbu  t1, 0(t2)
	beqz t1, .Lsl_done
	addi t0, t0, 1
	j    .Lsl
.Lsl_done:
	mv   a0, t0
	ret

# streq(a0,a1) -> a0=1 if equal null-terminated strings
	.globl streq
	.type streq, @function
streq:
.Lse:
	lbu  t0, 0(a0)
	lbu  t1, 0(a1)
	bne  t0, t1, .Lse_no
	beqz t0, .Lse_yes
	addi a0, a0, 1
	addi a1, a1, 1
	j    .Lse
.Lse_yes:
	li   a0, 1
	ret
.Lse_no:
	li   a0, 0
	ret

# strcpy_ret(a0=src null-term, a1=dst) -> a0 = dst cursor after copy (no NUL)
	.type strcpy_ret, @function
strcpy_ret:
.Lsc:
	lbu  t0, 0(a0)
	beqz t0, .Lsc_done
	sb   t0, 0(a1)
	addi a0, a0, 1
	addi a1, a1, 1
	j    .Lsc
.Lsc_done:
	mv   a0, a1
	ret

# mcpy(a0=dst, a1=src, a2=len) -> a0 = dst+len   (memcpy returning end cursor)
	.globl mcpy
	.type mcpy, @function
mcpy:
	li   t0, 0
.Lmc:
	bge  t0, a2, .Lmc_done
	add  t2, a1, t0
	lbu  t1, 0(t2)
	add  t2, a0, t0
	sb   t1, 0(t2)
	addi t0, t0, 1
	j    .Lmc
.Lmc_done:
	add  a0, a0, a2
	ret

# write_all(a0=fd, a1=buf, a2=len) — loops until all written
	.globl write_all
	.type write_all, @function
write_all:
	addi sp, sp, -48
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	mv   s0, sp
	mv   s1, a0                     # fd
	mv   s2, a1                     # buf
	mv   s3, a2                     # remaining
.Lwa:
	beqz s3, .Lwa_done
	mv   a0, s1
	mv   a1, s2
	mv   a2, s3
	ksys SYS_write
	blez a0, .Lwa_done              # error/EOF → stop
	add  s2, s2, a0
	sub  s3, s3, a0
	j    .Lwa
.Lwa_done:
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 48
	ret

# fputs_stderr(a0=asciz) — write a C string to stderr
	.type fputs_stderr, @function
fputs_stderr:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	mv   s1, a0                     # save ptr
	call strlen                     # a0 = len
	mv   a2, a0
	mv   a1, s1
	li   a0, STDERR
	call write_all
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

# parse_u16(a0=asciz decimal) -> a0 = value
	.type parse_u16, @function
parse_u16:
	li   t0, 0                      # acc
	li   t2, 10
.Lpu:
	lbu  t1, 0(a0)
	beqz t1, .Lpu_done
	li   t3, '0'
	bltu t1, t3, .Lpu_done
	li   t3, '9'
	bgtu t1, t3, .Lpu_done
	mul  t0, t0, t2                 # acc *= 10
	addi t1, t1, -'0'
	add  t0, t0, t1
	addi a0, a0, 1
	j    .Lpu
.Lpu_done:
	mv   a0, t0
	ret

# extract_b64(a0=filebuf, a1=filelen, a2=dst) -> a0 = dst length.
# Skips whole lines beginning with '-'; copies base64 chars from other lines. Leaf.
	.type extract_b64, @function
extract_b64:
	mv   t0, a0                     # p
	add  t1, a0, a1                 # end
	mv   t2, a2                     # out cursor
	mv   t3, a2                     # out start
.Lxb_line:
	bgeu t0, t1, .Lxb_done
	lbu  t4, 0(t0)                  # peek first char of line
	li   t5, '-'
	bne  t4, t5, .Lxb_copy
	# skip line (to after '\n')
.Lxb_skip:
	bgeu t0, t1, .Lxb_done
	lbu  t4, 0(t0)
	addi t0, t0, 1
	li   t5, 10
	bne  t4, t5, .Lxb_skip
	j    .Lxb_line
.Lxb_copy:
	bgeu t0, t1, .Lxb_done
	lbu  t4, 0(t0)
	addi t0, t0, 1
	li   t5, 10
	beq  t4, t5, .Lxb_line
	li   t5, 13
	beq  t4, t5, .Lxb_copy          # skip CR
	sb   t4, 0(t2)
	addi t2, t2, 1
	j    .Lxb_copy
.Lxb_done:
	sub  a0, t2, t3
	ret

# b64_decode(a0=src, a1=srclen, a2=dst) -> a0 = out length. Standard alphabet.
	.type b64_decode, @function
b64_decode:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s3, a0                     # src
	mv   s4, a1                     # srclen
	mv   s5, a2                     # dst
	li   s2, 0                      # i (src index)
	li   s1, 0                      # o (out index)
.Lbd_loop:
	sub  t0, s4, s2                 # remaining
	li   t1, 4
	blt  t0, t1, .Lbd_done          # need 4 input chars
	add  t4, s3, s2                 # base = src + i (survives leaf b64_val calls)
	lbu  a0, 0(t4)
	call b64_val
	mv   t0, a0                     # c0
	lbu  a0, 1(t4)
	call b64_val
	mv   t1, a0                     # c1
	lbu  a0, 2(t4)
	call b64_val
	mv   t2, a0                     # c2 (0..63 or 0xFF for '=')
	lbu  a0, 3(t4)
	call b64_val
	mv   t3, a0                     # c3
	addi s2, s2, 4
	# byte0 = c0<<2 | c1>>4
	slli a0, t0, 2
	srli t5, t1, 4
	or   a0, a0, t5
	add  t6, s5, s1
	sb   a0, 0(t6)
	addi s1, s1, 1
	# if c2 == pad, stop
	li   t5, 0xFF
	beq  t2, t5, .Lbd_done
	# byte1 = c1<<4 | c2>>2
	slli a0, t1, 4
	srli t5, t2, 2
	or   a0, a0, t5
	add  t6, s5, s1
	sb   a0, 0(t6)
	addi s1, s1, 1
	# if c3 == pad, stop
	li   t5, 0xFF
	beq  t3, t5, .Lbd_done
	# byte2 = c2<<6 | c3
	slli a0, t2, 6
	or   a0, a0, t3
	add  t6, s5, s1
	sb   a0, 0(t6)
	addi s1, s1, 1
	j    .Lbd_loop
.Lbd_done:
	mv   a0, s1
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

# b64_val(a0=char) -> a0 = 6-bit value, or 0xFF for '=' / invalid. Leaf.
# Uses ONLY a0 + t5 for compare constants — must not touch t0-t4 (b64_decode holds c0-c3 in
# t0-t3 and `base` in t4 live across the four b64_val calls; t5 is dead there). See b64_decode.
	.type b64_val, @function
b64_val:
	li   t5, 'A'
	bltu a0, t5, .Lbv_1
	li   t5, 'Z'
	bgtu a0, t5, .Lbv_1
	addi a0, a0, -'A'               # 0..25
	ret
.Lbv_1:
	li   t5, 'a'
	bltu a0, t5, .Lbv_2
	li   t5, 'z'
	bgtu a0, t5, .Lbv_2
	addi a0, a0, -'a'
	addi a0, a0, 26                 # 26..51
	ret
.Lbv_2:
	li   t5, '0'
	bltu a0, t5, .Lbv_3
	li   t5, '9'
	bgtu a0, t5, .Lbv_3
	addi a0, a0, -'0'
	addi a0, a0, 52                 # 52..61
	ret
.Lbv_3:
	li   t5, '+'
	bne  a0, t5, .Lbv_4
	li   a0, 62
	ret
.Lbv_4:
	li   t5, '/'
	bne  a0, t5, .Lbv_pad
	li   a0, 63
	ret
.Lbv_pad:
	li   a0, 0xFF                   # '=' or anything else
	ret

	.section .note.GNU-stack,"",@progbits   # mark stack non-executable (hygiene)
