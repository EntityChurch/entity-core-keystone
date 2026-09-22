// host.s — entity-core-protocol-asm-arm64 entry + boot path. Ported from asm-x86_64/src/host.s.
// GAS aarch64. Entry is `main` (cc-driver startup; libc initialized — A-ASM-001).
//
// Boot: parse CLI → load identity (PEM keypair → 32-byte seed → FFI pubkey → peer_id)
//       → socket/bind/listen → print LISTENING → accept loop.
// Transport is raw syscalls. Codec/crypto/peer-id are FFI (libentitycore_codec).
//
// Concurrency: clone(SIGCHLD)-per-connection. The generic syscall table has NO fork
// (__NR_fork undefined) — the x86-64 peer's `fork` becomes `clone(SIGCHLD,0,0,0,0)`,
// which with a NULL child stack is fork-equivalent (COW). See A-ARM64-001.

	.include "macros.s"

// ---- FFI imports (libentitycore_codec) ----
	.extern ec_ed25519_seed_to_pubkey
	.extern ec_peerid_format
// ---- module imports ----
	.extern conn_serve                     // dispatch.s: handle one accepted connection (x0=connfd)
	.extern peer_bootstrap                 // dispatch.s: build store + identity-derived state

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
	.balign 8
.Lconn_timeo:	.quad 30, 0   // struct timeval { tv_sec = 30, tv_usec = 0 }

	.bss
	.lcomm g_name_ptr, 8
	.lcomm g_port_ascii, 8
	.lcomm g_port_ascii_len, 8
	.lcomm g_port_num, 8            // host-order u16 in low bytes
	.lcomm g_validate, 8           // 0/1
	.globl g_opengrants
	.lcomm g_opengrants, 8         // 0/1
	.lcomm g_listenfd, 8
	.lcomm g_live_conns, 8   // §4.10(c) admission counter (parent only)
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
	.type main, %function
// main(x0=argc, x1=argv, x2=envp)
main:
	stp  x29, x30, [sp, #-96]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	stp  x23, x24, [sp, #48]
	str  x25, [sp, #64]

	mov  x21, x0                    // argc
	mov  x22, x1                    // argv
	adr_l x9, g_envp
	str  x2, [x9]

	// defaults
	adr_l x9, s_default_name
	adr_l x10, g_name_ptr
	str  x9, [x10]
	adr_l x9, g_validate
	str  xzr, [x9]
	adr_l x9, g_opengrants
	str  xzr, [x9]
	adr_l x9, g_port_num
	str  xzr, [x9]

	// -- parse argv[1..] --
	mov  x19, #1                    // i = 1
.Largloop:
	cmp  x19, x21
	b.ge .Largdone
	ldr  x23, [x22, x19, lsl #3]    // argv[i]
	// --port ?
	mov  x0, x23
	adr_l x1, s_arg_port
	bl   streq
	cbz  x0, .Lnot_port
	add  x19, x19, #1
	cmp  x19, x21
	b.ge .Largdone
	ldr  x9, [x22, x19, lsl #3]
	adr_l x10, g_port_ascii
	str  x9, [x10]
	mov  x0, x9
	bl   strlen
	adr_l x10, g_port_ascii_len
	str  x0, [x10]
	adr_l x9, g_port_ascii
	ldr  x0, [x9]
	bl   parse_u16
	adr_l x9, g_port_num
	str  x0, [x9]
	b    .Larg_next
.Lnot_port:
	mov  x0, x23
	adr_l x1, s_arg_name
	bl   streq
	cbz  x0, .Lnot_name
	add  x19, x19, #1
	cmp  x19, x21
	b.ge .Largdone
	ldr  x9, [x22, x19, lsl #3]
	adr_l x10, g_name_ptr
	str  x9, [x10]
	b    .Larg_next
.Lnot_name:
	mov  x0, x23
	adr_l x1, s_arg_val
	bl   streq
	cbz  x0, .Lnot_val
	mov  x9, #1
	adr_l x10, g_validate
	str  x9, [x10]
	b    .Larg_next
.Lnot_val:
	mov  x0, x23
	adr_l x1, s_arg_open
	bl   streq
	cbz  x0, .Larg_next
	mov  x9, #1
	adr_l x10, g_opengrants
	str  x9, [x10]
.Larg_next:
	add  x19, x19, #1
	b    .Largloop
.Largdone:

	// -- build keypair path: HOME + "/.entity/peers/" + NAME + "/keypair" --
	bl   find_home                  // x0 = HOME ptr
	adr_l x1, b_path
	bl   strcpy_ret                 // x0 = cursor after HOME
	mov  x25, x0
	adr_l x0, s_pathmid
	mov  x1, x25
	bl   strcpy_ret
	mov  x25, x0
	adr_l x9, g_name_ptr
	ldr  x0, [x9]
	mov  x1, x25
	bl   strcpy_ret
	mov  x25, x0
	adr_l x0, s_pathend
	mov  x1, x25
	bl   strcpy_ret
	strb wzr, [x0]                  // NUL-terminate path (x0 = final cursor)

	// -- openat(AT_FDCWD, path, O_RDONLY) --
	mov  x0, #AT_FDCWD
	adr_l x1, b_path
	mov  x2, #0                     // O_RDONLY
	mov  x3, #0
	ksys SYS_openat
	tbnz x0, #63, .Lfatal_open
	mov  x23, x0                    // fd
	// read(fd, b_file, 4096)
	mov  x0, x23
	adr_l x1, b_file
	mov  x2, #4096
	ksys SYS_read
	mov  x25, x0                    // filelen
	cmp  x0, #0
	b.le .Lfatal_open
	mov  x0, x23
	ksys SYS_close

	// -- extract base64 body, decode -> g_seed --
	adr_l x0, b_file
	mov  x1, x25
	adr_l x2, b_b64
	bl   extract_b64                // x0 = b64 len
	mov  x1, x0                     // len
	adr_l x0, b_b64
	adr_l x2, g_seed
	bl   b64_decode                 // x0 = out len
	cmp  x0, #SEED_LEN
	b.ne .Lfatal_b64

	// -- FFI: seed -> pubkey --
	adr_l x0, g_seed
	adr_l x1, g_pubkey
	bl   ec_ed25519_seed_to_pubkey
	cbnz w0, .Lfatal_b64
	// -- FFI: peer_id = base58(varint(1)||varint(0)||pubkey) --
	// ec_peerid_format(key_type, hash_type, digest, digest_len, out, out_cap, out_len).
	// 7 args → x0..x6 (all in registers on AAPCS64; no stack arg, unlike x86-64's 7th on stack).
	mov  x0, #1                     // key_type = ed25519
	mov  x1, #0                     // hash_type = 0 (identity)
	adr_l x2, g_pubkey
	mov  x3, #PUBKEY_LEN
	adr_l x4, g_peerid
	mov  x5, #128
	adr_l x6, g_peerid_len
	bl   ec_peerid_format
	cbnz w0, .Lfatal_b64

	// -- peer_bootstrap (store + identity-derived state) --
	bl   peer_bootstrap

	// -- socket(AF_INET, SOCK_STREAM, 0) --
	mov  x0, #AF_INET
	mov  x1, #SOCK_STREAM
	mov  x2, #0
	ksys SYS_socket
	tbnz x0, #63, .Lfatal_sock
	mov  x23, x0                    // listenfd
	adr_l x9, g_listenfd
	str  x0, [x9]

	// setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &1, 4)
	mov  x0, x23
	mov  x1, #SOL_SOCKET
	mov  x2, #SO_REUSEADDR
	adr_l x3, .Lone
	mov  x4, #4
	ksys SYS_setsockopt

	// build sockaddr_in
	adr_l x9, b_sockaddr
	mov  w10, #AF_INET
	strh w10, [x9]                  // sin_family
	adr_l x11, g_port_num
	ldr  w10, [x11]
	rev16 w10, w10                  // host -> network (BE) 16-bit
	strh w10, [x9, #2]              // sin_port
	mov  w10, #0x007f
	movk w10, #0x0100, lsl #16      // 127.0.0.1 (LE word 0x0100007f -> bytes 7f 00 00 01)
	str  w10, [x9, #4]              // sin_addr
	str  xzr, [x9, #8]

	// bind(fd, &sockaddr, 16)
	mov  x0, x23
	adr_l x1, b_sockaddr
	mov  x2, #16
	ksys SYS_bind
	tbnz x0, #63, .Lfatal_sock
	// listen(fd, 128)
	mov  x0, x23
	mov  x1, #128
	ksys SYS_listen
	tbnz x0, #63, .Lfatal_sock

	bl   print_listening

	// -- accept loop: clone(SIGCHLD) per connection --
	// Mirrors the x86-64 fork-per-connection model (A-ASM-003): drains all exited children
	// (wait4 WNOHANG) so zombies never accumulate, accepts, clones a worker per connection,
	// serves inline on clone failure (never drops a connection).
.Laccept:
	bl   reap_children              // drain zombies before parking in accept4
	adr_l x9, g_listenfd
	ldr  x0, [x9]
	mov  x1, #0                     // addr = NULL
	mov  x2, #0                     // addrlen = NULL
	mov  x3, #0                     // flags = 0
	ksys SYS_accept4
	tbnz x0, #63, .Laccept          // EINTR/again → retry
	mov  x23, x0                    // connfd (callee-saved across clone)
	// Reap AGAIN, here, before the admission decision — not only above.
	//
	// The reap above runs before a BLOCKING accept4, so every child that exits while
	// the parent is parked in it is still counted as live when the parent wakes. At
	// an idle peer that is invisible; at the bound it is fatal, and it is exactly how
	// a working admission cap presents as a dead peer: on x86-64 the peer correctly
	// refused 194 of 256 flood connections and then refused the ONE probe that
	// followed, because the count still read 64 with every child already gone. The
	// oracle named it outright — "admission slots leaked; the bound must release when
	// connections close". A bound that never releases is not a bound, it is an outage
	// with a threshold.
	bl   reap_children
	// §4.10(c) admission: over the bound, refuse by closing. The spec names close as
	// an allowed refusal ("an implementation MAY instead refuse by closing"), and it
	// is the only one available here — a 503 frame would need the request_id, which
	// is not read until after admission. Refusing costs one close and keeps the
	// accept loop hot, which is the property the check actually gates.
	adr_l x9, g_live_conns
	ldr  x10, [x9]
	cmp  x10, #MAX_CONNS
	b.lt .Ladmit
	mov  x0, x23
	ksys SYS_close
	b    .Laccept
.Ladmit:
	// clone(SIGCHLD, 0, 0, 0, 0) == fork
	mov  x0, #SIGCHLD
	mov  x1, #0
	mov  x2, #0
	mov  x3, #0
	mov  x4, #0
	ksys SYS_clone
	tbnz x0, #63, .Lserve_inline    // clone FAILED (resource pressure) → serve in-process
	cbnz x0, .Lparent               // parent: pid>0
	// --- child ---
	// The listening socket was inherited across the clone and is NOT this child's to
	// hold. Measured on x86-64: every stuck child kept its fd open on the parent's
	// listen inode, so the port stayed bound by processes that were never going to
	// serve it again. Close it first — before anything that can block — so it cannot
	// outlive the decision to serve one connection.
	adr_l x9, g_listenfd
	ldr  x0, [x9]
	ksys SYS_close
	mov  x0, x23                    // connfd
	mov  x1, #IPPROTO_TCP
	mov  x2, #TCP_NODELAY
	adr_l x3, .Lone
	mov  x4, #4
	ksys SYS_setsockopt
	mov  x0, x23
	bl   set_conn_deadlines
	mov  x0, x23
	bl   conn_serve                 // handles + closes the connection
	mov  x0, #0
	ksys SYS_exit_group             // child exits
.Lserve_inline:
	// clone failed — handle inline in the parent (brief head-of-line blocking under genuine
	// clone exhaustion) so every connection is still answered.
	mov  x0, x23
	mov  x1, #IPPROTO_TCP
	mov  x2, #TCP_NODELAY
	adr_l x3, .Lone
	mov  x4, #4
	ksys SYS_setsockopt
	mov  x0, x23
	bl   set_conn_deadlines
	mov  x0, x23
	bl   conn_serve
	mov  x0, x23
	ksys SYS_close
	b    .Laccept
.Lparent:
	adr_l x9, g_live_conns          // admitted one; reap_children decrements on exit
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	mov  x0, x23                    // close our copy of connfd
	ksys SYS_close
	b    .Laccept

// reap_children — wait4(WNOHANG) until dry, decrementing the live-connection count
// once per reaped child. Called both before the blocking accept4 and again after it
// returns, so the §4.10(c) count the admission test reads is never stale.
//
// x23 holds the accept loop's connfd and is untouched here. x30 is saved because the
// caller reaches this with `bl`.
	.type reap_children, @function
reap_children:
	stp  x29, x30, [sp, #-16]!
.Lrc_loop:
	mov  x0, #-1
	mov  x1, #0                     // status = NULL
	mov  x2, #WNOHANG
	mov  x3, #0
	ksys SYS_wait4
	cmp  x0, #0
	b.le .Lrc_done                  // 0 = none exited, <0 = ECHILD
	adr_l x9, g_live_conns
	ldr  x10, [x9]
	sub  x10, x10, #1
	str  x10, [x9]
	b    .Lrc_loop
.Lrc_done:
	ldp  x29, x30, [sp], #16
	ret

// set_conn_deadlines(x0 = connfd) — an idle deadline on a served connection.
//
// Without one, a cloned child that is waiting on bytes that never arrive blocks in
// read(2) FOREVER. On a goroutine-per-connection peer that costs a parked goroutine;
// here it costs a whole process holding a 16 MiB COW b_req, so it is an accumulation
// defect, and §4.10's "rejection is clean, not collapse" is what it eventually breaks.
//
// This is a SOCKET-level idle deadline on a connection this child owns exclusively
// and serves one frame at a time. It is deliberately NOT the §6.11(c) per-request
// deadline, which that section requires and separately forbids being implemented as
// a connection-wide primitive that races across concurrent in-flight requests —
// there are no concurrent in-flight requests inside one child.
//
// 30 s is well above any inter-frame gap the suite produces and well below the point
// at which stuck children matter. read_full already treats a short/failed read as
// end-of-connection, so an expiry lands on the existing close-and-exit path.
	.type set_conn_deadlines, @function
set_conn_deadlines:
	stp  x29, x30, [sp, #-16]!
	stp  x19, x20, [sp, #-16]!
	mov  x19, x0                    // connfd, kept across both setsockopt calls
	mov  x1, #SOL_SOCKET
	mov  x2, #SO_RCVTIMEO
	adr_l x3, .Lconn_timeo
	mov  x4, #16
	ksys SYS_setsockopt
	mov  x0, x19
	mov  x1, #SOL_SOCKET
	mov  x2, #SO_SNDTIMEO
	adr_l x3, .Lconn_timeo
	mov  x4, #16
	ksys SYS_setsockopt
	ldp  x19, x20, [sp], #16
	ldp  x29, x30, [sp], #16
	ret

.Lfatal_open:
	adr_l x0, s_err_open
	b    .Lfatal
.Lfatal_b64:
	adr_l x0, s_err_b64
	b    .Lfatal
.Lfatal_sock:
	adr_l x0, s_err_sock
.Lfatal:
	bl   fputs_stderr
	mov  x0, #1
	ksys SYS_exit_group

// =====================================================================
// print_listening — writes the LISTENING readiness line to stdout.
//   LISTENING 127.0.0.1:PORT peer_id=PID open_grants=B validate=B\n
// =====================================================================
	.type print_listening, %function
print_listening:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x19, [sp, #16]
	adr_l x19, b_line               // cursor
	// "LISTENING 127.0.0.1:"
	mov  x0, x19
	adr_l x1, s_listen_pre
	mov  x2, #s_listen_pre_len
	bl   mcpy
	mov  x19, x0
	// PORT (ascii from argv)
	mov  x0, x19
	adr_l x9, g_port_ascii
	ldr  x1, [x9]
	adr_l x9, g_port_ascii_len
	ldr  x2, [x9]
	bl   mcpy
	mov  x19, x0
	// " peer_id="
	mov  x0, x19
	adr_l x1, s_pid_eq
	mov  x2, #s_pid_eq_len
	bl   mcpy
	mov  x19, x0
	// PID
	mov  x0, x19
	adr_l x1, g_peerid
	adr_l x9, g_peerid_len
	ldr  x2, [x9]
	bl   mcpy
	mov  x19, x0
	// " open_grants="
	mov  x0, x19
	adr_l x1, s_og_eq
	mov  x2, #s_og_eq_len
	bl   mcpy
	mov  x19, x0
	adr_l x9, g_opengrants
	ldr  x0, [x9]
	bl   bool_str                   // x1=ptr, x2=len
	mov  x0, x19
	bl   mcpy
	mov  x19, x0
	// " validate="
	mov  x0, x19
	adr_l x1, s_val_eq
	mov  x2, #s_val_eq_len
	bl   mcpy
	mov  x19, x0
	adr_l x9, g_validate
	ldr  x0, [x9]
	bl   bool_str
	mov  x0, x19
	bl   mcpy
	mov  x19, x0
	mov  w9, #10                    // '\n'
	strb w9, [x19]
	add  x19, x19, #1
	// write_all(1, b_line, x19 - b_line)
	adr_l x1, b_line
	sub  x2, x19, x1
	mov  x0, #STDOUT
	bl   write_all
	ldr  x19, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

// bool_str(x0=0/1) -> x1=ptr, x2=len
	.type bool_str, %function
bool_str:
	cbz  x0, .Lbs_false
	adr_l x1, s_true
	mov  x2, #s_true_len
	ret
.Lbs_false:
	adr_l x1, s_false
	mov  x2, #s_false_len
	ret

// =====================================================================
// find_home() -> x0 = ptr to HOME value (or "/root"). Scans envp for "HOME=".
// =====================================================================
	.type find_home, %function
find_home:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x19, [sp, #16]
	adr_l x9, g_envp
	ldr  x19, [x9]                  // envp (callee-saved across strprefix)
.Lfh_loop:
	ldr  x0, [x19]                  // env string
	cbz  x0, .Lfh_default
	adr_l x1, s_home_key
	bl   strprefix                  // x0=1 if str starts with "HOME="
	cbnz x0, .Lfh_found
	add  x19, x19, #8
	b    .Lfh_loop
.Lfh_found:
	ldr  x0, [x19]
	add  x0, x0, #5                 // skip "HOME="
	b    .Lfh_ret
.Lfh_default:
	adr_l x0, s_default_home
.Lfh_ret:
	ldr  x19, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

// strprefix(x0=str, x1=prefix) -> x0=1 if str starts with prefix
	.type strprefix, %function
strprefix:
.Lsp_loop:
	ldrb w9, [x1]                   // prefix char
	cbz  w9, .Lsp_yes               // prefix exhausted → match
	ldrb w10, [x0]                  // str char
	cmp  w9, w10
	b.ne .Lsp_no
	add  x0, x0, #1
	add  x1, x1, #1
	b    .Lsp_loop
.Lsp_yes:
	mov  x0, #1
	ret
.Lsp_no:
	mov  x0, #0
	ret

// =====================================================================
// String / IO helpers (shared)
// =====================================================================
// strlen(x0) -> x0
	.globl strlen
	.type strlen, %function
strlen:
	mov  x9, #0
.Lsl:
	ldrb w10, [x0, x9]
	cbz  w10, .Lsl_done
	add  x9, x9, #1
	b    .Lsl
.Lsl_done:
	mov  x0, x9
	ret

// streq(x0,x1) -> x0=1 if equal null-terminated strings
	.globl streq
	.type streq, %function
streq:
.Lse:
	ldrb w9, [x0]
	ldrb w10, [x1]
	cmp  w9, w10
	b.ne .Lse_no
	cbz  w9, .Lse_yes
	add  x0, x0, #1
	add  x1, x1, #1
	b    .Lse
.Lse_yes:
	mov  x0, #1
	ret
.Lse_no:
	mov  x0, #0
	ret

// strcpy_ret(x0=src null-term, x1=dst) -> x0 = dst cursor after copy (no NUL)
	.type strcpy_ret, %function
strcpy_ret:
.Lsc:
	ldrb w9, [x0]
	cbz  w9, .Lsc_done
	strb w9, [x1]
	add  x0, x0, #1
	add  x1, x1, #1
	b    .Lsc
.Lsc_done:
	mov  x0, x1
	ret

// mcpy(x0=dst, x1=src, x2=len) -> x0 = dst+len   (memcpy returning end cursor)
	.globl mcpy
	.type mcpy, %function
mcpy:
	mov  x9, #0
.Lmc:
	cmp  x9, x2
	b.ge .Lmc_done
	ldrb w10, [x1, x9]
	strb w10, [x0, x9]
	add  x9, x9, #1
	b    .Lmc
.Lmc_done:
	add  x0, x0, x2
	ret

// write_all(x0=fd, x1=buf, x2=len) — loops until all written
	.globl write_all
	.type write_all, %function
write_all:
	stp  x29, x30, [sp, #-48]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	str  x21, [sp, #32]
	mov  x19, x0                    // fd
	mov  x20, x1                    // buf
	mov  x21, x2                    // remaining
.Lwa:
	cbz  x21, .Lwa_done
	mov  x0, x19
	mov  x1, x20
	mov  x2, x21
	ksys SYS_write
	cmp  x0, #0
	b.le .Lwa_done                  // error/EOF → stop
	add  x20, x20, x0
	sub  x21, x21, x0
	b    .Lwa
.Lwa_done:
	ldr  x21, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #48
	ret

// fputs_stderr(x0=asciz) — write a C string to stderr
	.type fputs_stderr, %function
fputs_stderr:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x19, [sp, #16]
	mov  x19, x0                    // save ptr
	bl   strlen                     // x0 = len
	mov  x2, x0
	mov  x1, x19
	mov  x0, #STDERR
	bl   write_all
	ldr  x19, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

// parse_u16(x0=asciz decimal) -> x0 = value
	.type parse_u16, %function
parse_u16:
	mov  x9, #0                     // acc
	mov  w11, #10
.Lpu:
	ldrb w10, [x0]
	cbz  w10, .Lpu_done
	cmp  w10, #'0'
	b.lo .Lpu_done
	cmp  w10, #'9'
	b.hi .Lpu_done
	mul  x9, x9, x11                // acc *= 10
	sub  w10, w10, #'0'
	add  x9, x9, x10
	add  x0, x0, #1
	b    .Lpu
.Lpu_done:
	mov  x0, x9
	ret

// extract_b64(x0=filebuf, x1=filelen, x2=dst) -> x0 = dst length.
// Skips whole lines beginning with '-'; copies base64 chars from other lines. Leaf.
	.type extract_b64, %function
extract_b64:
	mov  x9, x0                     // p
	add  x10, x0, x1                // end
	mov  x11, x2                    // out cursor
	mov  x12, x2                    // out start
.Lxb_line:
	cmp  x9, x10
	b.hs .Lxb_done
	ldrb w13, [x9]                  // peek first char of line
	cmp  w13, #'-'
	b.ne .Lxb_copy
	// skip line (to after '\n')
.Lxb_skip:
	cmp  x9, x10
	b.hs .Lxb_done
	ldrb w13, [x9]
	add  x9, x9, #1
	cmp  w13, #10
	b.ne .Lxb_skip
	b    .Lxb_line
.Lxb_copy:
	cmp  x9, x10
	b.hs .Lxb_done
	ldrb w13, [x9]
	add  x9, x9, #1
	cmp  w13, #10
	b.eq .Lxb_line
	cmp  w13, #13
	b.eq .Lxb_copy                  // skip CR
	strb w13, [x11]
	add  x11, x11, #1
	b    .Lxb_copy
.Lxb_done:
	sub  x0, x11, x12
	ret

// b64_decode(x0=src, x1=srclen, x2=dst) -> x0 = out length. Standard alphabet.
	.type b64_decode, %function
b64_decode:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x21, x0                    // src
	mov  x22, x1                    // srclen
	mov  x23, x2                    // dst
	mov  x20, #0                    // i (src index)
	mov  x19, #0                    // o (out index)
.Lbd_loop:
	sub  x9, x22, x20               // remaining
	cmp  x9, #4
	b.lt .Lbd_done                  // need 4 input chars
	add  x13, x21, x20              // base = src + i (survives leaf b64_val calls)
	ldrb w0, [x13]
	bl   b64_val
	mov  w9, w0                     // c0
	ldrb w0, [x13, #1]
	bl   b64_val
	mov  w10, w0                    // c1
	ldrb w0, [x13, #2]
	bl   b64_val
	mov  w11, w0                    // c2 (0..63 or 0xFF for '=')
	ldrb w0, [x13, #3]
	bl   b64_val
	mov  w12, w0                    // c3
	add  x20, x20, #4
	// byte0 = c0<<2 | c1>>4
	lsl  w0, w9, #2
	lsr  w14, w10, #4
	orr  w0, w0, w14
	strb w0, [x23, x19]
	add  x19, x19, #1
	// if c2 == pad, stop
	cmp  w11, #0xFF
	b.eq .Lbd_done
	// byte1 = c1<<4 | c2>>2
	lsl  w0, w10, #4
	lsr  w14, w11, #2
	orr  w0, w0, w14
	strb w0, [x23, x19]
	add  x19, x19, #1
	// if c3 == pad, stop
	cmp  w12, #0xFF
	b.eq .Lbd_done
	// byte2 = c2<<6 | c3
	lsl  w0, w11, #6
	orr  w0, w0, w12
	strb w0, [x23, x19]
	add  x19, x19, #1
	b    .Lbd_loop
.Lbd_done:
	mov  x0, x19
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

// b64_val(w0=char) -> w0 = 6-bit value, or 0xFF for '=' / invalid. Leaf (only w0).
	.type b64_val, %function
b64_val:
	cmp  w0, #'A'
	b.lo .Lbv_1
	cmp  w0, #'Z'
	b.hi .Lbv_1
	sub  w0, w0, #'A'               // 0..25
	ret
.Lbv_1:
	cmp  w0, #'a'
	b.lo .Lbv_2
	cmp  w0, #'z'
	b.hi .Lbv_2
	sub  w0, w0, #'a'
	add  w0, w0, #26                // 26..51
	ret
.Lbv_2:
	cmp  w0, #'0'
	b.lo .Lbv_3
	cmp  w0, #'9'
	b.hi .Lbv_3
	sub  w0, w0, #'0'
	add  w0, w0, #52                // 52..61
	ret
.Lbv_3:
	cmp  w0, #'+'
	b.ne .Lbv_4
	mov  w0, #62
	ret
.Lbv_4:
	cmp  w0, #'/'
	b.ne .Lbv_pad
	mov  w0, #63
	ret
.Lbv_pad:
	mov  w0, #0xFF                  // '=' or anything else
	ret

	.section .note.GNU-stack,"",%progbits   // mark stack non-executable (hygiene)
