# codec.s — L2 native canonical ECF codec (x86-64, GAS/AT&T). Milestone 1.
#
# Replaces the FFI codec's canonical-CBOR core with hand-written asm — the L2
# discovery bet ("can the canonical N1-N4 invariants be expressed in asm, byte-
# exact?"). This file implements the F6 Class-A hook `ec_encode_bare_value`: a
# recursive-descent TRANSCODER that reads one CBOR value and re-emits it in
# canonical form, re-deriving canonical shape from the decoded value (NOT passing
# bytes through): shortest integer heads (RFC 8949 Rule 1), the shortest-float
# f16/f32/f64 ladder (Rule 4/4a), definite-length only (Rule 3), and a recursive
# major-type-6 tag REJECT at every depth (N2). Fed the 3-way-locked corpus's
# golden bytes, an identity result proves the canonical logic (a wrong ladder/head
# choice diverges from golden).
#
# Milestone-1 scope: map entries are emitted in input order. The corpus map_keys
# vectors are already canonical (pre-sorted), so they pass; genuine length-then-lex
# key SORTING (for arbitrary input) + synthetic unsorted coverage lands in M1b.
# f16 subnormal *input* decode is a documented gap (no corpus vector); it rejects
# rather than silently mis-decode.
#
# ABI (C-ABI spec §4.1, test-only F6 hook):
#   int32_t ec_encode_bare_value(const uint8_t *in, size_t in_len,
#                                uint8_t *out, size_t out_cap, size_t *out_len);
#   EC_OK(0) + canonical bytes in out / *out_len ; EC_DECODE_ERROR(-3) on malformed
#   or tag ; EC_OUT_OF_SPACE(-2) if out too small.
#
# Single-threaded use only (harness + the peer's epoll loop, A-ASM-003): a static
# unwind target (err_rsp) lets any leaf abort deep recursion in one hop. No libc,
# no aligned-SSE memory ops (so stack alignment across recursion is a non-issue).
#
# ecf_scratch capacity. Must track dispatch.s's MAX_FRAME / b_req (16 MiB): the only
# values ec_content_hash is asked about are entities that arrived inside one frame,
# and a canonical re-encode never expands its input. codec.s is deliberately
# standalone (it does not .include macros.s -- `make diff` and `make parse-test`
# link it with no dispatch.o), so the constant is restated here rather than shared;
# if MAX_FRAME moves, this moves with it.
	.equ	ECF_SCRATCH_CAP, 0x1000000	# 16 MiB, == dispatch.s MAX_FRAME
#
# Global register state for the duration of one call (callee-saved, set in prologue):
#   r12 = in_cur   r13 = in_end   r14 = out_cur   r15 = out_end
#   rbx = out_base r bp = out_len_ptr
# Scratch (caller-saved): rax rcx rdx rsi rdi r8 r9 r10 r11. The float ladder keeps
# persistent values in r8..r11 (emit_byte/emit_be preserve those; they touch only
# rax/rcx/rdx/rsi/rdi/r14/flags).

	.text

# ---- error trampolines (shared by all helpers) ----------------------------
.Lreject:
	movl	$-3, %eax		# EC_DECODE_ERROR
	jmp	.Lunwind
.Loverflow:
	movl	$-2, %eax		# EC_OUT_OF_SPACE
	jmp	.Lunwind
.Lunwind:
	movq	err_rsp(%rip), %rsp	# discard all recursion frames
	jmp	.Lepi

# ---- public entry ----------------------------------------------------------
	.globl	ec_encode_bare_value
	.type	ec_encode_bare_value,@function
ec_encode_bare_value:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	%rsp, err_rsp(%rip)	# unwind target = frame base (6 regs saved)
	# rdi=in rsi=in_len rdx=out rcx=out_cap r8=out_len_ptr
	movq	%rdi, %r12		# in_cur
	leaq	(%rdi,%rsi), %r13	# in_end
	movq	%rdx, %r14		# out_cur
	movq	%rdx, %rbx		# out_base
	leaq	(%rdx,%rcx), %r15	# out_end
	movq	%r8, %rbp		# out_len_ptr
	call	transcode
	cmpq	%r12, %r13		# all input consumed?
	jne	.Lreject		# trailing bytes → malformed
	movq	%r14, %rax
	subq	%rbx, %rax		# *out_len = out_cur - out_base
	movq	%rax, (%rbp)
	xorl	%eax, %eax		# EC_OK
.Lepi:
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret

# ---- rd_head: decode one CBOR head at r12 ----------------------------------
# out: cl=major(0-7), dl=ai(0-31), rax=argument. advances r12 past head+arg bytes.
# rejects ai 28-31 (incl indefinite 31). preserves r8-r15,rbx,rbp.
rd_head:
	cmpq	%r12, %r13
	jbe	.Lreject		# no byte available
	movzbl	(%r12), %eax
	incq	%r12
	movl	%eax, %edx
	andl	$0x1f, %edx		# ai
	shrl	$5, %eax		# major
	movl	%eax, %ecx		# cl = major
	cmpl	$24, %edx
	jb	.rh_lt24
	je	.rh_1
	cmpl	$25, %edx
	je	.rh_2
	cmpl	$26, %edx
	je	.rh_4
	cmpl	$27, %edx
	je	.rh_8
	jmp	.Lreject		# ai 28-31
.rh_lt24:
	movzbl	%dl, %eax		# arg = ai
	ret
.rh_1:
	cmpq	%r12, %r13
	jbe	.Lreject
	movzbl	(%r12), %eax
	incq	%r12
	ret
.rh_2:
	leaq	2(%r12), %rax
	cmpq	%rax, %r13
	jb	.Lreject
	xorq	%rax, %rax
	movzbl	0(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	1(%r12), %esi
	orq	%rsi, %rax
	addq	$2, %r12
	ret
.rh_4:
	leaq	4(%r12), %rax
	cmpq	%rax, %r13
	jb	.Lreject
	xorq	%rax, %rax
	movzbl	0(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	1(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	2(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	3(%r12), %esi
	orq	%rsi, %rax
	addq	$4, %r12
	ret
.rh_8:
	leaq	8(%r12), %rax
	cmpq	%rax, %r13
	jb	.Lreject
	xorq	%rax, %rax
	movzbl	0(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	1(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	2(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	3(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	4(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	5(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	6(%r12), %esi
	orq	%rsi, %rax
	shlq	$8, %rax
	movzbl	7(%r12), %esi
	orq	%rsi, %rax
	addq	$8, %r12
	ret

# ---- skip_value: advance r12 over one CBOR value (no emit) -----------------
# used by .tc_map's scan pass to find pair/key spans. recursive for containers.
# does NOT reject tags (major 6) here — the emit pass (transcode) rejects them;
# skip must traverse the tagged content so the scan spans stay correct.
skip_value:
	call	rd_head			# cl=major, dl=ai, rax=arg; r12 past head+arg
	movzbl	%cl, %ecx
	cmpl	$2, %ecx
	je	.sk_str
	cmpl	$3, %ecx
	je	.sk_str
	cmpl	$4, %ecx
	je	.sk_arr
	cmpl	$5, %ecx
	je	.sk_map
	cmpl	$6, %ecx
	je	.sk_tag
	ret				# major 0/1/7: arg already consumed
.sk_str:
	leaq	(%r12,%rax), %rdx
	cmpq	%rdx, %r13
	jb	.Lreject
	movq	%rdx, %r12
	ret
.sk_arr:
	testq	%rax, %rax
	jz	.sk_ret
	pushq	%rax			# remaining count
	subq	$8, %rsp		# keep call sites aligned
.ska_loop:
	call	skip_value
	movq	8(%rsp), %rax
	decq	%rax
	movq	%rax, 8(%rsp)
	jnz	.ska_loop
	addq	$8, %rsp
	popq	%rax
	ret
.sk_map:
	addq	%rax, %rax		# 2*count values
	testq	%rax, %rax
	jz	.sk_ret
	pushq	%rax
	subq	$8, %rsp
.skm_loop:
	call	skip_value
	movq	8(%rsp), %rax
	decq	%rax
	movq	%rax, 8(%rsp)
	jnz	.skm_loop
	addq	$8, %rsp
	popq	%rax
	ret
.sk_tag:
	jmp	skip_value		# tail: skip the one tagged content value
.sk_ret:
	ret

# ---- emit_byte: dil -> out ; bounds-checked ; advances r14 -----------------
emit_byte:
	cmpq	%r14, %r15
	jbe	.Loverflow		# out_end <= out_cur → no space
	movb	%dil, (%r14)
	incq	%r14
	ret

# ---- emit_be: emit rax as esi bytes, big-endian (MSB first) ----------------
# clobbers rax? no (reads only). clobbers rcx,rsi,rdi. esi in [1..8].
emit_be:
	movl	%esi, %ecx
	decl	%ecx
	shll	$3, %ecx		# shift for MSB = (n-1)*8
.eb_loop:
	movq	%rax, %rdi
	shrq	%cl, %rdi		# bring target byte to bits 7..0
	movzbl	%dil, %edi
	pushq	%rax
	pushq	%rcx
	call	emit_byte
	popq	%rcx
	popq	%rax
	subl	$8, %ecx
	jns	.eb_loop
	ret

# ---- emit_uint: r10b=base(major<<5), rax=value -> minimal head -------------
# preserves rax. clobbers rcx,rdx,rsi,rdi.
emit_uint:
	cmpq	$24, %rax
	jae	.eu2
	movb	%r10b, %dil
	orb	%al, %dil
	jmp	emit_byte		# tail-call: emits 1 byte, returns to caller
.eu2:
	cmpq	$0x100, %rax
	jae	.eu3
	movb	%r10b, %dil
	orb	$24, %dil
	call	emit_byte
	movl	$1, %esi
	jmp	emit_be
.eu3:
	cmpq	$0x10000, %rax
	jae	.eu4
	movb	%r10b, %dil
	orb	$25, %dil
	call	emit_byte
	movl	$2, %esi
	jmp	emit_be
.eu4:
	movq	$0x100000000, %rdx
	cmpq	%rdx, %rax
	jae	.eu5
	movb	%r10b, %dil
	orb	$26, %dil
	call	emit_byte
	movl	$4, %esi
	jmp	emit_be
.eu5:
	movb	%r10b, %dil
	orb	$27, %dil
	call	emit_byte
	movl	$8, %esi
	jmp	emit_be

# ---- transcode: read one value at r12, write canonical to r14 --------------
transcode:
	call	rd_head			# cl=major, dl=ai, rax=arg
	movzbl	%cl, %ecx
	cmpl	$0, %ecx
	je	.tc_uint
	cmpl	$1, %ecx
	je	.tc_nint
	cmpl	$2, %ecx
	je	.tc_bytes
	cmpl	$3, %ecx
	je	.tc_text
	cmpl	$4, %ecx
	je	.tc_array
	cmpl	$5, %ecx
	je	.tc_map
	cmpl	$6, %ecx
	je	.Lreject		# major 6 = tag → reject (recursive: at any depth)
	jmp	.tc_simple		# major 7

.tc_uint:
	movb	$0x00, %r10b
	jmp	emit_uint		# tail: emits head, returns
.tc_nint:
	movb	$0x20, %r10b
	jmp	emit_uint

.tc_bytes:
	movb	$0x40, %r10b
	jmp	.tc_str_common
.tc_text:
	movb	$0x60, %r10b
.tc_str_common:
	call	emit_uint		# rax=len preserved
	movq	%rax, %rcx		# count
	leaq	(%r12,%rcx), %rax
	cmpq	%rax, %r13
	jb	.Lreject		# not enough input
	leaq	(%r14,%rcx), %rax
	cmpq	%rax, %r15
	jb	.Loverflow		# not enough output
.cp_loop:
	testq	%rcx, %rcx
	jz	.cp_done
	movzbl	(%r12), %eax
	movb	%al, (%r14)
	incq	%r12
	incq	%r14
	decq	%rcx
	jmp	.cp_loop
.cp_done:
	ret

.tc_array:
	movb	$0x80, %r10b
	call	emit_uint		# rax=count
	# loop count times
.arr_loop:
	testq	%rax, %rax
	jz	.arr_done
	decq	%rax
	pushq	%rax
	call	transcode
	popq	%rax
	jmp	.arr_loop
.arr_done:
	ret

# .tc_map — canonical map: emit head, then re-emit key/value pairs in canonical
# length-then-lex key order (RFC 8949 §4.2.1). Two passes over the input map:
#   pass 1 (scan)  — record each pair's input start + its encoded-key span
#   sort           — selection sort the records by (key_len asc, key bytes asc)
#   pass 2 (emit)  — transcode each pair (key then value) in sorted order
# Keys are compared as their INPUT-encoded bytes; for canonical input that equals
# the canonical key, and the transcoder re-canonicalizes keys/values on emit. The
# corpus map_keys vectors are pre-sorted (so they'd pass either way) — the sort is
# proven by the synthetic unsorted vectors in the harness and (M2) by content_hash.3.
# Scratch is rsp-relative; nested maps get their own frame. Cap 32 pairs (protocol
# maps are small; larger → EC_DECODE_ERROR, documented).
.tc_map:
	movb	$0xa0, %r10b
	call	emit_uint		# rax=count (pairs); r14 advanced by head
	testq	%rax, %rax
	jz	.map_empty
	cmpq	$32, %rax
	ja	.Lreject
	subq	$1040, %rsp		# scratch frame (16-aligned)
	movq	%rax, 0(%rsp)		# count
	# ---- pass 1: scan pair + key spans ----
	movq	$0, 8(%rsp)		# i = 0
.scan_loop:
	movq	8(%rsp), %rcx
	cmpq	0(%rsp), %rcx
	jae	.scan_done
	imulq	$24, %rcx, %rdx
	leaq	24(%rsp,%rdx), %rdx	# &rec[i]
	movq	%r12, 0(%rdx)		# pair_start
	movq	%r12, 8(%rdx)		# key_ptr
	call	skip_value		# advance r12 over key
	movq	8(%rsp), %rcx
	imulq	$24, %rcx, %rdx
	leaq	24(%rsp,%rdx), %rdx	# &rec[i] again (rdx clobbered by call)
	movq	%r12, %rax
	subq	8(%rdx), %rax		# key_len = r12 - key_ptr
	movq	%rax, 16(%rdx)
	call	skip_value		# advance r12 over value
	incq	8(%rsp)
	jmp	.scan_loop
.scan_done:
	movq	%r12, 16(%rsp)		# map_end (input ptr past the whole map)
	# ---- selection sort records by (key_len, key bytes); no calls in this block ----
	leaq	24(%rsp), %r11		# records base
	xorq	%r8, %r8		# p = 0
.sel_outer:
	movq	0(%rsp), %rax
	decq	%rax			# count-1
	cmpq	%rax, %r8
	jae	.sort_done
	movq	%r8, %r9		# m = p
	leaq	1(%r8), %r10		# k = p+1
.sel_inner:
	cmpq	0(%rsp), %r10
	jae	.sel_swap
	# compare rec[k] (a) vs rec[m] (b): if a < b then m = k
	imulq	$24, %r10, %rax
	leaq	(%r11,%rax), %rsi	# &rec[k]
	imulq	$24, %r9, %rax
	leaq	(%r11,%rax), %rdi	# &rec[m]
	movq	16(%rsi), %rax		# len_a
	movq	16(%rdi), %rdx		# len_b
	cmpq	%rdx, %rax
	jb	.sel_take		# len_a < len_b → a smaller
	ja	.sel_next		# len_a > len_b → keep m
	# equal length: memcmp key bytes (register-vs-memory cmp avoids a 2nd temp,
	# so r8=p / r9=m / r10=k stay intact through the inner loop)
	movq	8(%rsi), %rsi		# kptr_a
	movq	8(%rdi), %rdi		# kptr_b
	xorq	%rcx, %rcx
.sel_mc:
	cmpq	%rax, %rcx		# rax = len (== len_a)
	jae	.sel_next		# all equal → keep m (stable)
	movzbl	(%rsi,%rcx), %edx	# byte_a
	cmpb	(%rdi,%rcx), %dl	# byte_a - byte_b
	jb	.sel_take		# a < b → a smaller → m = k
	ja	.sel_next		# a > b → keep m
	incq	%rcx
	jmp	.sel_mc
.sel_take:
	movq	%r10, %r9		# m = k
.sel_next:
	incq	%r10
	jmp	.sel_inner
.sel_swap:
	# swap rec[p] and rec[m] via temp at [rsp+800]
	imulq	$24, %r8, %rax
	leaq	(%r11,%rax), %rsi	# &rec[p]
	imulq	$24, %r9, %rax
	leaq	(%r11,%rax), %rdi	# &rec[m]
	movq	0(%rsi), %rax
	movq	8(%rsi), %rcx
	movq	16(%rsi), %rdx
	movq	0(%rdi), %r10
	movq	%r10, 0(%rsi)
	movq	8(%rdi), %r10
	movq	%r10, 8(%rsi)
	movq	16(%rdi), %r10
	movq	%r10, 16(%rsi)
	movq	%rax, 0(%rdi)
	movq	%rcx, 8(%rdi)
	movq	%rdx, 16(%rdi)
	incq	%r8			# p++
	jmp	.sel_outer
.sort_done:
	# ---- pass 2: emit pairs in sorted order ----
	movq	$0, 8(%rsp)		# i = 0
.emit_loop:
	movq	8(%rsp), %rcx
	cmpq	0(%rsp), %rcx
	jae	.emit_done
	imulq	$24, %rcx, %rdx
	movq	24(%rsp,%rdx), %r12	# r12 = pair_start[i]
	call	transcode		# key
	call	transcode		# value
	incq	8(%rsp)
	jmp	.emit_loop
.emit_done:
	movq	16(%rsp), %r12		# resume at map_end
	addq	$1040, %rsp
	ret
.map_empty:
	ret

# ---- major 7: simple values + floats ---------------------------------------
# dl=ai, rax=arg (for f16/f32/f64 arg = raw BE payload bits).
.tc_simple:
	cmpl	$20, %edx
	jb	.Lreject		# simple < 20 unused here
	cmpl	$23, %edx
	jbe	.ts_prim		# 20/21/22/23 = false/true/null/undefined
	cmpl	$25, %edx
	je	.ts_f16
	cmpl	$26, %edx
	je	.ts_f32
	cmpl	$27, %edx
	je	.ts_f64
	jmp	.Lreject		# ai 24 (simple 1-byte) / others: not needed → reject
.ts_prim:
	movl	$0xe0, %edi
	orl	%edx, %edi		# 0xf4/0xf5/0xf6/0xf7
	jmp	emit_byte
.ts_f16:
	# rax = 16-bit f16 bits → f64 bits → ladder
	call	f16_to_f64
	jmp	emit_float
.ts_f32:
	# rax = 32-bit f32 bits → f64 bits via cvt
	movd	%eax, %xmm0
	cvtss2sd %xmm0, %xmm0
	movq	%xmm0, %rax
	jmp	emit_float
.ts_f64:
	# rax already = f64 bits
	jmp	emit_float

# ---- f16_to_f64: eax(16-bit f16) -> rax(f64 bit pattern) -------------------
# handles zero / normal / inf / nan. f16 subnormal input → reject (documented gap).
f16_to_f64:
	movl	%eax, %r9d
	andl	$0x8000, %r9d		# sign16 (bit15)
	shlq	$48, %r9		# → f64 sign bit63
	movl	%eax, %r8d
	shrl	$10, %r8d
	andl	$0x1f, %r8d		# exp16
	movl	%eax, %r10d
	andl	$0x3ff, %r10d		# mant16
	testl	%r8d, %r8d
	jnz	.h_expnz
	testl	%r10d, %r10d
	jz	.h_zero
	jmp	.Lreject		# f16 subnormal input (no corpus vector) — gap
.h_zero:
	movq	%r9, %rax		# ±0
	ret
.h_expnz:
	cmpl	$0x1f, %r8d
	je	.h_infnan
	# normal: f64_exp = exp16 + 1008 ; mant64 = mant16 << 42
	leaq	1008(%r8), %rax
	shlq	$52, %rax
	movq	%r10, %rdx
	shlq	$42, %rdx
	orq	%rdx, %rax
	orq	%r9, %rax
	ret
.h_infnan:
	testl	%r10d, %r10d
	jz	.h_inf
	movq	$0x7ff8000000000000, %rax	# quiet NaN
	orq	%r9, %rax
	ret
.h_inf:
	movq	$0x7ff0000000000000, %rax
	orq	%r9, %rax
	ret

# ---- emit_float: rax = f64 bit pattern -> canonical shortest float ----------
# ladder: NaN→f9 7e00 ; try f16 (exact) ; try f32 (round-trip exact) ; else f64.
# persistent: r11=orig f64 bits, r8=exp, r9=sign, r10=scratch/mant.
emit_float:
	movq	%rax, %r11		# orig bits
	movq	%rax, %r8
	shrq	$52, %r8
	andl	$0x7ff, %r8d		# exp
	cmpl	$0x7ff, %r8d
	jne	.ef_finite
	# inf or nan
	movq	$0xfffffffffffff, %rdx
	movq	%r11, %rax
	andq	%rdx, %rax		# mant
	testq	%rax, %rax
	jz	.ef_inf
	# NaN → canonical f9 7e00
	movl	$0xf9, %edi
	call	emit_byte
	movl	$0x7e, %edi
	call	emit_byte
	xorl	%edi, %edi
	call	emit_byte
	ret
.ef_inf:
	movq	%r11, %r9
	shrq	$63, %r9		# sign
	shlq	$15, %r9
	orq	$0x7c00, %r9		# f16 inf
	movl	$0xf9, %edi
	call	emit_byte
	movq	%r9, %rax
	movl	$2, %esi
	jmp	emit_be
.ef_finite:
	movq	%r11, %r9
	shrq	$63, %r9		# sign (0/1)
	movq	$0xfffffffffffff, %rdx
	movq	%r11, %r10
	andq	%rdx, %r10		# mant (52 bits)
	testl	%r8d, %r8d
	jnz	.ef_normtry
	testq	%r10, %r10
	jnz	.ef_f32try		# f64 subnormal → not f16
	# ±0 → f16
	movq	%r9, %rax
	shlq	$15, %rax
	jmp	.ef_emit_f16
.ef_normtry:
	# need E=exp-1023 in [-14,15] → exp in [1009,1038]
	cmpl	$1009, %r8d
	jl	.ef_f32try
	cmpl	$1038, %r8d
	jg	.ef_f32try
	# low 42 mantissa bits must be zero
	movq	$0x3ffffffffff, %rdx
	movq	%r10, %rax
	andq	%rdx, %rax
	testq	%rax, %rax
	jnz	.ef_f32try
	# build f16: m16=mant>>42 ; e16=exp-1008 ; s<<15
	movq	%r10, %rax
	shrq	$42, %rax		# m16
	movl	%r8d, %ecx
	subl	$1008, %ecx		# e16
	shll	$10, %ecx
	orl	%ecx, %eax
	movq	%r9, %rcx
	shlq	$15, %rcx
	orq	%rcx, %rax
.ef_emit_f16:
	movq	%rax, %r10		# stash (emit_be preserves rax but emit_byte path below is fine)
	movl	$0xf9, %edi
	call	emit_byte
	movq	%r10, %rax
	movl	$2, %esi
	jmp	emit_be
.ef_f32try:
	movq	%r11, %xmm0		# f64 bits
	cvtsd2ss %xmm0, %xmm1		# → f32
	cvtss2sd %xmm1, %xmm2		# → f64
	movq	%xmm2, %rax
	cmpq	%rax, %r11
	jne	.ef_f64
	movd	%xmm1, %eax		# f32 bits
	movl	$0xfa, %edi
	pushq	%rax
	call	emit_byte
	popq	%rax
	movl	$4, %esi
	jmp	emit_be
.ef_f64:
	movl	$0xfb, %edi
	call	emit_byte
	movq	%r11, %rax
	movl	$8, %esi
	jmp	emit_be

# ---- build_ecf: emit canonical entity {data,type} to the output cursor --------
# in: r12=data_cur, r13=data_end (data as CBOR bytes), r8=type_ptr, r9=type_len,
#     r14=out_cur, r15=out_end, rbx=out_base (caller sets the destination). Emits the
# fixed-order entity map
#   a2 · "data" · canonicalize(data) · "type" · text(type)
# ("data" and "type" are both 5-byte encoded keys; "data" < "type" lexicographically,
# so the fixed order IS canonical). data is canonicalized (incl. key-sort) by the
# transcoder. returns rax = ecf length. Requires the caller's prologue (err_rsp set).
build_ecf:
	pushq	%r8			# type_ptr (survive transcode's r8 clobber)
	pushq	%r9			# type_len
	movl	$0xa2, %edi
	call	emit_byte
	movl	$0x64, %edi		# "data": 64 64 61 74 61
	call	emit_byte
	movl	$0x64, %edi
	call	emit_byte
	movl	$0x61, %edi
	call	emit_byte
	movl	$0x74, %edi
	call	emit_byte
	movl	$0x61, %edi
	call	emit_byte
	call	transcode		# canonical (sorted) data value
	movl	$0x64, %edi		# "type": 64 74 79 70 65
	call	emit_byte
	movl	$0x74, %edi
	call	emit_byte
	movl	$0x79, %edi
	call	emit_byte
	movl	$0x70, %edi
	call	emit_byte
	movl	$0x65, %edi
	call	emit_byte
	popq	%r9			# type_len
	popq	%r8			# type_ptr
	movq	%r9, %rax
	movb	$0x60, %r10b
	pushq	%r8			# save across emit_uint
	call	emit_uint		# text head; rax=len preserved
	popq	%r8
	movq	%rax, %rcx
	leaq	(%r14,%rcx), %rax
	cmpq	%rax, %r15
	jb	.Loverflow
.be_cp:
	testq	%rcx, %rcx
	jz	.be_done
	movzbl	(%r8), %eax
	movb	%al, (%r14)
	incq	%r8
	incq	%r14
	decq	%rcx
	jmp	.be_cp
.be_done:
	movq	%r14, %rax
	subq	%rbx, %rax		# ecf length
	ret

# ---- ec_encode_ecf(type,tlen,data,dlen, out,cap,out_len) -------------------
# Canonical ECF of {type,data} written to the caller's buffer (data key-sorted).
	.globl	ec_encode_ecf
	.type	ec_encode_ecf,@function
ec_encode_ecf:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	%rsp, err_rsp(%rip)
	movq	56(%rsp), %rbp		# out_len_ptr (7th arg)
	movq	%r8, %r14		# out_cur   (5th arg = out)
	movq	%r8, %rbx		# out_base
	leaq	(%r8,%r9), %r15		# out_end = out + cap (6th arg)
	movq	%rdx, %r12		# data cur
	leaq	(%rdx,%rcx), %r13	# data end
	movq	%rdi, %r8		# type ptr  (after r8/r9 consumed as out/cap)
	movq	%rsi, %r9		# type len
	call	build_ecf		# rax = ecf_len (dest = the caller's out)
	movq	%rax, (%rbp)		# *out_len
	xorl	%eax, %eax
	jmp	.Lepi

# ---- ec_content_hash(type,tlen,data,dlen, out[33]) -------------------------
# out = varint(0x00) ‖ SHA-256(ECF({type,data})). SHA-256 stays FFI at L2.
	.globl	ec_content_hash
	.type	ec_content_hash,@function
ec_content_hash:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	%rsp, err_rsp(%rip)
	movq	%r8, %rbp		# final out (33 bytes)
	movq	%rdx, %r12		# data cur
	leaq	(%rdx,%rcx), %r13	# data end
	movq	%rdi, %r8		# type ptr
	movq	%rsi, %r9		# type len
	leaq	ecf_scratch(%rip), %r14	# ECF → scratch
	leaq	ecf_scratch(%rip), %rbx
	leaq	ecf_scratch+ECF_SCRATCH_CAP(%rip), %r15
	call	build_ecf		# ecf in scratch; rax=ecf_len
	leaq	ecf_scratch(%rip), %rdi
	movq	%rax, %rsi
	leaq	1(%rbp), %rdx		# digest → out+1
	pushq	%rbp			# 16-align for the FFI SSE
	call	ec_sha256
	popq	%rbp
	movb	$0, (%rbp)		# varint(format 0x00)
	xorl	%eax, %eax
	jmp	.Lepi

# ---- ec_content_hash_with_format(type,tlen,data,dlen, fmt, out,cap,out_len) --
# out = varint(fmt) ‖ SHA-256(ECF). (This corpus's format-code vectors keep SHA-256
# as the digest; the byte-framing under test is the multi-byte LEB128 fmt prefix.)
	.globl	ec_content_hash_with_format
	.type	ec_content_hash_with_format,@function
ec_content_hash_with_format:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	%rsp, err_rsp(%rip)
	movq	%r9, %rbp		# out ptr
	movq	%rdx, %r12		# data cur
	leaq	(%rdx,%rcx), %r13	# data end
	# emit varint(fmt) at out[0..]; r10 = vlen. (fmt in r8)
	movq	%r8, %rcx		# fmt
	xorq	%r10, %r10
.vf_loop:
	cmpq	$0x80, %rcx
	jb	.vf_last
	movl	%ecx, %edx
	andl	$0x7f, %edx
	orl	$0x80, %edx
	movb	%dl, (%rbp,%r10)
	incq	%r10
	shrq	$7, %rcx
	jmp	.vf_loop
.vf_last:
	movb	%cl, (%rbp,%r10)
	incq	%r10
	movq	%rdi, %r8		# type ptr
	movq	%rsi, %r9		# type len
	leaq	ecf_scratch(%rip), %r14	# ECF → scratch
	leaq	ecf_scratch(%rip), %rbx
	leaq	ecf_scratch+ECF_SCRATCH_CAP(%rip), %r15
	pushq	%r10			# save vlen across build_ecf
	call	build_ecf		# rax=ecf_len
	popq	%r10
	leaq	ecf_scratch(%rip), %rdi
	movq	%rax, %rsi
	leaq	(%rbp,%r10), %rdx	# digest → out+vlen
	pushq	%r10			# save vlen + 16-align for FFI
	call	ec_sha256
	popq	%r10
	movq	64(%rsp), %rax		# out_len_ptr (8th arg, at entry+16 → +48 after 6 push)
	leaq	32(%r10), %rdx		# *out_len = vlen + 32
	movq	%rdx, (%rax)
	xorl	%eax, %eax
	jmp	.Lepi

# ---- ec_peerid_format(kt, ht, digest, dlen, out, cap, out_len) -------------
# out (ASCII, not null-terminated) = base58( varint(kt) ‖ varint(ht) ‖ digest ).
# Crypto-free (no FFI). Standalone register discipline (does not use the transcoder
# globals / err_rsp). Byte-carry base58 (Bitcoin alphabet). Single-threaded scratch.
	.globl	ec_peerid_format
	.type	ec_peerid_format,@function
ec_peerid_format:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	movq	%r8, %r14		# out ptr
	movq	56(%rsp), %r15		# out_len_ptr (7th arg, entry+8 → +48)
	movq	%rdx, %r10		# digest ptr (survive .pf_varint's edx clobber)
	# --- build payload: varint(kt) ‖ varint(ht) ‖ digest ---
	leaq	pid_payload(%rip), %r12	# payload base
	movq	%r12, %rbx		# payload cursor
	movq	%rdi, %rax		# kt
	call	.pf_varint
	movq	%rsi, %rax		# ht
	call	.pf_varint
.pf_dcp:					# copy digest (r10 ptr, rcx len)
	testq	%rcx, %rcx
	jz	.pf_dcpdone
	movzbl	(%r10), %eax
	movb	%al, (%rbx)
	incq	%r10
	incq	%rbx
	decq	%rcx
	jmp	.pf_dcp
.pf_dcpdone:
	movq	%rbx, %r13
	subq	%r12, %r13		# r13 = plen
	# --- base58 encode payload[r12..+plen) into pid_digits (little-endian) ---
	xorq	%rbp, %rbp		# dlen = 0
	movq	%r12, %rsi		# payload cursor
	movq	%r13, %rcx		# remaining
	leaq	pid_digits(%rip), %r8	# digits base
.b58_byte:
	testq	%rcx, %rcx
	jz	.b58_bytes_done
	movzbl	(%rsi), %r9d		# carry = byte
	incq	%rsi
	decq	%rcx
	xorq	%r10, %r10		# j = 0
.b58_inner:
	cmpq	%rbp, %r10
	jae	.b58_inner_done
	movzbl	(%r8,%r10), %eax
	shll	$8, %eax		# digit*256
	addl	%eax, %r9d		# carry += that
	movl	%r9d, %eax
	xorl	%edx, %edx
	movl	$58, %r11d
	divl	%r11d			# eax=carry/58, edx=carry%58
	movb	%dl, (%r8,%r10)
	movl	%eax, %r9d
	incq	%r10
	jmp	.b58_inner
.b58_inner_done:
.b58_carry:
	testl	%r9d, %r9d
	jz	.b58_byte
	movl	%r9d, %eax
	xorl	%edx, %edx
	movl	$58, %r11d
	divl	%r11d
	movb	%dl, (%r8,%rbp)
	incq	%rbp
	movl	%eax, %r9d
	jmp	.b58_carry
.b58_bytes_done:
	# leading zero bytes in payload → leading '1' chars
	movq	%r12, %rsi
	movq	%r13, %rcx
	xorq	%r9, %r9
.b58_lz:
	testq	%rcx, %rcx
	jz	.b58_lz_done
	cmpb	$0, (%rsi)
	jne	.b58_lz_done
	incq	%r9
	incq	%rsi
	decq	%rcx
	jmp	.b58_lz
.b58_lz_done:
	movq	%r14, %rbx		# out start (for length)
	leaq	.Lb58alpha(%rip), %r11
.b58_ones:
	testq	%r9, %r9
	jz	.b58_ones_done
	movb	$0x31, (%r14)		# '1'
	incq	%r14
	decq	%r9
	jmp	.b58_ones
.b58_ones_done:
	movq	%rbp, %rcx		# dlen; emit digits[dlen-1..0]
.b58_emit:
	testq	%rcx, %rcx
	jz	.b58_emit_done
	decq	%rcx
	movzbl	(%r8,%rcx), %eax
	movzbl	(%r11,%rax), %eax	# alphabet[digit]
	movb	%al, (%r14)
	incq	%r14
	jmp	.b58_emit
.b58_emit_done:
	movq	%r14, %rax
	subq	%rbx, %rax
	movq	%rax, (%r15)		# *out_len
	xorl	%eax, %eax
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
.pf_varint:				# rax=value, emit LEB128 at [rbx], advance rbx
	cmpq	$0x80, %rax
	jb	.pfv_last
	movl	%eax, %edx
	andl	$0x7f, %edx
	orl	$0x80, %edx
	movb	%dl, (%rbx)
	incq	%rbx
	shrq	$7, %rax
	jmp	.pf_varint
.pfv_last:
	movb	%al, (%rbx)
	incq	%rbx
	ret

# ---- ec_peerid_parse(b58, b58len, *kt, *ht, digest, *dlen) -----------------
# Inverse of ec_peerid_format: base58 DECODE (byte-carry bignum) → raw bytes,
# then LEB128-decode the two leading varints (key_type, hash_type); the remainder
# is the digest. Crypto-free (no FFI), single-threaded static scratch. Return:
#   0 (EC_OK) · -1 (EC_INVALID_ARGUMENT, NULL b58) · -8 (EC_PEERID_INVALID).
# Mirrors the C-ABI reference (base58.c/codec.c): invalid char, LEB overflow/
# run-off, or need>256 raw bytes all fail as EC_PEERID_INVALID.
	.globl	ec_peerid_parse
	.type	ec_peerid_parse,@function
ec_peerid_parse:
	pushq	%rbx
	pushq	%rbp
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	subq	$32, %rsp		# locals: 0=zeros 8=bufsz 16=i
	testq	%rdi, %rdi
	jz	.Lpp_inval		# NULL b58 → EC_INVALID_ARGUMENT
	movq	%rdi, %r12		# b58 ptr
	movq	%rsi, %r13		# b58 len
	movq	%rdx, %rbx		# *out_key_type
	movq	%rcx, %rbp		# *out_hash_type
	movq	%r8,  %r14		# out_digest ptr
	movq	%r9,  %r15		# *out_digest_len
	# --- count leading '1' chars → zeros ---
	xorq	%r11, %r11
.Lpp_z:
	cmpq	%r13, %r11
	jae	.Lpp_zdone
	cmpb	$0x31, (%r12,%r11)	# '1'
	jne	.Lpp_zdone
	incq	%r11
	jmp	.Lpp_z
.Lpp_zdone:
	movq	%r11, 0(%rsp)		# zeros
	# bufsz = (len - zeros)*733/1000 + 1
	movq	%r13, %rax
	subq	%r11, %rax		# rest = len - zeros
	imulq	$733, %rax, %rax
	xorl	%edx, %edx
	movl	$1000, %ecx
	divq	%rcx			# rax = rest*733/1000
	incq	%rax			# bufsz
	cmpq	$512, %rax
	ja	.Lpp_bad		# would overflow pid_bin scratch
	movq	%rax, 8(%rsp)		# bufsz
	# --- zero the bignum accumulator pid_bin[0..512) ---
	leaq	pid_bin(%rip), %rdi
	xorl	%eax, %eax
	movl	$512, %ecx
	rep stosb			# DF=0 per SysV ABI on entry
	# --- byte-carry decode: for each char, bin = bin*58 + val ---
	movq	0(%rsp), %rax
	movq	%rax, 16(%rsp)		# i = zeros
.Lpp_outer:
	movq	16(%rsp), %rax
	cmpq	%r13, %rax
	jae	.Lpp_odone
	movzbl	(%r12,%rax), %ecx	# cl = in[i]
	call	.pp_b58val		# eax = index or -1
	testl	%eax, %eax
	js	.Lpp_bad		# invalid character
	movl	%eax, %r9d		# carry = val
	movq	8(%rsp), %rcx		# j = bufsz
	leaq	pid_bin(%rip), %r8
.Lpp_inner:
	testq	%rcx, %rcx
	jz	.Lpp_inner_done
	decq	%rcx
	movzbl	(%r8,%rcx), %eax
	imull	$58, %eax, %eax		# 58 * bin[j]
	addl	%eax, %r9d		# carry += ...
	movl	%r9d, %eax
	movb	%al, (%r8,%rcx)		# bin[j] = carry & 0xff
	shrl	$8, %r9d		# carry >>= 8
	jmp	.Lpp_inner
.Lpp_inner_done:
	incq	16(%rsp)
	jmp	.Lpp_outer
.Lpp_odone:
	# --- start = first non-zero byte in bin[0..bufsz) ---
	movq	8(%rsp), %rcx		# bufsz
	leaq	pid_bin(%rip), %r8
	xorq	%r9, %r9		# start
.Lpp_start:
	cmpq	%rcx, %r9
	jae	.Lpp_startdone
	cmpb	$0, (%r8,%r9)
	jne	.Lpp_startdone
	incq	%r9
	jmp	.Lpp_start
.Lpp_startdone:
	# need = zeros + (bufsz - start)
	movq	8(%rsp), %rax
	subq	%r9, %rax
	addq	0(%rsp), %rax
	cmpq	$256, %rax
	ja	.Lpp_bad		# raw buffer is 256 (matches C out_cap)
	movq	%rax, %rdx		# raw_len (kept across the copy below)
	# --- materialize raw: zeros zero-bytes, then bin[start..bufsz) ---
	leaq	pid_raw(%rip), %rdi
	movq	0(%rsp), %rcx		# zeros
.Lpp_wz:
	testq	%rcx, %rcx
	jz	.Lpp_wzdone
	movb	$0, (%rdi)
	incq	%rdi
	decq	%rcx
	jmp	.Lpp_wz
.Lpp_wzdone:
	movq	8(%rsp), %r10		# bufsz
.Lpp_wb:
	cmpq	%r10, %r9		# r9 = start (cursor)
	jae	.Lpp_wbdone
	movzbl	(%r8,%r9), %eax
	movb	%al, (%rdi)
	incq	%rdi
	incq	%r9
	jmp	.Lpp_wb
.Lpp_wbdone:
	# --- n1 = leb(raw, raw_len) → key_type ---
	leaq	pid_raw(%rip), %rsi
	call	.pp_leb			# rax=val rcx=consumed(0=fail); rdx=len
	testq	%rcx, %rcx
	jz	.Lpp_bad
	movq	%rax, (%rbx)		# *out_key_type
	addq	%rcx, %rsi		# raw + n1
	subq	%rcx, %rdx		# raw_len - n1
	# --- n2 = leb(raw+n1, raw_len-n1) → hash_type ---
	call	.pp_leb
	testq	%rcx, %rcx
	jz	.Lpp_bad
	movq	%rax, (%rbp)		# *out_hash_type
	movq	%rdx, %r9		# (raw_len - n1)
	subq	%rcx, %r9		# dlen = that - n2
	addq	%rcx, %rsi		# digest start = raw + n1 + n2
	movq	%r9, (%r15)		# *out_digest_len
	# --- copy digest bytes → out_digest ---
	xorq	%r10, %r10
.Lpp_dcp:
	cmpq	%r9, %r10
	jae	.Lpp_dcpdone
	movzbl	(%rsi,%r10), %eax
	movb	%al, (%r14,%r10)
	incq	%r10
	jmp	.Lpp_dcp
.Lpp_dcpdone:
	xorl	%eax, %eax		# EC_OK
	jmp	.Lpp_ret
.Lpp_bad:
	movl	$-8, %eax		# EC_PEERID_INVALID
	jmp	.Lpp_ret
.Lpp_inval:
	movl	$-1, %eax		# EC_INVALID_ARGUMENT
.Lpp_ret:
	addq	$32, %rsp
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%rbp
	popq	%rbx
	ret
# reverse alphabet lookup: cl = char → eax = index (0..57) or -1. Clobbers rax,r8.
.pp_b58val:
	leaq	.Lb58alpha(%rip), %r8
	xorl	%eax, %eax
.Lppv_l:
	cmpl	$58, %eax
	jae	.Lppv_nf
	cmpb	%cl, (%r8,%rax)
	je	.Lppv_ret
	incl	%eax
	jmp	.Lppv_l
.Lppv_nf:
	movl	$-1, %eax
.Lppv_ret:
	ret
# LEB128 decode: rsi=ptr rdx=len → rax=value, rcx=consumed (0 = overflow/run-off).
# Reads only; leaves rsi/rdx intact. Clobbers rax,rcx,r8,r9,r10,r11.
.pp_leb:
	xorq	%rax, %rax		# result
	xorl	%r8d, %r8d		# shift
	xorq	%r11, %r11		# i
.Lpl_l:
	cmpq	%rdx, %r11
	jae	.Lpl_fail		# ran off the end
	cmpl	$64, %r8d
	jae	.Lpl_fail		# overflow
	movzbl	(%rsi,%r11), %r9d	# b
	movl	%r9d, %r10d
	andl	$0x7f, %r10d		# low 7 bits
	movl	%r8d, %ecx		# cl = shift
	shlq	%cl, %r10
	orq	%r10, %rax		# result |= low7 << shift
	incq	%r11
	testb	$0x80, %r9b
	jz	.Lpl_done		# no continuation → done
	addl	$7, %r8d
	jmp	.Lpl_l
.Lpl_done:
	movq	%r11, %rcx		# consumed = i+1
	ret
.Lpl_fail:
	xorq	%rcx, %rcx
	ret

	.section .rodata
.Lb58alpha:
	.ascii	"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

	.bss
	.align	8
err_rsp:
	.quad	0
	.align	16
# Sized against the input this codec can LEGALLY be handed, not against a guess:
# an entity reaching ec_content_hash arrived inside the peer's request buffer, which
# is MAX_FRAME (dispatch.s b_req, 16 MiB), and a canonical re-encode never expands.
# At 64 KiB this buffer was 256x smaller than the frame the peer advertises, so any
# entity over ~65.5 KiB of ECF returned EC_OUT_OF_SPACE -- see ECF_SCRATCH_CAP.
# One buffer per PROCESS (.bss, demand-paged, COW per fork), not per call: build_ecf
# recurses on the stack and writes into this single arena, so the cost is the pages
# an actual ECF touches, not a per-level multiple.
ecf_scratch:
	.space	ECF_SCRATCH_CAP
	.align	8
pid_payload:
	.space	256
pid_digits:
	.space	512
	.align	8
pid_bin:				# base58-decode bignum accumulator
	.space	512
	.align	8
pid_raw:				# decoded raw bytes (varints ‖ digest)
	.space	256

	.section .note.GNU-stack,"",@progbits
