# cbor.s — minimal canonical-CBOR reader + writer for the envelope/data-map layer.
# (A-ASM-004: the FFI decomposes entities, not the envelope/data maps — so the peer
# hand-rolls this map layer even at Level 1.) GAS/AT&T.
#
# READER (normal ABI, rdi in / rax out):
#   read_head(rdi=ptr)  -> rax=ptr-after-head, rcx=major(0..7), rdx=argument(uint)
#   skip_value(rdi=ptr) -> rax=ptr-after-value  (recursive)
#   map_find(rdi=map, rsi=key, rdx=keylen) -> rax=value-ptr, or 0 if absent
#   get_text(rdi=valptr) -> rax=bytes-ptr, rdx=len   (value must be text/bytes)
#   memeq(rdi,rsi,rcx) -> rax=1 if the rcx bytes are equal
#
# WRITER — cursor convention: %r15 is the append cursor (read + advanced in place).
#   Prims clobber only rax/rcx (+ their arg regs); r12-r14/rbx are preserved so the
#   caller can hold saved pointers across a build. Set up args, `call w_*`.
#   w_u8(dil) w_map(sil=n) w_arr(sil=n) w_uint(rsi=val)
#   w_txt(rsi=ptr,rdx=len) w_bstr(rsi=ptr,rdx=len) w_raw(rsi=ptr,rdx=len)
#   w_cstr(rdi=asciz)

	.include "macros.s"
	.extern strlen

	.text

# =========================== READER ===========================
	.globl read_head
	.type read_head, @function
read_head:
	movzbl (%rdi), %r9d
	mov  %r9d, %ecx
	shr  $5, %ecx                    # major
	mov  %r9d, %r10d
	and  $0x1f, %r10d                # low 5 bits
	lea  1(%rdi), %rax               # past initial byte
	cmp  $24, %r10d
	jb   .Lrh_small
	je   .Lrh_1
	cmp  $25, %r10d
	je   .Lrh_2
	cmp  $26, %r10d
	je   .Lrh_4
	# 27 → 8-byte big-endian argument
	mov  (%rax), %rdx
	bswap %rdx
	add  $8, %rax
	ret
.Lrh_small:
	movl %r10d, %edx
	ret
.Lrh_1:
	movzbl (%rax), %edx
	inc  %rax
	ret
.Lrh_2:
	movzbl (%rax), %edx              # hi
	shl  $8, %edx
	movzbl 1(%rax), %r11d            # lo
	or   %r11d, %edx
	add  $2, %rax
	ret
.Lrh_4:
	mov  (%rax), %edx
	bswap %edx
	add  $4, %rax
	ret

	.globl skip_value
	.type skip_value, @function
skip_value:
	push %rbx
	call read_head                   # rax=afterhead, rcx=major, rdx=arg
	mov  %rax, %rdi
	cmp  $2, %rcx
	jb   .Lsv_done                   # 0/1 uint/nint
	cmp  $3, %rcx
	jbe  .Lsv_bytes                  # 2 bytes / 3 text
	cmp  $4, %rcx
	je   .Lsv_array
	cmp  $5, %rcx
	je   .Lsv_map
	cmp  $6, %rcx
	je   .Lsv_tag
	jmp  .Lsv_done                   # 7 simple/float: head already consumed
.Lsv_bytes:
	add  %rdx, %rdi
	jmp  .Lsv_done
.Lsv_map:
	lea  (%rdx,%rdx), %rdx           # 2*count items
.Lsv_array:
	mov  %rdx, %rbx
.Lsv_a:
	test %rbx, %rbx
	jz   .Lsv_done
	call skip_value
	mov  %rax, %rdi
	dec  %rbx
	jmp  .Lsv_a
.Lsv_tag:
	call skip_value
	mov  %rax, %rdi
.Lsv_done:
	mov  %rdi, %rax
	pop  %rbx
	ret

	.globl map_find
	.type map_find, @function
# map_find(rdi=map_ptr, rsi=key_ptr, rdx=key_len) -> rax = value_ptr | 0
map_find:
	push %rbx
	push %r12
	push %r13
	push %r14
	mov  %rsi, %r12                  # key ptr
	mov  %rdx, %r13                  # key len
	call read_head                   # rax=afterhdr, rcx=major(5), rdx=count
	mov  %rax, %r14                  # cursor
	mov  %rdx, %rbx                  # remaining pairs
.Lmf_loop:
	test %rbx, %rbx
	jz   .Lmf_none
	mov  %r14, %rdi
	call read_head                   # rax=keybytes, rdx=this key len
	mov  %rax, %r8                   # key bytes
	mov  %rdx, %r9                   # this key len
	lea  (%r8,%r9), %r10             # value ptr = keybytes + keylen
	cmp  %r13, %r9
	jne  .Lmf_skip
	mov  %r12, %rdi
	mov  %r8, %rsi
	mov  %r9, %rcx
	call memeq
	test %rax, %rax
	jnz  .Lmf_found
.Lmf_skip:
	mov  %r10, %rdi
	call skip_value
	mov  %rax, %r14
	dec  %rbx
	jmp  .Lmf_loop
.Lmf_found:
	mov  %r10, %rax
	jmp  .Lmf_ret
.Lmf_none:
	xor  %eax, %eax
.Lmf_ret:
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

	.globl get_text
	.type get_text, @function
# get_text(rdi=valptr) -> rax=bytes ptr, rdx=len   (text/bytes value)
get_text:
	call read_head                   # rax=after head (=bytes), rdx=len
	ret

	.globl memeq
	.type memeq, @function
memeq:
.Lme:	test %rcx, %rcx
	jz   .Lme_yes
	mov  (%rdi), %al
	mov  (%rsi), %dl
	cmp  %dl, %al
	jne  .Lme_no
	inc  %rdi
	inc  %rsi
	dec  %rcx
	jmp  .Lme
.Lme_yes:
	mov  $1, %eax
	ret
.Lme_no:
	xor  %eax, %eax
	ret

# =========================== WRITER (cursor = %r15) ===========================
	.globl w_u8
	.type w_u8, @function
w_u8:
	mov  %dil, (%r15)
	inc  %r15
	ret

	.globl w_map
	.type w_map, @function
w_map:
	mov  %sil, %al
	or   $0xa0, %al
	mov  %al, (%r15)
	inc  %r15
	ret

	.globl w_arr
	.type w_arr, @function
w_arr:
	mov  %sil, %al
	or   $0x80, %al
	mov  %al, (%r15)
	inc  %r15
	ret

	.globl w_uint
	.type w_uint, @function
# w_uint(rsi=val)
w_uint:
	cmp  $24, %rsi
	jae  .Lwu_1
	mov  %sil, (%r15)
	inc  %r15
	ret
.Lwu_1:
	cmp  $256, %rsi
	jae  .Lwu_2
	movb $0x18, (%r15)
	inc  %r15
	mov  %sil, (%r15)
	inc  %r15
	ret
.Lwu_2:
	cmp  $65536, %rsi
	jae  .Lwu_4
	movb $0x19, (%r15)
	inc  %r15
	mov  %si, %ax
	xchg %al, %ah
	mov  %ax, (%r15)
	add  $2, %r15
	ret
.Lwu_4:
	mov  %rsi, %rax
	shr  $32, %rax
	test %rax, %rax
	jnz  .Lwu_8
	movb $0x1a, (%r15)
	inc  %r15
	mov  %esi, %eax
	bswap %eax
	mov  %eax, (%r15)
	add  $4, %r15
	ret
.Lwu_8:
	movb $0x1b, (%r15)
	inc  %r15
	mov  %rsi, %rax
	bswap %rax
	mov  %rax, (%r15)
	add  $8, %r15
	ret

	.globl w_txt
	.type w_txt, @function
# w_txt(rsi=ptr, rdx=len) — text string (major 3)
w_txt:
	mov  $0x60, %r8b
	jmp  w_str_common
	.globl w_bstr
	.type w_bstr, @function
# w_bstr(rsi=ptr, rdx=len) — byte string (major 2)
w_bstr:
	mov  $0x40, %r8b
w_str_common:
	cmp  $24, %rdx
	jae  .Lws_long
	mov  %dl, %al
	or   %r8b, %al
	mov  %al, (%r15)
	inc  %r15
	jmp  w_raw_copy
.Lws_long:
	cmp  $256, %rdx
	jae  .Lws_2
	mov  %r8b, %al
	or   $0x18, %al                  # 0x58 (bytes) / 0x78 (text): +0x18 one-byte len
	mov  %al, (%r15)
	inc  %r15
	mov  %dl, (%r15)
	inc  %r15
	jmp  w_raw_copy
.Lws_2:
	mov  %r8b, %al
	or   $0x19, %al                  # two-byte len form
	mov  %al, (%r15)
	inc  %r15
	mov  %dx, %ax
	xchg %al, %ah
	mov  %ax, (%r15)
	add  $2, %r15
	# fall through to copy

	.globl w_raw
	.type w_raw, @function
# w_raw(rsi=ptr, rdx=len) — copy len bytes verbatim (embed a pre-built CBOR value)
w_raw:
w_raw_copy:
	xor  %rcx, %rcx
.Lwr_c:
	cmp  %rdx, %rcx
	jae  .Lwr_done
	mov  (%rsi,%rcx), %al
	mov  %al, (%r15)
	inc  %r15
	inc  %rcx
	jmp  .Lwr_c
.Lwr_done:
	ret

	.globl w_cstr
	.type w_cstr, @function
# w_cstr(rdi=asciz) — emit as a text string
w_cstr:
	push %rdi
	call strlen                      # rax = len
	pop  %rsi                        # ptr
	mov  %rax, %rdx
	jmp  w_txt

# =========================== STRICT CHECKER ===========================
# The readers above are DELIBERATELY lenient: map_find/skip_value walk whatever
# shape they are handed, which is what lets a refusal path recover a request_id
# out of a frame the strict pass has already condemned. Nothing else in this file
# asks whether the bytes are a legal canonical-ECF value at all.
#
# cbor_check_frame is that question, and §4.11 is why it has to be asked BEFORE
# dispatch rather than inside it: a frame that never becomes an Envelope is owed a
# coded EXECUTE_RESPONSE, and the cause decides the code. The two causes this pass
# separates are the two the section names:
#
#   a CBOR tag in any position  →  ENTITY-CBOR-ENCODING §6.3 tag policy
#                                  (`non_canonical_ecf`, and §6.3 already MUSTs it)
#   anything else               →  "never becomes an Envelope" (`invalid_request`)
#
# It is also the bound that makes the LENIENT readers safe. skip_value recurses with
# no depth cap and no end pointer, so 16 MiB of 0x81 (array(1)) nested is a stack
# smash reachable by anyone who can send bytes, and read_head treats additional-info
# 31 as the 8-byte form and reads eight bytes that are not there. Running this pass
# first means every later walk of b_req is over bytes already proven in-bounds,
# finite and shallower than 128 — so this is a bound on the whole module, not a
# local check.
#
# NOT checked here, deliberately, and it is a recorded debt rather than an oversight:
# MINIMAL head form and DUPLICATE map keys. Both are canonicalization rules this peer
# has never enforced on the decode side, both would refuse inputs that reach handlers
# today, and folding either into a §4.11 commit would bury a separate finding inside
# an unrelated one.

	.bss
	.lcomm g_saw_tag,    8
	.lcomm g_chk_depth,  8

	.text
	.globl cbor_check_frame
	.type cbor_check_frame, @function
# cbor_check_frame(rdi = ptr, rsi = end) -> rax = 0 OK | 1 TAG | 2 INVALID
#
# TAG wins over a clean structure but not over a broken one: a frame that is both
# truncated and tagged is INVALID, because the tag was read out of bytes whose shape
# was never established.
cbor_check_frame:
	push %rbx
	push %r12
	mov  %rsi, %r12                  # end
	movq $0, g_saw_tag(%rip)
	movq $0, g_chk_depth(%rip)
	call cbor_check                  # rdi=ptr, rsi=end -> rax = after | 0
	test %rax, %rax
	jz   .Lcf_invalid
	cmp  %r12, %rax
	jne  .Lcf_invalid                # trailing bytes after the top-level value: the
					 # frame length and the value disagree, which is a
					 # framing fault and not a tag-policy one
	cmpq $0, g_saw_tag(%rip)
	jne  .Lcf_tag
	xor  %eax, %eax
	jmp  .Lcf_ret
.Lcf_tag:
	mov  $1, %eax
	jmp  .Lcf_ret
.Lcf_invalid:
	mov  $2, %eax
.Lcf_ret:
	pop  %r12
	pop  %rbx
	ret

	.type cbor_check, @function
# cbor_check(rdi = ptr, rsi = end) -> rax = ptr-after-value | 0 if not a legal value.
# Records a major-6 tag anywhere in g_saw_tag and keeps walking, so one pass answers
# both questions. Every read is bounds-checked against `end` before it happens.
cbor_check:
	push %rbx
	push %r12
	push %r13
	push %r14
	push %r15
	mov  %rdi, %r12                  # p
	mov  %rsi, %r13                  # end
	incq g_chk_depth(%rip)
	cmpq $128, g_chk_depth(%rip)
	ja   .Lcc_bad                    # canonical ECF nesting is shallow; a frame deeper
					 # than this is hostile, and the cap is what keeps
					 # the recursion off the guard page
	cmp  %r13, %r12
	jae  .Lcc_bad                    # no initial byte
	movzbl (%r12), %eax
	inc  %r12
	mov  %eax, %r14d
	shr  $5, %r14d                   # r14 = major
	and  $0x1f, %eax                 # eax = additional info
	xor  %r15, %r15                  # r15 = argument
	cmp  $24, %eax
	jb   .Lcc_small
	je   .Lcc_a1
	cmp  $25, %eax
	je   .Lcc_a2
	cmp  $26, %eax
	je   .Lcc_a4
	cmp  $27, %eax
	je   .Lcc_a8
	jmp  .Lcc_bad                    # 28/29/30 reserved · 31 indefinite-length. Canonical
					 # ECF admits neither, and read_head would decode 31 as
					 # the 8-byte form and read past the frame.
.Lcc_small:
	mov  %eax, %r15d
	jmp  .Lcc_have
.Lcc_a1:
	lea  1(%r12), %rcx
	cmp  %r13, %rcx
	ja   .Lcc_bad
	movzbl (%r12), %r15d
	mov  %rcx, %r12
	jmp  .Lcc_have
.Lcc_a2:
	lea  2(%r12), %rcx
	cmp  %r13, %rcx
	ja   .Lcc_bad
	movzbl (%r12), %r15d
	shl  $8, %r15d
	movzbl 1(%r12), %eax
	or   %eax, %r15d
	mov  %rcx, %r12
	jmp  .Lcc_have
.Lcc_a4:
	lea  4(%r12), %rcx
	cmp  %r13, %rcx
	ja   .Lcc_bad
	mov  (%r12), %eax
	bswap %eax
	mov  %eax, %r15d
	mov  %rcx, %r12
	jmp  .Lcc_have
.Lcc_a8:
	lea  8(%r12), %rcx
	cmp  %r13, %rcx
	ja   .Lcc_bad
	mov  (%r12), %r15
	bswap %r15
	mov  %rcx, %r12
.Lcc_have:
	cmp  $2, %r14
	jb   .Lcc_done                   # 0 uint / 1 nint — the head is the whole value
	cmp  $3, %r14
	jbe  .Lcc_bytes                  # 2 bytes / 3 text
	cmp  $4, %r14
	je   .Lcc_arr
	cmp  $5, %r14
	je   .Lcc_map
	cmp  $6, %r14
	je   .Lcc_tag
	jmp  .Lcc_done                   # 7 simple/float — argument bytes already consumed
.Lcc_bytes:
	mov  %r13, %rcx
	sub  %r12, %rcx                  # bytes remaining in the frame
	cmp  %r15, %rcx
	jb   .Lcc_bad                    # a declared length longer than the frame. Compared
					 # this way round rather than as p+arg, which wraps
					 # on a 2^64-1 length and passes.
	add  %r15, %r12
	jmp  .Lcc_done
.Lcc_map:
	mov  %r15, %rcx
	shr  $63, %rcx
	jnz  .Lcc_bad                    # 2*count would wrap
	add  %r15, %r15                  # a map is 2*count items
.Lcc_arr:
	mov  %r15, %rbx
.Lcc_items:
	test %rbx, %rbx
	jz   .Lcc_done
	mov  %r12, %rdi
	mov  %r13, %rsi
	call cbor_check
	test %rax, %rax
	jz   .Lcc_bad                    # a huge declared count terminates HERE, on the
					 # first element that has no bytes left — the loop
					 # cannot run longer than the frame
	mov  %rax, %r12
	dec  %rbx
	jmp  .Lcc_items
.Lcc_tag:
	movq $1, g_saw_tag(%rip)
	mov  %r12, %rdi
	mov  %r13, %rsi
	call cbor_check
	test %rax, %rax
	jz   .Lcc_bad
	mov  %rax, %r12
.Lcc_done:
	decq g_chk_depth(%rip)
	mov  %r12, %rax
	jmp  .Lcc_ret
.Lcc_bad:
	decq g_chk_depth(%rip)
	xor  %eax, %eax
.Lcc_ret:
	pop  %r15
	pop  %r14
	pop  %r13
	pop  %r12
	pop  %rbx
	ret

	.section .note.GNU-stack,"",@progbits
