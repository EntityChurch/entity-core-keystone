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

	.section .note.GNU-stack,"",@progbits
