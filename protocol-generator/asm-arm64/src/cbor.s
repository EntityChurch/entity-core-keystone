// cbor.s — minimal canonical-CBOR reader + writer for the envelope/data-map layer.
// (A-ASM-004: the FFI decomposes entities, not the envelope/data maps — so the peer
// hand-rolls this map layer even at Level 1.) Ported from asm-x86_64/src/cbor.s.
// GAS aarch64.
//
// READER (x0 in / x0 out; read_head multi-returns x1=major, x2=arg):
//   read_head(x0=ptr)  -> x0=ptr-after-head, x1=major(0..7), x2=argument(uint)
//   skip_value(x0=ptr) -> x0=ptr-after-value  (recursive)
//   map_find(x0=map, x1=key, x2=keylen) -> x0=value-ptr, or 0 if absent
//   get_text(x0=valptr) -> x0=bytes-ptr, x2=len   (value must be text/bytes)
//   memeq(x0,x1,x2=len) -> x0=1 if the x2 bytes are equal
//
// WRITER — cursor convention: x24 (was x86 r15) is the append cursor, advanced in place.
//   Prims clobber only x0/x9-x11 (+ their arg regs); x19-x23 are preserved so the caller
//   can hold saved pointers across a build. Args match the x86 source: value/ptr in x1
//   (rsi), len in x2 (rdx); w_u8/w_cstr take x0 (rdi).
//   w_u8(x0=byte) w_map(x1=n) w_arr(x1=n) w_uint(x1=val)
//   w_txt(x1=ptr,x2=len) w_bstr(x1=ptr,x2=len) w_raw(x1=ptr,x2=len)
//   w_cstr(x0=asciz)

	.include "macros.s"
	.extern strlen

	.text

// =========================== READER ===========================
	.globl read_head
	.type read_head, %function
read_head:
	ldrb w9, [x0]                    // first byte
	lsr  w1, w9, #5                  // major = byte>>5
	and  w10, w9, #0x1f              // low 5 bits
	add  x0, x0, #1                  // past initial byte
	cmp  w10, #24
	b.lo .Lrh_small
	b.eq .Lrh_1
	cmp  w10, #25
	b.eq .Lrh_2
	cmp  w10, #26
	b.eq .Lrh_4
	// 27 → 8-byte big-endian argument
	ldr  x2, [x0]
	rev  x2, x2
	add  x0, x0, #8
	ret
.Lrh_small:
	mov  w2, w10
	ret
.Lrh_1:
	ldrb w2, [x0]
	add  x0, x0, #1
	ret
.Lrh_2:
	ldrb w2, [x0]                    // hi
	lsl  w2, w2, #8
	ldrb w11, [x0, #1]              // lo
	orr  w2, w2, w11
	add  x0, x0, #2
	ret
.Lrh_4:
	ldr  w2, [x0]
	rev  w2, w2
	add  x0, x0, #4
	ret

	.globl skip_value
	.type skip_value, %function
// The cursor threads through x0 (x0 is both the incoming ptr and read_head's returned
// after-ptr), so no separate rdi/rax split is needed. x19 = item counter (callee-saved,
// preserved across the recursion).
skip_value:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x19, [sp, #16]
	bl   read_head                   // x0=after, x1=major, x2=arg
	cmp  x1, #2
	b.lo .Lsv_done                   // 0/1 uint/nint
	cmp  x1, #3
	b.ls .Lsv_bytes                  // 2 bytes / 3 text
	cmp  x1, #4
	b.eq .Lsv_array
	cmp  x1, #5
	b.eq .Lsv_map
	cmp  x1, #6
	b.eq .Lsv_tag
	b    .Lsv_done                   // 7 simple/float: head already consumed
.Lsv_bytes:
	add  x0, x0, x2                  // ptr += len
	b    .Lsv_done
.Lsv_map:
	lsl  x2, x2, #1                  // 2*count items
.Lsv_array:
	mov  x19, x2
.Lsv_a:
	cbz  x19, .Lsv_done
	bl   skip_value                  // x0 in/out threads the cursor
	sub  x19, x19, #1
	b    .Lsv_a
.Lsv_tag:
	bl   skip_value
.Lsv_done:
	ldr  x19, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

	.globl map_find
	.type map_find, %function
// map_find(x0=map_ptr, x1=key_ptr, x2=key_len) -> x0 = value_ptr | 0
// x19=remaining pairs, x20=value ptr (callee-saved so it survives memeq/skip_value),
// x21=key ptr, x22=key len, x23=cursor.
map_find:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x21, x1                     // key ptr
	mov  x22, x2                     // key len
	bl   read_head                   // x0=afterhdr, x1=major(5), x2=count
	mov  x23, x0                     // cursor
	mov  x19, x2                     // remaining pairs
.Lmf_loop:
	cbz  x19, .Lmf_none
	mov  x0, x23
	bl   read_head                   // x0=keybytes, x2=this key len
	add  x20, x0, x2                 // value ptr = keybytes + keylen
	cmp  x22, x2                     // key len match?
	b.ne .Lmf_skip
	mov  x1, x0                      // this key bytes
	mov  x0, x21                     // our key ; x2 already = this key len
	bl   memeq
	cbnz x0, .Lmf_found
.Lmf_skip:
	mov  x0, x20
	bl   skip_value
	mov  x23, x0
	sub  x19, x19, #1
	b    .Lmf_loop
.Lmf_found:
	mov  x0, x20
	b    .Lmf_ret
.Lmf_none:
	mov  x0, #0
.Lmf_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

	.globl get_text
	.type get_text, %function
// get_text(x0=valptr) -> x0=bytes ptr, x2=len   (text/bytes value)
get_text:
	b    read_head                   // tail call: x0=after(=bytes), x2=len

	.globl memeq
	.type memeq, %function
// memeq(x0=a, x1=b, x2=len) -> x0=1 if equal. Leaf (only x0/x1/x2/x9/x10).
memeq:
.Lme:
	cbz  x2, .Lme_yes
	ldrb w9, [x0]
	ldrb w10, [x1]
	cmp  w9, w10
	b.ne .Lme_no
	add  x0, x0, #1
	add  x1, x1, #1
	sub  x2, x2, #1
	b    .Lme
.Lme_yes:
	mov  x0, #1
	ret
.Lme_no:
	mov  x0, #0
	ret

// =========================== WRITER (cursor = x24) ===========================
	.globl w_u8
	.type w_u8, %function
w_u8:                                // x0 = byte
	strb w0, [x24]
	add  x24, x24, #1
	ret

	.globl w_map
	.type w_map, %function
w_map:                               // x1 = n (<24)
	mov  w9, #0xa0
	orr  w9, w9, w1
	strb w9, [x24]
	add  x24, x24, #1
	ret

	.globl w_arr
	.type w_arr, %function
w_arr:                               // x1 = n (<24)
	mov  w9, #0x80
	orr  w9, w9, w1
	strb w9, [x24]
	add  x24, x24, #1
	ret

	.globl w_uint
	.type w_uint, %function
// w_uint(x1=val) — shortest-length unsigned integer head.
w_uint:
	cmp  x1, #24
	b.hs .Lwu_1
	strb w1, [x24]
	add  x24, x24, #1
	ret
.Lwu_1:
	cmp  x1, #256
	b.hs .Lwu_2
	mov  w9, #0x18
	strb w9, [x24]
	add  x24, x24, #1
	strb w1, [x24]
	add  x24, x24, #1
	ret
.Lwu_2:
	cmp  x1, #65536
	b.hs .Lwu_4
	mov  w9, #0x19
	strb w9, [x24]
	add  x24, x24, #1
	rev16 w9, w1                     // 2-byte big-endian
	strh w9, [x24]
	add  x24, x24, #2
	ret
.Lwu_4:
	lsr  x9, x1, #32
	cbnz x9, .Lwu_8
	mov  w9, #0x1a
	strb w9, [x24]
	add  x24, x24, #1
	rev  w9, w1                      // 4-byte big-endian
	str  w9, [x24]
	add  x24, x24, #4
	ret
.Lwu_8:
	mov  w9, #0x1b
	strb w9, [x24]
	add  x24, x24, #1
	rev  x9, x1                      // 8-byte big-endian
	str  x9, [x24]
	add  x24, x24, #8
	ret

	.globl w_txt
	.type w_txt, %function
// w_txt(x1=ptr, x2=len) — text string (major 3)
w_txt:
	mov  w10, #0x60
	b    w_str_common
	.globl w_bstr
	.type w_bstr, %function
// w_bstr(x1=ptr, x2=len) — byte string (major 2)
w_bstr:
	mov  w10, #0x40
w_str_common:
	cmp  x2, #24
	b.hs .Lws_long
	orr  w9, w10, w2                 // major | len (len<24)
	strb w9, [x24]
	add  x24, x24, #1
	b    w_raw_copy
.Lws_long:
	cmp  x2, #256
	b.hs .Lws_2
	mov  w9, #0x18
	orr  w9, w9, w10                 // 0x58 (bytes) / 0x78 (text): +0x18 one-byte len
	strb w9, [x24]
	add  x24, x24, #1
	strb w2, [x24]
	add  x24, x24, #1
	b    w_raw_copy
.Lws_2:
	mov  w9, #0x19
	orr  w9, w9, w10                 // two-byte len form
	strb w9, [x24]
	add  x24, x24, #1
	rev16 w9, w2
	strh w9, [x24]
	add  x24, x24, #2
	// fall through to copy

	.globl w_raw
	.type w_raw, %function
// w_raw(x1=ptr, x2=len) — copy len bytes verbatim (embed a pre-built CBOR value)
w_raw:
w_raw_copy:
	mov  x9, #0                      // index
.Lwr_c:
	cmp  x9, x2
	b.hs .Lwr_done
	ldrb w11, [x1, x9]
	strb w11, [x24]
	add  x24, x24, #1
	add  x9, x9, #1
	b    .Lwr_c
.Lwr_done:
	ret

	.globl w_cstr
	.type w_cstr, %function
// w_cstr(x0=asciz) — emit as a text string
w_cstr:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x19, [sp, #16]
	mov  x19, x0                     // save ptr (callee-saved across strlen)
	bl   strlen                      // x0 = len
	mov  x2, x0                      // len → x2 (rdx)
	mov  x1, x19                     // ptr → x1 (rsi)
	ldr  x19, [sp, #16]
	ldp  x29, x30, [sp], #32
	b    w_txt                       // tail call

	.section .note.GNU-stack,"",%progbits
