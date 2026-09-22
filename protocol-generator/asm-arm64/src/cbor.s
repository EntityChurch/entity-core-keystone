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

// =========================== STRICT CHECKER ===========================
// The readers above are DELIBERATELY lenient: map_find/skip_value walk whatever shape
// they are handed, which is what lets a refusal path recover a request_id out of a frame
// the strict pass has already condemned. Nothing else in this file asks whether the bytes
// are a legal canonical-ECF value at all.
//
// cbor_check_frame is that question, and §4.11 is why it has to be asked BEFORE dispatch
// rather than inside it: a frame that never becomes an Envelope is owed a coded
// EXECUTE_RESPONSE, and the CAUSE decides the code.
//
//   a CBOR tag in any position  →  ENTITY-CBOR-ENCODING §6.3 tag policy
//                                  (`non_canonical_ecf`, and §6.3 already MUSTs it)
//   anything else               →  "never becomes an Envelope" (`invalid_request`)
//
// It is also the bound that makes the LENIENT readers safe. skip_value recurses with no
// depth cap and no end pointer, so 16 MiB of nested array(1) is a stack smash reachable by
// anyone who can send bytes, and read_head treats additional-info 31 as the 8-byte form
// and reads eight bytes that are not there. Running this pass first means every later walk
// of b_req is over bytes already proven in-bounds, finite and shallower than 128.
//
// NOT checked here, deliberately, and it is a recorded debt rather than an oversight:
// MINIMAL head form and DUPLICATE map keys.

	.bss
	.lcomm g_saw_tag,    8
	.lcomm g_chk_depth,  8

	.text
	.globl cbor_check_frame
	.type cbor_check_frame, %function
// cbor_check_frame(x0 = ptr, x1 = end) -> x0 = 0 OK | 1 TAG | 2 INVALID
//
// TAG wins over a clean structure but not over a broken one: a frame that is both
// truncated and tagged is INVALID, because the tag was read out of bytes whose shape was
// never established.
cbor_check_frame:
	stp  x29, x30, [sp, #-32]!
	mov  x29, sp
	str  x19, [sp, #16]
	mov  x19, x1                     // end
	adr_l x9, g_saw_tag
	str  xzr, [x9]
	adr_l x9, g_chk_depth
	str  xzr, [x9]
	bl   cbor_check
	cbz  x0, .Lcf_invalid
	cmp  x0, x19
	b.ne .Lcf_invalid                // trailing bytes: the frame length and the value
					 // disagree, which is a framing fault, not a tag one
	adr_l x9, g_saw_tag
	ldr  x9, [x9]
	cbnz x9, .Lcf_tag
	mov  x0, #0
	b    .Lcf_ret
.Lcf_tag:
	mov  x0, #1
	b    .Lcf_ret
.Lcf_invalid:
	mov  x0, #2
.Lcf_ret:
	ldr  x19, [sp, #16]
	ldp  x29, x30, [sp], #32
	ret

	.type cbor_check, %function
// cbor_check(x0 = ptr, x1 = end) -> x0 = ptr-after-value | 0 if not a legal value.
// Records a major-6 tag anywhere in g_saw_tag and keeps walking, so one pass answers both
// questions. Every read is bounds-checked against `end` before it happens.
// x19 = p, x20 = end, x21 = major, x22 = argument, x23 = item counter.
cbor_check:
	stp  x29, x30, [sp, #-64]!
	mov  x29, sp
	stp  x19, x20, [sp, #16]
	stp  x21, x22, [sp, #32]
	str  x23, [sp, #48]
	mov  x19, x0                     // p
	mov  x20, x1                     // end
	adr_l x9, g_chk_depth
	ldr  x10, [x9]
	add  x10, x10, #1
	str  x10, [x9]
	cmp  x10, #128
	b.hi .Lcc_bad                    // canonical ECF nesting is shallow; a frame deeper
					 // than this is hostile, and the cap is what keeps the
					 // recursion off the guard page
	cmp  x19, x20
	b.hs .Lcc_bad                    // no initial byte
	ldrb w9, [x19]
	add  x19, x19, #1
	lsr  w21, w9, #5                 // major
	and  w9, w9, #0x1f               // additional info
	mov  x22, #0
	cmp  w9, #24
	b.lo .Lcc_small
	b.eq .Lcc_a1
	cmp  w9, #25
	b.eq .Lcc_a2
	cmp  w9, #26
	b.eq .Lcc_a4
	cmp  w9, #27
	b.eq .Lcc_a8
	b    .Lcc_bad                    // 28/29/30 reserved · 31 indefinite-length. Canonical
					 // ECF admits neither, and read_head would decode 31 as
					 // the 8-byte form and read past the frame.
.Lcc_small:
	mov  w22, w9
	b    .Lcc_have
.Lcc_a1:
	add  x10, x19, #1
	cmp  x10, x20
	b.hi .Lcc_bad
	ldrb w22, [x19]
	mov  x19, x10
	b    .Lcc_have
.Lcc_a2:
	add  x10, x19, #2
	cmp  x10, x20
	b.hi .Lcc_bad
	ldrb w22, [x19]
	lsl  w22, w22, #8
	ldrb w11, [x19, #1]
	orr  w22, w22, w11
	mov  x19, x10
	b    .Lcc_have
.Lcc_a4:
	add  x10, x19, #4
	cmp  x10, x20
	b.hi .Lcc_bad
	ldr  w22, [x19]
	rev  w22, w22                    // a W-register write zero-extends into x22
	mov  x19, x10
	b    .Lcc_have
.Lcc_a8:
	add  x10, x19, #8
	cmp  x10, x20
	b.hi .Lcc_bad
	ldr  x22, [x19]
	rev  x22, x22
	mov  x19, x10
.Lcc_have:
	cmp  x21, #2
	b.lo .Lcc_done                   // 0 uint / 1 nint — the head is the whole value
	cmp  x21, #3
	b.ls .Lcc_bytes                  // 2 bytes / 3 text
	cmp  x21, #4
	b.eq .Lcc_arr
	cmp  x21, #5
	b.eq .Lcc_map
	cmp  x21, #6
	b.eq .Lcc_tag
	b    .Lcc_done                   // 7 simple/float — argument bytes already consumed
.Lcc_bytes:
	sub  x10, x20, x19               // bytes remaining in the frame
	cmp  x10, x22
	b.lo .Lcc_bad                    // a declared length longer than the frame. Compared
					 // this way round rather than as p+arg, which wraps on
					 // a 2^64-1 length and passes.
	add  x19, x19, x22
	b    .Lcc_done
.Lcc_map:
	lsr  x10, x22, #63
	cbnz x10, .Lcc_bad               // 2*count would wrap
	lsl  x22, x22, #1                // a map is 2*count items
.Lcc_arr:
	mov  x23, x22
.Lcc_items:
	cbz  x23, .Lcc_done
	mov  x0, x19
	mov  x1, x20
	bl   cbor_check
	cbz  x0, .Lcc_bad                // a huge declared count terminates HERE, on the first
					 // element with no bytes left — the loop cannot run
					 // longer than the frame
	mov  x19, x0
	sub  x23, x23, #1
	b    .Lcc_items
.Lcc_tag:
	adr_l x9, g_saw_tag
	mov  x10, #1
	str  x10, [x9]
	mov  x0, x19
	mov  x1, x20
	bl   cbor_check
	cbz  x0, .Lcc_bad
	mov  x19, x0
.Lcc_done:
	adr_l x9, g_chk_depth
	ldr  x10, [x9]
	sub  x10, x10, #1
	str  x10, [x9]
	mov  x0, x19
	b    .Lcc_ret
.Lcc_bad:
	adr_l x9, g_chk_depth
	ldr  x10, [x9]
	sub  x10, x10, #1
	str  x10, [x9]
	mov  x0, #0
.Lcc_ret:
	ldr  x23, [sp, #48]
	ldp  x21, x22, [sp, #32]
	ldp  x19, x20, [sp, #16]
	ldp  x29, x30, [sp], #64
	ret

	.section .note.GNU-stack,"",%progbits
