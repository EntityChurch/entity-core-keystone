# cbor.s — minimal canonical-CBOR reader + writer for the envelope/data-map layer.
# (A-ASM-004: the FFI decomposes entities, not the envelope/data maps — so the peer
# hand-rolls this map layer even at Level 1.) Ported from asm-arm64/src/cbor.s.
# GAS riscv64 (RV64GC). Register/ABI map: see macros.s.
#
# READER (a0 in / a0 out; read_head multi-returns a1=major, a2=arg):
#   read_head(a0=ptr)  -> a0=ptr-after-head, a1=major(0..7), a2=argument(uint)
#   skip_value(a0=ptr) -> a0=ptr-after-value  (recursive)
#   map_find(a0=map, a1=key, a2=keylen) -> a0=value-ptr, or 0 if absent
#   get_text(a0=valptr) -> a0=bytes-ptr, a2=len   (value must be text/bytes)
#   memeq(a0,a1,a2=len) -> a0=1 if the a2 bytes are equal
#
# WRITER — cursor convention: s6 (was aarch64 x24 / x86 r15) is the append cursor, advanced
#   in place. Prims clobber only a0/t0-t2 (+ their arg regs); s1-s5 are preserved so the caller
#   can hold saved pointers across a build. Args match the sibling source: value/ptr in a1,
#   len in a2; w_u8/w_cstr take a0.
#   w_u8(a0=byte) w_map(a1=n) w_arr(a1=n) w_uint(a1=val)
#   w_txt(a1=ptr,a2=len) w_bstr(a1=ptr,a2=len) w_raw(a1=ptr,a2=len)
#   w_cstr(a0=asciz)

	.include "macros.s"
	.extern strlen

	.text

# =========================== READER ===========================
	.globl read_head
	.type read_head, @function
read_head:
	lbu  t0, 0(a0)                   # first byte
	srli a1, t0, 5                   # major = byte>>5
	andi t1, t0, 0x1f                # low 5 bits
	addi a0, a0, 1                   # past initial byte
	li   t2, 24
	bltu t1, t2, .Lrh_small          # <24 → immediate
	beq  t1, t2, .Lrh_1              # ==24 → 1-byte
	li   t2, 25
	beq  t1, t2, .Lrh_2              # ==25 → 2-byte
	li   t2, 26
	beq  t1, t2, .Lrh_4             # ==26 → 4-byte
	# 27 → 8-byte big-endian argument
	ld   a2, 0(a0)
	bswap64 a2, a2
	addi a0, a0, 8
	ret
.Lrh_small:
	mv   a2, t1
	ret
.Lrh_1:
	lbu  a2, 0(a0)
	addi a0, a0, 1
	ret
.Lrh_2:
	lbu  a2, 0(a0)                   # hi
	slli a2, a2, 8
	lbu  t2, 1(a0)                   # lo
	or   a2, a2, t2
	addi a0, a0, 2
	ret
.Lrh_4:
	lwu  a2, 0(a0)
	bswap32 a2, a2
	addi a0, a0, 4
	ret

	.globl skip_value
	.type skip_value, @function
# The cursor threads through a0 (a0 is both the incoming ptr and read_head's returned
# after-ptr). s1 = item counter (callee-saved, preserved across the recursion).
skip_value:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	call read_head                   # a0=after, a1=major, a2=arg
	li   t0, 2
	bltu a1, t0, .Lsv_done           # 0/1 uint/nint
	li   t0, 3
	bgeu t0, a1, .Lsv_bytes          # a1<=3 → 2 bytes / 3 text
	li   t0, 4
	beq  a1, t0, .Lsv_array
	li   t0, 5
	beq  a1, t0, .Lsv_map
	li   t0, 6
	beq  a1, t0, .Lsv_tag
	j    .Lsv_done                   # 7 simple/float: head already consumed
.Lsv_bytes:
	add  a0, a0, a2                  # ptr += len
	j    .Lsv_done
.Lsv_map:
	slli a2, a2, 1                   # 2*count items
.Lsv_array:
	mv   s1, a2
.Lsv_a:
	beqz s1, .Lsv_done
	call skip_value                  # a0 in/out threads the cursor
	addi s1, s1, -1
	j    .Lsv_a
.Lsv_tag:
	call skip_value
.Lsv_done:
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

	.globl map_find
	.type map_find, @function
# map_find(a0=map_ptr, a1=key_ptr, a2=key_len) -> a0 = value_ptr | 0
# s1=remaining pairs, s2=value ptr (callee-saved so it survives memeq/skip_value),
# s3=key ptr, s4=key len, s5=cursor.
map_find:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s3, a1                      # key ptr
	mv   s4, a2                      # key len
	call read_head                   # a0=afterhdr, a1=major(5), a2=count
	mv   s5, a0                      # cursor
	mv   s1, a2                      # remaining pairs
.Lmf_loop:
	beqz s1, .Lmf_none
	mv   a0, s5
	call read_head                   # a0=keybytes, a2=this key len
	add  s2, a0, a2                  # value ptr = keybytes + keylen
	bne  s4, a2, .Lmf_skip           # key len match?
	mv   a1, a0                      # this key bytes
	mv   a0, s3                      # our key ; a2 already = this key len
	call memeq
	bnez a0, .Lmf_found
.Lmf_skip:
	mv   a0, s2
	call skip_value
	mv   s5, a0
	addi s1, s1, -1
	j    .Lmf_loop
.Lmf_found:
	mv   a0, s2
	j    .Lmf_ret
.Lmf_none:
	li   a0, 0
.Lmf_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

	.globl get_text
	.type get_text, @function
# get_text(a0=valptr) -> a0=bytes ptr, a2=len   (text/bytes value)
get_text:
	tail read_head                   # tail call: a0=after(=bytes), a2=len

	.globl memeq
	.type memeq, @function
# memeq(a0=a, a1=b, a2=len) -> a0=1 if equal. Leaf (only a0/a1/a2/t0/t1).
memeq:
.Lme:
	beqz a2, .Lme_yes
	lbu  t0, 0(a0)
	lbu  t1, 0(a1)
	bne  t0, t1, .Lme_no
	addi a0, a0, 1
	addi a1, a1, 1
	addi a2, a2, -1
	j    .Lme
.Lme_yes:
	li   a0, 1
	ret
.Lme_no:
	li   a0, 0
	ret

# =========================== WRITER (cursor = s6) ===========================
	.globl w_u8
	.type w_u8, @function
w_u8:                                # a0 = byte
	sb   a0, 0(s6)
	addi s6, s6, 1
	ret

	.globl w_map
	.type w_map, @function
w_map:                               # a1 = n (<24)
	li   t0, 0xa0
	or   t0, t0, a1
	sb   t0, 0(s6)
	addi s6, s6, 1
	ret

	.globl w_arr
	.type w_arr, @function
w_arr:                               # a1 = n (<24)
	li   t0, 0x80
	or   t0, t0, a1
	sb   t0, 0(s6)
	addi s6, s6, 1
	ret

	.globl w_uint
	.type w_uint, @function
# w_uint(a1=val) — shortest-length unsigned integer head.
w_uint:
	li   t0, 24
	bgeu a1, t0, .Lwu_1
	sb   a1, 0(s6)
	addi s6, s6, 1
	ret
.Lwu_1:
	li   t0, 256
	bgeu a1, t0, .Lwu_2
	li   t0, 0x18
	sb   t0, 0(s6)
	addi s6, s6, 1
	sb   a1, 0(s6)
	addi s6, s6, 1
	ret
.Lwu_2:
	li   t0, 65536
	bgeu a1, t0, .Lwu_4
	li   t0, 0x19
	sb   t0, 0(s6)
	addi s6, s6, 1
	bswap16 t0, a1                   # 2-byte big-endian
	sh   t0, 0(s6)
	addi s6, s6, 2
	ret
.Lwu_4:
	srli t0, a1, 32
	bnez t0, .Lwu_8
	li   t0, 0x1a
	sb   t0, 0(s6)
	addi s6, s6, 1
	bswap32 t0, a1                   # 4-byte big-endian
	sw   t0, 0(s6)
	addi s6, s6, 4
	ret
.Lwu_8:
	li   t0, 0x1b
	sb   t0, 0(s6)
	addi s6, s6, 1
	bswap64 t0, a1                   # 8-byte big-endian
	sd   t0, 0(s6)
	addi s6, s6, 8
	ret

	.globl w_txt
	.type w_txt, @function
# w_txt(a1=ptr, a2=len) — text string (major 3)
w_txt:
	li   t1, 0x60
	j    w_str_common
	.globl w_bstr
	.type w_bstr, @function
# w_bstr(a1=ptr, a2=len) — byte string (major 2)
w_bstr:
	li   t1, 0x40
w_str_common:
	li   t0, 24
	bgeu a2, t0, .Lws_long
	or   t0, t1, a2                  # major | len (len<24)
	sb   t0, 0(s6)
	addi s6, s6, 1
	j    w_raw_copy
.Lws_long:
	li   t0, 256
	bgeu a2, t0, .Lws_2
	li   t0, 0x18
	or   t0, t0, t1                  # 0x58 (bytes) / 0x78 (text): +0x18 one-byte len
	sb   t0, 0(s6)
	addi s6, s6, 1
	sb   a2, 0(s6)
	addi s6, s6, 1
	j    w_raw_copy
.Lws_2:
	li   t0, 0x19
	or   t0, t0, t1                  # two-byte len form
	sb   t0, 0(s6)
	addi s6, s6, 1
	bswap16 t0, a2
	sh   t0, 0(s6)
	addi s6, s6, 2
	# fall through to copy

	.globl w_raw
	.type w_raw, @function
# w_raw(a1=ptr, a2=len) — copy len bytes verbatim (embed a pre-built CBOR value)
w_raw:
w_raw_copy:
	li   t0, 0                       # index
.Lwr_c:
	bgeu t0, a2, .Lwr_done
	add  t3, a1, t0
	lbu  t2, 0(t3)
	sb   t2, 0(s6)
	addi s6, s6, 1
	addi t0, t0, 1
	j    .Lwr_c
.Lwr_done:
	ret

	.globl w_cstr
	.type w_cstr, @function
# w_cstr(a0=asciz) — emit as a text string
w_cstr:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	mv   s1, a0                      # save ptr (callee-saved across strlen)
	call strlen                      # a0 = len
	mv   a2, a0                      # len → a2
	mv   a1, s1                      # ptr → a1
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	tail w_txt                       # tail call

# =========================== STRICT CHECKER ===========================
# The readers above are DELIBERATELY lenient: map_find/skip_value walk whatever shape they
# are handed, which is what lets a refusal path recover a request_id out of a frame the
# strict pass has already condemned. Nothing else in this file asks whether the bytes are a
# legal canonical-ECF value at all.
#
# cbor_check_frame is that question, and §4.11 is why it has to be asked BEFORE dispatch
# rather than inside it: a frame that never becomes an Envelope is owed a coded
# EXECUTE_RESPONSE, and the CAUSE decides the code.
#
#   a CBOR tag in any position  ->  ENTITY-CBOR-ENCODING §6.3 tag policy
#                                   (`non_canonical_ecf`, and §6.3 already MUSTs it)
#   anything else               ->  "never becomes an Envelope" (`invalid_request`)
#
# It is also the bound that makes the LENIENT readers safe. skip_value recurses with no
# depth cap and no end pointer, so 16 MiB of nested array(1) is a stack smash reachable by
# anyone who can send bytes, and read_head treats additional-info 31 as the 8-byte form and
# reads eight bytes that are not there. Running this pass first means every later walk of
# b_req is over bytes already proven in-bounds, finite and shallower than 128.
#
# NOT checked here, deliberately, and it is a recorded debt rather than an oversight:
# MINIMAL head form and DUPLICATE map keys.

	.bss
	.lcomm g_saw_tag,    8
	.lcomm g_chk_depth,  8

	.text
	.globl cbor_check_frame
	.type cbor_check_frame, @function
# cbor_check_frame(a0 = ptr, a1 = end) -> a0 = 0 OK | 1 TAG | 2 INVALID
#
# TAG wins over a clean structure but not over a broken one: a frame that is both truncated
# and tagged is INVALID, because the tag was read out of bytes whose shape was never
# established.
cbor_check_frame:
	addi sp, sp, -32
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	mv   s0, sp
	mv   s1, a1                      # end
	adr_l t0, g_saw_tag
	sd   zero, 0(t0)
	adr_l t0, g_chk_depth
	sd   zero, 0(t0)
	call cbor_check
	beqz a0, .Lcf_invalid
	bne  a0, s1, .Lcf_invalid        # trailing bytes: the frame length and the value
					 # disagree, which is a framing fault, not a tag one
	adr_l t0, g_saw_tag
	ld   t0, 0(t0)
	bnez t0, .Lcf_tag
	li   a0, 0
	j    .Lcf_ret
.Lcf_tag:
	li   a0, 1
	j    .Lcf_ret
.Lcf_invalid:
	li   a0, 2
.Lcf_ret:
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 32
	ret

	.type cbor_check, @function
# cbor_check(a0 = ptr, a1 = end) -> a0 = ptr-after-value | 0 if not a legal value.
# Records a major-6 tag anywhere in g_saw_tag and keeps walking, so one pass answers both
# questions. Every read is bounds-checked against `end` before it happens.
# s1 = p, s2 = end, s3 = major, s4 = argument, s5 = item counter.
# NB t5/t6 are the bswap macros' internal scratch and are never held live across one.
cbor_check:
	addi sp, sp, -64
	sd   s0, 0(sp)
	sd   ra, 8(sp)
	sd   s1, 16(sp)
	sd   s2, 24(sp)
	sd   s3, 32(sp)
	sd   s4, 40(sp)
	sd   s5, 48(sp)
	mv   s0, sp
	mv   s1, a0                      # p
	mv   s2, a1                      # end
	adr_l t0, g_chk_depth
	ld   t1, 0(t0)
	addi t1, t1, 1
	sd   t1, 0(t0)
	li   t2, 128
	bgtu t1, t2, .Lcc_bad            # canonical ECF nesting is shallow; a frame deeper than
					 # this is hostile, and the cap is what keeps the
					 # recursion off the guard page
	bgeu s1, s2, .Lcc_bad            # no initial byte
	lbu  t0, 0(s1)
	addi s1, s1, 1
	srli s3, t0, 5                   # major
	andi t0, t0, 0x1f                # additional info
	li   s4, 0
	li   t1, 24
	bltu t0, t1, .Lcc_small
	beq  t0, t1, .Lcc_a1
	li   t1, 25
	beq  t0, t1, .Lcc_a2
	li   t1, 26
	beq  t0, t1, .Lcc_a4
	li   t1, 27
	beq  t0, t1, .Lcc_a8
	j    .Lcc_bad                    # 28/29/30 reserved · 31 indefinite-length. Canonical
					 # ECF admits neither, and read_head would decode 31 as
					 # the 8-byte form and read past the frame.
.Lcc_small:
	mv   s4, t0
	j    .Lcc_have
.Lcc_a1:
	addi t1, s1, 1
	bgtu t1, s2, .Lcc_bad
	lbu  s4, 0(s1)
	mv   s1, t1
	j    .Lcc_have
.Lcc_a2:
	addi t1, s1, 2
	bgtu t1, s2, .Lcc_bad
	lbu  s4, 0(s1)
	slli s4, s4, 8
	lbu  t2, 1(s1)
	or   s4, s4, t2
	mv   s1, t1
	j    .Lcc_have
.Lcc_a4:
	addi t1, s1, 4
	bgtu t1, s2, .Lcc_bad
	lwu  t2, 0(s1)
	bswap32 s4, t2
	mv   s1, t1
	j    .Lcc_have
.Lcc_a8:
	addi t1, s1, 8
	bgtu t1, s2, .Lcc_bad
	ld   t2, 0(s1)
	bswap64 s4, t2
	mv   s1, t1
.Lcc_have:
	li   t0, 2
	bltu s3, t0, .Lcc_done           # 0 uint / 1 nint — the head is the whole value
	li   t0, 3
	bgeu t0, s3, .Lcc_bytes          # 2 bytes / 3 text
	li   t0, 4
	beq  s3, t0, .Lcc_arr
	li   t0, 5
	beq  s3, t0, .Lcc_map
	li   t0, 6
	beq  s3, t0, .Lcc_tag
	j    .Lcc_done                   # 7 simple/float — argument bytes already consumed
.Lcc_bytes:
	sub  t0, s2, s1                  # bytes remaining in the frame
	bltu t0, s4, .Lcc_bad            # a declared length longer than the frame. Compared this
					 # way round rather than as p+arg, which wraps on a
					 # 2^64-1 length and passes.
	add  s1, s1, s4
	j    .Lcc_done
.Lcc_map:
	srli t0, s4, 63
	bnez t0, .Lcc_bad                # 2*count would wrap
	slli s4, s4, 1                   # a map is 2*count items
.Lcc_arr:
	mv   s5, s4
.Lcc_items:
	beqz s5, .Lcc_done
	mv   a0, s1
	mv   a1, s2
	call cbor_check
	beqz a0, .Lcc_bad                # a huge declared count terminates HERE, on the first
					 # element with no bytes left — the loop cannot run longer
					 # than the frame
	mv   s1, a0
	addi s5, s5, -1
	j    .Lcc_items
.Lcc_tag:
	adr_l t0, g_saw_tag
	li    t1, 1
	sd    t1, 0(t0)
	mv   a0, s1
	mv   a1, s2
	call cbor_check
	beqz a0, .Lcc_bad
	mv   s1, a0
.Lcc_done:
	adr_l t0, g_chk_depth
	ld   t1, 0(t0)
	addi t1, t1, -1
	sd   t1, 0(t0)
	mv   a0, s1
	j    .Lcc_ret
.Lcc_bad:
	adr_l t0, g_chk_depth
	ld   t1, 0(t0)
	addi t1, t1, -1
	sd   t1, 0(t0)
	li   a0, 0
.Lcc_ret:
	ld   s5, 48(sp)
	ld   s4, 40(sp)
	ld   s3, 32(sp)
	ld   s2, 24(sp)
	ld   s1, 16(sp)
	ld   ra, 8(sp)
	ld   s0, 0(sp)
	addi sp, sp, 64
	ret

	.section .note.GNU-stack,"",@progbits
