# ffi_smoke.s — de-risk the asm → C-ABI FFI bridge (S1/S2 seam).
#
# Proves three mechanics end-to-end before the full peer is built:
#   1. SysV AMD64 call into libentitycore_codec (args in rdi/rsi/rdx, ret in eax,
#      16-byte stack alignment at the `call`).
#   2. Dynamic link + load of libentitycore_codec.so (the codec .so resolves).
#   3. Raw Linux syscall (write, #1) for output — the transport substrate mechanic.
#
# Test: ec_sha256("abc") must equal the RFC 6234 KAT
#   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
# byte-for-byte. Exit 0 + PASS line on match; exit 1 + FAIL line otherwise.
#
# GAS / AT&T syntax. Entry is `main` (cc-driver startup; libc initialized) — A-ASM-001.

	.section .rodata
input:
	.ascii "abc"
	.set input_len, . - input
expected:                       # SHA-256("abc"), the KAT digest, 32 bytes
	.byte 0xba,0x78,0x16,0xbf, 0x8f,0x01,0xcf,0xea
	.byte 0x41,0x41,0x40,0xde, 0x5d,0xae,0x22,0x23
	.byte 0xb0,0x03,0x61,0xa3, 0x96,0x17,0x7a,0x9c
	.byte 0xb4,0x10,0xff,0x61, 0xf2,0x00,0x15,0xad
pass_msg:
	.ascii "FFI-BRIDGE PASS: ec_sha256(\"abc\") byte-exact vs RFC6234 KAT\n"
	.set pass_len, . - pass_msg
fail_msg:
	.ascii "FFI-BRIDGE FAIL: ec_sha256 mismatch or nonzero status\n"
	.set fail_len, . - fail_msg

	.bss
	.lcomm digest, 32               # ec_sha256 output buffer

	.text
	.globl main
	.type main, @function
main:
	push %rbp
	mov  %rsp, %rbp                 # rsp now 16-aligned → calls are ABI-legal

	# ec_sha256(input, input_len, digest)  — rdi, rsi, rdx; status in eax
	lea  input(%rip), %rdi
	mov  $input_len, %rsi
	lea  digest(%rip), %rdx
	call ec_sha256
	test %eax, %eax
	jnz  .Lfail                     # EC_OK == 0; anything else fails

	# byte-compare digest[0..32) against the KAT
	lea  digest(%rip), %rsi
	lea  expected(%rip), %rdi
	mov  $32, %rcx
.Lcmp:
	mov  (%rsi), %al
	mov  (%rdi), %dl
	cmp  %dl, %al
	jne  .Lfail
	inc  %rsi
	inc  %rdi
	dec  %rcx
	jnz  .Lcmp

	# PASS: raw write(1, pass_msg, pass_len) then return 0
	mov  $1, %rax                   # SYS_write
	mov  $1, %rdi                   # fd = stdout
	lea  pass_msg(%rip), %rsi
	mov  $pass_len, %rdx
	syscall
	xor  %eax, %eax
	leave
	ret

.Lfail:
	mov  $1, %rax                   # SYS_write
	mov  $1, %rdi
	lea  fail_msg(%rip), %rsi
	mov  $fail_len, %rdx
	syscall
	mov  $1, %eax
	leave
	ret

	.section .note.GNU-stack,"",@progbits   # mark stack non-executable (hygiene)
