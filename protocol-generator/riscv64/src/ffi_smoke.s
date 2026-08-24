# ffi_smoke.s — de-risk the riscv64 asm → C-ABI FFI bridge (S1/S2 seam).
# Ported from asm-arm64/src/ffi_smoke.s. Proves three mechanics end-to-end before the
# full peer is built:
#   1. LP64D call into libentitycore_codec (args in a0/a1/a2, ret in a0, sp 16-aligned at call).
#   2. Dynamic link + load of the CROSS-BUILT riscv64 libentitycore_codec.so.
#   3. Raw Linux syscall (write, #64 on the generic table) — the transport substrate mechanic.
#
# Test: ec_sha256("abc") must equal the RFC 6234 KAT
#   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
# byte-for-byte. Exit 0 + PASS line on match; exit 1 + FAIL line otherwise.
#
# GAS riscv64. Entry is `main` (cc-driver startup; libc initialized).

.set SYS_write, 64                  # generic table (asm-generic/unistd.h), not x86-64's 1

.section .rodata
input:
    .ascii "abc"
    .set input_len, . - input
expected:                           # SHA-256("abc"), the KAT digest, 32 bytes
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
.lcomm digest, 32                   # ec_sha256 output buffer

.text
.global main
.type main, @function
main:
    addi sp, sp, -16
    sd   ra, 8(sp)
    sd   s0, 0(sp)
    mv   s0, sp

    # ec_sha256(input, input_len, digest) — a0,a1,a2; status in a0
    lla  a0, input
    li   a1, input_len
    lla  a2, digest
    call ec_sha256
    bnez a0, .Lfail                 # EC_OK == 0; anything else fails

    # byte-compare digest[0..32) against the KAT
    lla  a1, digest
    lla  a0, expected
    li   a2, 32
.Lcmp:
    lbu  t0, 0(a0)
    lbu  t1, 0(a1)
    bne  t0, t1, .Lfail
    addi a0, a0, 1
    addi a1, a1, 1
    addi a2, a2, -1
    bnez a2, .Lcmp

    # PASS: raw write(1, pass_msg, pass_len) then return 0
    li   a0, 1
    lla  a1, pass_msg
    li   a2, pass_len
    li   a7, SYS_write
    ecall
    li   a0, 0
    ld   s0, 0(sp)
    ld   ra, 8(sp)
    addi sp, sp, 16
    ret

.Lfail:
    li   a0, 1
    lla  a1, fail_msg
    li   a2, fail_len
    li   a7, SYS_write
    ecall
    li   a0, 1
    ld   s0, 0(sp)
    ld   ra, 8(sp)
    addi sp, sp, 16
    ret

.section .note.GNU-stack,"",@progbits   # mark stack non-executable (hygiene)
