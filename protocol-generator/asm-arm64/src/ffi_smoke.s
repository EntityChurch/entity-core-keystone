// ffi_smoke.s — de-risk the aarch64 asm → C-ABI FFI bridge (S1/S2 seam).
// Ported from asm-x86_64/src/ffi_smoke.s. Proves three mechanics end-to-end before the
// full peer is built:
//   1. AAPCS64 call into libentitycore_codec (args in x0/x1/x2, ret in w0, 16-byte SP
//      alignment at the `bl`).
//   2. Dynamic link + load of the CROSS-BUILT aarch64 libentitycore_codec.so.
//   3. Raw Linux syscall (write, #64 on the generic table) — the transport substrate mechanic.
//
// Test: ec_sha256("abc") must equal the RFC 6234 KAT
//   ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad
// byte-for-byte. Exit 0 + PASS line on match; exit 1 + FAIL line otherwise.
//
// GAS aarch64 (native ARM syntax). Entry is `main` (cc-driver startup; libc initialized).

.set SYS_write, 64                  // generic table (asm-generic/unistd.h), not x86-64's 1

.section .rodata
input:
    .ascii "abc"
    .set input_len, . - input
expected:                           // SHA-256("abc"), the KAT digest, 32 bytes
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
.lcomm digest, 32                   // ec_sha256 output buffer

.text
.global main
.type main, %function
main:
    stp x29, x30, [sp, #-16]!       // SP now 16-aligned → calls are ABI-legal
    mov x29, sp

    // ec_sha256(input, input_len, digest) — x0,x1,x2; status in w0
    adrp x0, input
    add  x0, x0, :lo12:input
    mov  x1, #input_len
    adrp x2, digest
    add  x2, x2, :lo12:digest
    bl   ec_sha256
    cbnz w0, .Lfail                 // EC_OK == 0; anything else fails

    // byte-compare digest[0..32) against the KAT
    adrp x1, digest
    add  x1, x1, :lo12:digest
    adrp x0, expected
    add  x0, x0, :lo12:expected
    mov  x2, #32
.Lcmp:
    ldrb w3, [x0], #1
    ldrb w4, [x1], #1
    cmp  w3, w4
    b.ne .Lfail
    subs x2, x2, #1
    b.ne .Lcmp

    // PASS: raw write(1, pass_msg, pass_len) then return 0
    mov  x0, #1
    adrp x1, pass_msg
    add  x1, x1, :lo12:pass_msg
    mov  x2, #pass_len
    mov  x8, #SYS_write
    svc  #0
    mov  w0, #0
    ldp  x29, x30, [sp], #16
    ret

.Lfail:
    mov  x0, #1
    adrp x1, fail_msg
    add  x1, x1, :lo12:fail_msg
    mov  x2, #fail_len
    mov  x8, #SYS_write
    svc  #0
    mov  w0, #1
    ldp  x29, x30, [sp], #16
    ret

.section .note.GNU-stack,"",%progbits   // mark stack non-executable (hygiene)
