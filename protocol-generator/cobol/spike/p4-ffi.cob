>>SOURCE FORMAT FREE
*> ===================================================================
*> SPIKE PROBE 4 — C-ABI FFI ergonomics from GnuCOBOL.
*>
*> The COBOL peer is FFI-everything: no native COBOL CBOR or crypto, so
*> EVERY codec/crypto op crosses into libentitycore_codec over the C-ABI
*> (ffi-generator/c-abi/spec/). This probe exercises the exact calling
*> convention the whole peer will depend on, against a REAL codec symbol:
*>
*>   int32_t ec_sha256(const uint8_t *data, size_t len, uint8_t *out32);
*>
*> Under test:
*>   - CALL "ec_sha256" resolving to a symbol in a linked .so
*>     (cob_resolve -> dlsym(RTLD_DEFAULT) finds the linked library),
*>   - BY REFERENCE  for const uint8_t* / uint8_t* (pointer to buffer),
*>   - BY VALUE      for size_t (8-byte COMP-5 -> 64-bit C arg),
*>   - RETURNING into a 4-byte signed COMP-5 for the int32 status.
*>
*> Oracle: SHA256("abc") =
*>   ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
*> ===================================================================
identification division.
program-id. p4-ffi.

data division.
working-storage section.
01 in-data     pic x(3)  value "abc".
01 in-len      pic 9(18) comp-5 value 3.
01 digest.
   05 dg-byte  pic x occurs 32.
01 rc          pic s9(9) comp-5.

01 byte-cell.
   05 byte-char pic x.
01 byte-num redefines byte-cell pic 9(2) comp-x.

01 hex-out     pic x(64).
01 hp          pic 9(4) comp.
01 nib         pic 9(2).
01 hex-digits  pic x(16) value "0123456789abcdef".
01 i           pic 9(4) comp.
01 expected    pic x(64)
    value "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".

procedure division.
    call "ec_sha256" using
        by reference in-data
        by value     in-len
        by reference digest
        returning    rc
    end-call
    display "P4 ec_sha256 returned rc = " rc " (expect 0)"

    move 1 to hp
    perform varying i from 1 by 1 until i > 32
        move dg-byte(i) to byte-char
        divide byte-num by 16 giving nib
        move hex-digits(nib + 1:1) to hex-out(hp:1)
        add 1 to hp
        move function mod(byte-num 16) to nib
        move hex-digits(nib + 1:1) to hex-out(hp:1)
        add 1 to hp
    end-perform

    display "P4 digest   = " hex-out
    display "P4 expected = " expected

    if rc = 0 and hex-out = expected
        display "P4 RESULT: PASS (C-ABI FFI byte-exact from COBOL)"
    else
        display "P4 RESULT: FAIL"
    end-if
    stop run.
end program p4-ffi.
