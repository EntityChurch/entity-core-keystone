>>SOURCE FORMAT FREE
*> ===================================================================
*> SPIKE PROBE 2 — Variable-length byte buffers vs PIC fixed-width.
*>
*> CBOR is a variable-length byte stream. COBOL records are fixed PIC
*> width. Question: can we carry a growable byte vector idiomatically,
*> index/slice it, and read a byte's NUMERIC value (needed to parse a
*> CBOR initial byte = major-type<<5 | additional-info)?
*>
*> Technique under test:
*>   - a max-size PIC X(N) buffer + an explicit used-length counter
*>     (the COBOL idiom for a growable buffer),
*>   - reference modification BUF(offset:len) for slicing/appending,
*>   - REDEFINES over PIC X with COMP-X (unsigned binary) to read a
*>     byte as a 0..255 number, then / 32 and MOD 32 to split the
*>     CBOR major type from the additional info (no native bit ops).
*> ===================================================================
identification division.
program-id. p2-varlen.

data division.
working-storage section.
01 cbor-buf        pic x(256).
01 buf-used        pic 9(4) comp value 0.

*> one-byte numeric view (COMP-X = unsigned binary; 9(2)->1 byte, 9(3)->2 bytes,
*> so a SINGLE byte must be 9(2) COMP-X or the redefine reads past the cell)
01 byte-cell.
   05 byte-char    pic x.
01 byte-num redefines byte-cell pic 9(2) comp-x.

01 major-type      pic 9(2).
01 addl-info       pic 9(2).
01 i               pic 9(4) comp.
01 hex-out         pic x(64).
01 hp              pic 9(4) comp.
01 nib             pic 9(2).
01 hex-digits      pic x(16) value "0123456789abcdef".

procedure division.
*> --- build a small CBOR sequence by appending into the buffer ---
*>   0x83        = array(3)            major 4, addl 3
*>   0x01        = uint 1
*>   0x18 0x2a   = uint 42 (1-byte follow)
*>   0x63 61 62 63 = text(3) "abc"
    move 0 to buf-used

    *> append using reference modification at the used offset
    call 'PUTB' using cbor-buf buf-used x"83"
    call 'PUTB' using cbor-buf buf-used x"01"
    call 'PUTB' using cbor-buf buf-used x"18"
    call 'PUTB' using cbor-buf buf-used x"2a"
    call 'PUTB' using cbor-buf buf-used x"63"
    call 'PUTB' using cbor-buf buf-used x"61"
    call 'PUTB' using cbor-buf buf-used x"62"
    call 'PUTB' using cbor-buf buf-used x"63"

    display "P2 built buffer used-length = " buf-used " (expected 0008)"

    *> hex-dump the variable slice
    move 1 to hp
    perform varying i from 1 by 1 until i > buf-used
        move cbor-buf(i:1) to byte-char
        divide byte-num by 16 giving nib
        move hex-digits(nib + 1:1) to hex-out(hp:1)
        add 1 to hp
        move function mod(byte-num 16) to nib
        move hex-digits(nib + 1:1) to hex-out(hp:1)
        add 1 to hp
    end-perform
    display "P2 buffer hex = " hex-out(1:hp - 1) " (expected 830118 2a636162 63)"

    *> --- parse the CBOR initial byte (first byte) ---
    move cbor-buf(1:1) to byte-char
    divide byte-num by 32 giving major-type
    move function mod(byte-num 32) to addl-info
    display "P2 initial byte 0x83 -> major-type=" major-type
            " addl-info=" addl-info " (expected major=04 addl=03)"

    if buf-used = 8 and major-type = 4 and addl-info = 3
        display "P2 RESULT: PASS (growable buffer + byte-numeric parse work)"
    else
        display "P2 RESULT: FAIL"
    end-if
    stop run.
end program p2-varlen.

*> ---- PUTB: append a single byte at offset (1-based used counter) ----
identification division.
program-id. PUTB.
data division.
linkage section.
01 lk-buf   pic x(256).
01 lk-used  pic 9(4) comp.
01 lk-byte  pic x.
procedure division using lk-buf lk-used lk-byte.
    add 1 to lk-used
    move lk-byte to lk-buf(lk-used:1)
    goback.
end program PUTB.
