>>SOURCE FORMAT FREE
*> Unit tests for the CBOR canonical transcoder (cbor.cob), exercising the
*> logic the canonical corpus can't (non-minimal -> minimal; unsorted -> sorted)
*> plus identity + reject paths. Hardcoded inputs, self-checking.
identification division.
program-id. cbor-unit.
data division.
working-storage section.
01 in-buf       pic x(256).
01 in-off       pic 9(9) comp-5.
01 out-buf      pic x(256).
01 out-len      pic 9(9) comp-5.
01 st       pic s9(9) comp-5.
01 exp-buf      pic x(256).
01 exp-len      pic 9(9) comp-5.
01 npass        pic 9(4) value 0.
01 nfail        pic 9(4) value 0.
01 tname        pic x(32).
procedure division.
    *> 1: minimal int identity (24 -> 0x1818)
    move x"1818" to in-buf
    move x"1818" to exp-buf  move 2 to exp-len
    move "int-minimal-identity" to tname
    perform run-canon

    *> 2: non-minimal head re-derived to minimal (uint 24 as 2-byte -> 1-byte)
    move x"190018" to in-buf
    move x"1818" to exp-buf  move 2 to exp-len
    move "int-minimization" to tname
    perform run-canon

    *> 3: map key canonical sort ({"b":1,"a":1} -> {"a":1,"b":1})
    move x"a2616201616101" to in-buf
    move x"a2616101616201" to exp-buf  move 7 to exp-len
    move "map-key-sort" to tname
    perform run-canon

    *> 4: map sort by length-first ('z' before 'aa')  {"aa":2,"z":1}->{"z":1,"aa":2}
    move x"a262616102617a01" to in-buf
    move x"a2617a0162616102" to exp-buf  move 8 to exp-len
    move "map-len-then-lex" to tname
    perform run-canon

    *> 5: nested identity (two-level map)
    move x"a1656f75746572a165696e6e657201" to in-buf
    move x"a1656f75746572a165696e6e657201" to exp-buf  move 15 to exp-len
    move "nested-identity" to tname
    perform run-canon

    *> 6: float16 passthrough (1.0 = 0xf93c00)
    move x"f93c00" to in-buf
    move x"f93c00" to exp-buf  move 3 to exp-len
    move "float16-passthrough" to tname
    perform run-canon

    *> 7: tag reject (tag 0 wrapping text -> st 3)
    move x"c0613161" to in-buf
    move "tag-reject" to tname
    perform run-reject

    *> 8: bytes passthrough (h'00112233' -> identity)
    move x"4400112233" to in-buf
    move x"4400112233" to exp-buf  move 5 to exp-len
    move "bytes-identity" to tname
    perform run-canon

    display " "
    display "cbor-unit: " npass " passed, " nfail " failed"
    if nfail = 0
        display "cbor-unit RESULT: PASS"
        move 0 to return-code
    else
        display "cbor-unit RESULT: FAIL"
        move 1 to return-code
    end-if
    stop run.

run-canon.
    move 1 to in-off
    move 0 to out-len
    move 0 to st
    call "cbor-canon" using in-buf in-off out-buf out-len st
    evaluate true
        when st not = 0
            display "FAIL " tname " (st=" st ")"
            add 1 to nfail
        when out-len not = exp-len
            display "FAIL " tname " (len got=" out-len " want=" exp-len ")"
            add 1 to nfail
        when out-buf(1:out-len) not = exp-buf(1:exp-len)
            display "FAIL " tname " (bytes differ)"
            add 1 to nfail
        when other
            display "PASS " tname
            add 1 to npass
    end-evaluate.

run-reject.
    move 1 to in-off
    move 0 to out-len
    move 0 to st
    call "cbor-canon" using in-buf in-off out-buf out-len st
    if st = 3
        display "PASS " tname " (rejected)"
        add 1 to npass
    else
        display "FAIL " tname " (st=" st " not rejected)"
        add 1 to nfail
    end-if.
end program cbor-unit.
