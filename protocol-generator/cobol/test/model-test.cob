>>SOURCE FORMAT FREE
*> Round-trip test for model.cob: encode entity {type:"test/v1", data:{value:42}},
*> confirm the embedded content_hash equals the corpus content_hash.2 vector
*> (0095fecc...), then decode it back and confirm type + data recovered + the
*> §1.8 hash-fidelity check passes.
identification division.
program-id. model-test.
data division.
working-storage section.
01 etype       pic x(7)  value "test/v1".
01 etype-len   pic 9(9) comp-5 value 7.
01 edata       pic x(16).
01 edata-len   pic 9(9) comp-5 value 9.
01 wire        pic x(512).
01 wire-len    pic 9(9) comp-5 value 0.
01 st          pic s9(9) comp-5.
01 exp-hash    pic x(33).
01 nfail       pic 9(4) value 0.

*> decode outputs
01 doff        pic 9(9) comp-5.
01 dt-off      pic 9(9) comp-5.
01 dt-len      pic 9(9) comp-5.
01 dd-off      pic 9(9) comp-5.
01 dd-len      pic 9(9) comp-5.

*> locate the embedded content_hash inside the encoded wire entity
01 voff        pic 9(9) comp-5.
01 found       pic 9(1).
01 scan        pic 9(9) comp-5.
01 rhmaj       pic 9(2) comp-5.
01 rhaddl      pic 9(2) comp-5.
01 rharg       pic 9(18) comp-5.
01 kn          pic x(32).
01 knl         pic 9(9) comp-5.
procedure division.
    move x"a16576616c7565182a" to edata    *> {"value": 42}
    move x"0095fecc27f633079ab9a4a7f97c740f617228f2eaae88b6958ae69b2ba73089eb"
      to exp-hash

    *> encode
    move 0 to wire-len
    call "entity-encode" using etype etype-len edata edata-len
                              wire wire-len st
    if st not = 0
        display "FAIL encode (status " st ")"  add 1 to nfail
    else
        display "PASS encode (wire-len " wire-len ")"
    end-if

    *> the embedded content_hash must equal the corpus vector
    move 1 to scan
    move "content_hash" to kn  move 12 to knl
    call "cbor-find-key" using wire scan kn knl voff found st
    move voff to scan
    call "cbor-read-head" using wire scan rhmaj rhaddl rharg st
    if rharg = 33 and wire(scan:33) = exp-hash(1:33)
        display "PASS content_hash matches corpus content_hash.2"
    else
        display "FAIL content_hash mismatch"  add 1 to nfail
    end-if

    *> decode + fidelity check
    move 1 to doff
    call "entity-decode" using wire doff dt-off dt-len dd-off dd-len st
    evaluate true
        when st not = 0
            display "FAIL decode (status " st ")"  add 1 to nfail
        when wire(dt-off:dt-len) not = etype(1:etype-len)
            display "FAIL decode type mismatch"  add 1 to nfail
        when dd-len not = edata-len
            display "FAIL decode data-len " dd-len " want " edata-len
            add 1 to nfail
        when wire(dd-off:dd-len) not = edata(1:edata-len)
            display "FAIL decode data bytes mismatch"  add 1 to nfail
        when other
            display "PASS decode (type + data recovered, fidelity ok)"
    end-evaluate

    if nfail = 0
        display "model-test RESULT: PASS"  move 0 to return-code
    else
        display "model-test RESULT: FAIL"  move 1 to return-code
    end-if
    stop run.
end program model-test.
