>>SOURCE FORMAT FREE
*> entity-core-protocol-cobol — identity layer self-test.
*> Verifies: (1) §1.5 Ed25519 peer_id derivation byte-matches the cohort
*> reference for the default seed (0x11 x 32); (2) FFI sign/verify round-trip
*> (good signature accepts, tampered message rejects).
identification division.
program-id. ident-test.
data division.
working-storage section.
01 seed        pic x(32).
01 pub         pic x(32).
01 peerid      pic x(128).
01 peerid-len  pic 9(9) comp-5.
01 pent        pic x(8192).
01 pent-len    pic 9(9) comp-5.
01 idhash      pic x(33).
01 expected    pic x(46) value
   "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg".
01 sigbuf      pic x(64).
01 msg33       pic x(33).
01 msglen      pic 9(18) comp-5 value 33.
01 ok          pic 9(1).
01 rc          pic s9(9) comp-5.
01 fails       pic 9(4) comp-5 value 0.
procedure division.
    move all x"11" to seed
    call "ident-of-seed" using seed pub peerid peerid-len
        pent pent-len idhash

    if peerid-len = 46 and peerid(1:46) = expected
        display "PASS peer_id = " expected
    else
        display "FAIL peer_id (len " peerid-len "): " peerid(1:peerid-len)
        add 1 to fails
    end-if

    *> sign/verify round-trip over a 33-byte message
    move all x"42" to msg33
    call "ec_ed25519_sign" using
        by reference seed by reference msg33 by value msglen
        by reference sigbuf returning rc
    call "verify-sig" using pub msg33 sigbuf ok
    if ok = 1
        display "PASS sign/verify accepts a valid signature"
    else
        display "FAIL sign/verify rejected a valid signature"
        add 1 to fails
    end-if

    *> tamper the message -> must reject
    move x"43" to msg33(1:1)
    call "verify-sig" using pub msg33 sigbuf ok
    if ok = 0
        display "PASS sign/verify rejects a tampered message"
    else
        display "FAIL sign/verify accepted a tampered message"
        add 1 to fails
    end-if

    if fails = 0
        display "ident-test RESULT: PASS"
        stop run returning 0
    else
        display "ident-test RESULT: FAIL (" fails ")"
        stop run returning 1
    end-if.
end program ident-test.
