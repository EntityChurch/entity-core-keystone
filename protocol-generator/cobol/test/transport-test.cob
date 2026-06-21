>>SOURCE FORMAT FREE
*> Transport round-trip over a real socket (socketpair): build an envelope whose
*> root is an entity {type:"test/v1", data:{value:42}}, write it as a length-
*> prefixed frame on fd0, read it back on fd1, decode the envelope -> root entity,
*> and confirm type + data + §1.8 hash fidelity survive the wire. Proves
*> netshim.c + wire.cob (framing) + model.cob (entity/envelope) end-to-end.
identification division.
program-id. transport-test.
data division.
working-storage section.
01 fds.
   05 fd0  pic s9(9) comp-5.
   05 fd1  pic s9(9) comp-5.
01 rc          pic s9(9) comp-5.
01 etype       pic x(7)  value "test/v1".
01 edata       pic x(16).
01 ent         pic x(512).
01 ent-len     pic 9(9) comp-5 value 0.
01 emptymap    pic x(1)  value x"a0".
01 env         pic x(1024).
01 env-len     pic 9(9) comp-5 value 0.
01 st          pic s9(9) comp-5.

01 rbuf        pic x(1024).
01 rlen        pic 9(9) comp-5.
01 roff        pic 9(9) comp-5.
01 voff        pic 9(9) comp-5.
01 found       pic 9(1).
01 kn          pic x(32).
01 knl         pic 9(9) comp-5.
01 root-off    pic 9(9) comp-5.
01 dt-off pic 9(9) comp-5.  01 dt-len pic 9(9) comp-5.
01 dd-off pic 9(9) comp-5.  01 dd-len pic 9(9) comp-5.
01 nfail       pic 9(4) value 0.
procedure division.
    move x"a16576616c7565182a" to edata        *> {"value":42}

    *> socketpair
    call "ec_socketpair" using by reference fds returning rc
    if rc not = 0
        display "FAIL socketpair"  move 1 to return-code  stop run
    end-if

    *> build entity, then envelope {root:entity, included:{}}
    move 0 to ent-len
    call "entity-encode" using etype 7 edata 9 ent ent-len st
    move 0 to env-len
    call "envelope-encode" using ent ent-len emptymap 1 env env-len

    *> write frame on fd0, read on fd1
    call "write-frame" using fd0 env env-len st
    if st not = 0 then display "FAIL write-frame"  add 1 to nfail end-if
    call "read-frame" using fd1 rbuf 1024 rlen st
    if st not = 0
        display "FAIL read-frame (status " st ")"  add 1 to nfail
    else
        display "PASS frame round-trip (" rlen " bytes)"
    end-if

    *> the read payload must equal what we sent
    if rlen = env-len and rbuf(1:rlen) = env(1:env-len)
        display "PASS framed envelope bytes identical"
    else
        display "FAIL framed bytes differ"  add 1 to nfail
    end-if

    *> decode envelope -> find root -> decode entity -> verify
    move 1 to roff
    move "root" to kn  move 4 to knl
    call "cbor-find-key" using rbuf roff kn knl voff found st
    if found = 0
        display "FAIL no root in envelope"  add 1 to nfail
    else
        move voff to root-off
        call "entity-decode" using rbuf root-off dt-off dt-len dd-off dd-len st
        evaluate true
            when st not = 0
                display "FAIL root entity decode (status " st ")"  add 1 to nfail
            when rbuf(dt-off:dt-len) not = etype(1:7)
                display "FAIL root type mismatch"  add 1 to nfail
            when other
                display "PASS root entity recovered + fidelity ok"
        end-evaluate
    end-if

    call "ec_fd_close" using by value fd0 returning rc
    call "ec_fd_close" using by value fd1 returning rc

    if nfail = 0
        display "transport-test RESULT: PASS"  move 0 to return-code
    else
        display "transport-test RESULT: FAIL"  move 1 to return-code
    end-if
    stop run.
end program transport-test.
