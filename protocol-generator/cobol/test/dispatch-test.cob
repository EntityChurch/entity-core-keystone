>>SOURCE FORMAT FREE
*> entity-core-protocol-cobol — dispatch skeleton self-test (in-process).
*> Builds an EXECUTE envelope for an unknown handler, runs dispatch, and checks
*> the response is a 404 handler_not_found EXECUTE_RESPONSE with the request_id
*> echoed. Exercises the full build -> canon -> dispatch -> decode pipeline.
identification division.
program-id. dispatch-test.
data division.
working-storage section.
01 t-exec   pic x(23) value "system/protocol/execute".
01 t-exec-len pic 9(9) comp-5 value 23.
01 k-rid    pic x(10) value "request_id".
01 k-uri    pic x(3)  value "uri".
01 k-op     pic x(9)  value "operation".
01 v-rid    pic x(2)  value "r1".
01 v-uri    pic x(7)  value "foo/bar".
01 v-op     pic x(3)  value "get".
01 one      pic 9(9) comp-5 value 1.
01 n3       pic 9(18) comp-5 value 3.
01 n2       pic 9(9) comp-5 value 2.
01 n7       pic 9(9) comp-5 value 7.
01 n9       pic 9(9) comp-5 value 9.
01 n10      pic 9(9) comp-5 value 10.
01 nd       pic x(8192).
01 nd-len   pic 9(9) comp-5.
01 exec-ent pic x(8192).
01 exec-len pic 9(9) comp-5.
01 exec-hash pic x(33).
01 inc0     pic x(8).
01 inc0-len pic 9(9) comp-5.
01 env      pic x(65535).
01 env-len  pic 9(9) comp-5.
01 n0       pic 9(18) comp-5 value 0.
01 st       pic s9(9) comp-5.
01 conn     pic x(256).
01 resp     pic x(65535).
01 resp-len pic 9(9) comp-5.
01 hasresp  pic 9(1).
01 root-off pic 9(9) comp-5.
01 root-fnd pic 9(1).
01 voff     pic 9(9) comp-5.
01 vfnd     pic 9(1).
01 k-stat   pic x(6) value "status".
01 k-stat-len pic 9(9) comp-5 value 6.
01 rstatus   pic 9(18) comp-5.
01 got-rid  pic x(128).
01 got-rid-len pic 9(9) comp-5.
01 k-rid-len pic 9(9) comp-5 value 10.
01 fails    pic 9(4) comp-5 value 0.
procedure division.
    *> build EXECUTE data {request_id, uri, operation}
    move 0 to nd-len
    call "b-map"  using nd nd-len n3
    call "b-text" using nd nd-len k-rid n10
    call "b-text" using nd nd-len v-rid n2
    call "b-text" using nd nd-len k-uri n3
    call "b-text" using nd nd-len v-uri n7
    call "b-text" using nd nd-len k-op n9
    call "b-text" using nd nd-len v-op n3
    call "b-entity" using t-exec t-exec-len nd nd-len
        exec-ent exec-len exec-hash st
    *> envelope {root: exec, included: {}}
    move 0 to inc0-len
    call "b-map" using inc0 inc0-len n0
    call "env-wrap" using exec-ent exec-len inc0 inc0-len env env-len

    *> dispatch
    call "dispatch" using conn env env-len resp resp-len hasresp
    if hasresp not = 1
        display "FAIL no response for EXECUTE" add 1 to fails
    end-if

    *> decode response: rstatus = 404, request_id echoed
    call "env-root-off" using resp root-off root-fnd
    if root-fnd = 0
        display "FAIL response has no root" add 1 to fails
    else
        call "ent-field" using resp root-off k-stat k-stat-len voff vfnd
        if vfnd = 1
            call "read-uint" using resp voff rstatus
            if rstatus = 404
                display "PASS rstatus 404 handler_not_found"
            else
                display "FAIL rstatus = " rstatus add 1 to fails
            end-if
        else
            display "FAIL no rstatus field" add 1 to fails
        end-if
        call "ent-field" using resp root-off k-rid k-rid-len voff vfnd
        if vfnd = 1
            call "read-text" using resp voff got-rid got-rid-len
            if got-rid-len = 2 and got-rid(1:2) = "r1"
                display "PASS request_id echoed"
            else
                display "FAIL request_id = " got-rid(1:got-rid-len) add 1 to fails
            end-if
        else
            display "FAIL no request_id in response" add 1 to fails
        end-if
    end-if

    if fails = 0
        display "dispatch-test RESULT: PASS"
        stop run returning 0
    else
        display "dispatch-test RESULT: FAIL (" fails ")"
        stop run returning 1
    end-if.
end program dispatch-test.
