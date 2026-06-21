>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — message builders (§3.2/§3.3).
*>
*> EXECUTE_RESPONSE (§3.3) carries {request_id, status, result} where result is a
*> nested wire entity. error_result (§3.3) is system/protocol/error {code,...}.
*> empty_params (§3.2) is primitive/any with the empty map. All produce a wire
*> entity (canonical {data,type,content_hash}) + its 33-byte hash via b-entity.
*>
*> Sub-programs: error-result, make-response, empty-params, hash-entity (a
*> primitive/any wrapper holding {hash: bytes} for the tree get mode=hash path).
*> ===================================================================

*> ---- error-result --------------------------------------------------
identification division.
program-id. error-result.
data division.
working-storage section.
01 t-err  pic x(21) value "system/protocol/error".
01 t-err-len pic 9(9) comp-5 value 21.
01 k-code pic x(4) value "code".
01 n1     pic 9(18) comp-5 value 1.
01 n4     pic 9(9) comp-5 value 4.
01 nd     pic x(8192).
01 nd-len pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
linkage section.
01 lk-code pic x(128).
01 lk-code-len pic 9(9) comp-5.
01 lk-out pic x(8192).
01 lk-out-len pic 9(9) comp-5.
01 lk-hash pic x(33).
procedure division using lk-code lk-code-len lk-out lk-out-len lk-hash.
    move 0 to nd-len
    call "b-map"  using nd nd-len n1
    call "b-text" using nd nd-len k-code n4
    call "b-text" using nd nd-len lk-code lk-code-len
    call "b-entity" using t-err t-err-len nd nd-len
        lk-out lk-out-len lk-hash st
    goback.
end program error-result.

*> ---- make-response -------------------------------------------------
*> {request_id, status, result} where result is a raw nested wire entity.
identification division.
program-id. make-response.
data division.
working-storage section.
01 t-resp pic x(32) value "system/protocol/execute/response".
01 t-resp-len pic 9(9) comp-5 value 32.
01 k-rid  pic x(10) value "request_id".
01 k-stat pic x(6)  value "status".
01 k-res  pic x(6)  value "result".
01 one    pic 9(9) comp-5 value 1.
01 n3     pic 9(18) comp-5 value 3.
01 n6     pic 9(9) comp-5 value 6.
01 n10    pic 9(9) comp-5 value 10.
01 ws-status pic 9(18) comp-5.
01 nd     pic x(65535).
01 nd-len pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
linkage section.
01 lk-rid pic x(128).
01 lk-rid-len pic 9(9) comp-5.
01 lk-stat pic 9(9) comp-5.
01 lk-result pic x(60000).
01 lk-result-len pic 9(9) comp-5.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-hash pic x(33).
procedure division using lk-rid lk-rid-len lk-stat lk-result lk-result-len
                        lk-out lk-out-len lk-hash.
    move lk-stat to ws-status
    move 0 to nd-len
    call "b-map"  using nd nd-len n3
    call "b-text" using nd nd-len k-rid n10
    call "b-text" using nd nd-len lk-rid lk-rid-len
    call "b-text" using nd nd-len k-stat n6
    call "b-uint" using nd nd-len ws-status
    call "b-text" using nd nd-len k-res n6
    call "b-raw"  using nd nd-len lk-result one lk-result-len
    call "b-entity" using t-resp t-resp-len nd nd-len
        lk-out lk-out-len lk-hash st
    goback.
end program make-response.

*> ---- empty-params --------------------------------------------------
identification division.
program-id. empty-params.
data division.
working-storage section.
01 t-any  pic x(13) value "primitive/any".
01 t-any-len pic 9(9) comp-5 value 13.
01 n0     pic 9(18) comp-5 value 0.
01 nd     pic x(64).
01 nd-len pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
linkage section.
01 lk-out pic x(8192).
01 lk-out-len pic 9(9) comp-5.
01 lk-hash pic x(33).
procedure division using lk-out lk-out-len lk-hash.
    move 0 to nd-len
    call "b-map" using nd nd-len n0
    call "b-entity" using t-any t-any-len nd nd-len
        lk-out lk-out-len lk-hash st
    goback.
end program empty-params.
