>>SOURCE FORMAT FREE
*> entity-core-protocol-cobol — connect handshake self-test (in-process).
*> Simulates the validator's exact §4.1/§4.6 wire exchange against the connect
*> handler using a second identity (seed 0x22) as the client:
*>   1. hello  -> 200, system/protocol/connect/hello, 32-byte nonce.
*>   2. authenticate (signed proof over the auth entity hash, peer+sig included)
*>      -> 200, system/capability/grant, token present in result + included.
*>   3. negative: a tampered nonce on a fresh connection -> 401 invalid_nonce.
identification division.
program-id. connect-test.
data division.
working-storage section.
01 seed-self pic x(32).
01 seed-cli  pic x(32).
01 cli-pub   pic x(32).
01 cli-peerid pic x(128).
01 cli-peerid-len pic 9(9) comp-5.
01 cli-pent  pic x(8192).
01 cli-pent-len pic 9(9) comp-5.
01 cli-idhash pic x(33).
01 one       pic 9(9) comp-5 value 1.
01 n1        pic 9(18) comp-5 value 1.
01 n2        pic 9(18) comp-5 value 2.
01 n3        pic 9(18) comp-5 value 3.
01 n4        pic 9(18) comp-5 value 4.
01 n7        pic 9(18) comp-5 value 7.
01 n8        pic 9(18) comp-5 value 8.
01 n23       pic 9(18) comp-5 value 23.
01 n32       pic 9(9) comp-5 value 32.
01 n33       pic 9(9) comp-5 value 33.
*> field-key constants
01 k-rid     pic x(10) value "request_id".
01 k-uri     pic x(3)  value "uri".
01 k-op      pic x(9)  value "operation".
01 k-params  pic x(6)  value "params".
01 k-pid     pic x(7)  value "peer_id".
01 k-pk      pic x(10) value "public_key".
01 k-kt      pic x(8)  value "key_type".
01 k-nonce   pic x(5)  value "nonce".
01 k-result  pic x(6)  value "result".
01 k-status  pic x(6)  value "status".
01 k-token   pic x(5)  value "token".
01 v-uri     pic x(23) value "system/protocol/connect".
01 v-ed      pic x(7)  value "ed25519".
01 t-any     pic x(13) value "primitive/any".
01 t-any-len pic 9(9) comp-5 value 13.
01 t-auth    pic x(36) value "system/protocol/connect/authenticate".
01 t-auth-len pic 9(9) comp-5 value 36.
01 t-exec    pic x(23) value "system/protocol/execute".
01 t-exec-len pic 9(9) comp-5 value 23.
*> buffers
01 pent-buf  pic x(8192).
01 pent-len  pic 9(9) comp-5.
01 phash     pic x(33).
01 exec-ent  pic x(8192).
01 exec-len  pic 9(9) comp-5.
01 exec-hash pic x(33).
01 nd        pic x(8192).
01 nd-len    pic 9(9) comp-5.
01 incmap-c  pic x(16384).
01 incmap-c-len pic 9(9) comp-5.
01 env       pic x(65535).
01 env-len   pic 9(9) comp-5.
01 conn      pic x(256).
01 conn2     pic x(256).
01 resp      pic x(65535).
01 resp-len  pic 9(9) comp-5.
01 hasresp   pic 9(1).
01 rroot     pic 9(9) comp-5.
01 rfnd      pic 9(1).
01 voff      pic 9(9) comp-5.
01 vfnd      pic 9(1).
01 res-off   pic 9(9) comp-5.
01 rstatus   pic 9(18) comp-5.
01 rtype     pic x(64).
01 rtype-len pic 9(9) comp-5.
01 nonce     pic x(32).
01 nonce-len pic 9(9) comp-5.
01 auth-ent  pic x(8192).
01 auth-len  pic 9(9) comp-5.
01 auth-hash pic x(33).
01 sig-ent   pic x(8192).
01 sig-len   pic 9(9) comp-5.
01 sig-hash  pic x(33).
01 toff      pic 9(9) comp-5.
01 ttype     pic x(64).
01 ttype-len pic 9(9) comp-5.
01 t-tok     pic x(23) value "system/capability/token".
01 fails     pic 9(4) comp-5 value 0.
01 bst       pic s9(9) comp-5.
*> key-length constants
01 n3key     pic 9(9) comp-5 value 3.
01 n5key     pic 9(9) comp-5 value 5.
01 n6key     pic 9(9) comp-5 value 6.
01 n9key     pic 9(9) comp-5 value 9.
01 n10key    pic 9(9) comp-5 value 10.
01 n0c       pic 9(18) comp-5 value 0.
01 n2c       pic 9(18) comp-5 value 2.
*> per-message work vars
01 wk-op     pic x(32).
01 wk-op-len pic 9(9) comp-5.
01 wk-rid    pic x(32).
01 wk-rid-len pic 9(9) comp-5.
01 open-flag pic 9(1) comp-5 value 1.
01 conf-flag pic 9(1) comp-5 value 0.

procedure division.
    move all x"11" to seed-self
    move all x"22" to seed-cli
    *> peer under test: open grants
    call "ps-init" using seed-self open-flag conf-flag
    *> client identity
    call "ident-of-seed" using seed-cli cli-pub cli-peerid cli-peerid-len
        cli-pent cli-pent-len cli-idhash
    move all x"00" to conn
    move all x"00" to conn2

    *> ---------- 1. hello ----------
    *> params entity {peer_id: cli}
    move 0 to nd-len
    call "b-map"  using nd nd-len n1
    call "b-text" using nd nd-len k-pid n7
    call "b-text" using nd nd-len cli-peerid cli-peerid-len
    call "b-entity" using t-any t-any-len nd nd-len pent-buf pent-len phash bst
    perform build-exec-with-params
       *> uses op "hello", rid "connect-hello"
    move "hello" to wk-op  move 5 to wk-op-len
    move "connect-hello" to wk-rid  move 13 to wk-rid-len
    perform assemble-exec
    call "dispatch" using conn env env-len resp resp-len hasresp
    perform decode-resp
    if rstatus = 200
        display "PASS hello status 200"
    else
        display "FAIL hello status " rstatus  add 1 to fails
    end-if
    *> result type + nonce
    call "ent-field" using resp rroot k-result n6key voff vfnd
    move voff to res-off
    call "ent-type" using resp res-off rtype rtype-len
    if rtype-len = 29 and rtype(1:29) = "system/protocol/connect/hello"
        display "PASS hello result type"
    else
        display "FAIL hello result type " rtype(1:rtype-len)  add 1 to fails
    end-if
    call "ent-field" using resp res-off k-nonce n5key voff vfnd
    move 0 to nonce-len
    if vfnd = 1 then call "read-bytes" using resp voff nonce nonce-len end-if
    if nonce-len = 32
        display "PASS hello 32-byte nonce"
    else
        display "FAIL hello nonce len " nonce-len  add 1 to fails
    end-if

    *> ---------- 2. authenticate ----------
    *> auth entity {peer_id, public_key, key_type, nonce(echoed)}
    move 0 to nd-len
    call "b-map"  using nd nd-len n4
    call "b-text" using nd nd-len k-pid n7
    call "b-text" using nd nd-len cli-peerid cli-peerid-len
    call "b-text" using nd nd-len k-pk n10key
    call "b-bytes" using nd nd-len cli-pub one n32
    call "b-text" using nd nd-len k-kt n8
    call "b-text" using nd nd-len v-ed n7
    call "b-text" using nd nd-len k-nonce n5key
    call "b-bytes" using nd nd-len nonce one n32
    call "b-entity" using t-auth t-auth-len nd nd-len auth-ent auth-len auth-hash bst
    *> client signs the auth entity hash
    call "sign-entity" using seed-cli cli-idhash auth-hash
        sig-ent sig-len sig-hash
    *> exec with params = auth entity, included = {client peer, signature}
    move auth-ent to pent-buf  move auth-len to pent-len
    move "authenticate" to wk-op  move 12 to wk-op-len
    move "connect-authenticate" to wk-rid  move 20 to wk-rid-len
    perform assemble-exec-auth
    call "dispatch" using conn env env-len resp resp-len hasresp
    perform decode-resp
    if rstatus = 200
        display "PASS authenticate status 200"
    else
        display "FAIL authenticate status " rstatus  add 1 to fails
    end-if
    call "ent-field" using resp rroot k-result n6key voff vfnd
    move voff to res-off
    call "ent-type" using resp res-off rtype rtype-len
    if rtype-len = 23 and rtype(1:23) = "system/capability/grant"
        display "PASS grant result type"
    else
        display "FAIL grant result type " rtype(1:rtype-len)  add 1 to fails
    end-if
    call "ent-field" using resp res-off k-token n5key voff vfnd
    if vfnd = 1
        display "PASS token in grant result"
    else
        display "FAIL token missing in grant result"  add 1 to fails
    end-if

    *> ---------- 3. negative: tampered nonce on fresh connection ----------
    *> fresh hello on conn2
    move 0 to nd-len
    call "b-map"  using nd nd-len n1
    call "b-text" using nd nd-len k-pid n7
    call "b-text" using nd nd-len cli-peerid cli-peerid-len
    call "b-entity" using t-any t-any-len nd nd-len pent-buf pent-len phash bst
    move "hello" to wk-op  move 5 to wk-op-len
    move "h2" to wk-rid  move 2 to wk-rid-len
    perform assemble-exec
    call "dispatch" using conn2 env env-len resp resp-len hasresp
    perform decode-resp
    call "ent-field" using resp rroot k-result n6key voff vfnd
    move voff to res-off
    call "ent-field" using resp res-off k-nonce n5key voff vfnd
    call "read-bytes" using resp voff nonce nonce-len
    *> tamper the echoed nonce
    move x"FF" to nonce(1:1)
    move 0 to nd-len
    call "b-map"  using nd nd-len n4
    call "b-text" using nd nd-len k-pid n7
    call "b-text" using nd nd-len cli-peerid cli-peerid-len
    call "b-text" using nd nd-len k-pk n10key
    call "b-bytes" using nd nd-len cli-pub one n32
    call "b-text" using nd nd-len k-kt n8
    call "b-text" using nd nd-len v-ed n7
    call "b-text" using nd nd-len k-nonce n5key
    call "b-bytes" using nd nd-len nonce one n32
    call "b-entity" using t-auth t-auth-len nd nd-len auth-ent auth-len auth-hash bst
    call "sign-entity" using seed-cli cli-idhash auth-hash
        sig-ent sig-len sig-hash
    move auth-ent to pent-buf  move auth-len to pent-len
    move "authenticate" to wk-op  move 12 to wk-op-len
    move "a2" to wk-rid  move 2 to wk-rid-len
    perform assemble-exec-auth
    call "dispatch" using conn2 env env-len resp resp-len hasresp
    perform decode-resp
    if rstatus = 401
        display "PASS tampered nonce rejected (401)"
    else
        display "FAIL tampered nonce status " rstatus  add 1 to fails
    end-if

    if fails = 0
        display "connect-test RESULT: PASS"
        stop run returning 0
    else
        display "connect-test RESULT: FAIL (" fails ")"
        stop run returning 1
    end-if.

*> ---- helpers -------------------------------------------------------
assemble-exec.
    *> exec data {request_id, uri, operation, params}, included {}
    move 0 to nd-len
    call "b-map"  using nd nd-len n4
    call "b-text" using nd nd-len k-rid n10key
    call "b-text" using nd nd-len wk-rid wk-rid-len
    call "b-text" using nd nd-len k-uri n3key
    call "b-text" using nd nd-len v-uri n23
    call "b-text" using nd nd-len k-op n9key
    call "b-text" using nd nd-len wk-op wk-op-len
    call "b-text" using nd nd-len k-params n6key
    call "b-raw"  using nd nd-len pent-buf one pent-len
    call "b-entity" using t-exec t-exec-len nd nd-len exec-ent exec-len exec-hash bst
    move 0 to incmap-c-len
    call "b-map" using incmap-c incmap-c-len n0c
    call "env-wrap" using exec-ent exec-len incmap-c incmap-c-len env env-len.

assemble-exec-auth.
    move 0 to nd-len
    call "b-map"  using nd nd-len n4
    call "b-text" using nd nd-len k-rid n10key
    call "b-text" using nd nd-len wk-rid wk-rid-len
    call "b-text" using nd nd-len k-uri n3key
    call "b-text" using nd nd-len v-uri n23
    call "b-text" using nd nd-len k-op n9key
    call "b-text" using nd nd-len wk-op wk-op-len
    call "b-text" using nd nd-len k-params n6key
    call "b-raw"  using nd nd-len pent-buf one pent-len
    call "b-entity" using t-exec t-exec-len nd nd-len exec-ent exec-len exec-hash bst
    *> included { client peer, signature }
    move 0 to incmap-c-len
    call "b-map"   using incmap-c incmap-c-len n2c
    call "b-bytes" using incmap-c incmap-c-len cli-idhash one n33
    call "b-raw"   using incmap-c incmap-c-len cli-pent one cli-pent-len
    call "b-bytes" using incmap-c incmap-c-len sig-hash one n33
    call "b-raw"   using incmap-c incmap-c-len sig-ent one sig-len
    call "env-wrap" using exec-ent exec-len incmap-c incmap-c-len env env-len.

build-exec-with-params.
    continue.

decode-resp.
    call "env-root-off" using resp rroot rfnd
    call "ent-field" using resp rroot k-status n6key voff vfnd
    move 0 to rstatus
    if vfnd = 1 then call "read-uint" using resp voff rstatus end-if.

end program connect-test.
