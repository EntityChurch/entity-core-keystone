>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — peer brain (§6.5 dispatch chain).
*>
*> One connection's request->response logic. dispatch parses the inbound envelope
*> (§3.1 {root, included}), routes the EXECUTE root (§3.3), and builds the response
*> envelope. Non-EXECUTE roots get no response (§3.3 server side ignores them).
*>
*> This file grows the brain incrementally; the substrate (codec/model/store/
*> identity/build) sits proven underneath. Helpers: env-wrap (build a response
*> envelope from a root entity + an included map), env-root-off / env-inc-off
*> (locate the root entity / included map in an inbound envelope buffer).
*> ===================================================================

*> ---- env-root-off : offset of the root entity in an envelope buffer
identification division.
program-id. env-root-off.
data division.
working-storage section.
01 kn  pic x(4) value "root".
01 knl pic 9(9) comp-5 value 4.
01 fnd pic 9(1).
01 st  pic s9(9) comp-5.
01 moff pic 9(9) comp-5 value 1.
linkage section.
01 lk-buf pic x(65535).
01 lk-off pic 9(9) comp-5.
01 lk-found pic 9(1).
procedure division using lk-buf lk-off lk-found.
    call "cbor-find-key" using lk-buf moff kn knl lk-off lk-found st
    goback.
end program env-root-off.

*> ---- env-inc-off : offset of the included map (0/absent -> found=0)
identification division.
program-id. env-inc-off.
data division.
working-storage section.
01 kn  pic x(8) value "included".
01 knl pic 9(9) comp-5 value 8.
01 st  pic s9(9) comp-5.
01 moff pic 9(9) comp-5 value 1.
linkage section.
01 lk-buf pic x(65535).
01 lk-off pic 9(9) comp-5.
01 lk-found pic 9(1).
procedure division using lk-buf lk-off lk-found.
    call "cbor-find-key" using lk-buf moff kn knl lk-off lk-found st
    goback.
end program env-inc-off.

*> ---- env-wrap : {root, included} envelope, canonicalized -----------
*> LK-ROOT(1:LK-ROOT-LEN) is a wire entity; LK-INC(1:LK-INC-LEN) is an already-
*> built CBOR map value (use map(0) 0xA0 for none). Output canonical frame payload.
identification division.
program-id. env-wrap.
data division.
working-storage section.
01 k-root pic x(4) value "root".
01 k-inc  pic x(8) value "included".
01 one    pic 9(9) comp-5 value 1.
01 n2     pic 9(18) comp-5 value 2.
01 n4     pic 9(9) comp-5 value 4.
01 n8     pic 9(9) comp-5 value 8.
01 nbuf   pic x(65535).
01 nlen   pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
linkage section.
01 lk-root pic x(65535).
01 lk-root-len pic 9(9) comp-5.
01 lk-inc pic x(65535).
01 lk-inc-len pic 9(9) comp-5.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
procedure division using lk-root lk-root-len lk-inc lk-inc-len lk-out lk-out-len.
    move 0 to nlen
    call "b-map"  using nbuf nlen n2
    call "b-text" using nbuf nlen k-root n4
    call "b-raw"  using nbuf nlen lk-root one lk-root-len
    call "b-text" using nbuf nlen k-inc n8
    call "b-raw"  using nbuf nlen lk-inc one lk-inc-len
    call "b-canon" using nbuf nlen lk-out lk-out-len st
    goback.
end program env-wrap.

*> ---- dispatch (§6.5 chain) -----------------------------------------
*> Parse the inbound envelope, route the EXECUTE root through the §6.5 chain
*> (ingest → verify_request → resolve_handler → check_permission → handler),
*> build the response frame into LK-OUT. LK-HASRESP=0 => no response (§3.3).
identification division.
program-id. dispatch.
data division.
working-storage section.
01 root-off  pic 9(9) comp-5.
01 root-fnd  pic 9(1).
01 inc-off   pic 9(9) comp-5.
01 inc-fnd   pic 9(1).
01 rtype     pic x(64).
01 rtype-len pic 9(9) comp-5.
01 t-exec    pic x(23) value "system/protocol/execute".
01 voff      pic 9(9) comp-5.
01 vfnd      pic 9(1).
01 f         pic 9(1).
01 rid       pic x(128).
01 rid-len   pic 9(9) comp-5.
01 uri       pic x(900).
01 uri-len   pic 9(9) comp-5.
01 nuri      pic x(900).
01 nuri-len  pic 9(9) comp-5.
01 t-connect pic x(23) value "system/protocol/connect".
01 k-rid     pic x(10) value "request_id".
01 k-rid-len pic 9(9) comp-5 value 10.
01 k-uri     pic x(3)  value "uri".
01 k-uri-len pic 9(9) comp-5 value 3.
01 k-cap     pic x(10) value "capability".
01 k-cap-len pic 9(9) comp-5 value 10.
01 verdict   pic 9(1).
01 local     pic x(128).
01 locallen  pic 9(9) comp-5.
01 path      pic x(900).
01 pathlen   pic 9(9) comp-5.
01 tp        pic x(128).
01 tplen     pic 9(9) comp-5.
01 pat       pic x(900).
01 patlen    pic 9(9) comp-5.
01 hfound    pic 9(1).
01 caph      pic x(33).
01 cl        pic 9(9) comp-5.
01 capbuf    pic x(8192).
01 caplen    pic 9(9) comp-5.
01 capfnd    pic 9(1).
01 granter   pic x(128).
01 granterlen pic 9(9) comp-5.
01 perm      pic 9(1).
01 spat      pic x(900).
01 splen     pic 9(9) comp-5.
01 pfx       pic 9(9) comp-5.
01 rstatus    pic 9(9) comp-5.
01 errcode      pic x(64).
01 errcode-len  pic 9(9) comp-5.
01 res-ent   pic x(60000).
01 res-len   pic 9(9) comp-5.
01 res-hash  pic x(33).
01 resp-ent  pic x(65535).
01 resp-len  pic 9(9) comp-5.
01 resp-hash pic x(33).
01 incmap    pic x(16384).
01 incmap-len pic 9(9) comp-5.
01 n0        pic 9(18) comp-5 value 0.
linkage section.
01 lk-conn   pic x(256).
01 lk-env    pic x(65535).
01 lk-env-len pic 9(9) comp-5.
01 lk-out    pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-hasresp pic 9(1).
procedure division using lk-conn lk-env lk-env-len lk-out lk-out-len lk-hasresp.
    move 0 to lk-hasresp
    move 0 to lk-out-len
    call "env-root-off" using lk-env root-off root-fnd
    if root-fnd = 0 then goback end-if
    call "ent-type" using lk-env root-off rtype rtype-len
    if not (rtype-len = 23 and rtype(1:23) = t-exec) then
        goback
    end-if
    move 1 to lk-hasresp
    move spaces to rid  move 0 to rid-len
    call "ent-field" using lk-env root-off k-rid k-rid-len voff vfnd
    if vfnd = 1 then call "read-text" using lk-env voff rid rid-len end-if
    move spaces to uri  move 0 to uri-len
    call "ent-field" using lk-env root-off k-uri k-uri-len voff vfnd
    if vfnd = 1 then call "read-text" using lk-env voff uri uri-len end-if
    call "env-inc-off" using lk-env inc-off inc-fnd
    call "ps-peerid" using local locallen

    move 0 to incmap-len
    call "b-map" using incmap incmap-len n0

    if uri-len = 23 and uri(1:23) = t-connect
        call "connect-handler" using lk-conn lk-env root-off inc-off inc-fnd
            rstatus res-ent res-len res-hash incmap incmap-len
    else
        perform do-chain
    end-if

    call "make-response" using rid rid-len rstatus res-ent res-len
        resp-ent resp-len resp-hash
    call "env-wrap" using resp-ent resp-len incmap incmap-len
        lk-out lk-out-len
    goback.

*> ---- §6.5 dispatch chain -------------------------------------------
do-chain.
    call "ingest-signatures" using lk-env inc-off inc-fnd
    call "verify-request" using lk-env root-off inc-off inc-fnd verdict
    evaluate verdict
        when 1
            move 401 to rstatus
            move "authentication_failed" to errcode move 21 to errcode-len
            call "error-result" using errcode errcode-len res-ent res-len res-hash
            exit paragraph
        when 4
            move 401 to rstatus
            move "unresolvable_grantee" to errcode move 20 to errcode-len
            call "error-result" using errcode errcode-len res-ent res-len res-hash
            exit paragraph
        when 2
            move 403 to rstatus
            move "capability_denied" to errcode move 17 to errcode-len
            call "error-result" using errcode errcode-len res-ent res-len res-hash
            exit paragraph
        when 3
            move 400 to rstatus
            move "chain_depth_exceeded" to errcode move 20 to errcode-len
            call "error-result" using errcode errcode-len res-ent res-len res-hash
            exit paragraph
    end-evaluate
    *> verdict 0 = allow. normalize + canonicalize uri -> path
    if uri-len >= 9 and uri(1:9) = "entity://"
        move "/" to nuri(1:1)
        compute nuri-len = uri-len - 9
        if nuri-len > 0 then move uri(10:nuri-len) to nuri(2:nuri-len) end-if
        compute nuri-len = nuri-len + 1
    else
        move uri(1:uri-len) to nuri(1:uri-len)
        move uri-len to nuri-len
    end-if
    call "cap-canon" using nuri nuri-len local locallen path pathlen
    *> §1.4 inbound must target the local peer
    call "cap-extract-peer" using path pathlen local locallen tp tplen
    if not (tplen = locallen and tp(1:tplen) = local(1:locallen))
        perform resp-404  exit paragraph
    end-if
    call "resolve-handler" using path pathlen pat patlen hfound
    if hfound = 0 then perform resp-404  exit paragraph end-if
    *> resolve caller capability
    call "ent-field" using lk-env root-off k-cap k-cap-len voff f
    if f = 0 then perform resp-403  exit paragraph end-if
    call "read-bytes" using lk-env voff caph cl
    call "cap-resolve" using lk-env inc-off inc-fnd caph capbuf caplen capfnd
    if capfnd = 0 then perform resp-403  exit paragraph end-if
    *> §PR-8 granter frame
    call "cap-granter-peer" using lk-env inc-off inc-fnd capbuf granter granterlen
    *> §5.2 check_permission
    call "cap-check-perm" using lk-env root-off capbuf pat patlen
        granter granterlen perm
    if perm = 0 then perform resp-403  exit paragraph end-if
    *> route by stripped pattern
    compute pfx = locallen + 2
    compute splen = patlen - pfx
    if splen > 0 then move pat(pfx + 1:splen) to spat(1:splen) end-if
    evaluate true
        when splen = 11 and spat(1:11) = "system/tree"
            call "tree-handler" using lk-env root-off rstatus
                res-ent res-len res-hash
        when splen = 17 and spat(1:17) = "system/capability"
            call "capability-handler" using lk-env root-off rstatus
                res-ent res-len res-hash incmap incmap-len
        when splen = 14 and spat(1:14) = "system/handler"
            call "handlers-handler" using lk-env root-off rstatus
                res-ent res-len res-hash
        when splen = 11 and spat(1:11) = "system/type"
            call "types-handler" using lk-env root-off rstatus
                res-ent res-len res-hash
        when splen = 20 and spat(1:20) = "system/validate/echo"
            call "echo-handler" using lk-env root-off rstatus
                res-ent res-len res-hash
        when splen = 33 and spat(1:33) = "system/validate/dispatch-outbound"
            call "dispatch-outbound-handler" using lk-env root-off rstatus
                res-ent res-len res-hash
        when other
            perform resp-404
    end-evaluate.

resp-404.
    move 404 to rstatus
    move "handler_not_found" to errcode move 17 to errcode-len
    call "error-result" using errcode errcode-len res-ent res-len res-hash.

resp-403.
    move 403 to rstatus
    move "capability_denied" to errcode move 17 to errcode-len
    call "error-result" using errcode errcode-len res-ent res-len res-hash.
end program dispatch.
