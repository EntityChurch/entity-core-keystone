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
01 lk-buf pic x(524288).
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
01 lk-buf pic x(524288).
01 lk-off pic 9(9) comp-5.
01 lk-found pic 9(1).
procedure division using lk-buf lk-off lk-found.
    call "cbor-find-key" using lk-buf moff kn knl lk-off lk-found st
    goback.
end program env-inc-off.

*> ---- env-kind : classify an envelope root (§6.11 reentry pump) ------
*> LK-KIND: 2 = EXECUTE_RESPONSE, 1 = EXECUTE, 0 = other. Called by the C
*> reentry pump (ec_reentry) to recognize the awaited reply on the wire.
identification division.
program-id. env-kind.
data division.
working-storage section.
01 root-off  pic 9(9) comp-5.
01 root-fnd  pic 9(1).
01 rtype     pic x(64).
01 rtype-len pic 9(9) comp-5.
01 t-exec    pic x(23) value "system/protocol/execute".
01 t-resp    pic x(32) value "system/protocol/execute/response".
linkage section.
01 lk-buf  pic x(524288).
01 lk-len  pic 9(9) comp-5.
01 lk-kind pic 9(9) comp-5.
procedure division using lk-buf lk-len lk-kind.
    move 0 to lk-kind
    call "env-root-off" using lk-buf root-off root-fnd
    if root-fnd = 0 then goback end-if
    call "ent-type" using lk-buf root-off rtype rtype-len
    evaluate true
        when rtype-len = 32 and rtype(1:32) = t-resp
            move 2 to lk-kind
        when rtype-len = 23 and rtype(1:23) = t-exec
            move 1 to lk-kind
    end-evaluate
    goback.
end program env-kind.

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
01 nbuf   pic x(524288).
01 nlen   pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
linkage section.
01 lk-root pic x(524288).
01 lk-root-len pic 9(9) comp-5.
01 lk-inc pic x(524288).
01 lk-inc-len pic 9(9) comp-5.
01 lk-out pic x(524288).
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

*> ---- oversize-result : the §4.10(a) 413 for a frame we refuse to buffer ----
*> §4.10(a) is a MUST: "the peer MUST reject an inbound EXECUTE whose wire size
*> exceeds its configured maximum with 413 payload_too_large, before fully
*> buffering or decoding it". The serve loop (netshim.c) had the first half and
*> not the second — it drained the oversize body and kept serving, which is
*> correct about the connection and answers NOTHING, so the caller waits out its
*> own deadline. That is a §4.9(c) silent drop, and it bills the caller, so it
*> reads as the peer being slow rather than wrong: `concurrency/t1_3_no_head_of_line`
*> reported "read response: i/o timeout" and was filed as a payload-capacity skip.
*>
*> The request_id is NOT available here by construction — refusing before decoding
*> is the point of the rule — so this is §4.10(a)'s other branch, the "best-effort
*> coded frame". The id goes out empty rather than guessed. The connection stays
*> up: MAY close is permitted, and closing would drop the caller's pooled
*> connection and break every later request on it (the lean cascade).
identification division.
program-id. oversize-result.
data division.
working-storage section.
01 errc     pic x(17) value "payload_too_large".
01 errcl    pic 9(9) comp-5 value 17.
01 res-ent  pic x(524288). 01 res-len  pic 9(9) comp-5. 01 res-hash  pic x(33).
01 resp-ent pic x(524288). 01 resp-len pic 9(9) comp-5. 01 resp-hash pic x(33).
01 incmap   pic x(524288). 01 incmap-len pic 9(9) comp-5.
01 rid      pic x(128).   01 rid-len  pic 9(9) comp-5 value 0.
01 rstatus  pic 9(9) comp-5 value 413.
01 n0       pic 9(18) comp-5 value 0.
linkage section.
01 lk-out     pic x(524288).
01 lk-out-len pic 9(9) comp-5.
procedure division using lk-out lk-out-len.
    move spaces to rid
    move 0 to rid-len
    move 0 to incmap-len
    call "b-map" using incmap incmap-len n0
    call "error-result" using errc errcl res-ent res-len res-hash
    call "make-response" using rid rid-len rstatus res-ent res-len
        resp-ent resp-len resp-hash
    call "env-wrap" using resp-ent resp-len incmap incmap-len
        lk-out lk-out-len
    goback.
end program oversize-result.

*> ---- truncated-result : the §4.11 400 for a frame that never completed ----
*> A stream that ends mid-frame is "a length prefix that never completes" in
*> §4.11's own words, and it is owed a coded EXECUTE_RESPONSE like every other
*> pre-admission refusal. UNCORRELATED BY CONSTRUCTION -- the request_id lives
*> inside a frame that never arrived -- which is the section's "otherwise as a
*> best-effort coded frame carrying no correlation" branch. Written before the
*> close, because after it there is nowhere to write.
identification division.
program-id. truncated-result.
data division.
working-storage section.
01 errc     pic x(15) value "invalid_request".
01 errcl    pic 9(9) comp-5 value 15.
01 res-ent  pic x(524288). 01 res-len  pic 9(9) comp-5. 01 res-hash  pic x(33).
01 resp-ent pic x(524288). 01 resp-len pic 9(9) comp-5. 01 resp-hash pic x(33).
01 incmap   pic x(524288). 01 incmap-len pic 9(9) comp-5.
01 rid      pic x(128).   01 rid-len  pic 9(9) comp-5 value 0.
01 rstatus  pic 9(9) comp-5 value 400.
01 n0       pic 9(18) comp-5 value 0.
linkage section.
01 lk-out     pic x(524288).
01 lk-out-len pic 9(9) comp-5.
procedure division using lk-out lk-out-len.
    move spaces to rid
    move 0 to rid-len
    move 0 to incmap-len
    call "b-map" using incmap incmap-len n0
    call "error-result" using errc errcl res-ent res-len res-hash
    call "make-response" using rid rid-len rstatus res-ent res-len
        resp-ent resp-len resp-hash
    call "env-wrap" using resp-ent resp-len incmap incmap-len
        lk-out lk-out-len
    goback.
end program truncated-result.

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
01 pre       pic 9(1).
01 kbind     pic 9(1).
01 t-resp    pic x(32) value "system/protocol/execute/response".
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
01 capbuf    pic x(524288).
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
01 res-ent   pic x(524288).
01 res-len   pic 9(9) comp-5.
01 res-hash  pic x(33).
01 resp-ent  pic x(524288).
01 resp-len  pic 9(9) comp-5.
01 resp-hash pic x(33).
01 incmap    pic x(524288).
01 incmap-len pic 9(9) comp-5.
01 n0        pic 9(18) comp-5 value 0.
linkage section.
01 lk-conn   pic x(256).
01 lk-env    pic x(524288).
01 lk-env-len pic 9(9) comp-5.
01 lk-out    pic x(524288).
01 lk-out-len pic 9(9) comp-5.
01 lk-hasresp pic 9(1).
procedure division using lk-conn lk-env lk-env-len lk-out lk-out-len lk-hasresp.
    move 0 to lk-hasresp
    move 0 to lk-out-len
    move spaces to rid  move 0 to rid-len
    move 0 to incmap-len
    call "b-map" using incmap incmap-len n0
*> ---- §4.11 DECODE BOUNDARY ----
*> Sited HERE, above everything, and the placement is the requirement rather than
*> a convenience: §4.11 is about frames refused PRE-ADMISSION, so each of these
*> causes has to be decided before the §1.4 address gate, before authentication
*> and before any capability question. A peer that runs its address gate first
*> answers `invalid_request` to a tagged frame and has not implemented §6.3's
*> decode-time reject at all -- it has merely refused the frame for an unrelated
*> reason that happens to share a code.
    call "frame-precheck" using lk-env lk-env-len pre
    if pre not = 0
        if pre = 1
            *> The frame is otherwise structurally sound -- frame-precheck reports
            *> TAG only when the walk completed and consumed exactly the frame --
            *> so the lenient readers are safe on it and the request_id is
            *> recoverable. That ordering is what makes the salvage legitimate
            *> rather than a second parse of condemned bytes.
            perform salvage-rid
            move 400 to rstatus
            move "non_canonical_ecf" to errcode  move 17 to errcode-len
        else
            *> No salvage: the shape was never established, so a field read over
            *> these bytes would be reading a structure that does not exist.
            move 400 to rstatus
            move "invalid_request" to errcode  move 15 to errcode-len
        end-if
        perform refuse-frame
        goback
    end-if
    call "inc-keys-bind" using lk-env kbind
    if kbind = 0
        perform salvage-rid
        move 400 to rstatus
        move "hash_mismatch" to errcode  move 13 to errcode-len
        perform refuse-frame
        goback
    end-if
    call "env-root-off" using lk-env root-off root-fnd
*> §4.11 -- the frame decoded and is NOT a well-formed request. Every one of these
*> arms used to leave lk-hasresp at 0, which answers NOTHING: §4.9(c)'s silent
*> drop, billed entirely to the caller's own §6.11(c) deadline, so it presents as
*> a slow peer rather than a wrong one. A decoded root is CORRELATABLE -- the
*> request_id is right there in it.
    if root-fnd = 0
        move 400 to rstatus
        move "invalid_request" to errcode  move 15 to errcode-len
        perform refuse-frame
        goback
    end-if
    call "ent-type" using lk-env root-off rtype rtype-len
    if rtype-len = 32 and rtype(1:32) = t-resp
        *> A response frame, not a request. Deliberately dropped: answering it
        *> would put a response on the wire for a response.
        goback
    end-if
    if not (rtype-len = 23 and rtype(1:23) = t-exec)
        perform salvage-rid
        move 400 to rstatus
        move "invalid_request" to errcode  move 15 to errcode-len
        perform refuse-frame
        goback
    end-if
    move 1 to lk-hasresp
    move spaces to rid  move 0 to rid-len
    call "ent-field" using lk-env root-off k-rid k-rid-len voff vfnd
    if vfnd = 1
        call "read-text" using lk-env voff rid rid-len
    else
        move 400 to rstatus
        move "invalid_request" to errcode  move 15 to errcode-len
        perform refuse-frame
        goback
    end-if
    move spaces to uri  move 0 to uri-len
    call "ent-field" using lk-env root-off k-uri k-uri-len voff vfnd
    if vfnd = 1 then call "read-text" using lk-env voff uri uri-len end-if
    call "env-inc-off" using lk-env inc-off inc-fnd
    call "ps-peerid" using local locallen

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

*> refuse-frame : emit a §4.11 pre-admission refusal through the ordinary
*> response path, so the framing, the correlation and the envelope shape are the
*> same ones every other answer uses.
refuse-frame.
    move 1 to lk-hasresp
    call "error-result" using errcode errcode-len res-ent res-len res-hash
    call "make-response" using rid rid-len rstatus res-ent res-len
        resp-ent resp-len resp-hash
    call "env-wrap" using resp-ent resp-len incmap incmap-len
        lk-out lk-out-len.

*> salvage-rid : recover root.data.request_id for a frame already proven walkable.
*> Leaves the response UNCORRELATED when any step is absent -- §4.11 provides for
*> exactly that ("otherwise as a best-effort coded frame carrying no
*> correlation"), and a correlation id that names a DIFFERENT request is worse
*> than none, because the caller matches it to something.
salvage-rid.
    move spaces to rid  move 0 to rid-len
    call "env-root-off" using lk-env root-off root-fnd
    if root-fnd = 0 then exit paragraph end-if
    call "ent-field" using lk-env root-off k-rid k-rid-len voff vfnd
    if vfnd = 1 then call "read-text" using lk-env voff rid rid-len end-if.

*> ---- §6.5 dispatch chain -------------------------------------------
do-chain.
    call "ingest-signatures" using lk-env inc-off inc-fnd
*> §4.7 (0.8.2.6) -- THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate
*> used to sit after the verify-request evaluate below, so a pre-establishment
*> EXECUTE naming a FOREIGN namespace took the 401 an unauthenticated request
*> takes. §4.7's own reason: a 401 directs the caller to authenticate and retry,
*> and for a foreign-namespace address that retry cannot succeed at any
*> authentication state -- so the 401 names a remedy that does not exist. §6.5
*> step 3 calls it a gate, not an ordering preference, and §1.4 makes the
*> downstream permission check unreachable here.
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
    call "cap-extract-peer" using path pathlen local locallen tp tplen
    if not (tplen = locallen and tp(1:tplen) = local(1:locallen))
        perform resp-400-invreq  exit paragraph
    end-if
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
    *> verdict 0 = allow. `path` was already normalized, canonicalized and
    *> address-gated above the verify-request call -- §4.7 0.8.2.6 orders the
    *> address before authentication -- so reaching this line means it is local.
    call "resolve-handler" using path pathlen pat patlen hfound
    if hfound = 0 then perform resp-404  exit paragraph end-if
    *> Strip "/{local}/" to the bare handler id BEFORE the permission check.
    *> §5.2 F40 makes the handlers dimension ID-scope, matched literally against
    *> the grant's patterns — and every grant this peer writes names handlers
    *> relatively ("system/tree", "system/capability"). Comparing the ABSOLUTE
    *> resolved path against those only worked while the matcher canonicalized
    *> both sides, which is precisely the frame-on-an-id-scope-dimension defect
    *> F40 exists to catch; with literal matching the value has to be the id.
    compute pfx = locallen + 2
    compute splen = patlen - pfx
    move spaces to spat
    if splen > 0 then move pat(pfx + 1:splen) to spat(1:splen) end-if
    *> resolve caller capability
    call "ent-field" using lk-env root-off k-cap k-cap-len voff f
    if f = 0 then perform resp-403  exit paragraph end-if
    call "read-bytes" using lk-env voff caph cl
    call "cap-resolve" using lk-env inc-off inc-fnd caph capbuf caplen capfnd
    if capfnd = 0 then perform resp-403  exit paragraph end-if
    *> §PR-8 granter frame
    call "cap-granter-peer" using lk-env inc-off inc-fnd capbuf granter granterlen
    *> §5.2 check_permission
    call "cap-check-perm" using lk-env root-off capbuf spat splen
        granter granterlen perm
    if perm = 0 then perform resp-403  exit paragraph end-if
    *> route by the same stripped pattern
    evaluate true
        when splen = 11 and spat(1:11) = "system/tree"
            call "tree-handler" using lk-env root-off rstatus
                res-ent res-len res-hash capbuf spat splen
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
            *> inc-off/inc-fnd are threaded so §7a.2a's merged bundle can start
            *> from the PARENT envelope's `included`, and spat/splen so §1.4's
            *> PD-2 gate reads the OWNING handler's own grant (§6.8) at
            *> system/capability/grants/{pattern} rather than re-deriving one.
            call "dispatch-outbound-handler" using lk-env root-off rstatus
                res-ent res-len res-hash inc-off inc-fnd spat splen
        when other
            perform resp-501-nobody
    end-evaluate.

resp-404.
    move 404 to rstatus
    move "handler_not_found" to errcode move 17 to errcode-len
    call "error-result" using errcode errcode-len res-ent res-len res-hash.

*> §6.6 (F62) — TWO MISSES, TWO ANSWERS. Reaching the ladder above means
*> resolve-handler ALREADY answered hfound=1, i.e. it walked the entity tree and
*> found a `system/handler` entity bound at this prefix; the hfound=0 arm took
*> resp-404 twenty lines up. So a `when other` here is not "no such handler" —
*> it is a handler this peer RESOLVED and has no body to run, because the wire
*> register op (§6.2 WRITE 1) binds a system/handler entity carrying an
*> `expression_path` and this peer has no §6.13(a) entity-native evaluator.
*> Spelling that miss `404 handler_not_found` made the peer contradict itself:
*> it answered 200 to a register, 200 to a tree.get of the entity it had just
*> written, and then handler_not_found at that same pattern.
*>
*> §6.6 calls a dispatch index an optimisation whose results MUST be equivalent
*> to the tree walk. The walk was already here and already correct; the ladder
*> below it is BODY SELECTION, not resolution, and only its verdict was wrong.
*> `no_handler_body` is what datalog/nim/oz and the reference peer answer; it
*> appears in no spec revision and the cohort spells this four ways — that gap
*> is registered as F60 and is deliberately not invented around here.
resp-501-nobody.
    move 501 to rstatus
    move "no_handler_body" to errcode move 15 to errcode-len
    call "error-result" using errcode errcode-len res-ent res-len res-hash.

*> §1.4 / §6.5 step 3 — the ADDRESS gate, ahead of handler resolution and
*> check_permission. Its own paragraph rather than resp-404's: a 404 here would
*> assert "this peer has no such handler", which is false of a peer that has it
*> and is refusing the address (§6.2, 0.8.2.2).
resp-400-invreq.
    move 400 to rstatus
    move "invalid_request" to errcode move 15 to errcode-len
    call "error-result" using errcode errcode-len res-ent res-len res-hash.

resp-403.
    move 403 to rstatus
    move "capability_denied" to errcode move 17 to errcode-len
    call "error-result" using errcode errcode-len res-ent res-len res-hash.
end program dispatch.
