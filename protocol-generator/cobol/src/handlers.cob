>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — system handlers (§6.2/§6.3) + bootstrap (§6.9).
*>
*> bootstrap binds the MUST system-handler entities so §6.6 resolve-handler can
*> find them; tree-handler is §6.3 get/put/listing; capability-handler is §6.2
*> request/revoke. Each handler fills (status, result-entity, result-hash) and
*> optionally an included map (capability grant deliveries).
*> ===================================================================

*> ---- mkpath : "/{local}/{rel}" -------------------------------------
identification division.
program-id. mkpath.
data division.
working-storage section.
01 local pic x(128).
01 locallen pic 9(9) comp-5.
01 p     pic 9(9) comp-5.
linkage section.
01 lk-rel    pic x(700).
01 lk-rellen pic 9(9) comp-5.
01 lk-out    pic x(700).
01 lk-outlen pic 9(9) comp-5.
procedure division using lk-rel lk-rellen lk-out lk-outlen.
    call "ps-peerid" using local locallen
    move "/" to lk-out(1:1)
    move local(1:locallen) to lk-out(2:locallen)
    compute p = 2 + locallen
    move "/" to lk-out(p:1)
    add 1 to p
    if lk-rellen > 0 then move lk-rel(1:lk-rellen) to lk-out(p:lk-rellen) end-if
    compute lk-outlen = 1 + locallen + 1 + lk-rellen
    goback.
end program mkpath.

*> ---- get-target : resource.targets[0] (text) + present ------------
identification division.
program-id. get-target.
data division.
working-storage section.
01 resoff pic 9(9) comp-5.
01 rgf     pic 9(1).
01 toff   pic 9(9) comp-5.
01 tf     pic 9(1).
01 cur    pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 st     pic s9(9) comp-5.
01 k-rsrc pic x(8) value "resource".
01 k-rsrc-len pic 9(9) comp-5 value 8.
01 k-tgts pic x(7) value "targets".
01 k-tgts-len pic 9(9) comp-5 value 7.
linkage section.
01 lk-env    pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-tgt    pic x(900).
01 lk-tgtlen pic 9(9) comp-5.
01 lk-found  pic 9(1).
procedure division using lk-env lk-rootoff lk-tgt lk-tgtlen lk-found.
    move 0 to lk-found
    move 0 to lk-tgtlen
    call "ent-field" using lk-env lk-rootoff k-rsrc k-rsrc-len resoff rgf
    if rgf = 0 then goback end-if
    call "cbor-find-key" using lk-env resoff k-tgts k-tgts-len toff tf st
    if tf = 0 then goback end-if
    move toff to cur
    call "cbor-read-head" using lk-env cur maj addl arg st
    if maj not = 4 or arg = 0 then goback end-if
    call "cbor-read-head" using lk-env cur maj addl arg st
    if maj not = 3 then goback end-if
    move arg to lk-tgtlen
    if lk-tgtlen > 0 and lk-tgtlen <= 900 then move lk-env(cur:lk-tgtlen) to lk-tgt(1:lk-tgtlen) end-if
    move 1 to lk-found
    goback.
end program get-target.

*> ---- boot-handler : bind one MUST handler entity + interface -------
identification division.
program-id. boot-handler.
data division.
working-storage section.
01 nd     pic x(8192).
01 nd-len pic 9(9) comp-5.
01 ent    pic x(8192).
01 entlen pic 9(9) comp-5.
01 hash   pic x(33).
01 iface  pic x(700).
01 ifacelen pic 9(9) comp-5.
01 rel    pic x(700).
01 rellen pic 9(9) comp-5.
01 path   pic x(700).
01 pathlen pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 n1     pic 9(18) comp-5 value 1.
01 n3     pic 9(18) comp-5 value 3.
01 n0     pic 9(18) comp-5 value 0.
01 k-iface pic x(9) value "interface".
01 k-iface-len pic 9(9) comp-5 value 9.
01 k-name pic x(4) value "name".
01 k-name-len pic 9(9) comp-5 value 4.
01 k-ops  pic x(10) value "operations".
01 k-ops-len pic 9(9) comp-5 value 10.
01 k-pat  pic x(7) value "pattern".
01 k-pat-len pic 9(9) comp-5 value 7.
01 t-hdl  pic x(14) value "system/handler".
01 t-hdl-len pic 9(9) comp-5 value 14.
01 t-iface pic x(24) value "system/handler/interface".
01 t-iface-len pic 9(9) comp-5 value 24.
01 s-hpfx pic x(15) value "system/handler/".
linkage section.
01 lk-pat2   pic x(64).
01 lk-patlen pic 9(9) comp-5.
01 lk-name   pic x(32).
01 lk-namelen pic 9(9) comp-5.
01 lk-ops    pic x(8192).
01 lk-opslen pic 9(9) comp-5.
procedure division using lk-pat2 lk-patlen lk-name lk-namelen lk-ops lk-opslen.
    *> interface rel = "system/handler/{pattern}"
    move s-hpfx to iface(1:15)
    move lk-pat2(1:lk-patlen) to iface(16:lk-patlen)
    compute ifacelen = 15 + lk-patlen
    *> (1) handler entity at /{local}/{pattern}
    move 0 to nd-len
    call "b-map"  using nd nd-len n1
    call "b-text" using nd nd-len k-iface k-iface-len
    call "b-text" using nd nd-len iface ifacelen
    call "b-entity" using t-hdl t-hdl-len nd nd-len ent entlen hash st
    move lk-pat2(1:lk-patlen) to rel(1:lk-patlen)
    move lk-patlen to rellen
    call "mkpath" using rel rellen path pathlen
    call "store-bind" using path pathlen ent entlen hash
    *> (2) interface entity at /{local}/system/handler/{pattern}
    move 0 to nd-len
    call "b-map"  using nd nd-len n3
    call "b-text" using nd nd-len k-name k-name-len
    call "b-text" using nd nd-len lk-name lk-namelen
    call "b-text" using nd nd-len k-ops k-ops-len
    call "b-raw"  using nd nd-len lk-ops one lk-opslen
    call "b-text" using nd nd-len k-pat k-pat-len
    call "b-text" using nd nd-len lk-pat2 lk-patlen
    call "b-entity" using t-iface t-iface-len nd nd-len ent entlen hash st
    move iface(1:ifacelen) to rel(1:ifacelen)
    move ifacelen to rellen
    call "mkpath" using rel rellen path pathlen
    call "store-bind" using path pathlen ent entlen hash
    goback.
end program boot-handler.

*> ---- op-spec : append {input_type?, output_type?} to a buffer ------
identification division.
program-id. op-spec.
data division.
working-storage section.
01 cnt    pic 9(18) comp-5.
01 k-in   pic x(10) value "input_type".
01 k-in-len pic 9(9) comp-5 value 10.
01 k-out  pic x(11) value "output_type".
01 k-out-len pic 9(9) comp-5 value 11.
linkage section.
01 lk-in     pic x(64).
01 lk-inlen  pic 9(9) comp-5.
01 lk-ot     pic x(64).
01 lk-otlen  pic 9(9) comp-5.
01 lk-buf    pic x(8192).
01 lk-buflen pic 9(9) comp-5.
procedure division using lk-in lk-inlen lk-ot lk-otlen lk-buf lk-buflen.
    move 0 to cnt
    if lk-inlen > 0 then add 1 to cnt end-if
    if lk-otlen > 0 then add 1 to cnt end-if
    call "b-map" using lk-buf lk-buflen cnt
    if lk-inlen > 0
        call "b-text" using lk-buf lk-buflen k-in k-in-len
        call "b-text" using lk-buf lk-buflen lk-in lk-inlen
    end-if
    if lk-otlen > 0
        call "b-text" using lk-buf lk-buflen k-out k-out-len
        call "b-text" using lk-buf lk-buflen lk-ot lk-otlen
    end-if
    goback.
end program op-spec.

*> ---- bootstrap : §6.9 boot the MUST system handlers ----------------
identification division.
program-id. bootstrap.
data division.
working-storage section.
01 pat    pic x(64).
01 patlen pic 9(9) comp-5.
01 nm     pic x(32).
01 nmlen  pic 9(9) comp-5.
01 ops    pic x(8192).
01 opslen pic 9(9) comp-5.
01 openf  pic 9(1).
01 conff  pic 9(1).
01 ne     pic x(4) value "echo".
01 ndp    pic x(8) value "dispatch".
01 c4     pic 9(9) comp-5 value 4.
01 nm-get pic x(3) value "get".
01 nm-put pic x(3) value "put".
01 nm-reg pic x(8) value "register".
01 nm-unr pic x(10) value "unregister".
01 nm-val pic x(8) value "validate".
01 nm-req pic x(7) value "request".
01 nm-rev pic x(6) value "revoke".
01 nm-cfg pic x(9) value "configure".
01 nm-del pic x(8) value "delegate".
01 nm-hel pic x(5) value "hello".
01 nm-aut pic x(12) value "authenticate".
01 n0     pic 9(18) comp-5 value 0.
01 n1     pic 9(18) comp-5 value 1.
01 n2     pic 9(18) comp-5 value 2.
01 n4     pic 9(18) comp-5 value 4.
01 c3     pic 9(9) comp-5 value 3.
01 c5     pic 9(9) comp-5 value 5.
01 c6     pic 9(9) comp-5 value 6.
01 c7     pic 9(9) comp-5 value 7.
01 c8     pic 9(9) comp-5 value 8.
01 c9     pic 9(9) comp-5 value 9.
01 c10    pic 9(9) comp-5 value 10.
01 c12    pic 9(9) comp-5 value 12.
procedure division.
    *> system/tree : get, put
    move 0 to opslen
    call "b-map" using ops opslen n2
    call "b-text" using ops opslen nm-get c3   call "b-map" using ops opslen n0
    call "b-text" using ops opslen nm-put c3   call "b-map" using ops opslen n0
    move "system/tree" to pat  move 11 to patlen
    move "Tree" to nm  move 4 to nmlen
    call "boot-handler" using pat patlen nm nmlen ops opslen
    *> system/handler : register, unregister
    move 0 to opslen
    call "b-map" using ops opslen n2
    call "b-text" using ops opslen nm-reg c8   call "b-map" using ops opslen n0
    call "b-text" using ops opslen nm-unr c10  call "b-map" using ops opslen n0
    move "system/handler" to pat  move 14 to patlen
    move "Handlers" to nm  move 8 to nmlen
    call "boot-handler" using pat patlen nm nmlen ops opslen
    *> system/type : validate
    move 0 to opslen
    call "b-map" using ops opslen n1
    call "b-text" using ops opslen nm-val c8   call "b-map" using ops opslen n0
    move "system/type" to pat  move 11 to patlen
    move "Types" to nm  move 5 to nmlen
    call "boot-handler" using pat patlen nm nmlen ops opslen
    *> system/capability : request, revoke, configure, delegate
    move 0 to opslen
    call "b-map" using ops opslen n4
    call "b-text" using ops opslen nm-req c7   call "b-map" using ops opslen n0
    call "b-text" using ops opslen nm-rev c6   call "b-map" using ops opslen n0
    call "b-text" using ops opslen nm-cfg c9   call "b-map" using ops opslen n0
    call "b-text" using ops opslen nm-del c8   call "b-map" using ops opslen n0
    move "system/capability" to pat  move 17 to patlen
    move "Capability" to nm  move 10 to nmlen
    call "boot-handler" using pat patlen nm nmlen ops opslen
    *> system/protocol/connect : hello, authenticate
    move 0 to opslen
    call "b-map" using ops opslen n2
    call "b-text" using ops opslen nm-hel c5   call "b-map" using ops opslen n0
    call "b-text" using ops opslen nm-aut c12  call "b-map" using ops opslen n0
    move "system/protocol/connect" to pat  move 23 to patlen
    move "Connect" to nm  move 7 to nmlen
    call "boot-handler" using pat patlen nm nmlen ops opslen
    *> §7a conformance handlers (only under --validate; off by default).
    call "ps-flags" using openf conff
    if conff = 1
        move 0 to opslen
        call "b-map" using ops opslen n1
        call "b-text" using ops opslen ne c4  call "b-map" using ops opslen n0
        move "system/validate/echo" to pat  move 20 to patlen
        move "validate-echo" to nm  move 13 to nmlen
        call "boot-handler" using pat patlen nm nmlen ops opslen
        move 0 to opslen
        call "b-map" using ops opslen n1
        call "b-text" using ops opslen ndp c8  call "b-map" using ops opslen n0
        move "system/validate/dispatch-outbound" to pat  move 33 to patlen
        move "validate-dispatch-outbound" to nm  move 26 to nmlen
        call "boot-handler" using pat patlen nm nmlen ops opslen
    end-if
    call "publish-types"
    goback.
end program bootstrap.

*> ---- build-listing : §3.9 system/tree/listing for a prefix ---------
identification division.
program-id. build-listing.
data division.
working-storage section.
01 cnt    pic 9(9) comp-5.
01 fcnt   pic 9(9) comp-5.
01 incl   pic 9(1) occurs 256.
01 dment  pic x(8192).
01 dmlen  pic 9(9) comp-5.
01 dmf    pic 9(1).
01 dmtype pic x(64).
01 dmtlen pic 9(9) comp-5.
01 t-delmark pic x(22) value "system/deletion-marker".
01 i      pic 9(9) comp-5.
01 seg    pic x(256).
01 seglen pic 9(9) comp-5.
01 lhash  pic x(33).
01 hashp  pic 9(1).
01 child  pic 9(1).
01 lent   pic x(4096).
01 lentlen pic 9(9) comp-5.
01 lehash pic x(33).
01 led    pic x(4096).
01 led-len pic 9(9) comp-5.
01 emap   pic x(60000).
01 emap-len pic 9(9) comp-5.
01 nd     pic x(60000).
01 nd-len pic 9(9) comp-5.
01 btrue  pic x value x"F5".
01 bfalse pic x value x"F4".
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 n1     pic 9(18) comp-5 value 1.
01 n2     pic 9(18) comp-5 value 2.
01 n4     pic 9(18) comp-5 value 4.
01 wcnt   pic 9(18) comp-5.
01 nzero   pic 9(18) comp-5 value 0.
01 n33    pic 9(9) comp-5 value 33.
01 k-hc   pic x(12) value "has_children".
01 k-hc-len pic 9(9) comp-5 value 12.
01 k-hash pic x(4) value "hash".
01 k-hash-len pic 9(9) comp-5 value 4.
01 k-cnt  pic x(5) value "count".
01 k-cnt-len pic 9(9) comp-5 value 5.
01 k-ent  pic x(7) value "entries".
01 k-ent-len pic 9(9) comp-5 value 7.
01 k-off  pic x(6) value "offset".
01 k-off-len pic 9(9) comp-5 value 6.
01 k-path pic x(4) value "path".
01 k-path-len pic 9(9) comp-5 value 4.
01 t-le   pic x(26) value "system/tree/listing-entry".
01 t-le-len pic 9(9) comp-5 value 25.
01 t-lst  pic x(20) value "system/tree/listing".
01 t-lst-len pic 9(9) comp-5 value 19.
linkage section.
01 lk-path2  pic x(700).
01 lk-plen   pic 9(9) comp-5.
01 lk-res    pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-path2 lk-plen lk-res lk-reslen lk-reshash.
    call "store-listing" using lk-path2 lk-plen cnt
    *> pass 1: filter out deletion-marker-bound leaves (§6.3 / CORE-TREE-DELETE-1)
    move 0 to fcnt
    perform varying i from 1 by 1 until i > cnt
        call "store-list-entry" using i seg seglen lhash hashp child
        move 1 to incl(i)
        if hashp = 1 and child = 0
            call "store-get-by-hash" using lhash dment dmlen dmf
            if dmf = 1
                call "ent-type" using dment one dmtype dmtlen
                if dmtlen = 22 and dmtype(1:22) = t-delmark
                    move 0 to incl(i)
                end-if
            end-if
        end-if
        if incl(i) = 1 then add 1 to fcnt end-if
    end-perform
    move fcnt to wcnt
    move 0 to emap-len
    call "b-map" using emap emap-len wcnt
    perform varying i from 1 by 1 until i > cnt
        if incl(i) = 0 then exit perform cycle end-if
        call "store-list-entry" using i seg seglen lhash hashp child
        *> listing-entry { has_children, hash? }
        move 0 to led-len
        if hashp = 1
            call "b-map"  using led led-len n2
            call "b-text" using led led-len k-hc k-hc-len
            if child = 1 then call "b-raw" using led led-len btrue one one
            else call "b-raw" using led led-len bfalse one one end-if
            call "b-text" using led led-len k-hash k-hash-len
            call "b-bytes" using led led-len lhash one n33
        else
            call "b-map"  using led led-len n1
            call "b-text" using led led-len k-hc k-hc-len
            if child = 1 then call "b-raw" using led led-len btrue one one
            else call "b-raw" using led led-len bfalse one one end-if
        end-if
        call "b-entity" using t-le t-le-len led led-len lent lentlen lehash st
        call "b-text" using emap emap-len seg seglen
        call "b-raw"  using emap emap-len lent one lentlen
    end-perform
    *> listing { count, entries, offset, path }
    move 0 to nd-len
    call "b-map"  using nd nd-len n4
    call "b-text" using nd nd-len k-cnt k-cnt-len
    call "b-uint" using nd nd-len wcnt
    call "b-text" using nd nd-len k-ent k-ent-len
    call "b-raw"  using nd nd-len emap one emap-len
    call "b-text" using nd nd-len k-off k-off-len
    call "b-uint" using nd nd-len nzero
    call "b-text" using nd nd-len k-path k-path-len
    call "b-text" using nd nd-len lk-path2 lk-plen
    call "b-entity" using t-lst t-lst-len nd nd-len lk-res lk-reslen lk-reshash st
    goback.
end program build-listing.

*> ---- tree-handler : §6.3 get / put / listing -----------------------
identification division.
program-id. tree-handler.
data division.
working-storage section.
01 op     pic x(32).
01 oplen  pic 9(9) comp-5.
01 voff   pic 9(9) comp-5.
01 vf     pic 9(1).
01 tgt    pic x(900).
01 tgtlen pic 9(9) comp-5.
01 tf     pic 9(1).
01 local  pic x(128).
01 locallen pic 9(9) comp-5.
01 path   pic x(900).
01 pathlen pic 9(9) comp-5.
01 okflag pic 9(1).
01 spath  pic x(700).
01 splen  pic 9(9) comp-5.
01 ent    pic x(8192).
01 entlen pic 9(9) comp-5.
01 ef     pic 9(1).
01 ehash  pic x(33).
01 gmode   pic x(16).
01 modelen pic 9(9) comp-5.
01 poff   pic 9(9) comp-5.
01 pfd     pic 9(1).
01 eoff   pic 9(9) comp-5.
01 endo   pic 9(9) comp-5.
01 nent   pic x(8192).
01 nentlen pic 9(9) comp-5.
01 nhash  pic x(33).
01 exph   pic x(33).
01 expl   pic 9(9) comp-5.
01 hasexp pic 9(1).
01 curh   pic x(33).
01 curf   pic 9(1).
01 nd     pic x(8192).
01 nd-len pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 n33    pic 9(9) comp-5 value 33.
01 zero33 pic x(33) value all x"00".
01 lastc  pic x.
01 k-op   pic x(9) value "operation".
01 k-op-len pic 9(9) comp-5 value 9.
01 k-params pic x(6) value "params".
01 k-params-len pic 9(9) comp-5 value 6.
01 k-gmode pic x(4) value "mode".
01 k-gmode-len pic 9(9) comp-5 value 4.
01 k-entk pic x(6) value "entity".
01 k-entk-len pic 9(9) comp-5 value 6.
01 k-exph pic x(13) value "expected_hash".
01 k-exph-len pic 9(9) comp-5 value 13.
01 t-hash pic x(11) value "system/hash".
01 t-hash-len pic 9(9) comp-5 value 11.
01 errc   pic x(32).
01 errcl  pic 9(9) comp-5.
linkage section.
01 lk-env    pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res    pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash.
    call "ps-peerid" using local locallen
    move spaces to op  move 0 to oplen
    call "ent-field" using lk-env lk-rootoff k-op k-op-len voff vf
    if vf = 1 then call "read-text" using lk-env voff op oplen end-if
    call "get-target" using lk-env lk-rootoff tgt tgtlen tf
    *> params entity offset
    call "ent-field" using lk-env lk-rootoff k-params k-params-len poff pfd

    *> §1.4 path validation (CORE-TREE-PATH-FLEX-1)
    if tf = 1
        call "path-flex-ok" using tgt tgtlen okflag
        if okflag = 0
            move 400 to lk-status
            move "invalid_path" to errc move 12 to errcl
            call "error-result" using errc errcl lk-res lk-reslen lk-reshash
            goback
        end-if
    end-if

    evaluate true
        when oplen = 3 and op(1:3) = "get"
            perform do-get
        when oplen = 3 and op(1:3) = "put"
            perform do-put
        when other
            move 501 to lk-status
            move "unsupported_operation" to errc move 21 to errcl
            call "error-result" using errc errcl lk-res lk-reslen lk-reshash
    end-evaluate
    goback.

do-get.
    *> no target -> list local root
    if tf = 0
        call "mkpath-root" using path pathlen
        call "build-listing" using path pathlen lk-res lk-reslen lk-reshash
        move 200 to lk-status
        exit paragraph
    end-if
    *> trailing slash or empty -> listing
    move tgt(tgtlen:1) to lastc
    if tgtlen = 0 or lastc = "/"
        call "cap-canon" using tgt tgtlen local locallen path pathlen
        call "build-listing" using path pathlen lk-res lk-reslen lk-reshash
        move 200 to lk-status
        exit paragraph
    end-if
    call "cap-canon" using tgt tgtlen local locallen path pathlen
    move path(1:pathlen) to spath(1:pathlen)  move pathlen to splen
    call "store-get-at" using spath splen ent entlen ef
    if ef = 0
        move 404 to lk-status
        move "not_found" to errc move 9 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        exit paragraph
    end-if
    *> gmode = params.gmode ?
    move spaces to gmode  move 0 to modelen
    if pfd = 1
        call "ent-field" using lk-env poff k-gmode k-gmode-len voff vf
        if vf = 1 then call "read-text" using lk-env voff gmode modelen end-if
    end-if
    if modelen = 4 and gmode(1:4) = "hash"
        call "ent-hash" using ent one ehash
        move 0 to nd-len
        call "b-bytes" using nd nd-len ehash one n33
        call "b-entity" using t-hash t-hash-len nd nd-len
            lk-res lk-reslen lk-reshash st
    else
        move ent(1:entlen) to lk-res(1:entlen)
        move entlen to lk-reslen
    end-if
    move 200 to lk-status.

do-put.
    if tf = 0
        move 400 to lk-status
        move "ambiguous_resource" to errc move 18 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        exit paragraph
    end-if
    call "cap-canon" using tgt tgtlen local locallen path pathlen
    move path(1:pathlen) to spath(1:pathlen)  move pathlen to splen
    *> extract params.entity (nested wire entity)
    if pfd = 0
        move 400 to lk-status
        move "unexpected_params" to errc move 17 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        exit paragraph
    end-if
    call "ent-field" using lk-env poff k-entk k-entk-len eoff vf
    if vf = 0
        move 400 to lk-status
        move "unexpected_params" to errc move 17 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        exit paragraph
    end-if
    move eoff to endo
    call "cbor-skip" using lk-env endo st
    compute nentlen = endo - eoff
    move lk-env(eoff:nentlen) to nent(1:nentlen)
    call "ent-hash" using nent one nhash
    *> expected_hash (optional)
    move 0 to hasexp
    call "ent-field" using lk-env poff k-exph k-exph-len voff vf
    if vf = 1
        call "read-bytes" using lk-env voff exph expl
        move 1 to hasexp
    end-if
    *> CAS
    call "store-hash-at" using spath splen curh curf
    if hasexp = 1
        if exph(1:33) = zero33
            if curf = 1 then perform put-conflict  exit paragraph end-if
        else
            if not (curf = 1 and curh(1:33) = exph(1:33))
                perform put-conflict  exit paragraph
            end-if
        end-if
    end-if
    call "store-bind" using spath splen nent nentlen nhash
    move 0 to nd-len
    call "b-bytes" using nd nd-len nhash one n33
    call "b-entity" using t-hash t-hash-len nd nd-len
        lk-res lk-reslen lk-reshash st
    move 200 to lk-status.

put-conflict.
    move 409 to lk-status
    move "hash_mismatch" to errc move 13 to errcl
    call "error-result" using errc errcl lk-res lk-reslen lk-reshash.
end program tree-handler.

*> ---- mkpath-root : "/{local}/" -------------------------------------
identification division.
program-id. mkpath-root.
data division.
working-storage section.
01 local pic x(128).
01 locallen pic 9(9) comp-5.
01 p pic 9(9) comp-5.
linkage section.
01 lk-out pic x(900).
01 lk-outlen pic 9(9) comp-5.
procedure division using lk-out lk-outlen.
    call "ps-peerid" using local locallen
    move "/" to lk-out(1:1)
    move local(1:locallen) to lk-out(2:locallen)
    compute p = 2 + locallen
    move "/" to lk-out(p:1)
    compute lk-outlen = locallen + 2
    goback.
end program mkpath-root.

*> ---- capability-handler : §6.2 request / revoke --------------------
identification division.
program-id. capability-handler.
data division.
working-storage section.
01 op     pic x(32).
01 oplen  pic 9(9) comp-5.
01 voff   pic 9(9) comp-5.
01 vf     pic 9(1).
01 poff   pic 9(9) comp-5.
01 pfd     pic 9(1).
01 author pic x(33).
01 al     pic 9(9) comp-5.
01 goff   pic 9(9) comp-5.
01 gf     pic 9(1).
01 endo   pic 9(9) comp-5.
01 grants pic x(8192).
01 grantslen pic 9(9) comp-5.
01 token  pic x(8192).
01 token-len pic 9(9) comp-5.
01 token-hash pic x(33).
01 csig   pic x(8192).
01 csig-len pic 9(9) comp-5.
01 csig-hash pic x(33).
01 myidhash pic x(33).
01 mypent pic x(8192).
01 mypent-len pic 9(9) comp-5.
01 nd     pic x(8192).
01 nd-len pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 n1     pic 9(18) comp-5 value 1.
01 n3map  pic 9(18) comp-5 value 3.
01 n0     pic 9(18) comp-5 value 0.
01 n33    pic 9(9) comp-5 value 33.
01 n33c   pic 9(9) comp-5 value 33.
01 k-op   pic x(9) value "operation".
01 k-op-len pic 9(9) comp-5 value 9.
01 k-params pic x(6) value "params".
01 k-params-len pic 9(9) comp-5 value 6.
01 k-author pic x(6) value "author".
01 k-author-len pic 9(9) comp-5 value 6.
01 k-grants pic x(6) value "grants".
01 k-grants-len pic 9(9) comp-5 value 6.
01 k-token pic x(5) value "token".
01 k-token-len pic 9(9) comp-5 value 5.
01 t-grant pic x(23) value "system/capability/grant".
01 t-grant-len pic 9(9) comp-5 value 23.
01 incoff  pic 9(9) comp-5.
01 incfnd  pic 9(1).
01 capbuf  pic x(8192).
01 caplen  pic 9(9) comp-5.
01 capfnd  pic 9(1).
01 caph    pic x(33).
01 cl      pic 9(9) comp-5.
01 cgoff   pic 9(9) comp-5.
01 cgf     pic 9(1).
01 reqcur  pic 9(9) comp-5.
01 reqcnt  pic 9(9) comp-5.
01 ccur    pic 9(9) comp-5.
01 callercnt pic 9(9) comp-5.
01 ri      pic 9(9) comp-5.
01 cj      pic 9(9) comp-5.
01 covered pic 9(1).
01 gsr     pic 9(1).
01 loc     pic x(128).
01 loclen  pic 9(9) comp-5.
01 maj     pic 9(2) comp-5.
01 addl    pic 9(2) comp-5.
01 arg     pic 9(18) comp-5.
01 k-cap   pic x(10) value "capability".
01 k-cap-len pic 9(9) comp-5 value 10.
01 token33 pic x(33).
01 tl      pic 9(9) comp-5.
01 pp      pic x(128).
01 pplen   pic 9(9) comp-5.
01 ishex   pic 9(1).
01 ispid   pic 9(1).
01 ci      pic 9(9) comp-5.
01 cch     pic x.
01 hexh    pic x(256).
01 hexlen  pic 9(9) comp-5.
01 rel     pic x(700).
01 rellen  pic 9(9) comp-5.
01 cpath   pic x(700).
01 cpathlen pic 9(9) comp-5.
01 nowv    pic 9(18) comp-5.
01 pent    pic x(8192).
01 pentlen pic 9(9) comp-5.
01 pendo   pic 9(9) comp-5.
01 phash   pic x(33).
01 mk-ent  pic x(8192).
01 mk-len  pic 9(9) comp-5.
01 mk-hash pic x(33).
01 zero33  pic x(33) value all x"00".
01 one33   pic 9(9) comp-5 value 33.
01 n2c     pic 9(18) comp-5 value 2.
01 k-pp    pic x(12) value "peer_pattern".
01 k-pp-len pic 9(9) comp-5 value 12.
01 k-ra    pic x(10) value "revoked_at".
01 k-ra-len pic 9(9) comp-5 value 10.
01 t-revoc pic x(28) value "system/capability/revocation".
01 t-revoc-len pic 9(9) comp-5 value 28.
01 s-revs  pic x(30) value "system/capability/revocations/".
01 s-pol   pic x(25) value "system/capability/policy/".
01 errc   pic x(32).
01 errcl  pic 9(9) comp-5.
linkage section.
01 lk-env    pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res    pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
01 lk-incmap pic x(16384).
01 lk-incmap-len pic 9(9) comp-5.
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash
                        lk-incmap lk-incmap-len.
    move spaces to op  move 0 to oplen
    call "ent-field" using lk-env lk-rootoff k-op k-op-len voff vf
    if vf = 1 then call "read-text" using lk-env voff op oplen end-if
    call "ent-field" using lk-env lk-rootoff k-params k-params-len poff pfd
    evaluate true
        when oplen = 7 and op(1:7) = "request"
            perform do-request
        when oplen = 6 and op(1:6) = "revoke"
            perform do-revoke
        when oplen = 9 and op(1:9) = "configure"
            perform do-configure
        when other
            move 501 to lk-status
            move "unsupported_operation" to errc move 21 to errcl
            call "error-result" using errc errcl lk-res lk-reslen lk-reshash
    end-evaluate
    goback.

do-request.
    *> grantee = author
    call "ent-field" using lk-env lk-rootoff k-author k-author-len voff vf
    if vf = 0
        move 403 to lk-status
        move "capability_denied" to errc move 17 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        exit paragraph
    end-if
    call "read-bytes" using lk-env voff author al
    *> req grants = params.grants (array, raw)
    move 0 to grantslen
    if pfd = 1
        call "ent-field" using lk-env poff k-grants k-grants-len goff gf
        if gf = 1
            move goff to endo
            call "cbor-skip" using lk-env endo st
            compute grantslen = endo - goff
            move lk-env(goff:grantslen) to grants(1:grantslen)
        end-if
    end-if
    if grantslen = 0
        move 0 to grantslen
        call "b-arr" using grants grantslen n0
    end-if
    *> §6.2 mint-time subset check: requested grants ⊆ caller's authority
    call "ps-peerid" using loc loclen
    call "env-inc-off" using lk-env incoff incfnd
    move 0 to capfnd
    call "ent-field" using lk-env lk-rootoff k-cap k-cap-len voff vf
    if vf = 1
        call "read-bytes" using lk-env voff caph cl
        call "inc-resolve" using lk-env incoff incfnd caph capbuf caplen capfnd
    end-if
    if capfnd = 0
        perform scope-exceeds  exit paragraph
    end-if
    call "ent-field" using capbuf one k-grants k-grants-len cgoff cgf
    if gf = 1
        move goff to reqcur
        call "cbor-read-head" using lk-env reqcur maj addl arg st
        move arg to reqcnt
        perform varying ri from 1 by 1 until ri > reqcnt
            move 0 to covered
            if cgf = 1
                move cgoff to ccur
                call "cbor-read-head" using capbuf ccur maj addl arg st
                move arg to callercnt
                perform varying cj from 1 by 1 until cj > callercnt
                    call "cap-grant-subset" using lk-env reqcur loc loclen
                        capbuf ccur loc loclen gsr
                    if gsr = 1 then move 1 to covered end-if
                    call "cbor-skip" using capbuf ccur st
                end-perform
            end-if
            if covered = 0
                perform scope-exceeds  exit paragraph
            end-if
            call "cbor-skip" using lk-env reqcur st
        end-perform
    end-if
    call "mint-token" using author grants grantslen
        token token-len token-hash csig csig-len csig-hash
    *> result = system/capability/grant { token: bytes token-hash }
    move 0 to nd-len
    call "b-map"   using nd nd-len n1
    call "b-text"  using nd nd-len k-token k-token-len
    call "b-bytes" using nd nd-len token-hash one n33c
    call "b-entity" using t-grant t-grant-len nd nd-len
        lk-res lk-reslen lk-reshash st
    *> included = { token, our peer, signature }
    call "ps-idhash" using myidhash
    call "ps-pent"   using mypent mypent-len
    move 0 to lk-incmap-len
    call "b-map"   using lk-incmap lk-incmap-len n3map
    call "b-bytes" using lk-incmap lk-incmap-len token-hash one n33c
    call "b-raw"   using lk-incmap lk-incmap-len token one token-len
    call "b-bytes" using lk-incmap lk-incmap-len myidhash one n33c
    call "b-raw"   using lk-incmap lk-incmap-len mypent one mypent-len
    call "b-bytes" using lk-incmap lk-incmap-len csig-hash one n33c
    call "b-raw"   using lk-incmap lk-incmap-len csig one csig-len
    move 200 to lk-status.

do-revoke.
    if pfd = 0 then perform cap-400-params  exit paragraph end-if
    call "ent-field" using lk-env poff k-token k-token-len voff vf
    if vf = 0 then perform cap-400-params  exit paragraph end-if
    call "read-bytes" using lk-env voff token33 tl
    if tl not = 33 or token33(1:33) = zero33 then perform cap-400-params  exit paragraph end-if
    call "ec_now_ms" using nowv
    move 0 to nd-len
    call "b-map"   using nd nd-len n2c
    call "b-text"  using nd nd-len k-ra k-ra-len
    call "b-uint"  using nd nd-len nowv
    call "b-text"  using nd nd-len k-token k-token-len
    call "b-bytes" using nd nd-len token33 one n33c
    call "b-entity" using t-revoc t-revoc-len nd nd-len mk-ent mk-len mk-hash st
    call "to-hex" using token33 one33 hexh hexlen
    move s-revs to rel(1:30)
    move hexh(1:hexlen) to rel(31:hexlen)
    compute rellen = 30 + hexlen
    call "mkpath" using rel rellen cpath cpathlen
    call "store-bind" using cpath cpathlen mk-ent mk-len mk-hash
    call "empty-params" using lk-res lk-reslen lk-reshash
    move 200 to lk-status.

do-configure.
    if pfd = 0 then perform cap-400-params  exit paragraph end-if
    call "ent-field" using lk-env poff k-pp k-pp-len voff vf
    if vf = 0 then perform cap-400-params  exit paragraph end-if
    call "read-text" using lk-env voff pp pplen
    *> is_hex: 66 lowercase hex chars
    move 0 to ishex
    if pplen = 66
        move 1 to ishex
        perform varying ci from 1 by 1 until ci > 66
            move pp(ci:1) to cch
            if not ((cch >= "0" and cch <= "9") or (cch >= "a" and cch <= "f"))
                move 0 to ishex
                exit perform
            end-if
        end-perform
    end-if
    call "cap-ispid" using pp pplen ispid
    if not ((pplen = 7 and pp(1:7) = "default") or ishex = 1 or ispid = 1)
        move 400 to lk-status
        move "invalid_peer_pattern" to errc move 20 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        exit paragraph
    end-if
    *> bind the params entity at policy/{peer_pattern}
    move poff to pendo
    call "cbor-skip" using lk-env pendo st
    compute pentlen = pendo - poff
    move lk-env(poff:pentlen) to pent(1:pentlen)
    call "ent-hash" using pent one phash
    move s-pol to rel(1:25)
    move pp(1:pplen) to rel(26:pplen)
    compute rellen = 25 + pplen
    call "mkpath" using rel rellen cpath cpathlen
    call "store-bind" using cpath cpathlen pent pentlen phash
    call "empty-params" using lk-res lk-reslen lk-reshash
    move 200 to lk-status.

cap-400-params.
    move 400 to lk-status
    move "unexpected_params" to errc move 17 to errcl
    call "error-result" using errc errcl lk-res lk-reslen lk-reshash.

scope-exceeds.
    move 403 to lk-status
    move "scope_exceeds_authority" to errc move 23 to errcl
    call "error-result" using errc errcl lk-res lk-reslen lk-reshash.
end program capability-handler.

*> ---- to-hex : bytes -> lowercase hex -------------------------------
identification division.
program-id. to-hex.
data division.
working-storage section.
01 hx   pic x(16) value "0123456789abcdef".
01 i    pic 9(9) comp-5.
01 o    pic 9(9) comp-5.
01 hi   pic 9(4) comp-5.
01 lo   pic 9(4) comp-5.
01 bb.
   05 bc pic x.
01 bn redefines bb pic 9(2) comp-x.
linkage section.
01 lk-src    pic x(64).
01 lk-len    pic 9(9) comp-5.
01 lk-out    pic x(256).
01 lk-outlen pic 9(9) comp-5.
procedure division using lk-src lk-len lk-out lk-outlen.
    move 0 to o
    perform varying i from 1 by 1 until i > lk-len
        move lk-src(i:1) to bc
        divide bn by 16 giving hi remainder lo
        add 1 to o  move hx(hi + 1:1) to lk-out(o:1)
        add 1 to o  move hx(lo + 1:1) to lk-out(o:1)
    end-perform
    compute lk-outlen = lk-len * 2
    goback.
end program to-hex.

*> ---- handlers-handler : §6.2 / §6.13a register, unregister ---------
identification division.
program-id. handlers-handler.
data division.
working-storage section.
01 op     pic x(32).
01 oplen  pic 9(9) comp-5.
01 voff   pic 9(9) comp-5.
01 vf     pic 9(1).
01 errc   pic x(32).
01 errcl  pic 9(9) comp-5.
01 k-op   pic x(9) value "operation".
01 k-op-len pic 9(9) comp-5 value 9.
linkage section.
01 lk-env pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash.
    move spaces to op  move 0 to oplen
    call "ent-field" using lk-env lk-rootoff k-op k-op-len voff vf
    if vf = 1 then call "read-text" using lk-env voff op oplen end-if
    evaluate true
        when oplen = 8 and op(1:8) = "register"
            call "do-register" using lk-env lk-rootoff lk-status
                lk-res lk-reslen lk-reshash
        when oplen = 10 and op(1:10) = "unregister"
            call "do-unregister" using lk-env lk-rootoff lk-status
                lk-res lk-reslen lk-reshash
        when other
            move 501 to lk-status
            move "unsupported_operation" to errc move 21 to errcl
            call "error-result" using errc errcl lk-res lk-reslen lk-reshash
    end-evaluate
    goback.
end program handlers-handler.

*> ---- reg-pattern : resource target system/handler/{pattern} --------
identification division.
program-id. reg-pattern.
data division.
working-storage section.
01 tgt    pic x(900).
01 tgtlen pic 9(9) comp-5.
01 tf     pic 9(1).
01 s-hpfx pic x(15) value "system/handler/".
linkage section.
01 lk-env pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-pat pic x(64).
01 lk-patlen pic 9(9) comp-5.
01 lk-ok  pic 9(1).
procedure division using lk-env lk-rootoff lk-pat lk-patlen lk-ok.
    move 0 to lk-ok
    move 0 to lk-patlen
    call "get-target" using lk-env lk-rootoff tgt tgtlen tf
    if tf = 0 then goback end-if
    if tgtlen <= 15 or tgt(1:15) not = s-hpfx then goback end-if
    compute lk-patlen = tgtlen - 15
    move tgt(16:lk-patlen) to lk-pat(1:lk-patlen)
    move 1 to lk-ok
    goback.
end program reg-pattern.

*> ---- do-register : §6.13a five writes ------------------------------
identification division.
program-id. do-register.
data division.
working-storage section.
01 pat    pic x(64).
01 patlen pic 9(9) comp-5.
01 ok     pic 9(1).
01 poff   pic 9(9) comp-5.
01 pfd    pic 9(1).
01 moff   pic 9(9) comp-5.
01 mf     pic 9(1).
01 voff   pic 9(9) comp-5.
01 vf     pic 9(1).
01 nm     pic x(64).
01 nmlen  pic 9(9) comp-5.
01 opsoff pic 9(9) comp-5.
01 opsf   pic 9(1).
01 ops    pic x(8192).
01 opslen pic 9(9) comp-5.
01 endo   pic 9(9) comp-5.
01 exoff  pic 9(9) comp-5.
01 exf    pic 9(1).
01 exprp  pic x(256).
01 exprlen pic 9(9) comp-5.
01 isoff  pic 9(9) comp-5.
01 isf    pic 9(1).
01 rsoff  pic 9(9) comp-5.
01 rsf    pic 9(1).
01 gscope pic x(8192).
01 gslen  pic 9(9) comp-5.
01 toff2  pic 9(9) comp-5.
01 tf2    pic 9(1).
01 idhash pic x(33).
01 token  pic x(8192).
01 token-len pic 9(9) comp-5.
01 token-hash pic x(33).
01 csig   pic x(8192).
01 csig-len pic 9(9) comp-5.
01 csig-hash pic x(33).
01 tdoff  pic 9(9) comp-5.
01 tdf    pic 9(1).
01 tdraw  pic x(8192).
01 tdrawlen pic 9(9) comp-5.
01 hexh   pic x(256).
01 hexlen pic 9(9) comp-5.
01 ent    pic x(8192).
01 entlen pic 9(9) comp-5.
01 hash   pic x(33).
01 rel    pic x(700).
01 rellen pic 9(9) comp-5.
01 path   pic x(700).
01 pathlen pic 9(9) comp-5.
01 iface  pic x(700).
01 ifacelen pic 9(9) comp-5.
01 nd     pic x(8192).
01 nd-len pic 9(9) comp-5.
01 mapcnt pic 9(18) comp-5.
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 one33  pic 9(9) comp-5 value 33.
01 n0     pic 9(18) comp-5 value 0.
01 n1     pic 9(18) comp-5 value 1.
01 n2     pic 9(18) comp-5 value 2.
01 cur    pic 9(9) comp-5.
01 maj    pic 9(2) comp-5.
01 addl   pic 9(2) comp-5.
01 arg    pic 9(18) comp-5.
01 tcnt   pic 9(9) comp-5.
01 ti     pic 9(9) comp-5.
01 tnoff  pic 9(9) comp-5.
01 tnlen  pic 9(9) comp-5.
01 tname  pic x(128).
01 tvoff  pic 9(9) comp-5.
01 tvend  pic 9(9) comp-5.
01 tvraw  pic x(4096).
01 tvlen  pic 9(9) comp-5.
01 errc   pic x(32).
01 errcl  pic 9(9) comp-5.
01 k-params pic x(6) value "params".
01 k-params-len pic 9(9) comp-5 value 6.
01 k-manifest pic x(8) value "manifest".
01 k-manifest-len pic 9(9) comp-5 value 8.
01 k-name pic x(4) value "name".
01 k-name-len pic 9(9) comp-5 value 4.
01 k-ops  pic x(10) value "operations".
01 k-ops-len pic 9(9) comp-5 value 10.
01 k-iface pic x(9) value "interface".
01 k-iface-len pic 9(9) comp-5 value 9.
01 k-pat  pic x(7) value "pattern".
01 k-pat-len pic 9(9) comp-5 value 7.
01 k-expr pic x(15) value "expression_path".
01 k-expr-len pic 9(9) comp-5 value 15.
01 k-iscope pic x(14) value "internal_scope".
01 k-iscope-len pic 9(9) comp-5 value 14.
01 k-rscope pic x(15) value "requested_scope".
01 k-rscope-len pic 9(9) comp-5 value 15.
01 k-types pic x(5) value "types".
01 k-types-len pic 9(9) comp-5 value 5.
01 k-grant pic x(5) value "grant".
01 k-grant-len pic 9(9) comp-5 value 5.
01 k-tp   pic x(33).
01 s-hpfx pic x(15) value "system/handler/".
01 s-grants pic x(25) value "system/capability/grants/".
01 s-sig  pic x(17) value "system/signature/".
01 s-type pic x(12) value "system/type/".
01 t-hdl  pic x(14) value "system/handler".
01 t-hdl-len pic 9(9) comp-5 value 14.
01 t-iface pic x(24) value "system/handler/interface".
01 t-iface-len pic 9(9) comp-5 value 24.
01 t-type pic x(11) value "system/type".
01 t-type-len pic 9(9) comp-5 value 11.
01 t-result pic x(31) value "system/handler/register-result".
01 t-result-len pic 9(9) comp-5 value 30.
linkage section.
01 lk-env pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash.
    call "reg-pattern" using lk-env lk-rootoff pat patlen ok
    if ok = 0
        move 400 to lk-status
        move "ambiguous_resource" to errc move 18 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        goback
    end-if
    call "ent-field" using lk-env lk-rootoff k-params k-params-len poff pfd
    if pfd = 0
        move 400 to lk-status
        move "unexpected_params" to errc move 17 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        goback
    end-if
    *> manifest map
    call "ent-field" using lk-env poff k-manifest k-manifest-len moff mf
    *> name (default = pattern)
    move pat(1:patlen) to nm(1:patlen)  move patlen to nmlen
    if mf = 1
        call "cbor-find-key" using lk-env moff k-name k-name-len voff vf st
        if vf = 1 then call "read-text" using lk-env voff nm nmlen end-if
    end-if
    *> operations: manifest.operations (raw) or empty map
    move 0 to opslen
    if mf = 1
        call "cbor-find-key" using lk-env moff k-ops k-ops-len opsoff opsf st
        if opsf = 1
            move opsoff to endo
            call "cbor-skip" using lk-env endo st
            compute opslen = endo - opsoff
            move lk-env(opsoff:opslen) to ops(1:opslen)
        end-if
    end-if
    if opslen = 0
        call "b-map" using ops opslen n0
    end-if
    *> expression_path (optional)
    move 0 to exprlen
    if mf = 1
        call "cbor-find-key" using lk-env moff k-expr k-expr-len exoff exf st
        if exf = 1 then call "read-text" using lk-env exoff exprp exprlen end-if
    end-if
    *> internal_scope (optional, raw)
    move 0 to isf
    if mf = 1
        call "cbor-find-key" using lk-env moff k-iscope k-iscope-len isoff isf st
    end-if
    *> requested_scope (optional, raw)
    call "ent-field" using lk-env poff k-rscope k-rscope-len rsoff rsf
    *> grant_scope = requested_scope ?? internal_scope ?? []
    move 0 to gslen
    if rsf = 1
        move rsoff to endo
        call "cbor-skip" using lk-env endo st
        compute gslen = endo - rsoff
        move lk-env(rsoff:gslen) to gscope(1:gslen)
    else
        if isf = 1
            move isoff to endo
            call "cbor-skip" using lk-env endo st
            compute gslen = endo - isoff
            move lk-env(isoff:gslen) to gscope(1:gslen)
        else
            move 0 to mapcnt
            call "b-arr" using gscope gslen mapcnt
        end-if
    end-if

    *> ---- (1) handler entity at /{local}/{pattern} ----
    move 0 to nd-len
    if exprlen > 0
        call "b-map" using nd nd-len n2
    else
        call "b-map" using nd nd-len n1
    end-if
    call "b-text" using nd nd-len k-iface k-iface-len
    move s-hpfx to iface(1:15)
    move pat(1:patlen) to iface(16:patlen)
    compute ifacelen = 15 + patlen
    call "b-text" using nd nd-len iface ifacelen
    if exprlen > 0
        call "b-text" using nd nd-len k-expr k-expr-len
        call "b-text" using nd nd-len exprp exprlen
    end-if
    call "b-entity" using t-hdl t-hdl-len nd nd-len ent entlen hash st
    move pat(1:patlen) to rel(1:patlen)  move patlen to rellen
    call "mkpath" using rel rellen path pathlen
    call "store-bind" using path pathlen ent entlen hash

    *> ---- (2) associated types ----
    if pfd = 1
        call "ent-field" using lk-env poff k-types k-types-len toff2 tf2
        if tf2 = 1
            move toff2 to cur
            call "cbor-read-head" using lk-env cur maj addl arg st
            if maj = 5
                move arg to tcnt
                perform varying ti from 1 by 1 until ti > tcnt
                    call "cbor-read-head" using lk-env cur maj addl arg st
                    move arg to tnlen  move cur to tnoff
                    add tnlen to cur
                    move lk-env(tnoff:tnlen) to tname(1:tnlen)
                    move cur to tvoff  move cur to tvend
                    call "cbor-skip" using lk-env tvend st
                    compute tvlen = tvend - tvoff
                    *> the type value IS the system/type data payload (already canonical)
                    call "b-entity" using t-type t-type-len lk-env(tvoff:tvlen) tvlen
                        ent entlen hash st
                    move s-type to rel(1:12)
                    move tname(1:tnlen) to rel(13:tnlen)
                    compute rellen = 12 + tnlen
                    call "mkpath" using rel rellen path pathlen
                    call "store-bind" using path pathlen ent entlen hash
                    move tvend to cur
                end-perform
            end-if
        end-if
    end-if

    *> ---- (3) self-signed grant token ----
    call "ps-idhash" using idhash
    call "mint-token" using idhash gscope gslen
        token token-len token-hash csig csig-len csig-hash
    move s-grants to rel(1:25)
    move pat(1:patlen) to rel(26:patlen)
    compute rellen = 25 + patlen
    call "mkpath" using rel rellen path pathlen
    call "store-bind" using path pathlen token token-len token-hash

    *> ---- (4) grant signature at the §3.5 invariant path ----
    call "to-hex" using token-hash one33 hexh hexlen
    move s-sig to rel(1:17)
    move hexh(1:hexlen) to rel(18:hexlen)
    compute rellen = 17 + hexlen
    call "mkpath" using rel rellen path pathlen
    call "store-bind" using path pathlen csig csig-len csig-hash

    *> ---- (5) interface entity at /{local}/system/handler/{pattern} ----
    move 0 to nd-len
    call "b-map"  using nd nd-len n2
    call "b-text" using nd nd-len k-name k-name-len
    call "b-text" using nd nd-len nm nmlen
    call "b-text" using nd nd-len k-ops k-ops-len
    call "b-raw"  using nd nd-len ops one opslen
    call "b-text" using nd nd-len k-pat k-pat-len
    call "b-text" using nd nd-len pat patlen
    call "b-entity" using t-iface t-iface-len nd nd-len ent entlen hash st
    move s-hpfx to rel(1:15)
    move pat(1:patlen) to rel(16:patlen)
    compute rellen = 15 + patlen
    call "mkpath" using rel rellen path pathlen
    call "store-bind" using path pathlen ent entlen hash

    *> ---- result: register-result { pattern, grant: token.data } ----
    call "ent-find-data" using token one tdoff st
    move tdoff to tvend
    call "cbor-skip" using token tvend st
    compute tdrawlen = tvend - tdoff
    move token(tdoff:tdrawlen) to tdraw(1:tdrawlen)
    move 0 to nd-len
    call "b-map"  using nd nd-len n2
    call "b-text" using nd nd-len k-grant k-grant-len
    call "b-raw"  using nd nd-len tdraw one tdrawlen
    call "b-text" using nd nd-len k-pat k-pat-len
    call "b-text" using nd nd-len pat patlen
    call "b-entity" using t-result t-result-len nd nd-len
        lk-res lk-reslen lk-reshash st
    move 200 to lk-status
    goback.
end program do-register.

*> ---- do-unregister : reverse the five writes -----------------------
identification division.
program-id. do-unregister.
data division.
working-storage section.
01 pat    pic x(64).
01 patlen pic 9(9) comp-5.
01 ok     pic 9(1).
01 rel    pic x(700).
01 rellen pic 9(9) comp-5.
01 path   pic x(700).
01 pathlen pic 9(9) comp-5.
01 gent   pic x(8192).
01 gentlen pic 9(9) comp-5.
01 gf     pic 9(1).
01 ghash  pic x(33).
01 hexh   pic x(256).
01 hexlen pic 9(9) comp-5.
01 s-grants pic x(25) value "system/capability/grants/".
01 s-sig  pic x(17) value "system/signature/".
01 s-hpfx pic x(15) value "system/handler/".
01 one    pic 9(9) comp-5 value 1.
01 one33  pic 9(9) comp-5 value 33.
01 errc   pic x(32).
01 errcl  pic 9(9) comp-5.
linkage section.
01 lk-env pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash.
    call "reg-pattern" using lk-env lk-rootoff pat patlen ok
    if ok = 0
        move 400 to lk-status
        move "ambiguous_resource" to errc move 18 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        goback
    end-if
    *> grant token -> remove its signature, then the grant
    move s-grants to rel(1:25)
    move pat(1:patlen) to rel(26:patlen)
    compute rellen = 25 + patlen
    call "mkpath" using rel rellen path pathlen
    call "store-get-at" using path pathlen gent gentlen gf
    if gf = 1
        call "ent-hash" using gent one ghash
        call "to-hex" using ghash one33 hexh hexlen
        move s-sig to rel(1:17)
        move hexh(1:hexlen) to rel(18:hexlen)
        compute rellen = 17 + hexlen
        call "mkpath" using rel rellen path pathlen
        call "store-unbind" using path pathlen
        move s-grants to rel(1:25)
        move pat(1:patlen) to rel(26:patlen)
        compute rellen = 25 + patlen
        call "mkpath" using rel rellen path pathlen
        call "store-unbind" using path pathlen
    end-if
    *> handler entity + interface
    move pat(1:patlen) to rel(1:patlen)  move patlen to rellen
    call "mkpath" using rel rellen path pathlen
    call "store-unbind" using path pathlen
    move s-hpfx to rel(1:15)
    move pat(1:patlen) to rel(16:patlen)
    compute rellen = 15 + patlen
    call "mkpath" using rel rellen path pathlen
    call "store-unbind" using path pathlen
    call "empty-params" using lk-res lk-reslen lk-reshash
    move 200 to lk-status
    goback.
end program do-unregister.

identification division.
program-id. types-handler.
data division.
working-storage section.
01 errc  pic x(32).
01 errcl pic 9(9) comp-5.
linkage section.
01 lk-env pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash.
    move 501 to lk-status
    move "unsupported_operation" to errc move 21 to errcl
    call "error-result" using errc errcl lk-res lk-reslen lk-reshash
    goback.
end program types-handler.

*> ---- echo-handler : §7a.1 verbatim echo of the params entity --------
identification division.
program-id. echo-handler.
data division.
working-storage section.
01 poff   pic 9(9) comp-5.
01 pfd    pic 9(1).
01 endo   pic 9(9) comp-5.
01 plen   pic 9(9) comp-5.
01 st     pic s9(9) comp-5.
01 one    pic 9(9) comp-5 value 1.
01 k-params pic x(6) value "params".
01 k-params-len pic 9(9) comp-5 value 6.
01 errc   pic x(32).
01 errcl  pic 9(9) comp-5.
linkage section.
01 lk-env pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash.
    call "ent-field" using lk-env lk-rootoff k-params k-params-len poff pfd
    if pfd = 0
        move 400 to lk-status
        move "invalid_params" to errc move 14 to errcl
        call "error-result" using errc errcl lk-res lk-reslen lk-reshash
        goback
    end-if
    move poff to endo
    call "cbor-skip" using lk-env endo st
    compute plen = endo - poff
    move lk-env(poff:plen) to lk-res(1:plen)
    move plen to lk-reslen
    call "ent-hash" using lk-env poff lk-reshash
    move 200 to lk-status
    goback.
end program echo-handler.

*> ---- dispatch-outbound-handler : §7a.2 §6.11 reentry seam -----------
*> A reentrant outbound EXECUTE back to the caller. In the single-threaded
*> poll-loop host the live reentry seam is wired via the C transport
*> (ec_reentry); this COBOL entry is the dispatch arm (see peer.cob).
identification division.
program-id. dispatch-outbound-handler.
data division.
working-storage section.
01 errc   pic x(32).
01 errcl  pic 9(9) comp-5.
linkage section.
01 lk-env pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-status pic 9(9) comp-5.
01 lk-res pic x(60000).
01 lk-reslen pic 9(9) comp-5.
01 lk-reshash pic x(33).
procedure division using lk-env lk-rootoff lk-status lk-res lk-reslen lk-reshash.
    move 503 to lk-status
    move "no_outbound_seam" to errc move 16 to errcl
    call "error-result" using errc errcl lk-res lk-reslen lk-reshash
    goback.
end program dispatch-outbound-handler.
