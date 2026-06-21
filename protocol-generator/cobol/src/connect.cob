>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — connect handler (§4.1, §4.6).
*>
*> hello (§4.1): issue a 32-byte nonce, return a system/protocol/connect/hello.
*> authenticate (§4.6): three-check proof-of-possession — nonce echo, Ed25519
*> signature over the authenticate entity hash (FFI), and identity binding
*> (claimed peer_id == peer_id derived from the presented public key). On success
*> mint the §4.4 initial capability (discovery floor, +open under --debug-open-
*> grants), sign it, and return system/capability/grant with token+granter+sig
*> in the included map.
*>
*> Per-connection state rides in LK-CONN (256-byte buffer the host zero-inits):
*>   c-estab(1) c-havenonce(1) c-nonce(32) c-hpid-len(4) c-hpid(64).
*> ===================================================================

*> ---- inc-find-sig-for : included system/signature targeting a hash --
*> Walk the included map at LK-INCOFF; return the offset of the first
*> system/signature entity whose data.target = LK-TARGET (LK-FOUND=1).
identification division.
program-id. inc-find-sig-for.
data division.
working-storage section.
01 cur     pic 9(9) comp-5.
01 entoff  pic 9(9) comp-5.
01 rmaj    pic 9(2) comp-5.
01 raddl   pic 9(2) comp-5.
01 rarg    pic 9(18) comp-5.
01 npairs  pic 9(9) comp-5.
01 i       pic 9(9) comp-5.
01 voff    pic 9(9) comp-5.
01 st      pic s9(9) comp-5.
01 etype   pic x(64).
01 etlen   pic 9(9) comp-5.
01 k-tgt   pic x(6) value "target".
01 k-tgt-len pic 9(9) comp-5 value 6.
01 tfnd    pic 9(1).
01 tgt33   pic x(33).
01 tlen    pic 9(9) comp-5.
01 t-sig   pic x(16) value "system/signature".
linkage section.
01 lk-buf    pic x(65535).
01 lk-incoff pic 9(9) comp-5.
01 lk-target pic x(33).
01 lk-sigoff pic 9(9) comp-5.
01 lk-found  pic 9(1).
procedure division using lk-buf lk-incoff lk-target lk-sigoff lk-found.
    move 0 to lk-found
    move lk-incoff to cur
    call "cbor-read-head" using lk-buf cur rmaj raddl rarg st
    if rmaj not = 5 then goback end-if
    move rarg to npairs
    perform varying i from 1 by 1 until i > npairs
        call "cbor-skip" using lk-buf cur st        *> skip the byte-string key
        move cur to entoff                          *> value entity offset
        call "ent-type" using lk-buf entoff etype etlen
        if etlen = 16 and etype(1:16) = t-sig
            call "ent-field" using lk-buf entoff k-tgt k-tgt-len voff tfnd
            if tfnd = 1
                call "read-bytes" using lk-buf voff tgt33 tlen
                if tlen = 33 and tgt33(1:33) = lk-target(1:33)
                    move entoff to lk-sigoff
                    move 1 to lk-found
                    exit perform
                end-if
            end-if
        end-if
        call "cbor-skip" using lk-buf cur st         *> advance past the value entity
    end-perform
    goback.
end program inc-find-sig-for.

*> ---- connect-handler -----------------------------------------------
identification division.
program-id. connect-handler.
data division.
working-storage section.
01 op       pic x(32).
01 op-len   pic 9(9) comp-5.
01 k-op     pic x(9) value "operation".
01 k-op-len pic 9(9) comp-5 value 9.
01 k-params pic x(6) value "params".
01 k-params-len pic 9(9) comp-5 value 6.
01 voff     pic 9(9) comp-5.
01 vfnd     pic 9(1).
01 params-off pic 9(9) comp-5.
01 pfnd     pic 9(1).
*> hello build
01 t-hello  pic x(29) value "system/protocol/connect/hello".
01 t-hello-len pic 9(9) comp-5 value 29.
01 k-peerid pic x(7) value "peer_id".
01 k-nonce  pic x(5) value "nonce".
01 k-proto  pic x(9) value "protocols".
01 k-ts     pic x(9) value "timestamp".
01 k-hf     pic x(12) value "hash_formats".
01 k-ktypes pic x(9) value "key_types".
01 v-proto  pic x(15) value "entity-core/1.0".
01 v-hf     pic x(12) value "ecfv1-sha256".
01 v-ed     pic x(7) value "ed25519".
01 my-peerid pic x(128).
01 my-peerid-len pic 9(9) comp-5.
01 nd       pic x(8192).
01 nd-len   pic 9(9) comp-5.
01 one      pic 9(9) comp-5 value 1.
01 n0map    pic 9(18) comp-5 value 0.
01 n3map    pic 9(18) comp-5 value 3.
01 n33-c    pic 9(9) comp-5 value 33.
01 n1       pic 9(18) comp-5 value 1.
01 n5       pic 9(18) comp-5 value 5.
01 n6       pic 9(18) comp-5 value 6.
01 n7       pic 9(18) comp-5 value 7.
01 n9       pic 9(18) comp-5 value 9.
01 n12      pic 9(18) comp-5 value 12.
01 n15      pic 9(18) comp-5 value 15.
01 n32      pic 9(9) comp-5 value 32.
01 ts       pic 9(18) comp-5 value 1700000000000.
01 st       pic s9(9) comp-5.
01 hh       pic x(33).
*> authenticate
01 pub      pic x(32).
01 publen   pic 9(9) comp-5.
01 echoed   pic x(32).
01 echolen  pic 9(9) comp-5.
01 claimed  pic x(128).
01 claimlen pic 9(9) comp-5.
01 authhash pic x(33).
01 sigoff   pic 9(9) comp-5.
01 sigfnd   pic 9(1).
01 k-sig    pic x(9) value "signature".
01 k-sig-len pic 9(9) comp-5 value 9.
01 k-pk     pic x(10) value "public_key".
01 k-pk-len pic 9(9) comp-5 value 10.
01 k-nc     pic x(5) value "nonce".
01 k-nc-len pic 9(9) comp-5 value 5.
01 k-pid    pic x(7) value "peer_id".
01 k-pid-len pic 9(9) comp-5 value 7.
01 sigbytes pic x(64).
01 sigblen  pic 9(9) comp-5.
01 verok    pic 9(1).
01 derived  pic x(128).
01 derivedlen pic 9(9) comp-5.
01 rpent    pic x(8192).
01 rpent-len pic 9(9) comp-5.
01 ridhash  pic x(33).
01 grants   pic x(8192).
01 grants-len pic 9(9) comp-5.
01 openf    pic 9(1).
01 conff    pic 9(1).
01 token    pic x(8192).
01 token-len pic 9(9) comp-5.
01 token-hash pic x(33).
01 csig     pic x(8192).
01 csig-len pic 9(9) comp-5.
01 csig-hash pic x(33).
01 myidhash pic x(33).
01 mypent   pic x(8192).
01 mypent-len pic 9(9) comp-5.
01 k-token  pic x(5) value "token".
01 t-grant  pic x(23) value "system/capability/grant".
01 t-grant-len pic 9(9) comp-5 value 23.
01 hfok     pic 9(1).
01 ktok     pic 9(1).
01 c7       pic 9(9) comp-5 value 7.
01 c9       pic 9(9) comp-5 value 9.
01 c12      pic 9(9) comp-5 value 12.
01 k-ktf    pic x(8) value "key_type".
01 k-ktf-len pic 9(9) comp-5 value 8.
01 ktval    pic x(32).
01 ktvallen pic 9(9) comp-5.
01 decbuf   pic x(256).
01 declen   pic 9(9) comp-5.
01 errc     pic x(32).
01 errc-len pic 9(9) comp-5.
linkage section.
01 lk-conn.
   05 c-estab     pic 9(1).
   05 c-havenonce pic 9(1).
   05 c-nonce     pic x(32).
   05 c-hpid-len  pic 9(9) comp-5.
   05 c-hpid      pic x(64).
01 lk-buf     pic x(65535).
01 lk-rootoff pic 9(9) comp-5.
01 lk-incoff  pic 9(9) comp-5.
01 lk-incfnd  pic 9(1).
01 lk-rstatus pic 9(9) comp-5.
01 lk-res     pic x(8192).
01 lk-res-len pic 9(9) comp-5.
01 lk-res-hash pic x(33).
01 lk-incmap  pic x(16384).
01 lk-incmap-len pic 9(9) comp-5.
procedure division using lk-conn lk-buf lk-rootoff lk-incoff lk-incfnd
                        lk-rstatus lk-res lk-res-len lk-res-hash
                        lk-incmap lk-incmap-len.
    move 0 to lk-incmap-len
    *> empty included map by default
    call "b-map" using lk-incmap lk-incmap-len n0map
    *> operation
    move spaces to op  move 0 to op-len
    call "ent-field" using lk-buf lk-rootoff k-op k-op-len voff vfnd
    if vfnd = 1 then call "read-text" using lk-buf voff op op-len end-if
    *> params entity offset
    move 0 to pfnd
    call "ent-field" using lk-buf lk-rootoff k-params k-params-len params-off pfnd

    evaluate true
        when op-len = 5 and op(1:5) = "hello"
            perform do-hello
        when op-len = 12 and op(1:12) = "authenticate"
            perform do-auth
        when other
            move 501 to lk-rstatus
            move "unsupported_operation" to errc move 21 to errc-len
            call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash
    end-evaluate
    goback.

*> ---- hello ---------------------------------------------------------
do-hello.
    if c-estab = 1
        move 409 to lk-rstatus
        move "connection_already_established" to errc move 30 to errc-len
        call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash
        exit paragraph
    end-if
    *> §4.5 negotiation: reject disjoint hash_formats / key_types
    if pfnd = 1
        call "neg-ok" using lk-buf params-off k-hf c12 v-hf c12 hfok
        if hfok = 0
            move 400 to lk-rstatus
            move "incompatible_hash_format" to errc move 24 to errc-len
            call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash
            exit paragraph
        end-if
        call "neg-ok" using lk-buf params-off k-ktypes c9 v-ed c7 ktok
        if ktok = 0
            move 400 to lk-rstatus
            move "unsupported_key_type" to errc move 20 to errc-len
            call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash
            exit paragraph
        end-if
    end-if
    *> capture the initiator's claimed peer_id (optional)
    if pfnd = 1
        call "ent-field" using lk-buf params-off k-pid k-pid-len voff vfnd
        if vfnd = 1
            call "read-text" using lk-buf voff c-hpid c-hpid-len
        end-if
    end-if
    *> issue a 32-byte nonce
    call "ec_random" using by reference c-nonce by value 32 returning st
    move 1 to c-havenonce
    call "ps-peerid" using my-peerid my-peerid-len
    *> hello data map(6)
    move 0 to nd-len
    call "b-map"  using nd nd-len n6
    call "b-text" using nd nd-len k-peerid n7
    call "b-text" using nd nd-len my-peerid my-peerid-len
    call "b-text" using nd nd-len k-nonce n5
    call "b-bytes" using nd nd-len c-nonce one n32
    call "b-text" using nd nd-len k-proto n9
    call "b-arr"  using nd nd-len n1
    call "b-text" using nd nd-len v-proto n15
    call "b-text" using nd nd-len k-ts n9
    call "b-uint" using nd nd-len ts
    call "b-text" using nd nd-len k-hf n12
    call "b-arr"  using nd nd-len n1
    call "b-text" using nd nd-len v-hf n12
    call "b-text" using nd nd-len k-ktypes n9
    call "b-arr"  using nd nd-len n1
    call "b-text" using nd nd-len v-ed n7
    call "b-entity" using t-hello t-hello-len nd nd-len
        lk-res lk-res-len lk-res-hash st
    move 200 to lk-rstatus.

*> ---- authenticate --------------------------------------------------
do-auth.
    if c-estab = 1
        move 409 to lk-rstatus
        move "connection_already_established" to errc move 30 to errc-len
        call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash
        exit paragraph
    end-if
    if c-havenonce = 0
        perform auth-401-nonce  exit paragraph
    end-if
    if pfnd = 0
        perform auth-401  exit paragraph
    end-if
    *> read public_key, echoed nonce, claimed peer_id from the params entity
    move 0 to publen
    call "ent-field" using lk-buf params-off k-pk k-pk-len voff vfnd
    if vfnd = 1 then call "read-bytes" using lk-buf voff pub publen end-if
    move 0 to echolen
    call "ent-field" using lk-buf params-off k-nc k-nc-len voff vfnd
    if vfnd = 1 then call "read-bytes" using lk-buf voff echoed echolen end-if
    move 0 to claimlen
    call "ent-field" using lk-buf params-off k-pid k-pid-len voff vfnd
    if vfnd = 1 then call "read-text" using lk-buf voff claimed claimlen end-if
    *> §4.6 / AGILITY-UNKNOWN-1: an unsupported key_type rides in the key_type
    *> field, a non-32-byte public_key, or the claimed peer_id's key_type byte.
    move 0 to ktvallen
    call "ent-field" using lk-buf params-off k-ktf k-ktf-len voff vfnd
    if vfnd = 1 then call "read-text" using lk-buf voff ktval ktvallen end-if
    if ktvallen > 0 and not (ktvallen = 7 and ktval(1:7) = "ed25519")
        perform auth-400-keytype  exit paragraph
    end-if
    *> the claimed peer_id's leading key_type byte (Base58-decoded) MUST be 0x01
    if claimlen > 0
        call "base58-decode" using claimed claimlen decbuf declen
        if declen >= 1 and decbuf(1:1) not = x"01"
            perform auth-400-keytype  exit paragraph
        end-if
    end-if
    *> the authenticate entity's own content_hash
    call "ent-hash" using lk-buf params-off authhash
    *> step 1: nonce echo
    if not (echolen = 32 and echoed(1:32) = c-nonce)
        perform auth-401-nonce  exit paragraph
    end-if
    if publen not = 32
        perform auth-400-keytype  exit paragraph
    end-if
    *> step 2: proof of possession — verify the signature over authhash
    if lk-incfnd = 0
        perform auth-401  exit paragraph
    end-if
    call "inc-find-sig-for" using lk-buf lk-incoff authhash sigoff sigfnd
    if sigfnd = 0
        perform auth-401  exit paragraph
    end-if
    call "ent-field" using lk-buf sigoff k-sig k-sig-len voff vfnd
    if vfnd = 0
        perform auth-401  exit paragraph
    end-if
    call "read-bytes" using lk-buf voff sigbytes sigblen
    call "verify-sig" using pub authhash sigbytes verok
    if verok = 0
        perform auth-401  exit paragraph
    end-if
    *> step 3: identity binding — claimed == derived peer_id
    call "peer-id-of-pubkey" using pub n32 derived derivedlen
    if not (claimlen = derivedlen and claimed(1:claimlen) = derived(1:derivedlen))
        move 401 to lk-rstatus
        move "identity_mismatch" to errc move 17 to errc-len
        call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash
        exit paragraph
    end-if
    *> hello/authenticate peer_id consistency
    if c-hpid-len > 0 and not (c-hpid-len = claimlen and c-hpid(1:c-hpid-len) = claimed(1:claimlen))
        move 401 to lk-rstatus
        move "identity_mismatch" to errc move 17 to errc-len
        call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash
        exit paragraph
    end-if
    *> success: mint the initial capability
    call "peer-entity-of-pubkey" using pub rpent rpent-len ridhash
    call "ps-flags" using openf conff
    move 0 to grants-len
    call "build-grants" using grants grants-len openf
    call "mint-token" using ridhash grants grants-len
        token token-len token-hash csig csig-len csig-hash
    move 1 to c-estab
    *> result = system/capability/grant {token: bytes token-hash}
    move 0 to nd-len
    call "b-map"   using nd nd-len n1
    call "b-text"  using nd nd-len k-token n5
    call "b-bytes" using nd nd-len token-hash one n33-c
    call "b-entity" using t-grant t-grant-len nd nd-len
        lk-res lk-res-len lk-res-hash st
    *> included = { token, our peer entity, token signature }
    call "ps-idhash" using myidhash
    call "ps-pent"   using mypent mypent-len
    move 0 to lk-incmap-len
    call "b-map"   using lk-incmap lk-incmap-len n3map
    call "b-bytes" using lk-incmap lk-incmap-len token-hash one n33-c
    call "b-raw"   using lk-incmap lk-incmap-len token one token-len
    call "b-bytes" using lk-incmap lk-incmap-len myidhash one n33-c
    call "b-raw"   using lk-incmap lk-incmap-len mypent one mypent-len
    call "b-bytes" using lk-incmap lk-incmap-len csig-hash one n33-c
    call "b-raw"   using lk-incmap lk-incmap-len csig one csig-len
    move 200 to lk-rstatus.

auth-401.
    move 401 to lk-rstatus
    move "authentication_failed" to errc move 21 to errc-len
    call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash.

auth-401-nonce.
    move 401 to lk-rstatus
    move "invalid_nonce" to errc move 13 to errc-len
    call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash.

auth-400-keytype.
    move 400 to lk-rstatus
    move "unsupported_key_type" to errc move 20 to errc-len
    call "error-result" using errc errc-len lk-res lk-res-len lk-res-hash.
end program connect-handler.

*> ---- neg-ok : §4.5 — an advertised string-set accepts the target ----
*> Returns 1 if the array at params.data.{key} is absent (no constraint) OR
*> contains the target string; 0 if present and disjoint.
identification division.
program-id. neg-ok.
data division.
working-storage section.
01 voff pic 9(9) comp-5.
01 f    pic 9(1).
01 cur  pic 9(9) comp-5.
01 maj  pic 9(2) comp-5.
01 addl pic 9(2) comp-5.
01 arg  pic 9(18) comp-5.
01 cnt  pic 9(9) comp-5.
01 i    pic 9(9) comp-5.
01 elen pic 9(9) comp-5.
01 st   pic s9(9) comp-5.
linkage section.
01 lk-buf    pic x(65535).
01 lk-poff   pic 9(9) comp-5.
01 lk-key    pic x(32).
01 lk-keylen pic 9(9) comp-5.
01 lk-tgt    pic x(32).
01 lk-tgtlen pic 9(9) comp-5.
01 lk-ok     pic 9(1).
procedure division using lk-buf lk-poff lk-key lk-keylen lk-tgt lk-tgtlen lk-ok.
    move 1 to lk-ok
    call "ent-field" using lk-buf lk-poff lk-key lk-keylen voff f
    if f = 0 then goback end-if
    move voff to cur
    call "cbor-read-head" using lk-buf cur maj addl arg st
    if maj not = 4 then goback end-if
    move arg to cnt
    move 0 to lk-ok
    perform varying i from 1 by 1 until i > cnt
        call "cbor-read-head" using lk-buf cur maj addl arg st
        move arg to elen
        if maj = 3 and elen = lk-tgtlen and lk-buf(cur:elen) = lk-tgt(1:lk-tgtlen)
            move 1 to lk-ok
        end-if
        add elen to cur
    end-perform
    goback.
end program neg-ok.
