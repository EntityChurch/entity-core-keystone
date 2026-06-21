>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — S2 codec conformance self-test.
*>
*> Loads the pinned normative fixture (conformance-vectors-v1.cbor), walks it
*> with the COBOL CBOR navigator (cbor.cob), and runs every vector:
*>   structural encode_equal (float/int/length/primitive/map_keys/nested/
*>     envelope)  -> canonicalizing transcoder, compare to `canonical`
*>   content_hash/peer_id/signature -> FFI (libentitycore_codec), compare
*>   decode_reject                  -> transcoder MUST reject (status 3)
*> Byte-identity or rejection per Appendix E §E.3. No running Go oracle needed
*> (the fixture carries its own cross-blessed canonical bytes).
*> ===================================================================
identification division.
program-id. codec-selftest.
environment division.
configuration section.
data division.
working-storage section.
01 fixture-path  pic x(256).
01 fixbuf        pic x(16384).
01 fixlen        pic 9(18) comp-5.
01 rc            pic s9(9) comp-5.

01 cur        pic 9(9) comp-5.
01 top-major     pic 9(2) comp-5.
01 top-addl      pic 9(2) comp-5.
01 nvec          pic 9(18) comp-5.
01 vec-i         pic 9(9) comp-5.
01 vmap-off      pic 9(9) comp-5.

01 found         pic 9(1).
01 voff          pic 9(9) comp-5.
01 rhmaj         pic 9(2) comp-5.
01 rhaddl        pic 9(2) comp-5.
01 rharg         pic 9(18) comp-5.
01 scan-off      pic 9(9) comp-5.
01 st            pic s9(9) comp-5.

01 id-str        pic x(64).
01 id-len        pic 9(9) comp-5.
01 cat           pic x(32).
01 kind-str      pic x(32).
01 kind-len      pic 9(9) comp-5.

01 canon-off     pic 9(9) comp-5.
01 canon-len     pic 9(9) comp-5.
01 input-off     pic 9(9) comp-5.

01 out-buf       pic x(8192).
01 out-len       pic 9(9) comp-5.
01 reject-end    pic 9(9) comp-5.
01 pk            pic 9(9) comp-5.

*> content_hash inputs
01 type-off      pic 9(9) comp-5.
01 type-len      pic 9(9) comp-5.
01 data-off      pic 9(9) comp-5.
01 data-len      pic 9(9) comp-5.
01 fmt-code      pic 9(18) comp-5.
01 has-fmt       pic 9(1).
01 ch-out        pic x(64).

*> peer_id inputs
01 key-type      pic 9(18) comp-5.
01 hash-type     pic 9(18) comp-5.
01 dig-off       pic 9(9) comp-5.
01 dig-len       pic 9(9) comp-5.
01 pid-out       pic x(128).
01 pid-len       pic 9(18) comp-5.

*> signature inputs
01 seed-off      pic 9(9) comp-5.
01 seed-len      pic 9(9) comp-5.
01 ent-off       pic 9(9) comp-5.
01 ecf-out       pic x(4096).
01 ecf-len       pic 9(18) comp-5.
01 sig-out       pic x(64).

*> tallies
01 npass         pic 9(4) value 0.
01 nfail         pic 9(4) value 0.
01 nskip         pic 9(4) value 0.
01 key-name      pic x(32).
01 key-name-len  pic 9(9) comp-5.

procedure division.
    *> locate + load the fixture (path from arg or default)
    accept fixture-path from command-line
    if fixture-path = spaces
        move "/work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
          to fixture-path
    end-if
    *> null-terminate for the C reader (first trailing-space -> NUL ends the path)
    inspect fixture-path replacing trailing space by x"00"
    call "ec_read_file" using
        by reference fixture-path
        by reference fixbuf
        by value 16384
        by reference fixlen
        returning rc
    if rc not = 0
        display "FATAL: cannot read fixture"
        move 1 to return-code
        stop run
    end-if
    display "loaded fixture: " fixlen " bytes"

    *> top must be an array(N)
    move 1 to cur
    call "cbor-read-head" using fixbuf cur top-major top-addl nvec st
    if top-major not = 4
        display "FATAL: fixture top is not an array (major=" top-major ")"
        move 1 to return-code
        stop run
    end-if
    display "vectors: " nvec
    display " "

    perform varying vec-i from 1 by 1 until vec-i > nvec
        move cur to vmap-off
        perform do-vector
        *> advance cur past this vector map
        call "cbor-skip" using fixbuf cur st
    end-perform

    display " "
    display "codec-selftest: " npass " pass, " nfail " fail, " nskip " skip"
    if nfail = 0
        display "codec-selftest RESULT: PASS"
        move 0 to return-code
    else
        display "codec-selftest RESULT: FAIL"
        move 1 to return-code
    end-if
    stop run.

*> ---- process one vector map at vmap-off ----------------------------
do-vector.
    *> id
    move "id" to key-name  move 2 to key-name-len
    perform find
    if found = 0 then perform vec-bad exit paragraph end-if
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to id-len
    move spaces to id-str
    move fixbuf(scan-off:id-len) to id-str(1:id-len)
    *> category = id up to '.'
    perform derive-cat

    *> kind
    move "kind" to key-name  move 4 to key-name-len
    perform find
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to kind-len
    move spaces to kind-str
    move fixbuf(scan-off:kind-len) to kind-str(1:kind-len)

    *> canonical (byte string)
    move "canonical" to key-name  move 9 to key-name-len
    perform find
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to canon-len
    move scan-off to canon-off

    *> input value offset (present on every vector)
    move "input" to key-name  move 5 to key-name-len
    perform find
    move voff to input-off

    *> dispatch
    evaluate true
        when kind-str(1:kind-len) = "decode_reject"
            perform do-reject
        when cat = "content_hash"
            perform do-content-hash
        when cat = "peer_id"
            perform do-peer-id
        when cat = "signature"
            perform do-signature
        when other
            perform do-structural
    end-evaluate.

*> find key-name in the vector map -> voff, found
find.
    call "cbor-find-key" using fixbuf vmap-off key-name key-name-len
                                voff found st.

derive-cat.
    move spaces to cat
    move 0 to scan-off
    inspect id-str tallying scan-off for characters before initial "."
    move id-str(1:scan-off) to cat.

vec-bad.
    add 1 to nfail
    display "FAIL vector " vec-i " (missing id)".

*> ---- structural: transcode input -> compare canonical --------------
do-structural.
    move input-off to scan-off
    move 0 to out-len
    move 0 to st
    call "cbor-canon" using fixbuf scan-off out-buf out-len st
    evaluate true
        when st not = 0
            add 1 to nfail
            display "FAIL " id-str(1:id-len) " (transcode status " st ")"
        when out-len not = canon-len
            add 1 to nfail
            display "FAIL " id-str(1:id-len) " (len " out-len " want " canon-len ")"
        when out-buf(1:out-len) not = fixbuf(canon-off:canon-len)
            add 1 to nfail
            display "FAIL " id-str(1:id-len) " (bytes differ)"
        when other
            add 1 to npass
    end-evaluate.

*> ---- decode_reject: feed canonical bytes to transcoder, expect reject.
*> Reject on either a structural error (tag/indefinite -> status 3) OR an
*> incomplete consume (trailing bytes after the top value): a canonical decoder
*> MUST consume exactly the input. (tag_reject.1/2/3 are map(2)+trailing;
*> tag_reject.4 is a bare tag.)
do-reject.
    move canon-off to scan-off
    move 0 to out-len
    move 0 to st
    call "cbor-canon" using fixbuf scan-off out-buf out-len st
    compute reject-end = canon-off + canon-len
    if st = 3 or scan-off not = reject-end
        add 1 to npass
    else
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (not rejected; consumed to "
                scan-off " of " reject-end ")"
    end-if.

*> ---- content_hash via FFI ------------------------------------------
do-content-hash.
    *> input map: type (text), data (value), optional format_code (uint)
    *> type
    move "type" to key-name  move 4 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to type-len
    move scan-off to type-off
    *> data: raw canonical span
    move "data" to key-name  move 4 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move voff to data-off
    move voff to scan-off
    call "cbor-skip" using fixbuf scan-off st
    compute data-len = scan-off - data-off
    *> optional format_code
    move "format_code" to key-name  move 11 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move 0 to has-fmt
    move 0 to fmt-code
    if found = 1
        move 1 to has-fmt
        move voff to scan-off
        call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
        move rharg to fmt-code
    end-if
    *> only format 0x00 / 0x01 supported by the C-ABI; others honest-skip
    if has-fmt = 1 and fmt-code > 1
        add 1 to nskip
        display "SKIP " id-str(1:id-len) " (format_code " fmt-code
                " unsupported by C-ABI, per vector carve-out)"
        exit paragraph
    end-if
    if has-fmt = 1
        call "ec_content_hash_with_format" using
            by reference fixbuf(type-off:type-len) by value type-len
            by reference fixbuf(data-off:data-len) by value data-len
            by value fmt-code
            by reference ch-out by value 64 by reference pid-len
            returning rc
    else
        call "ec_content_hash" using
            by reference fixbuf(type-off:type-len) by value type-len
            by reference fixbuf(data-off:data-len) by value data-len
            by reference ch-out
            returning rc
        move 33 to pid-len
    end-if
    if rc not = 0
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (ec_content_hash rc " rc ")"
        exit paragraph
    end-if
    if pid-len = canon-len and ch-out(1:canon-len) = fixbuf(canon-off:canon-len)
        add 1 to npass
    else
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (content_hash bytes differ)"
    end-if.

*> ---- peer_id via FFI -----------------------------------------------
do-peer-id.
    move "key_type" to key-name  move 8 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to key-type
    move "hash_type" to key-name  move 9 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to hash-type
    move "digest" to key-name  move 6 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to dig-len
    move scan-off to dig-off
    call "ec_peerid_format" using
        by value key-type by value hash-type
        by reference fixbuf(dig-off:dig-len) by value dig-len
        by reference pid-out by value 128 by reference pid-len
        returning rc
    if rc not = 0
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (ec_peerid_format rc " rc ")"
        exit paragraph
    end-if
    *> the canonical encoding of a peer_id value is a CBOR TEXT string; the FFI
    *> returns the raw base58 string, so wrap it in a text head before compare.
    move 0 to out-len
    call "emit-head" using out-buf out-len 3 pid-len
    perform varying pk from 1 by 1 until pk > pid-len
        add 1 to out-len
        move pid-out(pk:1) to out-buf(out-len:1)
    end-perform
    if out-len = canon-len and out-buf(1:out-len) = fixbuf(canon-off:canon-len)
        add 1 to npass
    else
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (peer_id bytes differ)"
    end-if.

*> ---- signature via FFI ---------------------------------------------
*> sign = ed25519_sign(seed, ECF({type,data}))  (reference: OCaml conformance.ml
*> signs the entity's ECF bytes, not the content_hash).
do-signature.
    *> seed (32 bytes)
    move "seed" to key-name  move 4 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to seed-len
    move scan-off to seed-off
    *> entity map
    move "entity" to key-name  move 6 to key-name-len
    call "cbor-find-key" using fixbuf input-off key-name key-name-len voff found st
    move voff to ent-off
    *> entity.type
    move "type" to key-name  move 4 to key-name-len
    call "cbor-find-key" using fixbuf ent-off key-name key-name-len voff found st
    move voff to scan-off
    call "cbor-read-head" using fixbuf scan-off rhmaj rhaddl rharg st
    move rharg to type-len
    move scan-off to type-off
    *> entity.data (raw canonical span)
    move "data" to key-name  move 4 to key-name-len
    call "cbor-find-key" using fixbuf ent-off key-name key-name-len voff found st
    move voff to data-off
    move voff to scan-off
    call "cbor-skip" using fixbuf scan-off st
    compute data-len = scan-off - data-off
    *> ECF-encode the entity, then sign the ECF bytes
    move 0 to ecf-len
    call "ec_encode_ecf" using
        by reference fixbuf(type-off:type-len) by value type-len
        by reference fixbuf(data-off:data-len) by value data-len
        by reference ecf-out by value 4096 by reference ecf-len
        returning rc
    if rc not = 0
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (ec_encode_ecf rc " rc ")"
        exit paragraph
    end-if
    call "ec_ed25519_sign" using
        by reference fixbuf(seed-off:seed-len)
        by reference ecf-out by value ecf-len
        by reference sig-out
        returning rc
    if rc not = 0
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (ec_ed25519_sign rc " rc ")"
        exit paragraph
    end-if
    if canon-len = 64 and sig-out(1:64) = fixbuf(canon-off:canon-len)
        add 1 to npass
    else
        add 1 to nfail
        display "FAIL " id-str(1:id-len) " (signature bytes differ)"
    end-if.
end program codec-selftest.
