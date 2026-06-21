>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — entity + envelope model (V7 §1.1, §3.1, §3.4).
*>
*> Entity wire form (§3.4) = canonical map(3) { data, type, content_hash }
*> (keys in canonical length-then-lex order: data, type, content_hash).
*>   - content_hash = FFI ec_content_hash(type, data) = varint(0)||SHA256(ECF).
*>   - data is already-canonical CBOR (built by cbor.cob / received on the wire).
*> Envelope (§3.1) = canonical map(2) { root, included } (root before included).
*>
*> Sub-programs: entity-encode, entity-decode (with §1.8 hash-fidelity check).
*> Builds on cbor.cob (emit-head / cbor-append / cbor-find-key / cbor-skip) and
*> libentitycore_codec (ec_content_hash).
*> ===================================================================

*> ---- entity-encode -------------------------------------------------
*> { data, type, content_hash } canonical entity from (type, data-canonical).
identification division.
program-id. entity-encode.
data division.
working-storage section.
01 hash33      pic x(33).
01 rc          pic s9(9) comp-5.
01 k-data      pic x(4)  value "data".
01 k-type      pic x(4)  value "type".
01 k-chash     pic x(12) value "content_hash".
01 one         pic 9(9) comp-5 value 1.
01 maj3        pic 9(2) comp-5 value 3.
01 maj2        pic 9(2) comp-5 value 2.
01 maj5        pic 9(2) comp-5 value 5.
01 n3          pic 9(18) comp-5 value 3.
01 n4          pic 9(18) comp-5 value 4.
01 n12         pic 9(18) comp-5 value 12.
01 n33         pic 9(18) comp-5 value 33.
01 tlen        pic 9(18) comp-5.
linkage section.
01 lk-type     pic x(65535).
01 lk-type-len pic 9(9) comp-5.
01 lk-data     pic x(65535).
01 lk-data-len pic 9(9) comp-5.
01 lk-out      pic x(65535).
01 lk-out-len  pic 9(9) comp-5.
01 lk-status   pic s9(9) comp-5.
procedure division using lk-type lk-type-len lk-data lk-data-len
                        lk-out lk-out-len lk-status.
    move 0 to lk-status
    *> content_hash via FFI
    call "ec_content_hash" using
        by reference lk-type(1:lk-type-len) by value lk-type-len
        by reference lk-data(1:lk-data-len) by value lk-data-len
        by reference hash33
        returning rc
    if rc not = 0
        move 4 to lk-status
        goback
    end-if
    *> map(3) head
    call "emit-head" using lk-out lk-out-len maj5 n3
    *> "data": <data canonical bytes>
    call "emit-head" using lk-out lk-out-len maj3 n4
    call "cbor-append" using lk-out lk-out-len k-data one n4
    call "cbor-append" using lk-out lk-out-len lk-data one lk-data-len
    *> "type": text(type)
    call "emit-head" using lk-out lk-out-len maj3 n4
    call "cbor-append" using lk-out lk-out-len k-type one n4
    move lk-type-len to tlen
    call "emit-head" using lk-out lk-out-len maj3 tlen
    call "cbor-append" using lk-out lk-out-len lk-type one lk-type-len
    *> "content_hash": bytes(33)
    call "emit-head" using lk-out lk-out-len maj3 n12
    call "cbor-append" using lk-out lk-out-len k-chash one n12
    call "emit-head" using lk-out lk-out-len maj2 n33
    call "cbor-append" using lk-out lk-out-len hash33 one n33
    goback.
end program entity-encode.

*> ---- entity-decode -------------------------------------------------
*> Parse a wire entity at LK-IN(LK-OFF:); return type + data spans. Validates
*> §1.8 hash fidelity (recompute content_hash, compare to carried). Advances
*> LK-OFF past the whole entity.
identification division.
program-id. entity-decode.
data division.
working-storage section.
01 voff        pic 9(9) comp-5.
01 found       pic 9(1).
01 scan        pic 9(9) comp-5.
01 rhmaj       pic 9(2) comp-5.
01 rhaddl      pic 9(2) comp-5.
01 rharg       pic 9(18) comp-5.
01 st2         pic s9(9) comp-5.
01 kn          pic x(32).
01 knl         pic 9(9) comp-5.
01 hash33      pic x(33).
01 chash-off   pic 9(9) comp-5.
01 chash-len   pic 9(9) comp-5.
01 rc          pic s9(9) comp-5.
linkage section.
01 lk-in       pic x(65535).
01 lk-off      pic 9(9) comp-5.
01 lk-type-off pic 9(9) comp-5.
01 lk-type-len pic 9(9) comp-5.
01 lk-data-off pic 9(9) comp-5.
01 lk-data-len pic 9(9) comp-5.
01 lk-status   pic s9(9) comp-5.
procedure division using lk-in lk-off lk-type-off lk-type-len
                        lk-data-off lk-data-len lk-status.
    move 0 to lk-status
    *> type
    move "type" to kn  move 4 to knl
    call "cbor-find-key" using lk-in lk-off kn knl voff found st2
    if found = 0 then move 3 to lk-status goback end-if
    move voff to scan
    call "cbor-read-head" using lk-in scan rhmaj rhaddl rharg st2
    move rharg to lk-type-len
    move scan to lk-type-off
    *> data (raw canonical span)
    move "data" to kn  move 4 to knl
    call "cbor-find-key" using lk-in lk-off kn knl voff found st2
    if found = 0 then move 3 to lk-status goback end-if
    move voff to lk-data-off
    move voff to scan
    call "cbor-skip" using lk-in scan st2
    compute lk-data-len = scan - lk-data-off
    *> content_hash fidelity (§1.8): recompute, compare to carried (if present)
    move "content_hash" to kn  move 12 to knl
    call "cbor-find-key" using lk-in lk-off kn knl voff found st2
    if found = 1
        move voff to scan
        call "cbor-read-head" using lk-in scan rhmaj rhaddl rharg st2
        move rharg to chash-len
        move scan to chash-off
        call "ec_content_hash" using
            by reference lk-in(lk-type-off:lk-type-len) by value lk-type-len
            by reference lk-in(lk-data-off:lk-data-len) by value lk-data-len
            by reference hash33
            returning rc
        if rc not = 0 or chash-len not = 33
            move 3 to lk-status goback
        end-if
        if hash33(1:33) not = lk-in(chash-off:33)
            move 5 to lk-status goback
        end-if
    end-if
    *> advance past the whole entity
    call "cbor-skip" using lk-in lk-off st2
    goback.
end program entity-decode.

*> ---- envelope-encode -----------------------------------------------
*> { root, included } canonical envelope (§3.1). LK-ROOT is an already-encoded
*> wire entity (LK-ROOT-LEN bytes). LK-INC is an already-encoded canonical map
*> of included entities (LK-INC-LEN bytes); pass the empty map 0xA0 for none.
*> Keys in canonical order: root(4) before included(8).
identification division.
program-id. envelope-encode.
data division.
working-storage section.
01 k-root      pic x(4)  value "root".
01 k-inc       pic x(8)  value "included".
01 one         pic 9(9) comp-5 value 1.
01 maj3        pic 9(2) comp-5 value 3.
01 maj5        pic 9(2) comp-5 value 5.
01 n2          pic 9(18) comp-5 value 2.
01 n4          pic 9(18) comp-5 value 4.
01 n8          pic 9(18) comp-5 value 8.
linkage section.
01 lk-root     pic x(65535).
01 lk-root-len pic 9(9) comp-5.
01 lk-inc      pic x(65535).
01 lk-inc-len  pic 9(9) comp-5.
01 lk-out      pic x(65535).
01 lk-out-len  pic 9(9) comp-5.
procedure division using lk-root lk-root-len lk-inc lk-inc-len lk-out lk-out-len.
    call "emit-head" using lk-out lk-out-len maj5 n2
    call "emit-head" using lk-out lk-out-len maj3 n4
    call "cbor-append" using lk-out lk-out-len k-root one n4
    call "cbor-append" using lk-out lk-out-len lk-root one lk-root-len
    call "emit-head" using lk-out lk-out-len maj3 n8
    call "cbor-append" using lk-out lk-out-len k-inc one n8
    call "cbor-append" using lk-out lk-out-len lk-inc one lk-inc-len
    goback.
end program envelope-encode.
