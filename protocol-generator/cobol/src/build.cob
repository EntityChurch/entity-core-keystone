>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — CBOR build convenience layer.
*>
*> The peer brain builds CBOR maps NAIVELY (any key order) then runs cbor-canon
*> over the whole buffer to produce the RFC 8949 §4.2 canonical form (key sort +
*> minimal heads). This avoids hand-sorting every map by (length, lex). Entity
*> construction (b-entity) canonicalizes the data map first, then calls
*> entity-encode (which hashes the canonical data via the FFI).
*>
*> Sub-programs (all append to LK-OUT, advancing LK-OUT-LEN):
*>   b-map / b-arr   map(count) / array(count) head
*>   b-text          a text item (used for keys AND text values)
*>   b-uint          an unsigned integer item
*>   b-bytes         a byte-string item from LK-SRC(LK-OFF:LK-N)
*>   b-raw           append already-encoded CBOR bytes verbatim
*>   b-canon         canonicalize LK-IN(1:LK-IN-LEN) -> LK-OUT(1:LK-OUT-LEN)
*>   b-entity        (type, naive-data) -> wire entity {data,type,content_hash}
*> ===================================================================

identification division.
program-id. b-map.
data division.
working-storage section.
01 maj5 pic 9(2) comp-5 value 5.
linkage section.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-count pic 9(18) comp-5.
procedure division using lk-out lk-out-len lk-count.
    call "emit-head" using lk-out lk-out-len maj5 lk-count
    goback.
end program b-map.

identification division.
program-id. b-arr.
data division.
working-storage section.
01 maj4 pic 9(2) comp-5 value 4.
linkage section.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-count pic 9(18) comp-5.
procedure division using lk-out lk-out-len lk-count.
    call "emit-head" using lk-out lk-out-len maj4 lk-count
    goback.
end program b-arr.

identification division.
program-id. b-text.
data division.
working-storage section.
01 maj3 pic 9(2) comp-5 value 3.
01 one  pic 9(9) comp-5 value 1.
01 nlen pic 9(18) comp-5.
linkage section.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-str pic x(65535).
01 lk-n   pic 9(9) comp-5.
procedure division using lk-out lk-out-len lk-str lk-n.
    move lk-n to nlen
    call "emit-head" using lk-out lk-out-len maj3 nlen
    call "cbor-append" using lk-out lk-out-len lk-str one lk-n
    goback.
end program b-text.

identification division.
program-id. b-uint.
data division.
working-storage section.
01 maj0 pic 9(2) comp-5 value 0.
linkage section.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-value pic 9(18) comp-5.
procedure division using lk-out lk-out-len lk-value.
    call "emit-head" using lk-out lk-out-len maj0 lk-value
    goback.
end program b-uint.

identification division.
program-id. b-bytes.
data division.
working-storage section.
01 maj2 pic 9(2) comp-5 value 2.
01 nlen pic 9(18) comp-5.
linkage section.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-src pic x(65535).
01 lk-off pic 9(9) comp-5.
01 lk-n   pic 9(9) comp-5.
procedure division using lk-out lk-out-len lk-src lk-off lk-n.
    move lk-n to nlen
    call "emit-head" using lk-out lk-out-len maj2 nlen
    call "cbor-append" using lk-out lk-out-len lk-src lk-off lk-n
    goback.
end program b-bytes.

identification division.
program-id. b-raw.
data division.
working-storage section.
01 one pic 9(9) comp-5 value 1.
linkage section.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-src pic x(65535).
01 lk-off pic 9(9) comp-5.
01 lk-n   pic 9(9) comp-5.
procedure division using lk-out lk-out-len lk-src lk-off lk-n.
    call "cbor-append" using lk-out lk-out-len lk-src lk-off lk-n
    goback.
end program b-raw.

*> ---- b-canon -------------------------------------------------------
*> Canonicalize a single CBOR value at LK-IN(1:) into LK-OUT (reset to 0).
identification division.
program-id. b-canon.
data division.
working-storage section.
01 ws-inoff pic 9(9) comp-5.
01 ws-st    pic s9(9) comp-5.
linkage section.
01 lk-in  pic x(65535).
01 lk-in-len pic 9(9) comp-5.
01 lk-out pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-status pic s9(9) comp-5.
procedure division using lk-in lk-in-len lk-out lk-out-len lk-status.
    move 1 to ws-inoff
    move 0 to lk-out-len
    call "cbor-canon" using lk-in ws-inoff lk-out lk-out-len lk-status
    goback.
end program b-canon.

*> ---- b-entity ------------------------------------------------------
*> Build a wire entity from (type, naive-data-bytes). Canonicalizes the data map
*> first (so the FFI content_hash covers canonical ECF), then entity-encode.
*> Returns the wire entity in LK-OUT (len LK-OUT-LEN) and its 33-byte hash.
identification division.
program-id. b-entity.
data division.
working-storage section.
01 ws-cdata   pic x(65535).
01 ws-cdata-len pic 9(9) comp-5.
01 ws-st      pic s9(9) comp-5.
01 hash33     pic x(33).
01 rc         pic s9(9) comp-5.
linkage section.
01 lk-type    pic x(128).
01 lk-type-len pic 9(9) comp-5.
01 lk-data    pic x(65535).
01 lk-data-len pic 9(9) comp-5.
01 lk-out     pic x(65535).
01 lk-out-len pic 9(9) comp-5.
01 lk-hash    pic x(33).
01 lk-status  pic s9(9) comp-5.
procedure division using lk-type lk-type-len lk-data lk-data-len
                        lk-out lk-out-len lk-hash lk-status.
    move 0 to lk-status
    *> canonicalize the data
    call "b-canon" using lk-data lk-data-len ws-cdata ws-cdata-len ws-st
    if ws-st not = 0 then move ws-st to lk-status goback end-if
    *> entity-encode(type, canonical-data) -> {data,type,content_hash}
    move 0 to lk-out-len
    call "entity-encode" using lk-type lk-type-len ws-cdata ws-cdata-len
        lk-out lk-out-len lk-status
    if lk-status not = 0 then goback end-if
    *> recompute the 33-byte content_hash to return alongside
    call "ec_content_hash" using
        by reference lk-type(1:lk-type-len) by value lk-type-len
        by reference ws-cdata(1:ws-cdata-len) by value ws-cdata-len
        by reference hash33 returning rc
    if rc not = 0 then move 4 to lk-status goback end-if
    move hash33 to lk-hash
    goback.
end program b-entity.
