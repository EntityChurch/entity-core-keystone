>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — entity field accessors (read side).
*>
*> A materialized entity is its wire form: canonical map(3) {data, type,
*> content_hash}. These walk a buffer at a given entity offset using the cbor.cob
*> navigation primitives. "field" access means: locate the "data" map, then a key
*> within it. read-text/bytes/uint decode a value item at an offset.
*>
*> Sub-programs:
*>   ent-find-data  entity-off -> offset of its "data" map value
*>   ent-field      entity-off, key -> value offset within the data map (+ found)
*>   ent-type       entity-off -> the "type" text (str, len)
*>   ent-hash       entity-off -> the 33-byte "content_hash"
*>   read-text      value-off -> text bytes (str, len)
*>   read-bytes     value-off -> byte string (out, len)
*>   read-uint      value-off -> unsigned integer value
*>   map-find       map-off, key -> value offset within an arbitrary map (+ found)
*> ===================================================================

*> ---- ent-find-data -------------------------------------------------
identification division.
program-id. ent-find-data.
data division.
working-storage section.
01 kn   pic x(4) value "data".
01 knl  pic 9(9) comp-5 value 4.
01 voff pic 9(9) comp-5.
01 fnd  pic 9(1).
01 st   pic s9(9) comp-5.
linkage section.
01 lk-buf  pic x(65535).
01 lk-eoff pic 9(9) comp-5.
01 lk-doff pic 9(9) comp-5.
01 lk-status pic s9(9) comp-5.
procedure division using lk-buf lk-eoff lk-doff lk-status.
    move 0 to lk-status
    call "cbor-find-key" using lk-buf lk-eoff kn knl voff fnd st
    if fnd = 0 then move 3 to lk-status move 0 to lk-doff
    else move voff to lk-doff end-if
    goback.
end program ent-find-data.

*> ---- ent-field -----------------------------------------------------
identification division.
program-id. ent-field.
data division.
working-storage section.
01 doff pic 9(9) comp-5.
01 st   pic s9(9) comp-5.
linkage section.
01 lk-buf  pic x(65535).
01 lk-eoff pic 9(9) comp-5.
01 lk-key  pic x(256).
01 lk-keylen pic 9(9) comp-5.
01 lk-voff pic 9(9) comp-5.
01 lk-found pic 9(1).
procedure division using lk-buf lk-eoff lk-key lk-keylen lk-voff lk-found.
    move 0 to lk-found
    call "ent-find-data" using lk-buf lk-eoff doff st
    if st not = 0 then goback end-if
    call "cbor-find-key" using lk-buf doff lk-key lk-keylen lk-voff lk-found st
    goback.
end program ent-field.

*> ---- map-find ------------------------------------------------------
*> Find a text key directly in the map at LK-MOFF (not an entity wrapper).
identification division.
program-id. map-find.
data division.
working-storage section.
01 st pic s9(9) comp-5.
linkage section.
01 lk-buf  pic x(65535).
01 lk-moff pic 9(9) comp-5.
01 lk-key  pic x(256).
01 lk-keylen pic 9(9) comp-5.
01 lk-voff pic 9(9) comp-5.
01 lk-found pic 9(1).
procedure division using lk-buf lk-moff lk-key lk-keylen lk-voff lk-found.
    call "cbor-find-key" using lk-buf lk-moff lk-key lk-keylen lk-voff lk-found st
    goback.
end program map-find.

*> ---- ent-type ------------------------------------------------------
identification division.
program-id. ent-type.
data division.
working-storage section.
01 kn   pic x(4) value "type".
01 knl  pic 9(9) comp-5 value 4.
01 voff pic 9(9) comp-5.
01 fnd  pic 9(1).
01 st   pic s9(9) comp-5.
linkage section.
01 lk-buf  pic x(65535).
01 lk-eoff pic 9(9) comp-5.
01 lk-str  pic x(256).
01 lk-len  pic 9(9) comp-5.
procedure division using lk-buf lk-eoff lk-str lk-len.
    move 0 to lk-len
    call "cbor-find-key" using lk-buf lk-eoff kn knl voff fnd st
    if fnd = 0 then goback end-if
    call "read-text" using lk-buf voff lk-str lk-len
    goback.
end program ent-type.

*> ---- ent-hash ------------------------------------------------------
identification division.
program-id. ent-hash.
data division.
working-storage section.
01 kn   pic x(12) value "content_hash".
01 knl  pic 9(9) comp-5 value 12.
01 voff pic 9(9) comp-5.
01 fnd  pic 9(1).
01 st   pic s9(9) comp-5.
01 blen pic 9(9) comp-5.
linkage section.
01 lk-buf  pic x(65535).
01 lk-eoff pic 9(9) comp-5.
01 lk-hash pic x(33).
procedure division using lk-buf lk-eoff lk-hash.
    move all x"00" to lk-hash
    call "cbor-find-key" using lk-buf lk-eoff kn knl voff fnd st
    if fnd = 0 then goback end-if
    call "read-bytes" using lk-buf voff lk-hash blen
    goback.
end program ent-hash.

*> ---- read-text -----------------------------------------------------
identification division.
program-id. read-text.
data division.
working-storage section.
01 scan pic 9(9) comp-5.
01 rmaj pic 9(2) comp-5.
01 raddl pic 9(2) comp-5.
01 rarg pic 9(18) comp-5.
01 st   pic s9(9) comp-5.
linkage section.
01 lk-buf pic x(65535).
01 lk-voff pic 9(9) comp-5.
01 lk-str pic x(65535).
01 lk-len pic 9(9) comp-5.
procedure division using lk-buf lk-voff lk-str lk-len.
    move lk-voff to scan
    call "cbor-read-head" using lk-buf scan rmaj raddl rarg st
    move rarg to lk-len
    if lk-len > 0 then move lk-buf(scan:lk-len) to lk-str(1:lk-len) end-if
    goback.
end program read-text.

*> ---- read-bytes ----------------------------------------------------
identification division.
program-id. read-bytes.
data division.
working-storage section.
01 scan pic 9(9) comp-5.
01 rmaj pic 9(2) comp-5.
01 raddl pic 9(2) comp-5.
01 rarg pic 9(18) comp-5.
01 st   pic s9(9) comp-5.
linkage section.
01 lk-buf pic x(65535).
01 lk-voff pic 9(9) comp-5.
01 lk-out pic x(65535).
01 lk-len pic 9(9) comp-5.
procedure division using lk-buf lk-voff lk-out lk-len.
    move lk-voff to scan
    call "cbor-read-head" using lk-buf scan rmaj raddl rarg st
    move rarg to lk-len
    if lk-len > 0 then move lk-buf(scan:lk-len) to lk-out(1:lk-len) end-if
    goback.
end program read-bytes.

*> ---- read-uint -----------------------------------------------------
identification division.
program-id. read-uint.
data division.
working-storage section.
01 scan pic 9(9) comp-5.
01 rmaj pic 9(2) comp-5.
01 raddl pic 9(2) comp-5.
01 rarg pic 9(18) comp-5.
01 st   pic s9(9) comp-5.
linkage section.
01 lk-buf pic x(65535).
01 lk-voff pic 9(9) comp-5.
01 lk-val pic 9(18) comp-5.
procedure division using lk-buf lk-voff lk-val.
    move lk-voff to scan
    call "cbor-read-head" using lk-buf scan rmaj raddl rarg st
    move rarg to lk-val
    goback.
end program read-uint.

*> ---- read-uint-ck --------------------------------------------------
*> CAP-6a: read an unsigned integer AND say whether it is representable.
*>
*> `read-uint` answers a value for any head it is pointed at — a negative
*> integer (major 1) yields its encoded magnitude, and an 8-byte argument past
*> this substrate's 9(18) range silently truncates in cbor-read-head's
*> accumulate. Both come back looking like ordinary numbers, so a caller that
*> compares them against `now` gets a plausible answer to a question it should
*> have refused: an accessor whose "value" conflates REPRESENTABLE with
*> MALFORMED is the temporal fail-open §6.2 CAP-6a names, and on a temporal
*> field it fails OPEN. Absence stays the caller's business (ent-field already
*> answers it); this answers "usable", never "present".
identification division.
program-id. read-uint-ck.
data division.
working-storage section.
01 ws-bc.
   05 ws-byte    pic x.
01 ws-bn redefines ws-bc pic 9(2) comp-x.
01 ws-i      pic 9(4) comp-5.
01 ws-nbytes pic 9(2) comp-5.
01 ws-major  pic 9(2) comp-5.
01 ws-addl   pic 9(2) comp-5.
01 ws-acc    pic 9(18) comp-5.
01 ws-off    pic 9(9) comp-5.
*> (10^18 - 1 - 255) / 256, the largest accumulator that can still absorb one
*> more byte without leaving 9(18). Past it the value is out of range for this
*> peer and MUST be refused rather than truncated.
01 ws-safe   pic 9(18) comp-5 value 3906249999999999.
linkage section.
01 lk-buf pic x(65535).
01 lk-voff pic 9(9) comp-5.
01 lk-val pic 9(18) comp-5.
01 lk-ok  pic 9(1).
procedure division using lk-buf lk-voff lk-val lk-ok.
    move 0 to lk-val
    move 0 to lk-ok
    move lk-voff to ws-off
    move lk-buf(ws-off:1) to ws-byte
    divide ws-bn by 32 giving ws-major
    compute ws-addl = function mod(ws-bn 32)
    if ws-major not = 0 then goback end-if
    add 1 to ws-off
    move 0 to ws-acc
    evaluate true
        when ws-addl <= 23
            move ws-addl to ws-acc
            move 0 to ws-nbytes
        when ws-addl = 24
            move 1 to ws-nbytes
        when ws-addl = 25
            move 2 to ws-nbytes
        when ws-addl = 26
            move 4 to ws-nbytes
        when ws-addl = 27
            move 8 to ws-nbytes
        when other
            goback
    end-evaluate
    perform varying ws-i from 1 by 1 until ws-i > ws-nbytes
        move lk-buf(ws-off:1) to ws-byte
        if ws-acc > ws-safe then goback end-if
        compute ws-acc = ws-acc * 256 + ws-bn
        add 1 to ws-off
    end-perform
    move ws-acc to lk-val
    move 1 to lk-ok
    goback.
end program read-uint-ck.
