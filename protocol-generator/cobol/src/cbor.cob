>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — canonical CBOR value codec (A-CBL-002).
*>
*> The codec C-ABI is entity-grained: ec_encode_ecf/ec_content_hash take the
*> entity `data` field as already-canonical CBOR. So this module owns the
*> canonical CBOR VALUE layer the FFI does not provide: a recursive
*> canonicalizing transcoder (decode CBOR -> re-emit RFC 8949 §4.2 canonical)
*> plus navigation helpers (read-head / skip / find-key) the peer + the codec
*> self-test use to walk nested CBOR.
*>
*> Canonical rules enforced (conformance-invariants N1-N3):
*>   - minimal integer head (shortest argument length)            [emit-head]
*>   - definite lengths only; indefinite (addl 31) -> reject
*>   - map keys ordered by encoded length then lexicographic       [CBOR-CANON map arm]
*>   - recursive major-type-6 (tag) reject anywhere                [N2]
*> Float (major 7, addl 25/26/27) is passed through verbatim (identity on the
*> canonical corpus input); float minimization lives in the FFI, not COBOL
*> (profile [codec], A-CBL-002).
*>
*> Sub-programs (callable, -fstatic-call):
*>   cbor-read-head  read one item head, return major/addl/arg, advance offset
*>   emit-head       append a minimal canonical head for (major,value)
*>   cbor-canon      RECURSIVE transcoder/validator: in -> canonical out
*>   cbor-skip       RECURSIVE: advance offset past one whole value
*>   cbor-find-key   locate a text key in a map, return the value offset
*> Status: 0 = OK, 3 = decode-error (EC_DECODE_ERROR), matching the C-ABI.
*> ===================================================================

*> ---- cbor-read-head ------------------------------------------------
*> Read the item at LK-BUF(LK-OFF:); return major (0-7), addl (0-31), and arg
*> (the head argument: value for ints, length for str, count for array/map,
*> raw bit pattern for floats). Advances LK-OFF past the head + argument bytes.
identification division.
program-id. cbor-read-head.
data division.
working-storage section.
01 ws-bc.
   05 ws-byte    pic x.
01 ws-bn redefines ws-bc pic 9(2) comp-x.
01 ws-i         pic 9(4) comp-5.
01 ws-nbytes    pic 9(2) comp-5.
linkage section.
01 lk-buf       pic x(65535).
01 lk-off       pic 9(9) comp-5.
01 lk-major     pic 9(2) comp-5.
01 lk-addl      pic 9(2) comp-5.
01 lk-arg       pic 9(18) comp-5.
01 lk-status    pic s9(9) comp-5.
procedure division using lk-buf lk-off lk-major lk-addl lk-arg lk-status.
    move 0 to lk-status
    move lk-buf(lk-off:1) to ws-byte
    divide ws-bn by 32 giving lk-major
    compute lk-addl = function mod(ws-bn 32)
    add 1 to lk-off
    move 0 to lk-arg
    evaluate true
        when lk-addl <= 23
            move lk-addl to lk-arg
        when lk-addl = 24
            move 1 to ws-nbytes
        when lk-addl = 25
            move 2 to ws-nbytes
        when lk-addl = 26
            move 4 to ws-nbytes
        when lk-addl = 27
            move 8 to ws-nbytes
        when other
            *> addl 28-30 reserved, 31 indefinite -> non-canonical, reject
            move 3 to lk-status
            move 0 to ws-nbytes
    end-evaluate
    if lk-status = 0 and lk-addl >= 24
        perform varying ws-i from 1 by 1 until ws-i > ws-nbytes
            move lk-buf(lk-off:1) to ws-byte
            compute lk-arg = lk-arg * 256 + ws-bn
            add 1 to lk-off
        end-perform
    end-if
    goback.
end program cbor-read-head.

*> ---- emit-head -----------------------------------------------------
*> Append the minimal canonical head for (major, value) to LK-OUT, advancing
*> LK-OUT-LEN. Re-derives the shortest argument length (RFC 8949 §4.2.1 Rule 1).
identification division.
program-id. emit-head.
data division.
working-storage section.
01 ws-base      pic 9(4) comp-5.
01 ws-first     pic 9(4) comp-5.
01 ws-nbytes    pic 9(2) comp-5.
01 ws-tmp       pic 9(18) comp-5.
01 ws-rem       pic 9(4) comp-5.
01 ws-i         pic 9(2) comp-5.
01 ws-rev.
   05 ws-rev-byte pic x occurs 8.
01 ws-ob.
   05 ws-ob-char pic x.
01 ws-on redefines ws-ob pic 9(2) comp-x.
linkage section.
01 lk-out       pic x(65535).
01 lk-out-len   pic 9(9) comp-5.
01 lk-major     pic 9(2) comp-5.
01 lk-value     pic 9(18) comp-5.
procedure division using lk-out lk-out-len lk-major lk-value.
    compute ws-base = lk-major * 32
    evaluate true
        when lk-value <= 23
            compute ws-first = ws-base + lk-value
            move 0 to ws-nbytes
        when lk-value <= 255
            compute ws-first = ws-base + 24
            move 1 to ws-nbytes
        when lk-value <= 65535
            compute ws-first = ws-base + 25
            move 2 to ws-nbytes
        when lk-value <= 4294967295
            compute ws-first = ws-base + 26
            move 4 to ws-nbytes
        when other
            compute ws-first = ws-base + 27
            move 8 to ws-nbytes
    end-evaluate
    *> emit the first (head) byte
    move ws-first to ws-on
    add 1 to lk-out-len
    move ws-ob-char to lk-out(lk-out-len:1)
    *> emit the argument big-endian (extract low bytes, reverse)
    if ws-nbytes > 0
        move lk-value to ws-tmp
        perform varying ws-i from ws-nbytes by -1 until ws-i < 1
            compute ws-rem = function mod(ws-tmp 256)
            move ws-rem to ws-on
            move ws-ob-char to ws-rev-byte(ws-i)
            compute ws-tmp = ws-tmp / 256
        end-perform
        perform varying ws-i from 1 by 1 until ws-i > ws-nbytes
            add 1 to lk-out-len
            move ws-rev-byte(ws-i) to lk-out(lk-out-len:1)
        end-perform
    end-if
    goback.
end program emit-head.

*> ---- cbor-canon (RECURSIVE) ----------------------------------------
*> Transcode one value at LK-IN(LK-IN-OFF:) to canonical form appended to
*> LK-OUT (advancing LK-OUT-LEN + LK-IN-OFF). Doubles as the validator: a
*> tag / indefinite / reserved head sets LK-STATUS = 3.
identification division.
program-id. cbor-canon recursive.
data division.
*> ALL per-frame state is LOCAL-STORAGE: cbor-canon recurses, and COBOL
*> WORKING-STORAGE is static/shared across recursive invocations (spike P1) —
*> a shared loop counter or scratch field corrupts the parent frame.
local-storage section.
01 ws-major     pic 9(2) comp-5.
01 ws-addl      pic 9(2) comp-5.
01 ws-arg       pic 9(18) comp-5.
01 ws-i         pic 9(9) comp-5.
01 ws-j         pic 9(9) comp-5.
01 ws-k         pic 9(9) comp-5.
01 ws-min       pic 9(9) comp-5.
01 ws-cmp       pic s9(4) comp-5.
01 ws-fhead.
   05 ws-fh-char pic x.
01 ws-fhn redefines ws-fhead pic 9(2) comp-x.
01 ws-fbytes    pic 9(2) comp-5.
01 ws-ftmp      pic 9(18) comp-5.
01 ws-frem      pic 9(4) comp-5.
01 ws-fbuf.
   05 ws-fbuf-byte pic x occurs 8.
*> per-frame map pair table (canonical key sort happens here)
01 ls-npairs    pic 9(9) comp-5.
01 ls-pairs.
   05 ls-pair occurs 64.
      10 ls-key      pic x(512).
      10 ls-key-len  pic 9(9) comp-5.
      10 ls-val      pic x(4096).
      10 ls-val-len  pic 9(9) comp-5.
01 ls-order.
   05 ls-ord-idx occurs 64 pic 9(9) comp-5.
01 ls-swap      pic 9(9) comp-5.
01 ls-a         pic 9(9) comp-5.
01 ls-b         pic 9(9) comp-5.
01 ls-kbuf      pic x(512).
01 ls-kbuf-len  pic 9(9) comp-5.
01 ls-vbuf      pic x(4096).
01 ls-vbuf-len  pic 9(9) comp-5.
linkage section.
01 lk-in        pic x(65535).
01 lk-in-off    pic 9(9) comp-5.
01 lk-out       pic x(65535).
01 lk-out-len   pic 9(9) comp-5.
01 lk-status    pic s9(9) comp-5.
procedure division using lk-in lk-in-off lk-out lk-out-len lk-status.
    call "cbor-read-head" using lk-in lk-in-off ws-major ws-addl ws-arg lk-status
    if lk-status not = 0
        goback
    end-if
    evaluate ws-major
        when 0
            call "emit-head" using lk-out lk-out-len ws-major ws-arg
        when 1
            call "emit-head" using lk-out lk-out-len ws-major ws-arg
        when 2
            call "emit-head" using lk-out lk-out-len ws-major ws-arg
            perform copy-payload
        when 3
            call "emit-head" using lk-out lk-out-len ws-major ws-arg
            perform copy-payload
        when 4
            call "emit-head" using lk-out lk-out-len ws-major ws-arg
            perform varying ws-i from 1 by 1 until ws-i > ws-arg
                call "cbor-canon" using lk-in lk-in-off lk-out lk-out-len lk-status
                if lk-status not = 0 then goback end-if
            end-perform
        when 5
            perform do-map
        when 7
            perform do-simple
        when other
            *> major 6 = tag -> reject (N2)
            move 3 to lk-status
    end-evaluate
    goback.

*> copy ws-arg raw bytes from input to output (bytes / text payload)
copy-payload.
    perform varying ws-i from 1 by 1 until ws-i > ws-arg
        add 1 to lk-out-len
        move lk-in(lk-in-off:1) to lk-out(lk-out-len:1)
        add 1 to lk-in-off
    end-perform.

*> major 7: simple values (re-emit head) + float (head byte + raw N BE bytes).
*> Float bytes pass through verbatim (ws-arg holds the bit pattern read BE);
*> float minimization lives in the FFI, not COBOL (A-CBL-002).
do-simple.
    evaluate ws-addl
        when 20
            move 244 to ws-fhn        *> 0xF4 false
            move 0 to ws-fbytes
            perform emit-fhead
        when 21
            move 245 to ws-fhn        *> 0xF5 true
            move 0 to ws-fbytes
            perform emit-fhead
        when 22
            move 246 to ws-fhn        *> 0xF6 null
            move 0 to ws-fbytes
            perform emit-fhead
        when 23
            move 247 to ws-fhn        *> 0xF7 undefined
            move 0 to ws-fbytes
            perform emit-fhead
        when 25
            move 249 to ws-fhn        *> 0xF9 float16
            move 2 to ws-fbytes
            perform emit-float
        when 26
            move 250 to ws-fhn        *> 0xFA float32
            move 4 to ws-fbytes
            perform emit-float
        when 27
            move 251 to ws-fhn        *> 0xFB float64
            move 8 to ws-fbytes
            perform emit-float
        when other
            move 3 to lk-status
    end-evaluate.

emit-fhead.
    add 1 to lk-out-len
    move ws-fh-char to lk-out(lk-out-len:1).

*> emit float head byte then ws-fbytes raw bytes of ws-arg, big-endian
emit-float.
    perform emit-fhead
    move ws-arg to ws-ftmp
    perform varying ws-i from ws-fbytes by -1 until ws-i < 1
        compute ws-frem = function mod(ws-ftmp 256)
        move ws-frem to ws-fhn
        move ws-fh-char to ws-fbuf-byte(ws-i)
        compute ws-ftmp = ws-ftmp / 256
    end-perform
    perform varying ws-i from 1 by 1 until ws-i > ws-fbytes
        add 1 to lk-out-len
        move ws-fbuf-byte(ws-i) to lk-out(lk-out-len:1)
    end-perform.

*> major 5: decode each pair into the local table, canonical-sort, emit
do-map.
    move ws-arg to ls-npairs
    if ls-npairs > 64
        move 3 to lk-status
        goback
    end-if
    perform varying ws-i from 1 by 1 until ws-i > ls-npairs
        *> key
        move spaces to ls-kbuf
        move 0 to ls-kbuf-len
        call "cbor-canon" using lk-in lk-in-off ls-kbuf ls-kbuf-len lk-status
        if lk-status not = 0 then goback end-if
        move ls-kbuf to ls-key(ws-i)
        move ls-kbuf-len to ls-key-len(ws-i)
        *> value
        move spaces to ls-vbuf
        move 0 to ls-vbuf-len
        call "cbor-canon" using lk-in lk-in-off ls-vbuf ls-vbuf-len lk-status
        if lk-status not = 0 then goback end-if
        move ls-vbuf to ls-val(ws-i)
        move ls-vbuf-len to ls-val-len(ws-i)
        move ws-i to ls-ord-idx(ws-i)
    end-perform
    *> bubble sort ls-ord-idx by (key-len, key bytes) ascending
    perform varying ws-i from 1 by 1 until ws-i >= ls-npairs
        perform varying ws-j from 1 by 1 until ws-j > ls-npairs - ws-i
            move ls-ord-idx(ws-j) to ls-a
            move ls-ord-idx(ws-j + 1) to ls-b
            perform key-cmp
            if ws-cmp > 0
                move ls-ord-idx(ws-j) to ls-swap
                move ls-ord-idx(ws-j + 1) to ls-ord-idx(ws-j)
                move ls-swap to ls-ord-idx(ws-j + 1)
            end-if
        end-perform
    end-perform
    *> emit map head + sorted pairs
    call "emit-head" using lk-out lk-out-len 5 ws-arg
    perform varying ws-i from 1 by 1 until ws-i > ls-npairs
        move ls-ord-idx(ws-i) to ls-a
        perform varying ws-k from 1 by 1 until ws-k > ls-key-len(ls-a)
            add 1 to lk-out-len
            move ls-key(ls-a)(ws-k:1) to lk-out(lk-out-len:1)
        end-perform
        perform varying ws-k from 1 by 1 until ws-k > ls-val-len(ls-a)
            add 1 to lk-out-len
            move ls-val(ls-a)(ws-k:1) to lk-out(lk-out-len:1)
        end-perform
    end-perform.

*> sets ws-cmp <0/0/>0 comparing pair ls-a vs ls-b by (len, lex)
key-cmp.
    evaluate true
        when ls-key-len(ls-a) < ls-key-len(ls-b)
            move -1 to ws-cmp
        when ls-key-len(ls-a) > ls-key-len(ls-b)
            move 1 to ws-cmp
        when other
            move ls-key-len(ls-a) to ws-min
            if ls-key(ls-a)(1:ws-min) < ls-key(ls-b)(1:ws-min)
                move -1 to ws-cmp
            else
                if ls-key(ls-a)(1:ws-min) > ls-key(ls-b)(1:ws-min)
                    move 1 to ws-cmp
                else
                    move 0 to ws-cmp
                end-if
            end-if
    end-evaluate.
end program cbor-canon.

*> ---- cbor-skip (RECURSIVE) -----------------------------------------
*> Advance LK-OFF past exactly one CBOR value (tolerant: skips tags too).
*> Used to walk the fixture; distinct from cbor-canon's strict reject.
identification division.
program-id. cbor-skip recursive.
data division.
local-storage section.
01 ws-major     pic 9(2) comp-5.
01 ws-addl      pic 9(2) comp-5.
01 ws-arg       pic 9(18) comp-5.
01 ws-i         pic 9(9) comp-5.
01 ws-n         pic 9(9) comp-5.
linkage section.
01 lk-buf       pic x(65535).
01 lk-off       pic 9(9) comp-5.
01 lk-status    pic s9(9) comp-5.
procedure division using lk-buf lk-off lk-status.
    call "cbor-read-head" using lk-buf lk-off ws-major ws-addl ws-arg lk-status
    *> read-head flags indefinite/reserved as status 3; tolerate for skipping
    move 0 to lk-status
    evaluate ws-major
        when 0
            continue
        when 1
            continue
        when 2
            add ws-arg to lk-off
        when 3
            add ws-arg to lk-off
        when 4
            perform varying ws-i from 1 by 1 until ws-i > ws-arg
                call "cbor-skip" using lk-buf lk-off lk-status
            end-perform
        when 5
            compute ws-n = ws-arg * 2
            perform varying ws-i from 1 by 1 until ws-i > ws-n
                call "cbor-skip" using lk-buf lk-off lk-status
            end-perform
        when 6
            call "cbor-skip" using lk-buf lk-off lk-status
        when 7
            *> simple/float arg bytes already consumed by read-head
            continue
    end-evaluate
    goback.
end program cbor-skip.

*> ---- cbor-find-key -------------------------------------------------
*> In the map at LK-BUF(LK-MAP-OFF:), locate text key LK-KEY(1:LK-KEY-LEN).
*> On hit: LK-VAL-OFF = offset of the value, LK-FOUND = 1. LK-MAP-OFF is left
*> unchanged (a scratch cursor is used internally).
identification division.
program-id. cbor-find-key.
data division.
working-storage section.
01 ws-cur       pic 9(9) comp-5.
01 ws-major     pic 9(2) comp-5.
01 ws-addl      pic 9(2) comp-5.
01 ws-arg       pic 9(18) comp-5.
01 ws-npairs    pic 9(9) comp-5.
01 ws-i         pic 9(9) comp-5.
01 ws-klen      pic 9(9) comp-5.
01 ws-koff      pic 9(9) comp-5.
01 ws-st        pic s9(9) comp-5.
linkage section.
01 lk-buf       pic x(65535).
01 lk-map-off   pic 9(9) comp-5.
01 lk-key       pic x(256).
01 lk-key-len   pic 9(9) comp-5.
01 lk-val-off   pic 9(9) comp-5.
01 lk-found     pic 9(1).
01 lk-status    pic s9(9) comp-5.
procedure division using lk-buf lk-map-off lk-key lk-key-len
                       lk-val-off lk-found lk-status.
    move 0 to lk-found
    move 0 to lk-status
    move lk-map-off to ws-cur
    call "cbor-read-head" using lk-buf ws-cur ws-major ws-addl ws-arg ws-st
    if ws-major not = 5
        move 3 to lk-status
        goback
    end-if
    move ws-arg to ws-npairs
    perform varying ws-i from 1 by 1 until ws-i > ws-npairs
        *> key (text)
        call "cbor-read-head" using lk-buf ws-cur ws-major ws-addl ws-arg ws-st
        move ws-arg to ws-klen
        move ws-cur to ws-koff
        add ws-klen to ws-cur          *> ws-cur now at value
        if ws-major = 3 and ws-klen = lk-key-len
            if lk-buf(ws-koff:ws-klen) = lk-key(1:lk-key-len)
                move ws-cur to lk-val-off
                move 1 to lk-found
                goback
            end-if
        end-if
        *> not a match: skip the value
        call "cbor-skip" using lk-buf ws-cur ws-st
    end-perform
    goback.
end program cbor-find-key.

*> ---- cbor-append ---------------------------------------------------
*> Append LK-N bytes from LK-SRC(LK-SRC-OFF:) onto LK-OUT, advancing LK-OUT-LEN.
*> The peer's entity/envelope builders use this with emit-head to construct
*> canonical CBOR maps (keys emitted in pre-sorted canonical order).
identification division.
program-id. cbor-append.
data division.
working-storage section.
01 ws-i  pic 9(9) comp-5.
linkage section.
01 lk-out      pic x(65535).
01 lk-out-len  pic 9(9) comp-5.
01 lk-src      pic x(65535).
01 lk-src-off  pic 9(9) comp-5.
01 lk-n        pic 9(9) comp-5.
procedure division using lk-out lk-out-len lk-src lk-src-off lk-n.
    perform varying ws-i from 0 by 1 until ws-i >= lk-n
        add 1 to lk-out-len
        move lk-src(lk-src-off + ws-i:1) to lk-out(lk-out-len:1)
    end-perform
    goback.
end program cbor-append.
