>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — wire framing (V7 §1.6).
*> Frame := [4-byte BE length][CBOR envelope payload]. read/write a full frame
*> over a fd using the netshim.c socket seam. 16 MiB max-frame (§1.6 / §4.10(a)
*> payload bound — over-limit -> reject before buffering).
*> ===================================================================

*> ---- write-frame ---------------------------------------------------
identification division.
program-id. write-frame.
data division.
working-storage section.
01 hdr.
   05 hdr-byte pic x occurs 4.
01 ob.
   05 ob-char pic x.
01 obn redefines ob pic 9(2) comp-x.
01 v        pic 9(9) comp-5.
01 b0       pic 9(9) comp-5.
01 rc       pic s9(18) comp-5.
linkage section.
01 lk-fd       pic s9(9) comp-5.
01 lk-payload  pic x(65535).
01 lk-len      pic 9(9) comp-5.
01 lk-status   pic s9(9) comp-5.
procedure division using lk-fd lk-payload lk-len lk-status.
    move 0 to lk-status
    *> 4-byte big-endian length header
    move lk-len to v
    compute b0 = function mod(v / 16777216, 256)  move b0 to obn  move ob-char to hdr-byte(1)
    compute b0 = function mod(v / 65536, 256)      move b0 to obn  move ob-char to hdr-byte(2)
    compute b0 = function mod(v / 256, 256)        move b0 to obn  move ob-char to hdr-byte(3)
    compute b0 = function mod(v, 256)              move b0 to obn  move ob-char to hdr-byte(4)
    call "ec_fd_write" using by value lk-fd by reference hdr by value 4 returning rc
    if rc not = 4 then move 1 to lk-status goback end-if
    call "ec_fd_write" using by value lk-fd by reference lk-payload by value lk-len
        returning rc
    if rc not = lk-len then move 1 to lk-status end-if
    goback.
end program write-frame.

*> ---- read-frame ----------------------------------------------------
*> Read one frame into LK-BUF (cap LK-MAX); LK-OUT-LEN = payload length.
*> LK-STATUS: 0 ok, 1 closed/error, 2 frame-too-large (§4.10 413 candidate).
identification division.
program-id. read-frame.
data division.
working-storage section.
01 hdr.
   05 hdr-byte pic x occurs 4.
01 ob.
   05 ob-char pic x.
01 obn redefines ob pic 9(2) comp-x.
01 i        pic 9(2) comp-5.
01 flen     pic 9(18) comp-5.
01 maxframe pic 9(18) comp-5 value 16777216.
01 rc       pic s9(18) comp-5.
linkage section.
01 lk-fd       pic s9(9) comp-5.
01 lk-buf      pic x(65535).
01 lk-max      pic 9(9) comp-5.
01 lk-out-len  pic 9(9) comp-5.
01 lk-status   pic s9(9) comp-5.
procedure division using lk-fd lk-buf lk-max lk-out-len lk-status.
    move 0 to lk-status
    move 0 to lk-out-len
    call "ec_fd_read" using by value lk-fd by reference hdr by value 4 returning rc
    if rc not = 4 then move 1 to lk-status goback end-if
    move 0 to flen
    perform varying i from 1 by 1 until i > 4
        move hdr-byte(i) to ob-char
        compute flen = flen * 256 + obn
    end-perform
    if flen > maxframe or flen > lk-max
        move 2 to lk-status goback
    end-if
    call "ec_fd_read" using by value lk-fd by reference lk-buf by value flen returning rc
    if rc not = flen then move 1 to lk-status goback end-if
    move flen to lk-out-len
    goback.
end program read-frame.
