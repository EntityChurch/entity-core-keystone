>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — core type registry (§9.5 floor).
*>
*> publish-types binds the 53 core type entities at /{local}/system/type/{name}
*> at bootstrap; a tree get over system/type/* then renders them (type_system).
*>
*> Render-from-model design (S8): the canonical ECF `data` payload for each core
*> type is loaded from src/core-types.dat (a committed table generated from the
*> cross-impl Go-rendered type-registry vectors — the same model the OCaml/cohort
*> peers render). b-entity wraps each payload as {data,type,content_hash}; because
*> the payload is already canonical, the FFI content_hash matches the vector.
*>
*> File format (repeated, big-endian): u16 name-len, name, u32 data-len, data.
*> ===================================================================
identification division.
program-id. publish-types.
data division.
working-storage section.
01 fbuf     pic x(20000).
01 flen     pic 9(9) comp-5.
01 maxlen   pic 9(9) comp-5 value 20000.
01 pos      pic 9(9) comp-5.
01 namelen  pic 9(9) comp-5.
01 tname    pic x(128).
01 datalen  pic 9(9) comp-5.
01 tdata    pic x(4096).
01 ent      pic x(8192).
01 entlen   pic 9(9) comp-5.
01 hash     pic x(33).
01 rel      pic x(700).
01 rellen   pic 9(9) comp-5.
01 path     pic x(700).
01 pathlen  pic 9(9) comp-5.
01 st       pic s9(9) comp-5.
01 dpath    pic x(32).
01 t-type   pic x(11) value "system/type".
01 t-type-len pic 9(9) comp-5 value 11.
01 s-tp     pic x(12) value "system/type/".
01 w2.
   05 w2b pic x(2).
01 w2n redefines w2 pic 9(4) comp-x.
01 w4.
   05 w4b pic x(4).
01 w4n redefines w4 pic 9(9) comp-x.
procedure division.
    move "src/core-types.dat" to dpath
    move x"00" to dpath(19:1)
    call "ec_read_file" using by reference dpath by reference fbuf
        by value maxlen returning flen
    if flen <= 0 then goback end-if
    move 1 to pos
    perform until pos >= flen
        move fbuf(pos:2) to w2b
        move w2n to namelen
        add 2 to pos
        move fbuf(pos:namelen) to tname(1:namelen)
        add namelen to pos
        move fbuf(pos:4) to w4b
        move w4n to datalen
        add 4 to pos
        move fbuf(pos:datalen) to tdata(1:datalen)
        add datalen to pos
        call "b-entity" using t-type t-type-len tdata datalen
            ent entlen hash st
        move s-tp to rel(1:12)
        move tname(1:namelen) to rel(13:namelen)
        compute rellen = 12 + namelen
        call "mkpath" using rel rellen path pathlen
        call "store-bind" using path pathlen ent entlen hash
    end-perform
    goback.
end program publish-types.
