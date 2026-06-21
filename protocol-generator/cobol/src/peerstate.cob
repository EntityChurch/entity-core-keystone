>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — peer identity + flags (static singleton).
*>
*> Holds the peer's derived identity (seed/pubkey/peer_id/peer-entity/
*> identity_hash) and the runtime flags (open_grants, conformance). One stateful
*> module (ENTRY points share WORKING-STORAGE). ps-init derives the identity from
*> the seed and seeds the content store with the local peer entity (used later for
*> root-granter resolution). Getters expose pieces to the dispatch brain.
*> ===================================================================
identification division.
program-id. peerstate.
data division.
working-storage section.
01 ps-seed     pic x(32).
01 ps-pub      pic x(32).
01 ps-peerid   pic x(128).
01 ps-peerid-len pic 9(9) comp-5.
01 ps-pent     pic x(8192).
01 ps-pent-len pic 9(9) comp-5.
01 ps-idhash   pic x(33).
01 ps-open     pic 9(1) value 0.
01 ps-conf     pic 9(1) value 0.
linkage section.
01 lk-seed     pic x(32).
01 lk-open     pic 9(1).
01 lk-conf     pic 9(1).
01 lk-out32    pic x(32).
01 lk-out33    pic x(33).
01 lk-str      pic x(128).
01 lk-len      pic 9(9) comp-5.
01 lk-ent      pic x(8192).
procedure division.
    goback.

*> ---- ps-init : derive identity + seed the store -------------------
entry "ps-init" using lk-seed lk-open lk-conf.
    move lk-seed to ps-seed
    move lk-open to ps-open
    move lk-conf to ps-conf
    call "ident-of-seed" using ps-seed ps-pub ps-peerid ps-peerid-len
        ps-pent ps-pent-len ps-idhash
    call "store-init"
    call "store-put" using ps-pent ps-pent-len ps-idhash
    goback.

entry "ps-seed" using lk-out32.
    move ps-seed to lk-out32  goback.
entry "ps-pubkey" using lk-out32.
    move ps-pub to lk-out32  goback.
entry "ps-idhash" using lk-out33.
    move ps-idhash to lk-out33  goback.
entry "ps-peerid" using lk-str lk-len.
    move ps-peerid to lk-str  move ps-peerid-len to lk-len  goback.
entry "ps-pent" using lk-ent lk-len.
    move ps-pent(1:ps-pent-len) to lk-ent(1:ps-pent-len)
    move ps-pent-len to lk-len  goback.
entry "ps-flags" using lk-open lk-conf.
    move ps-open to lk-open  move ps-conf to lk-conf  goback.
end program peerstate.
