>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — capability grants + token minting (§4.4/§5.4).
*>
*> build-grants emits the §4.4 discovery floor (tree get over system/type/* +
*> system/handler/*; capability request), optionally UNION'd with the degenerate
*> open scope (--debug-open-grants). mint-token builds + signs a root capability
*> token granted by us to a grantee (§5.5 root-at-local).
*>
*> Scope = map{include:[patterns]}; grant = map{handlers,resources,operations
*> [,peers]}. Built naive; the token's b-entity canonicalizes the whole data.
*> ===================================================================

*> ---- build-grants --------------------------------------------------
identification division.
program-id. build-grants.
data division.
working-storage section.
01 k-incl  pic x(7) value "include".
01 k-h     pic x(8) value "handlers".
01 k-r     pic x(9) value "resources".
01 k-o     pic x(10) value "operations".
01 k-p     pic x(5) value "peers".
01 s-tree  pic x(11) value "system/tree".
01 s-cap   pic x(17) value "system/capability".
01 s-typew pic x(13) value "system/type/*".
01 s-hdlw  pic x(16) value "system/handler/*".
01 s-get   pic x(3) value "get".
01 s-req   pic x(7) value "request".
01 s-star  pic x(1) value "*".
01 s-pp    pic x(4) value "/*/*".
01 nincl   pic 9(18) comp-5 value 7.
01 nh      pic 9(18) comp-5 value 8.
01 nr      pic 9(18) comp-5 value 9.
01 nops      pic 9(18) comp-5 value 10.
01 np      pic 9(18) comp-5 value 5.
01 nt      pic 9(18) comp-5 value 11.
01 ncap    pic 9(18) comp-5 value 17.
01 ntyw    pic 9(18) comp-5 value 13.
01 nhdw    pic 9(18) comp-5 value 16.
01 n0arr   pic 9(18) comp-5 value 0.
01 n1      pic 9(18) comp-5 value 1.
01 n2      pic 9(18) comp-5 value 2.
01 n3      pic 9(18) comp-5 value 3.
01 n4      pic 9(18) comp-5 value 4.
01 ng      pic 9(18) comp-5 value 3.
01 nrq     pic 9(18) comp-5 value 7.
01 narr    pic 9(18) comp-5.
linkage section.
01 lk-out  pic x(8192).
01 lk-out-len pic 9(9) comp-5.
01 lk-open pic 9(1).
procedure division using lk-out lk-out-len lk-open.
    if lk-open = 1 then move 3 to narr else move 2 to narr end-if
    call "b-arr" using lk-out lk-out-len narr
    *> grant 1: tree get over type/* + handler/*
    call "b-map"  using lk-out lk-out-len ng
    call "b-text" using lk-out lk-out-len k-h nh
    call "b-map"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len k-incl nincl
    call "b-arr"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len s-tree nt
    call "b-text" using lk-out lk-out-len k-r nr
    call "b-map"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len k-incl nincl
    call "b-arr"  using lk-out lk-out-len n2
    call "b-text" using lk-out lk-out-len s-typew ntyw
    call "b-text" using lk-out lk-out-len s-hdlw nhdw
    call "b-text" using lk-out lk-out-len k-o nops
    call "b-map"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len k-incl nincl
    call "b-arr"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len s-get ng
    *> grant 2: capability request
    call "b-map"  using lk-out lk-out-len ng
    call "b-text" using lk-out lk-out-len k-h nh
    call "b-map"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len k-incl nincl
    call "b-arr"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len s-cap ncap
    call "b-text" using lk-out lk-out-len k-r nr
    call "b-map"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len k-incl nincl
    call "b-arr"  using lk-out lk-out-len n0arr
    call "b-text" using lk-out lk-out-len k-o nops
    call "b-map"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len k-incl nincl
    call "b-arr"  using lk-out lk-out-len n1
    call "b-text" using lk-out lk-out-len s-req nrq
    *> grant 3 (open): * over everything
    if lk-open = 1
        call "b-map"  using lk-out lk-out-len n4
        call "b-text" using lk-out lk-out-len k-h nh
        call "b-map"  using lk-out lk-out-len n1
        call "b-text" using lk-out lk-out-len k-incl nincl
        call "b-arr"  using lk-out lk-out-len n1
        call "b-text" using lk-out lk-out-len s-star n1
        call "b-text" using lk-out lk-out-len k-r nr
        call "b-map"  using lk-out lk-out-len n1
        call "b-text" using lk-out lk-out-len k-incl nincl
        call "b-arr"  using lk-out lk-out-len n2
        call "b-text" using lk-out lk-out-len s-star n1
        call "b-text" using lk-out lk-out-len s-pp n4
        call "b-text" using lk-out lk-out-len k-o nops
        call "b-map"  using lk-out lk-out-len n1
        call "b-text" using lk-out lk-out-len k-incl nincl
        call "b-arr"  using lk-out lk-out-len n1
        call "b-text" using lk-out lk-out-len s-star n1
        call "b-text" using lk-out lk-out-len k-p np
        call "b-map"  using lk-out lk-out-len n1
        call "b-text" using lk-out lk-out-len k-incl nincl
        call "b-arr"  using lk-out lk-out-len n1
        call "b-text" using lk-out lk-out-len s-star n1
    end-if
    goback.
end program build-grants.

*> ---- mint-token ----------------------------------------------------
*> Build + sign a root capability token granted by us to GRANTEE_HASH.
*> Returns the token wire entity (+hash) and its signature entity (+hash).
identification division.
program-id. mint-token.
data division.
working-storage section.
01 t-tok   pic x(23) value "system/capability/token".
01 t-tok-len pic 9(9) comp-5 value 23.
01 k-grr   pic x(7)  value "granter".
01 k-gre   pic x(7)  value "grantee".
01 k-grants pic x(6) value "grants".
01 k-ca    pic x(10) value "created_at".
01 idhash  pic x(33).
01 nd      pic x(8192).
01 nd-len  pic 9(9) comp-5.
01 one     pic 9(9) comp-5 value 1.
01 n4      pic 9(18) comp-5 value 4.
01 n6      pic 9(9) comp-5 value 6.
01 n7      pic 9(9) comp-5 value 7.
01 n10     pic 9(9) comp-5 value 10.
01 n33     pic 9(9) comp-5 value 33.
01 created pic 9(18) comp-5 value 1700000000000.
01 st      pic s9(9) comp-5.
linkage section.
01 lk-grantee pic x(33).
01 lk-grants  pic x(8192).
01 lk-grants-len pic 9(9) comp-5.
01 lk-tok     pic x(8192).
01 lk-tok-len pic 9(9) comp-5.
01 lk-tok-hash pic x(33).
01 lk-sig     pic x(8192).
01 lk-sig-len pic 9(9) comp-5.
01 lk-sig-hash pic x(33).
procedure division using lk-grantee lk-grants lk-grants-len
                        lk-tok lk-tok-len lk-tok-hash
                        lk-sig lk-sig-len lk-sig-hash.
    call "ps-idhash" using idhash
    move 0 to nd-len
    call "b-map"   using nd nd-len n4
    call "b-text"  using nd nd-len k-grr n7
    call "b-bytes" using nd nd-len idhash one n33
    call "b-text"  using nd nd-len k-gre n7
    call "b-bytes" using nd nd-len lk-grantee one n33
    call "b-text"  using nd nd-len k-grants n6
    call "b-raw"   using nd nd-len lk-grants one lk-grants-len
    call "b-text"  using nd nd-len k-ca n10
    call "b-uint"  using nd nd-len created
    call "b-entity" using t-tok t-tok-len nd nd-len
        lk-tok lk-tok-len lk-tok-hash st
    *> sign the token
    call "sign-token" using lk-tok-hash lk-sig lk-sig-len lk-sig-hash
    goback.
end program mint-token.

*> sign-token: sign a target hash with our seed/identity (wraps sign-entity).
identification division.
program-id. sign-token.
data division.
working-storage section.
01 seed   pic x(32).
01 idhash pic x(33).
linkage section.
01 lk-target pic x(33).
01 lk-sig    pic x(8192).
01 lk-sig-len pic 9(9) comp-5.
01 lk-sig-hash pic x(33).
procedure division using lk-target lk-sig lk-sig-len lk-sig-hash.
    call "ps-seed" using seed
    call "ps-idhash" using idhash
    call "sign-entity" using seed idhash lk-target lk-sig lk-sig-len lk-sig-hash
    goback.
end program sign-token.
