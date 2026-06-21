>>SOURCE FORMAT FREE
*> ===================================================================
*> entity-core-protocol-cobol — identity (L1): keypair + derived entities
*> (§1.5, §3.5, §7.3, §7.4). Crypto is FFI (libentitycore_codec): seed->pubkey,
*> sign, verify. The peer entity is the v7.65 form {public_key, key_type} with
*> NO peer_id in the hashable basis.
*>
*> Sub-programs:
*>   ident-of-seed     seed(32) -> pubkey(32), peer_id text, peer-entity wire
*>                     bytes + 33-byte identity_hash
*>   sign-entity       (seed, identity_hash, target_hash) -> system/signature
*>                     wire entity + its 33-byte hash
*>   verify-sig        (pub32, msg33, sig64) -> 1 ok / 0 bad (FFI ec_ed25519_verify)
*> ===================================================================

*> ---- peer-entity-of-pubkey -----------------------------------------
*> The v7.65 system/peer entity {public_key, key_type} for a 32-byte pubkey,
*> plus its 33-byte content_hash (= the identity_hash).
identification division.
program-id. peer-entity-of-pubkey.
data division.
working-storage section.
01 t-peer      pic x(11) value "system/peer".
01 t-peer-len  pic 9(9) comp-5 value 11.
01 k-pub       pic x(10) value "public_key".
01 k-kt        pic x(8)  value "key_type".
01 v-ed        pic x(7)  value "ed25519".
01 nd          pic x(8192).
01 nd-len      pic 9(9) comp-5.
01 one         pic 9(9) comp-5 value 1.
01 n2          pic 9(18) comp-5 value 2.
01 n7          pic 9(9) comp-5 value 7.
01 n8          pic 9(9) comp-5 value 8.
01 n10         pic 9(9) comp-5 value 10.
01 n32         pic 9(9) comp-5 value 32.
01 st          pic s9(9) comp-5.
linkage section.
01 lk-pub      pic x(32).
01 lk-pent     pic x(8192).
01 lk-pent-len pic 9(9) comp-5.
01 lk-idhash   pic x(33).
procedure division using lk-pub lk-pent lk-pent-len lk-idhash.
    move 0 to nd-len
    call "b-map" using nd nd-len n2
    call "b-text" using nd nd-len k-pub n10
    call "b-bytes" using nd nd-len lk-pub one n32
    call "b-text" using nd nd-len k-kt n8
    call "b-text" using nd nd-len v-ed n7
    call "b-entity" using t-peer t-peer-len nd nd-len
        lk-pent lk-pent-len lk-idhash st
    goback.
end program peer-entity-of-pubkey.

*> ---- ident-of-seed -------------------------------------------------
identification division.
program-id. ident-of-seed.
data division.
working-storage section.
01 rc          pic s9(9) comp-5.
01 n32         pic 9(9) comp-5 value 32.
linkage section.
01 lk-seed     pic x(32).
01 lk-pub      pic x(32).
01 lk-peerid   pic x(128).
01 lk-peerid-len pic 9(9) comp-5.
01 lk-pent     pic x(8192).
01 lk-pent-len pic 9(9) comp-5.
01 lk-idhash   pic x(33).
procedure division using lk-seed lk-pub lk-peerid lk-peerid-len
                        lk-pent lk-pent-len lk-idhash.
    *> public key from the seed (FFI)
    call "ec_ed25519_seed_to_pubkey" using
        by reference lk-seed by reference lk-pub returning rc
    *> peer_id (§1.5 canonical)
    call "peer-id-of-pubkey" using lk-pub n32 lk-peerid lk-peerid-len
    *> peer entity + identity_hash
    call "peer-entity-of-pubkey" using lk-pub lk-pent lk-pent-len lk-idhash
    goback.
end program ident-of-seed.

*> ---- sign-entity ---------------------------------------------------
*> Produce a system/signature entity over TARGET_HASH (the 33-byte content_hash
*> of the signed entity), signed with SEED. signer = our identity_hash.
identification division.
program-id. sign-entity.
data division.
working-storage section.
01 rc          pic s9(9) comp-5.
01 sigbuf      pic x(64).
01 t-sig       pic x(16) value "system/signature".
01 t-sig-len   pic 9(9) comp-5 value 16.
01 k-target    pic x(6)  value "target".
01 k-signer    pic x(6)  value "signer".
01 k-algo      pic x(9)  value "algorithm".
01 k-sig       pic x(9)  value "signature".
01 v-ed        pic x(7)  value "ed25519".
01 nd          pic x(8192).
01 nd-len      pic 9(9) comp-5.
01 one         pic 9(9) comp-5 value 1.
01 n4          pic 9(18) comp-5 value 4.
01 n6          pic 9(9) comp-5 value 6.
01 n7          pic 9(9) comp-5 value 7.
01 n9          pic 9(9) comp-5 value 9.
01 n33         pic 9(9) comp-5 value 33.
01 n64         pic 9(9) comp-5 value 64.
01 msg33       pic 9(18) comp-5 value 33.
01 st          pic s9(9) comp-5.
linkage section.
01 lk-seed     pic x(32).
01 lk-idhash   pic x(33).
01 lk-target   pic x(33).
01 lk-out      pic x(8192).
01 lk-out-len  pic 9(9) comp-5.
01 lk-sighash  pic x(33).
procedure division using lk-seed lk-idhash lk-target lk-out lk-out-len lk-sighash.
    *> sign the 33-byte target hash (FFI)
    call "ec_ed25519_sign" using
        by reference lk-seed by reference lk-target by value msg33
        by reference sigbuf returning rc
    move 0 to nd-len
    call "b-map" using nd nd-len n4
    call "b-text"  using nd nd-len k-target n6
    call "b-bytes" using nd nd-len lk-target one n33
    call "b-text"  using nd nd-len k-signer n6
    call "b-bytes" using nd nd-len lk-idhash one n33
    call "b-text"  using nd nd-len k-algo n9
    call "b-text"  using nd nd-len v-ed n7
    call "b-text"  using nd nd-len k-sig n9
    call "b-bytes" using nd nd-len sigbuf one n64
    call "b-entity" using t-sig t-sig-len nd nd-len
        lk-out lk-out-len lk-sighash st
    goback.
end program sign-entity.

*> ---- verify-sig ----------------------------------------------------
*> 1 if SIG64 is a valid Ed25519 signature of MSG33 under PUB32, else 0.
identification division.
program-id. verify-sig.
data division.
working-storage section.
01 rc          pic s9(9) comp-5.
01 msglen      pic 9(18) comp-5 value 33.
linkage section.
01 lk-pub      pic x(32).
01 lk-msg      pic x(33).
01 lk-sig      pic x(64).
01 lk-ok       pic 9(1).
procedure division using lk-pub lk-msg lk-sig lk-ok.
    call "ec_ed25519_verify" using
        by reference lk-pub by reference lk-msg by value msglen
        by reference lk-sig returning rc
    if rc = 0 then move 1 to lk-ok else move 0 to lk-ok end-if
    goback.
end program verify-sig.
