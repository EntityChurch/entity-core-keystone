\ entity-core-protocol-forth — L1 identity: keystore + peer identity + signatures.
\
\ An identity is derived from a 32-byte Ed25519 SEED (the entity-core PEM = base64 of the
\ raw seed). From the seed we derive: the 32-byte public key (FFI), the `system/peer`
\ entity {public_key, key_type} (§3.5 — peer_id is NOT in the hashable basis), the
\ id_hash = content_hash(peer_entity), and the wire peer_id string (§1.5 canonical form:
\ Base58(varint(0x01) ‖ varint(0x00) ‖ raw-pubkey) — hash_type 0x00 identity-multihash).
\
\ Single-threaded peer: one identity per process. We keep the seed + derived material in
\ module VARIABLEs (copied into the durable store heap so they outlive an arena reset).

create id-seed  32 allot          \ the 32-byte seed (durable module storage)
create id-pub   32 allot          \ derived public key
variable id-peer-addr             \ durable addr of the system/peer entity record
variable id-peer-len
variable id-hash-addr             \ durable addr of id_hash (content_hash of peer entity)
variable id-hash-len
variable id-peerid-addr           \ durable addr of the base58 peer_id string
variable id-peerid-len

s" ed25519" 2constant KEY-TYPE-STR
1 constant KEY-TYPE-ED25519       \ §1.5 key_type code 0x01
0 constant HASH-TYPE-IDENTITY     \ §1.5 hash_type 0x00 identity-multihash

\ id-peer-entity ( -- eaddr eu )  build the system/peer entity {public_key, key_type} in
\ the arena. §3.5: exactly these two fields, canonical map order handled by the codec.
: id-peer-entity ( -- eaddr eu )
  am-mark { mk }
  [char] m b,  2 4 >be
  s" public_key" tv-text 2drop  id-pub 32 tv-bytes 2drop
  s" key_type"   tv-text 2drop  KEY-TYPE-STR tv-text 2drop
  mk am-span                                   \ ( data-map-addr data-map-len )
  s" system/peer" 2swap ent-make ;             \ ( type data -> ent )

\ id-init ( seed-addr seed-u -- )  install the identity from a 32-byte seed. Derives pub,
\ peer entity, id_hash, peer_id; stores durable copies. THROWs E-BAD-SEED on wrong length.
: id-init { saddr su -- }
  su 32 <> if E-BAD-SEED throw then
  saddr id-seed 32 move
  id-seed 32 crypto-ed25519-pubkey  drop id-pub 32 move   \ derive pubkey -> id-pub
  id-peer-entity  store-dup { pu } { paddr }              \ durable peer entity
  paddr id-peer-addr !  pu id-peer-len !
  paddr ent-hash store-dup id-hash-len ! id-hash-addr !   \ durable id_hash
  KEY-TYPE-ED25519 HASH-TYPE-IDENTITY id-pub 32 peerid-format
  store-dup id-peerid-len ! id-peerid-addr ! ;            \ durable peer_id string

: id-peer      ( -- eaddr eu )  id-peer-addr @ id-peer-len @ ;
: id-idhash    ( -- h-addr h-u )  id-hash-addr @ id-hash-len @ ;
: id-peerid    ( -- p-addr p-u )  id-peerid-addr @ id-peerid-len @ ;

\ ── signatures (§3.5 system/signature) ──
\ sig-entity ( target-addr target-u signer-addr signer-u sig-addr(64) -- eaddr eu )
\ build a system/signature {target, signer, algorithm:"ed25519", signature} entity.
: sig-entity { taddr tu sgnaddr sgnu sigaddr -- eaddr eu }
  am-mark { mk }
  [char] m b,  4 4 >be
  s" algorithm" tv-text 2drop  s" ed25519" tv-text 2drop
  s" signature" tv-text 2drop  sigaddr 64 tv-bytes 2drop
  s" signer"    tv-text 2drop  sgnaddr sgnu tv-bytes 2drop
  s" target"    tv-text 2drop  taddr tu tv-bytes 2drop
  mk am-span
  s" system/signature" 2swap ent-make ;

\ id-sign ( target-hash-addr target-hash-u -- sig-entity-addr sig-entity-u )  sign the
\ target content-hash bytes with our seed; build the system/signature entity (signer =
\ our id_hash). The full hash bytes (format-code ‖ digest) are the signed message (§4.6).
: id-sign { thaddr thu -- eaddr eu }
  id-seed  thaddr thu  crypto-ed25519-sign  drop { sigaddr }   \ 64-byte sig in arena
  thaddr thu  id-idhash  sigaddr  sig-entity ;

\ id-verify-sig ( sig-ent-addr pub-addr pub-u -- flag )  verify a system/signature entity's
\ signature over its `target` using the given public key. 1 valid / 0 invalid.
: id-verify-sig { sigent paddr pu -- flag }
  paddr pu 32 <> if 2drop drop false exit then drop
  sigent s" target"    ent-field dup 0= if drop false exit then tv-payload { tu } { taddr }
  sigent s" signature" ent-field dup 0= if drop false exit then tv-payload { su } { saddr }
  su 64 <> if false exit then
  paddr taddr tu saddr crypto-ed25519-verify ;

\ id-peerid-of-pub ( pub-addr pub-u -- peerid-addr peerid-u )  derive the §1.5 peer_id
\ string of an Ed25519 public key (identity-multihash form).
: id-peerid-of-pub { paddr pu -- pidaddr pidu }
  KEY-TYPE-ED25519 HASH-TYPE-IDENTITY paddr pu peerid-format ;
