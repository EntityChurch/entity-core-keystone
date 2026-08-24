\ entity-core-protocol-forth — peer_id canonical form (§1.5 canonical-form table).
\
\ peer_id wire form = Base58( varint(key_type) || varint(hash_type) || digest ), and the
\ peer_id VALUE on the wire is a CBOR text string wrapping that base58 string. For Ed25519
\ the §1.5 table sets hash_type = 0x00 identity-multihash with digest = the raw 32-byte
\ public key; the conformance vectors also exercise SHA-256 peer-ids (hash_type 0x01) and
\ a synthetic multi-byte key_type (peer_id.3, the N1 varint test).

\ peerid-format ( key_type hash_type digest-addr digest-u -- c-addr u )  build the base58
\ peer_id string into the arena; return its (addr,len). (Not CBOR-wrapped — the caller
\ wraps with tv-text when the peer_id appears as a wire value.)
\ small fixed scratch for the raw prefix+digest (varint kt + varint ht + <=57-byte digest).
create pid-raw  128 allot

\ raw-build ( kt ht daddr du -- raw-addr raw-len )  assemble varint(kt)‖varint(ht)‖digest
\ into pid-raw (a plain byte buffer, NOT the arena) via a tiny cursor. Keeps the base58
\ output span in the arena clean of the raw intermediate.
: raw-build { kt ht daddr du -- raddr rlen }
  kt pid-raw varint-to  { c }                       \ varint(kt)
  ht pid-raw c + varint-to  c +  to c               \ varint(ht)
  daddr pid-raw c +  du move  c du +  to c           \ ‖ digest
  pid-raw c ;

: peerid-format { kt ht daddr du -- c-addr u }
  kt ht daddr du raw-build                          ( raddr rlen )
  am-mark { mk }
  base58-encode
  mk am-span ;

\ peerid-parse ( c-addr u -- key_type hash_type digest-addr digest-u )  decode a base58
\ peer_id string. THROWs on a bad char / truncated varint.
: peerid-parse { c-addr u -- kt ht daddr du }
  am-mark { raw }
  c-addr u base58-decode
  raw am-span  { rlen } { raddr }               \ decoded bytes span
  raddr rlen varint-decode  { kt-consumed } { kt }
  raddr kt-consumed +  rlen kt-consumed -  varint-decode  { ht-consumed } { ht }
  kt ht
  raddr kt-consumed + ht-consumed +               \ digest addr
  rlen kt-consumed - ht-consumed - ;              \ digest len
