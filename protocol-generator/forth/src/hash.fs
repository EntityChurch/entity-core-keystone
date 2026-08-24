\ entity-core-protocol-forth — content_hash construction (ENTITY-CBOR-ENCODING §4.2):
\
\   content_hash = varint(format_code) || hash_alg(ECF({type, data}))
\
\ format_code 0x00 = ecfv1-sha256 (the §9.1 floor); 0x01 = ecfv1-sha384 (agility). The
\ format_code is NOT part of the hashed basis (only {type,data} is hashed) and its prefix
\ is a multicodec LEB128 varint (N1 — content_hash.4 uses a synthetic >=0x80 code). The
\ ECF encoding is the pure-Forth codec; the SHA crosses the C-ABI.

\ hash-content ( type-addr type-u data-tv-addr data-tv-u format_code -- hash-addr hash-u )
\ `data-tv` is any TV node (A-JAVA-010: entity data need not be a map). Builds the entity
\ TV {type: <text>, data: <tv>}, ECF-encodes it, hashes, prepends varint(format_code).
: hash-content { taddr tu daddr du fmt -- c-addr u }
  \ build the entity TV: m 2 (t"type" <type-text>) (t"data" <data-tv>)
  am-mark { entmk }
  [char] m b,  2 4 >be
  s" type" tv-text 2drop  taddr tu tv-text 2drop
  s" data" tv-text 2drop  daddr du bytes,
  entmk am-span                                    ( ent-tv-addr ent-tv-len )
  cbor-encode                                         ( wire-addr wire-len )
  fmt 1 = if crypto-sha384 else crypto-sha256 then    ( digest-addr digest-len )
  \ prepend varint(fmt): assemble into fresh arena space.
  am-mark { hmk }
  fmt varint-encode                                   \ varint prefix
  bytes,                                              \ append digest bytes
  hmk am-span ;
