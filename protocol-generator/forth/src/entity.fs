\ entity-core-protocol-forth — a materialized entity {type, data, content_hash} (§1.1,
\ §3.4) on top of the S2 codec value model.
\
\ THE STACK-MACHINE REP (A-FT-000/A-FT-009): Forth has no records, so an entity is a
\ self-delimiting byte string built in the arena (the same discipline as the TV rep in
\ cbor.fs) — and it passes as an (addr,len) span, never a typed object:
\     'E' | type-len(4 BE) | type | hash-len(4 BE) | hash | data-TV
\ The leading 'E' + fixed framing make it unambiguous; a bare (0,0) span is the safe
\ absent sentinel (a present entity is always tag 'E', >=1 byte — A-FT-007: absent is
\ NEVER the empty string, which is a legitimate wire text value).
\
\ content_hash covers ONLY {type, data} (§1.1); the WIRE form (ent->wire) carries it as a
\ third field so entities are self-describing across serialization (§3.1). `data` is an
\ ARBITRARY ECF value (§1.1 / A-JAVA-010) — a map for core-protocol entities, a scalar for
\ e.g. primitive/string — so the field-read helpers take the map VIEW (empty map for a
\ scalar) and never fault.

\ EC_TRACE-gated diagnostics (nonempty env => on). Used sparingly across the peer machinery.
s" EC_TRACE" getenv nip 0<> constant EC-TRACE?
: ec-trace ( n -- )  EC-TRACE? if ." [t " . ." ]" cr else drop then ;
: ec-tracem ( c-addr u -- )  EC-TRACE? if ." [t " type ." ]" cr else 2drop then ;

\ ── construction ── ent-make ( type-addr type-u data-tv-addr data-tv-u -- ent-addr ent-u )
\ Compute the §9.1 content_hash (SHA-256 floor, format_code 0x00) over {type,data} and lay
\ down the entity record in the arena.
: ent-make { taddr tu daddr du -- eaddr eu }
  taddr tu daddr du 0 hash-content { haddr hu }       \ content_hash (format 0x00)
  am-mark { mk }
  [char] E b,
  tu 4 >be  taddr tu bytes,
  hu 4 >be  haddr hu bytes,
  daddr du bytes,
  mk am-span ;

\ ent-admitted ( taddr tu daddr du haddr hu -- eaddr eu )  the §6.3 RECEIPT
\ constructor: bind an entity to a content_hash the CALLER has already verified
\ against hash-content. ent-make AUTHORS a hash; on the system/tree:put path that
\ is exactly what §6.3 (0.8.2.11) forbids — the submitter authors, the peer
\ verifies. Reachable only from the admission ladder, which has just proved the
\ carried bytes match.
: ent-admitted { taddr tu daddr du haddr hu -- eaddr eu }
  am-mark { mk }
  [char] E b,
  tu 4 >be  taddr tu bytes,
  hu 4 >be  haddr hu bytes,
  daddr du bytes,
  mk am-span ;

\ ── field accessors over the (addr,len) record ──
\ NOTE: @be is ( base-addr offset width -- u ) — always pass an explicit offset (A-FT-011).
: ent-type ( eaddr -- t-addr t-u )
  dup 1 4 @be { tu }  5 + tu ;                          \ ( addr+5 tu )
: >ent-hashp ( eaddr -- hp )  dup 1 4 @be 5 + + ;       \ addr of the hash-len field
: ent-hash ( eaddr -- h-addr h-u )
  >ent-hashp  dup 0 4 @be { hu }  4 + hu ;              \ ( hp+4 hu )
\ ent-data ( eaddr -- d-addr d-u )  the raw data-TV span. daddr = hashp + 4 + hash-len.
: ent-data ( eaddr -- d-addr d-u )
  >ent-hashp  dup 0 4 @be 4 + +  { daddr }
  daddr  daddr tv-node-len ;

\ ent-len ( eaddr -- u )  the total byte length of the self-delimiting entity record
\ (from the 'E' tag through the end of the data TV).
: ent-len ( eaddr -- u )
  dup ent-data + ( eaddr end-addr )  swap - ;

\ ent-data-map ( eaddr -- m-addr | 0 )  the data TV addr IF it is a map, else 0.
: ent-data-map ( eaddr -- maddr )
  ent-data drop dup c@ [char] m = if else drop 0 then ;

\ ── data-map field reads (return 0/0 or a marker on absent) ──
\ ent-text ( eaddr key-addr key-u -- v-addr v-u | 0 0 )  a text/bytes field value payload.
: ent-text { eaddr kaddr ku -- vaddr vu }
  eaddr ent-data-map dup 0= if drop 0 0 exit then
  kaddr ku tv-map-get dup 0= if drop 0 0 exit then
  tv-payload ;                                           \ payload bytes of the value TV

\ ent-field ( eaddr key-addr key-u -- vtv-addr | 0 )  the raw value TV addr for a key.
: ent-field { eaddr kaddr ku -- vaddr }
  eaddr ent-data-map dup 0= if drop 0 exit then
  kaddr ku tv-map-get ;

\ ent-uint ( eaddr key-addr key-u -- u present? )  an unsigned int field value.
: ent-uint { eaddr kaddr ku -- u present }
  eaddr kaddr ku ent-field dup 0= if drop 0 false exit then
  dup c@ [char] i <> if drop 0 false exit then
  tv-int-value true ;

\ ── wire form: {type, data, content_hash} as a map TV in the arena ──
\ ent->wire ( eaddr -- wtv-addr wtv-u )
: ent->wire { eaddr -- waddr wu }
  am-mark { mk }
  [char] m b,  3 4 >be
  s" type"         tv-text 2drop  eaddr ent-type tv-text 2drop
  s" data"         tv-text 2drop  eaddr ent-data bytes,
  s" content_hash" tv-text 2drop  eaddr ent-hash tv-bytes 2drop
  mk am-span ;

\ ent<-wire ( mtv-addr -- eaddr | 0 )  parse a wire entity map, RECOMPUTE the hash from
\ {type,data}, validate against the carried content_hash (§1.8 fidelity). Returns 0 (with
\ E-* THROWn) on a bad shape / mismatch — the caller CATCHes at the dispatch boundary.
-25200 constant E-MISSING-TYPE
-25201 constant E-MISSING-DATA
-25202 constant E-HASH-MISMATCH
: ent<-wire { mtv -- eaddr }
  mtv c@ [char] m <> if E-MISSING-TYPE throw then
  mtv s" type" tv-map-get dup 0= if E-MISSING-TYPE throw then
    dup c@ [char] t <> if E-MISSING-TYPE throw then tv-payload { tu } { taddr }
  mtv s" data" tv-map-get dup 0= if E-MISSING-DATA throw then { dtv }
  taddr tu  dtv dtv tv-node-len  ent-make { eaddr eu }
  mtv s" content_hash" tv-map-get dup if
    dup c@ [char] b = if
      tv-payload  eaddr ent-hash compare 0<> if E-HASH-MISMATCH throw then
    else drop then
  else drop then
  eaddr ;
