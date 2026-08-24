\ entity-core-protocol-forth — built-in handlers + the handler registry contract.
\
\ The registry is the §6.13(a) L0 peer-owner-write approach (the COBOL/Rexx shape): the
\ peer OWNER wires protocol ops to NATIVE handler words; community-installed handlers arrive
\ above the dispatcher interface (out of core scope). A handler is a `system/handler` entity
\ bound in the tree at its dispatch path (§6.6 resolves by the longest-prefix tree-walk).
\
\ The only handler with a full body at S3 is system/protocol/connect (§4.1 hello +
\ authenticate — the handshake the smoke exercises). system/tree / system/capability /
\ system/type are registered (so §6.6 resolves them and returns a real handler for the
\ authority-gated smoke leg) with minimal get/request bodies; full semantics are S4.
\
\ A handler word has the stack effect:  ( conn-idx exec-eaddr  arr lens nvar -- status result-eaddr result-eu )
\ where (arr lens nvar) is the inbound request's included set. The dispatcher maps the
\ status+result into an EXECUTE_RESPONSE.

\ ── connection state (per accepted/dialed connection) ──
\ A connection is an index into parallel arrays: fd, established?, issued-nonce, out-counter.
\ §4.10(c) admission: sized ABOVE the resource_bounds r3 flood (256 concurrent connects) plus
\ headroom for the post-flood keep-serving probe — so the peer accepts the whole flood AND
\ still hands out a slot for the follow-up handshake (the "kept serving" WARN path, not the
\ "fell over" FAIL). select()'s static fd_set holds 1024 fds; 320 conns stay well inside it.
320 constant MAX-CONNS
create conn-fd        MAX-CONNS cells allot
create conn-estab     MAX-CONNS cells allot
create conn-nonce     MAX-CONNS 32 * allot      \ 32-byte issued nonce per conn
create conn-has-nonce MAX-CONNS cells allot
create conn-outctr    MAX-CONNS cells allot
variable conn-count
: conn-reset ( -- )  0 conn-count ! ;
conn-reset
\ conn-free-slot ( -- idx | -1 )  a reclaimed slot (conn-fd == -1, a closed connection) below
\ conn-count, else -1. Closed connections tombstone their fd to -1 (conn-drop) so the slot is
\ reusable — without this a long conformance run (hundreds of short probe connections) would
\ exhaust the 64-slot table and start refusing accepts (the write-i/o-timeout symptom).
: conn-free-slot ( -- idx )
  conn-count @ 0 ?do  conn-fd i cells + @ -1 = if i unloop exit then  loop  -1 ;
\ conn-slot ( -- idx | -1 )  a slot to use: a reclaimed one if any, else grow conn-count.
: conn-slot ( -- idx )
  conn-free-slot dup 0>= if exit then  drop            \ reuse a tombstoned slot
  conn-count @ dup MAX-CONNS >= if drop -1 exit then   \ full: no slot
  dup 1+ conn-count ! ;                                 \ grow: return the new index
: conn-new { fd -- idx }
  conn-slot dup 0< if exit then { i }
  fd conn-fd i cells + !
  0 conn-estab i cells + !  0 conn-has-nonce i cells + !  0 conn-outctr i cells + !
  i ;
\ conn-drop ( idx -- )  tombstone a connection slot (its fd is already closed). The slot is
\ then reusable by conn-new; gather-fds skips a -1 fd.
: conn-drop ( idx -- )  -1 swap cells conn-fd + ! ;
: conn-fd@ ( idx -- fd )  cells conn-fd + @ ;
: conn-estab@ ( idx -- flag )  cells conn-estab + @ ;
: conn-set-estab ( idx -- )  1 swap cells conn-estab + ! ;
: conn-nonce-addr ( idx -- addr )  32 * conn-nonce + ;
: conn-next-out ( idx -- n )  dup cells conn-outctr + dup @ 1+ dup rot ! ;

\ ── a fresh 32-byte nonce (deterministic-ish: SHA256 of a counter + our id_hash; the smoke
\ needs uniqueness + reproducibility, not CSPRNG strength — §4.6 SHOULD, not MUST) ──
variable nonce-ctr
create nonce-seed-buf 40 allot
: mint-nonce { idx -- }
  nonce-ctr @ 1+ dup nonce-ctr !  nonce-seed-buf !     \ counter in first 8 bytes
  id-idhash { iu } { iaddr }                            \ our id_hash (addr,len)
  iaddr  nonce-seed-buf 8 +  iu 32 min  move           \ append id_hash after the counter
  nonce-seed-buf 40 crypto-sha256 drop { digaddr }     \ SHA256(counter++id_hash) -> 32 bytes
  digaddr  idx conn-nonce-addr  32  move               \ store into the conn's nonce slot
  1 idx cells conn-has-nonce + ! ;

\ ── the handler registry: pattern -> native word xt, bound as a system/handler in the tree ──
128 constant MAX-HANDLERS
create hnd-pat-addr  MAX-HANDLERS cells allot
create hnd-pat-len   MAX-HANDLERS cells allot
create hnd-xt        MAX-HANDLERS cells allot
variable hnd-count
: hnd-reset ( -- )  0 hnd-count ! ;
hnd-reset

\ register-handler ( pat-addr pat-u xt -- )  bind a native handler word at a dispatch path,
\ AND bind a system/handler entity in the tree (so §6.6 resolves it). §6.13(a).
: register-handler { paddr pu xt -- }
  hnd-count @ dup MAX-HANDLERS >= if drop exit then { i }
  paddr pu store-dup  hnd-pat-len i cells + !  hnd-pat-addr i cells + !
  xt hnd-xt i cells + !
  i 1+ hnd-count !
  \ bind a minimal system/handler entity at the path (data = {pattern: <path>})
  am-mark { mk }
  [char] m b,  1 4 >be
  s" pattern" tv-text 2drop  paddr pu tv-text 2drop
  mk am-span
  s" system/handler" 2swap ent-make { haddr hpu }
  paddr pu  haddr hpu  store-bind ;

\ ── §6.2 handler-manifest publishing: a system/handler/interface entity at
\ /<local>/system/handler/<pattern> carrying {pattern, name, operations:{op:{...}}} so the
\ oracle's `handlers` category (tree.get system/handler/<pattern>) finds each manifest. ──
create hi-path-buf 512 allot
\ hi-path ( pat-a pat-u -- p-a p-u )  build /<local>/system/handler/<pattern>.
: hi-path { pa pu -- ra ru }
  0 { c }
  [char] / hi-path-buf c! 1 to c
  id-peerid hi-path-buf c + swap dup { l } move  c l + to c
  s" /system/handler/" hi-path-buf c + swap dup { s2 } move  c s2 + to c
  pa hi-path-buf c + pu move  c pu + to c
  hi-path-buf c ;
\ ops-map-emit ( ops-a ops-u -- )  emit an operations map {op:{}} in place, keys = the
\ space-separated op names in `ops`. Appends the map header + one empty-map value per op.
variable ops-count  variable ops-prev-space
: count-ops { oa ou -- n }   \ number of space-separated tokens
  0 ops-count !  1 ops-prev-space !            \ primed as if the char before start is a space
  ou 0 ?do
    oa i + c@ bl = if 1 ops-prev-space !
    else ops-prev-space @ if 1 ops-count +! then  0 ops-prev-space ! then
  loop  ops-count @ ;
variable ops-tok-start
\ emit-op ( a start end -- )  if end>start, emit key=a[start..end) + an empty op-spec map value.
: emit-op { oa s e -- }
  e s <= if exit then
  oa s +  e s -  tv-text 2drop                         \ op key
  am-mark [char] m b, 0 4 >be drop ;                   \ empty op-spec map value (in place)
: ops-map-emit { oa ou -- }
  [char] m b, oa ou count-ops 4 >be                    \ map header (pair count = #ops)
  0 ops-tok-start !
  ou 1+ 0 ?do
    i ou = i ou < oa i + c@ bl = and or if             \ at a boundary (space or end)?
      oa ops-tok-start @ i emit-op
      i 1+ ops-tok-start !
    then
  loop ;                                                \ the map TV stays appended in place
\ publish-handler-iface ( pat-a pat-u name-a name-u ops-a ops-u -- )  bind the interface entity.
: publish-handler-iface { pa pu na nu oa ou -- }
  am-mark { mk }  [char] m b, 3 4 >be
  s" pattern"    tv-text 2drop  pa pu tv-text 2drop
  s" name"       tv-text 2drop  na nu tv-text 2drop
  s" operations" tv-text 2drop  oa ou ops-map-emit
  mk am-span  s" system/handler/interface" 2swap ent-make { ea eu }
  pa pu hi-path  ea eu store-bind ;

\ dispatch-path ( pat-a pat-u -- p-a p-u )  build /<local>/<pattern> (the peer-rooted dispatch
\ path a validator TreeGet(<pattern>) canonicalizes to).
create dp-path-buf 512 allot
: dispatch-path { pa pu -- ra ru }
  0 { c }
  [char] / dp-path-buf c! 1 to c
  id-peerid dp-path-buf c + swap dup { l } move  c l + to c
  [char] / dp-path-buf c + c!  c 1+ to c
  pa dp-path-buf c + pu move  c pu + to c
  dp-path-buf c ;
\ ifr-buf ( -- ) scratch for the interface ref "system/handler/<pattern>".
create ifr-buf 512 allot
\ publish-handler-dispatch ( pat-a pat-u -- )  bind the §6.2 N2 dispatch entity: a system/handler
\ {interface: "system/handler/<pattern>"} at /<local>/<pattern>. The `handlers` category's
\ handler_<name>_dispatch_type / _interface_ref checks TreeGet the bare pattern path and assert
\ type==system/handler + interface==system/handler/<pattern>.
: publish-handler-dispatch { pa pu -- }
  s" system/handler/" ifr-buf swap dup { pfxu } move
  pa ifr-buf pfxu + pu move
  ifr-buf pfxu pu +  { ifa ifu }                       \ interface ref value
  am-mark { mk }  [char] m b, 1 4 >be
  s" interface" tv-text 2drop  ifa ifu tv-text 2drop
  mk am-span  s" system/handler" 2swap ent-make { hea heu }   \ ( eaddr eu ) stack-order (A-FT-012)
  pa pu dispatch-path  hea heu store-bind ;

\ unregister-handler ( pat-addr pat-u -- )  drop the native binding + unbind the tree entity.
: unregister-handler { paddr pu -- }
  hnd-count @ 0 ?do
    hnd-pat-addr i cells + @  hnd-pat-len i cells + @  paddr pu compare 0= if
      0 hnd-xt i cells + !                 \ tombstone the native word
    then
  loop
  paddr pu store-unbind ;

\ hnd-lookup ( pat-addr pat-u -- xt | 0 )  the native word bound at exactly this pattern.
: hnd-lookup { paddr pu -- xt }
  hnd-count @ 0 ?do
    hnd-pat-addr i cells + @  hnd-pat-len i cells + @  paddr pu compare 0= if
      hnd-xt i cells + @ unloop exit
    then
  loop  0 ;

\ ── §6.6 handler resolution: backward tree-walk, longest prefix -> shortest ──
\ resolve-handler ( path-addr path-u -- pat-addr pat-u | 0 0 )  the longest path prefix
\ bound to a system/handler entity. Returns 0 0 if none (the dispatcher -> 404). A
\ begin/while loop carries the current prefix length on the stack; we shorten to the
\ previous '/' each miss. (No ?do here, so no unloop.)
: resolve-handler { paddr pu -- rpaddr rpu }
  pu                                              ( plen )
  begin dup 0> while
    dup { plen }
    paddr plen store-get-at ?dup if
      ent-type s" system/handler" compare 0= if
        drop paddr plen exit                       \ hit: return (addr, prefix-len)
      then
    then
    \ shorten to the previous '/' boundary (drop the last segment)
    plen 1-                                        ( k )
    begin dup 0> over paddr + c@ [char] / <> and while 1- repeat
  repeat
  drop 0 0 ;

\ ── the response included set (the outbound authority carrier a handler contributes to) ──
\ A handler that returns a capability (authenticate) adds the token + granter peer +
\ signature to this set; the dispatcher folds it into the response envelope. incB is the
\ single outbound builder (single-thread; reset per response).
: resp-inc-reset ( -- )  0 incB-n ! ;
: resp-inc-add { eaddr eu -- }  incB-addr incB-len incB-n  eaddr eu  inc-add ;

\ ── seed grant: a root single-sig capability token granting the §4.4 SHOULD floor ──
\ For S3 the token is a root cap whose granter == our id_hash, grantee == the authenticating
\ peer's id_hash. Grants: get on system/tree over system/handler. (Full policy-union is S4.)

\ hnd-now-ms ( -- ms )  wall-clock milliseconds since the Unix epoch (§2a handler-set
\ timestamps). Fits one 64-bit cell. A minted token stamps this into `created_at` so a
\ requested/delegated child cap is NEVER byte-identical to the seed cap even when its grant
\ and grantee coincide — otherwise the two collide on content_hash and revoking the child
\ silently revokes the seed (the §5.1 revocation cascade this MUST avoid). Rexx parity:
\ Peer_MintToken stamps Cap_NowMs() for the same reason.
: hnd-now-ms ( -- ms )  utime d>s 1000 / ;
\ text-array1 ( s-addr s-u -- atv-addr atv-u )  a 1-element text array TV.
: text-array1 { saddr su -- aaddr au }
  am-mark { mk }  [char] a b,  1 4 >be  saddr su tv-text 2drop  mk am-span ;
\ text-array2 ( a-addr a-u b-addr b-u -- atv-addr atv-u )  a 2-element text array TV.
: text-array2 { aaddr au baddr bu -- taddr tu }
  am-mark { mk }  [char] a b,  2 4 >be
  aaddr au tv-text 2drop  baddr bu tv-text 2drop  mk am-span ;
\ path-scope-inc1 ( s-addr s-u -- mtv )  {include: [s]} as a map TV.
: path-scope-inc1 { saddr su -- maddr mu }
  am-mark { mk }  [char] m b,  1 4 >be
  s" include" tv-text 2drop  saddr su text-array1 2drop  mk am-span ;
\ path-scope-inc2 ( a-addr a-u b-addr b-u -- mtv )  {include: [a,b]} as a map TV.
: path-scope-inc2 { aaddr au baddr bu -- maddr mu }
  am-mark { mk }  [char] m b,  1 4 >be
  s" include" tv-text 2drop  aaddr au baddr bu text-array2 2drop  mk am-span ;

\ mint-seed-token ( grantee-h-addr grantee-h-u -- token-eaddr token-eu )  build+bind a root
\ token entity granting the floor, then return it (the caller signs it + adds to included).
\ §4.4 SHOULD floor: under the peer-owner-write (--debug-open-grants) seed policy the
\ connection grant is the degenerate default→* — {handlers:[*], resources:[*], operations:[*]}
\ — so the validator's connection_grants_{tree_handler,types,handlers} coverage checks (which
\ probe system/tree over system/type/* and system/handler/* with `get`) all match, and the
\ authenticated EXECUTE legs (request_id_echoed, tree.get, handler manifest reads) authorize.
: mint-seed-token { gaddr gu -- teaddr teu }
  \ grant-entry (the §9.0 open-grants scope, byte-parity with the Rexx cohort peer's
  \ _open_grants_scope): {handlers:{include:[*]}, operations:{include:[*]},
  \ peers:{include:[*]}, resources:{include:[*, /*/*]}}. The resources dimension carries
  \ BOTH the bare "*" (local-namespace wildcard) AND "/*/*" (the cross-peer universal form,
  \ §1.4) so the validator's advertised-grant coverage checks — including the
  \ universal_address_space category's grants_sufficient gate, which probes a FOREIGN
  \ absolute path /<other>/... — see the foreign namespace covered.
  am-mark { gemk }
  [char] m b,  4 4 >be
  s" handlers"   tv-text 2drop  s" *" path-scope-inc1 2drop
  s" operations" tv-text 2drop  s" *" path-scope-inc1 2drop
  s" peers"      tv-text 2drop  s" *" path-scope-inc1 2drop
  s" resources"  tv-text 2drop  s" *" s" /*/*" path-scope-inc2 2drop
  gemk am-span { geu } { geaddr }
  \ token data: {grantee, granter, grants:[grant-entry], created_at}
  am-mark { tmk }
  [char] m b,  4 4 >be
  s" grantee"    tv-text 2drop  gaddr gu tv-bytes 2drop
  s" granter"    tv-text 2drop  id-idhash tv-bytes 2drop
  s" grants"     tv-text 2drop
     am-mark [char] a b, 1 4 >be  geaddr geu bytes,  drop
  s" created_at" tv-text 2drop  hnd-now-ms tv-uint 2drop
  tmk am-span
  s" system/capability/token" 2swap ent-make ;

\ ── status-code helpers ──
: op-eq ( exec-eaddr op$-addr op$-u -- flag )  { oa ou } exec-operation oa ou compare 0= ;

\ ── the connect handler (§4.1) — hello then authenticate ──
\ params-of ( exec-eaddr -- params-eaddr | 0 )  the params entity carried in the exec.
: params-of { exec -- pe }
  exec s" params" ent-field dup 0= if drop 0 exit then ent<-wire ;

\ tv-array-has ( atv-addr s-addr s-u -- flag )  is text `s` an element of the array TV? (0 if
\ atv is 0/not an array). Used by the §4.5 negotiation disjointness check.
: tv-array-has { atv saddr su -- flag }
  atv 0= if false exit then
  atv c@ [char] a <> if false exit then
  atv tv-count { n }
  n 0 ?do
    atv i tv-array-elem dup c@ [char] t = if
      tv-payload saddr su compare 0= if true unloop exit then
    else drop then
  loop  false ;

\ negotiation-disjoint ( params-eaddr key-addr key-u supported-addr supported-u -- flag )
\ §4.5 (A-RX-007 present-empty-vs-absent seam): true iff the request params carry `key` as an
\ array that does NOT include our single `supported` value. Absent key -> false (no constraint).
: negotiation-disjoint { p kaddr ku saddr su -- flag }
  p 0= if false exit then
  p kaddr ku ent-field dup 0= if drop false exit then { atv }
  atv c@ [char] a <> if false exit then          \ present but not an array: not our concern
  atv saddr su tv-array-has 0= ;                  \ present array without our value -> disjoint

\ hello-keytype-bad? ( params-eaddr|0 -- flag )  true iff params carry a peer_id whose
\ multihash key_type prefix is present and NOT ed25519 (0x01). Parses in an isolated arena
\ frame (peerid-parse appends the base58 decode; we rewind) and swallows a parse THROW
\ (a malformed peer_id defers to authenticate). Absent params / absent peer_id -> false.
: hello-keytype-bad? { p -- flag }
  p 0= if false exit then
  p s" peer_id" ent-text { pa pu }
  pu 0= if false exit then
  am-mark { mk0 }
  pa pu ['] peerid-parse catch { code }                \ ok: ( kt ht daddr du ) ; throw: ( pa pu )
  code if 2drop mk0 rewind false exit then             \ throw: drop the restored ( pa pu ); defer
  2drop drop { kt }                                    \ ok: drop du daddr ht, keep kt (bottom)
  mk0 rewind
  kt KEY-TYPE-ED25519 <> ;

\ hello response: {peer_id, nonce, protocols, timestamp, hash_formats, key_types}. §4.5:
\ the hello advertises the accept-sets (hash_formats=[ecfv1-sha256], key_types=[ed25519]); a
\ request that pins a DISJOINT set is rejected 400 before we issue a nonce.
: hnd-connect-hello { conn exec arr lens nvar -- status result-eaddr result-eu }
  conn conn-estab@ if
    409  s" connection_already_established" 0 0 error-result exit
  then
  exec params-of { hp }
  hp s" hash_formats" s" ecfv1-sha256" negotiation-disjoint
    if 400 s" incompatible_hash_format" 0 0 error-result exit then
  hp s" key_types" s" ed25519" negotiation-disjoint
    if 400 s" unsupported_key_type" 0 0 error-result exit then
  hp hello-keytype-bad? if 400 s" unsupported_key_type" 0 0 error-result exit then
  conn mint-nonce
  am-mark { mk }
  [char] m b,  6 4 >be
  s" peer_id"      tv-text 2drop  id-peerid tv-text 2drop
  s" nonce"        tv-text 2drop  conn conn-nonce-addr 32 tv-bytes 2drop
  s" protocols"    tv-text 2drop  s" entity-core/1.0" text-array1 2drop
  s" timestamp"    tv-text 2drop  0 tv-uint 2drop
  s" hash_formats" tv-text 2drop  s" ecfv1-sha256" text-array1 2drop
  s" key_types"    tv-text 2drop  s" ed25519" text-array1 2drop
  mk am-span
  s" system/protocol/connect/hello" 2swap ent-make
  200 -rot ;   \ ( status result-eaddr result-eu )

\ authenticate: verify nonce echo + signature + identity binding, then issue a grant.
: hnd-connect-auth { conn exec arr lens nvar -- status result-eaddr result-eu }
  \ RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed single-use
  \ nonce. The STATUS is pinned to 401 invalid_nonce -- a 409 state-conflict under-
  \ signals the replay.
  conn conn-estab@ if 401 s" invalid_nonce" 0 0 error-result exit then
  conn cells conn-has-nonce + @ 0= if 401 s" invalid_nonce" 0 0 error-result exit then
  exec params-of dup 0= if drop 401 s" authentication_failed" 0 0 error-result exit then { p }
  \ nonce echo check
  p s" nonce" ent-field dup 0= if drop 401 s" invalid_nonce" 0 0 error-result exit then
    tv-payload { nu } { naddr }
  nu 32 <>                                                  \ wrong length?
  naddr nu  conn conn-nonce-addr 32  compare 0<> or         \ or bytes differ from issued
    if 401 s" invalid_nonce" 0 0 error-result exit then
  \ public key + key_type
  p s" public_key" ent-field dup 0= if drop 400 s" unsupported_key_type" 0 0 error-result exit then
    tv-payload { pku } { pkaddr }
  pku 32 <> if 400 s" unsupported_key_type" 0 0 error-result exit then
  \ verify the authenticate signature (target = params entity content_hash) from included
  p ent-hash arr lens nvar cap-find-signature dup 0=
    if drop 401 s" authentication_failed" 0 0 error-result exit then
    { sig }
  sig pkaddr pku id-verify-sig 0= if 401 s" authentication_failed" 0 0 error-result exit then
  \ identity binding: claimed peer_id == peer_id derived from public_key
  p s" peer_id" ent-field dup 0= if drop 401 s" identity_mismatch" 0 0 error-result exit then
    tv-payload { claimu } { claimaddr }
  pkaddr pku id-peerid-of-pub  claimaddr claimu compare 0<>
    if 401 s" identity_mismatch" 0 0 error-result exit then
  \ SUCCESS: derive the authenticating peer's id_hash, mint a seed token, sign it, and put
  \ the token + granter (us) + signature into the response included set. Establish conn.
  \ grantee id_hash = content_hash(system/peer{public_key,key_type}) of the auth'd peer.
  am-mark { pmk }
  [char] m b,  2 4 >be
  s" public_key" tv-text 2drop  pkaddr pku tv-bytes 2drop
  s" key_type"   tv-text 2drop  s" ed25519" tv-text 2drop
  pmk am-span  s" system/peer" 2swap ent-make { grantee-peer-u } { grantee-peer }
  grantee-peer ent-hash mint-seed-token { teu } { teaddr }
  teaddr ent-hash id-sign { sigu } { sigaddr }     \ our signature over the token hash
  resp-inc-reset
  teaddr teu resp-inc-add
  id-peer resp-inc-add
  sigaddr sigu resp-inc-add
  grantee-peer grantee-peer-u resp-inc-add
  conn conn-set-estab
  \ result: system/capability/grant {token: <token content_hash>}
  am-mark { gmk }
  [char] m b,  1 4 >be
  s" token" tv-text 2drop  teaddr ent-hash tv-bytes 2drop
  gmk am-span  s" system/capability/grant" 2swap ent-make
  200 -rot ;

\ hnd-connect ( conn exec arr lens nvar -- status result-eaddr result-eu )  the dispatcher
\ for system/protocol/connect operations. Ordering (§4.2): hello before authenticate; an
\ unknown op is a sequence/unsupported error.
: hnd-connect { conn exec arr lens nvar -- status result-eaddr result-eu }
  exec s" hello" op-eq if conn exec arr lens nvar hnd-connect-hello exit then
  exec s" authenticate" op-eq if conn exec arr lens nvar hnd-connect-auth exit then
  400 s" connection_sequence_error" 0 0 error-result ;

\ ── the tree handler (§6.3): get an entity by path, or list a directory prefix ──
\ tree-canon ( path-a path-u -- ca cu )  a bare path is peer-rooted "/<local>/<path>"; an
\ absolute path is returned as-is. Built into a durable scratch buffer.
create tree-path-buf 1024 allot
: tree-canon { pa pu -- ca cu }
  pu 0> pa c@ [char] / = and if pa pu exit then     \ already absolute
  0 { c }
  [char] / tree-path-buf c! 1 to c
  id-peerid tree-path-buf c + swap dup { l } move  c l + to c
  [char] / tree-path-buf c + c!  c 1+ to c
  pa tree-path-buf c + pu move  c pu + to c
  tree-path-buf c ;

\ tree-target ( exec -- t-a t-u | 0 0 )  the resource.targets[0] text, or 0 0.
: tree-target { exec -- ta tu }
  exec s" resource" ent-field dup 0= if drop 0 0 exit then { rtv }
  rtv s" targets" tv-map-get dup 0= if drop 0 0 exit then
    dup c@ [char] a <> if drop 0 0 exit then
    dup tv-count 0= if drop 0 0 exit then
    0 tv-array-elem dup c@ [char] t <> if drop 0 0 exit then tv-payload ;

\ child-of? ( prefix-a prefix-u path-idx -- rem-a rem-u flag )  is the store path at index a
\ bound descendant of the prefix? (flag, on TOP for a following `if`) plus the remainder span
\ after the prefix. To dedup by IMMEDIATE child, the caller only emits an entry the FIRST time a
\ given child segment appears.
: child-of? { pfa pfu i -- ra ru flag }
  st-hash-addr i cells + @ 0= if 0 0 false exit then           \ tombstoned
  st-path-len i cells + @ pfu <= if 0 0 false exit then        \ not longer than prefix
  st-path-addr i cells + @  pfu  pfa pfu compare 0<> if 0 0 false exit then
  st-path-addr i cells + @ pfu +  st-path-len i cells + @ pfu -  true ;
\ child-seg ( rem-a rem-u -- seg-a seg-u has-children? )  the immediate child segment + whether
\ the remainder continues past it (a '/' -> the child has descendants).
: child-seg { ra ru -- sa su hc }
  ru 0 ?do  ra i + c@ [char] / = if ra i true unloop exit then  loop  ra ru false ;
\ seg-seen? ( pfa pfu upto-idx seg-a seg-u -- flag )  has this child segment already been emitted
\ by an earlier bound path under the prefix? (first-seen dedup for the listing).
: seg-seen? { pfa pfu upto sa su -- flag }
  upto 0 ?do
    pfa pfu i child-of? if                            \ ( csa csu )
      child-seg drop  sa su compare 0= if true unloop exit then   \ segments equal -> seen
    else 2drop then
  loop  false ;

\ tree-listing ( prefix-a prefix-u -- status result-eaddr result-eu )  build a
\ system/tree/listing {path, entries:{seg -> listing-entry}, count, offset} of the immediate
\ children of the (already-canonicalized, trailing-'/') prefix. Single pass: emit distinct
\ immediate children into the entries map (its pair-count patched afterward from the actual
\ count — avoids any count-vs-emit divergence risk).
\ be! ( u addr -- )  write u as a 4-byte big-endian field at addr (patch a TV count).
: be! { u addr -- }
  u 24 rshift 255 and addr c!  u 16 rshift 255 and addr 1+ c!
  u 8 rshift 255 and addr 2 + c!  u 255 and addr 3 + c! ;
variable listing-emitted
\ try-emit-child ( pfa pfu i -- )  if store-path[i] is a NEW immediate child of the prefix,
\ append its entries-map pair: seg -> {has_children, hash}. All locals are per-call (the loop
\ body itself carries none — a gforth locals-in-loop hazard we avoid by delegating here).
: try-emit-child { pfa pfu i -- }
  pfa pfu i child-of? 0= if 2drop exit then           \ not a child (drops ra ru if any)
  child-seg { sa su hc }                               \ ( -- ) sa/su = seg, hc = has-children
  pfa pfu i sa su seg-seen? if exit then               \ already emitted this segment
  sa su tv-text 2drop                                  \ key = child segment
  am-mark [char] m b, 2 4 >be
    s" has_children" tv-text 2drop  hc if [char] R else [char] F then b,
    s" hash" tv-text 2drop
      hc if 0 0 tv-bytes 2drop                          \ has children -> nil-ish (empty bytes)
      else st-hash-addr i cells + @ st-hash-len i cells + @ tv-bytes 2drop then
  drop
  1 listing-emitted +! ;
: tree-listing { pfa pfu -- status raddr ru }
  0 listing-emitted !
  am-mark { emk }  [char] m b, 0 4 >be              \ entries map header; count patched after emit
  st-count @ 0 ?do  pfa pfu i try-emit-child  loop
  listing-emitted @ emk 1 + be!                      \ patch the actual pair count
  emk am-span { ema emu }
  am-mark { mk }
  [char] m b,  4 4 >be
  s" path"    tv-text 2drop  pfa pfu tv-text 2drop
  s" entries" tv-text 2drop  ema emu bytes,
  s" count"   tv-text 2drop  listing-emitted @ tv-uint 2drop
  s" offset"  tv-text 2drop  0 tv-uint 2drop
  mk am-span  s" system/tree/listing" 2swap ent-make
  200 -rot ;

\ all-zero? ( a u -- flag )  are all u bytes at a zero?
: all-zero? { a u -- flag }
  u 0= if true exit then
  u 0 ?do  a i + c@ 0<> if false unloop exit then  loop  true ;

\ path-flex-ok? ( t-a t-u -- flag )  §1.4 R1 path validity: no NUL, no empty/./.. segments.
\ Reject a leading "./" or "../" or a "//" (empty segment) or a bare "." / ".." segment.
: seg-bad? { sa su -- flag }  \ is a single segment empty / "." / ".."?
  su 0= if true exit then
  su 1 = sa c@ [char] . = and if true exit then
  su 2 = sa c@ [char] . = and sa 1+ c@ [char] . = and if true exit then
  false ;
\ has-nul? ( a u -- flag )  does the span contain a 0x00 byte? (§1.4: no NUL in any segment.)
: has-nul? { a u -- flag }
  u 0 ?do  a i + c@ 0= if true unloop exit then  loop  false ;
\ slash-from-h ( a u start -- idx | -1 )  first '/' at or after start (handlers.fs-local copy;
\ capauthz.fs defines its own `slash-from`, loaded later).
: slash-from-h { a u start -- idx }
  u start ?do  a i + c@ [char] / = if i unloop exit then  loop  -1 ;
\ b58-char? ( c -- flag )  is c a Base58 alphabet char? (excludes 0 O I l)
s" 123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" 2constant B58-ALPHA
: b58-char? { c -- flag }
  B58-ALPHA nip 0 ?do  c B58-ALPHA drop i + c@ = if true unloop exit then  loop  false ;
\ seg-is-peerid? ( a u -- flag )  §1.4: a leading-'/' path's first segment MUST be a peer_id —
\ Base58, >= 46 chars (Rexx Cap_IsPeerId). A leading '/' onto a non-peer segment is malformed.
: seg-is-peerid? { a u -- flag }
  u 46 < if false exit then
  u 0 ?do  a i + c@ b58-char? 0= if false unloop exit then  loop  true ;
: path-flex-ok? { ta tu -- flag }
  tu 0= if false exit then
  ta tu has-nul? if false exit then                   \ §1.4: NUL byte invalid in any path
  \ A leading '/' means an ABSOLUTE path: its first segment MUST be a valid peer_id (§1.4).
  \ A leading '/' onto a non-peer segment (e.g. "/system/...") is malformed -> reject.
  ta c@ [char] / = if
    ta 1+ tu 1-  0 slash-from-h { fsl }               \ index of the next '/' (or -1)
    fsl 0< if ta 1+ tu 1- else ta 1+ fsl then seg-is-peerid? 0= if false exit then
  then
  \ walk '/'-separated segments; an absolute path's leading '/' yields an empty FIRST segment
  \ that is the peer-root marker (allowed) — so skip a single leading '/'.
  ta c@ [char] / = if ta 1+ tu 1- else ta tu then { pa pu }
  \ strip a single trailing '/'
  pu 0> pa pu 1- + c@ [char] / = and if pu 1- to pu then
  0 { s }
  pu 1+ 0 ?do
    i pu = i pu < pa i + c@ [char] / = and or if
      pa s +  i s -  seg-bad? if false unloop exit then
      i 1+ to s
    then
  loop  true ;

\ store-hash-at ( p-a p-u -- h-a h-u | 0 0 )  the content_hash bound at a tree path, or 0 0.
: store-hash-at { pa pu -- ha hu }
  pa pu st-find dup 0< if drop 0 0 exit then { idx }
  st-hash-addr idx cells + @ dup 0= if drop 0 0 exit then
  st-hash-len idx cells + @ ;

\ tree-put ( exec -- status raddr ru )  §6.3 put + §3.9 CAS. params: {entity, expected_hash}.
\ CAS: expected absent -> unconditional; zero-hash -> create-only (409 if bound); else must
\ equal the current binding (409 hash_mismatch). Returns system/hash{hash} on success.
: tree-put { exec -- status raddr ru }
  exec tree-target dup 0= if 2drop 400 s" ambiguous_resource" 0 0 error-result exit then { ta tu }
  ta tu path-flex-ok? 0= if 400 s" invalid_path" 0 0 error-result exit then
  ta tu tree-canon { ca cu }
  exec params-of dup 0= if drop 400 s" unexpected_params" 0 0 error-result exit then { p }
  p s" entity" ent-field { etv }                          \ the entity value TV
  etv 0= if 400 s" unexpected_params" 0 0 error-result exit then
  etv c@ [char] m = if etv ent<-wire else                  \ nested entity wire-map
    etv c@ [char] b = if etv tv-payload cbor-decode drop ent<-wire else 0 then then { ent }
  p s" expected_hash" ent-text { xa xu }                  \ CAS expectation (0 0 if absent)
  ca cu store-hash-at { curh curhu }                       \ current binding hash
  xu 0<> if
    xa xu all-zero? if
      curhu 0<> if 409 s" hash_mismatch" 0 0 error-result exit then   \ create-only: already bound
    else
      curhu 0= if 409 s" hash_mismatch" 0 0 error-result exit then    \ expected a binding, none
      xa xu curh curhu compare 0<> if 409 s" hash_mismatch" 0 0 error-result exit then
    then
  then
  ent 0= if 400 s" unexpected_params" 0 0 error-result exit then
  \ §9.5a deletion-marker: putting a system/deletion-marker tombstones the path (a subsequent
  \ get -> 404). We still bind the marker (so its hash is returned) then unbind the path.
  ca cu ent ent ent-len store-bind
  ent ent-type s" system/deletion-marker" compare 0= if ca cu store-unbind then
  am-mark { mk }  [char] m b, 1 4 >be
  s" hash" tv-text 2drop  ent ent-hash tv-bytes 2drop
  mk am-span  s" system/hash" 2swap ent-make  200 -rot ;

: hnd-tree { conn exec arr lens nvar -- status result-eaddr result-eu }
  exec s" put" op-eq if exec tree-put exit then
  exec s" get" op-eq 0= if 501 s" unsupported_operation" 0 0 error-result exit then
  exec tree-target { ta tu }
  ta 0= tu 0= or if                                   \ no target OR empty target -> list peer root
    s" /" tree-canon tree-listing exit
  then
  ta tu path-flex-ok? 0= if 400 s" invalid_path" 0 0 error-result exit then
  ta tu tree-canon { ca cu }
  cu 0> ca cu 1- + c@ [char] / = and if ca cu tree-listing exit then   \ trailing '/' -> listing
  ca cu store-get-at dup 0= if drop 404 s" not_found" 0 0 error-result exit then
  { e }  200 e e ent-len ;                                             \ ( status result-eaddr result-eu )

\ ── the capability handler (§6.2): request / configure / revoke / delegate ──
\ hexlc ( src-a src-u dst -- dst dst-u )  lowercase-hex-encode src bytes into dst.
create hexchars 16 allot
s" 0123456789abcdef" hexchars swap move
\ nib>hex ( nibble -- ascii )  a 0..15 nibble to its lowercase hex ASCII char.
: nib>hex ( n -- c )  hexchars + c@ ;
: hexlc { sa su dst -- da du }
  su 0 ?do
    sa i + c@ dup 4 rshift nib>hex  dst i 2* + c!
              15 and     nib>hex   dst i 2* 1+ + c!
  loop  dst su 2* ;

\ cap-abs ( sub-a sub-u -- p-a p-u )  build /<local>/system/capability/<sub> in a scratch buf.
create cap-abs-buf 1024 allot
: cap-abs { sa su -- pa pu }
  0 { c }
  [char] / cap-abs-buf c! 1 to c
  id-peerid cap-abs-buf c + swap dup { l } move  c l + to c
  s" /system/capability/" cap-abs-buf c + swap dup { s2 } move  c s2 + to c
  sa cap-abs-buf c + su move  c su + to c
  cap-abs-buf c ;

\ mint-grant-token ( grantee-h-a grantee-h-u grants-atv -- token-eaddr token-eu )  build a
\ single-sig token {grantee, granter=us, grants:[...], created_at} with the given grants array.
: mint-grant-token { gaddr gu gatv -- teaddr teu }
  am-mark { tmk }
  [char] m b,  4 4 >be
  s" grantee"    tv-text 2drop  gaddr gu tv-bytes 2drop
  s" granter"    tv-text 2drop  id-idhash tv-bytes 2drop
  s" grants"     tv-text 2drop  gatv gatv tv-node-len bytes,
  s" created_at" tv-text 2drop  hnd-now-ms tv-uint 2drop
  tmk am-span
  s" system/capability/token" 2swap ent-make ;

\ req-grants-bounded? ( exec arr lens nvar grants-atv -- flag )  §6.2: a `request`/`delegate`
\ handler MUST NOT mint a grant exceeding the caller's presented authority. Returns true iff
\ every requested grant is a subset of some grant on the PRESENTED cap (exec.capability). If no
\ cap is presented, the caller is the connection identity (§4.4 seed) → allow (bounded by the
\ seed). DEFERRED: filled in from capauthz.fs (which owns the §5.5 subset primitives, loaded
\ after this module). Default (pre-fill) is permissive so a boot before capauthz stays sane.
defer req-grants-bounded?
:noname { exec arr lens nvar gatv -- flag }  true ; is req-grants-bounded?

\ cap-request ( exec arr lens nvar author-h-a author-h-u -- status raddr ru )  mint a grant for
\ the caller, attenuated against the presented capability. The requested grants ride in
\ params.grants; grantee = the authenticated author. A requested grant that EXCEEDS the
\ presented cap's authority is refused 403 scope_exceeds_authority (§6.2 keystone accept-path).
: cap-request { exec arr lens nvar aa au -- status raddr ru }
  exec params-of dup 0= if drop 400 s" invalid_params" 0 0 error-result exit then { p }
  p s" grants" ent-field dup 0= if drop 400 s" invalid_params" 0 0 error-result exit then { gatv }
  gatv c@ [char] a <> if 400 s" invalid_params" 0 0 error-result exit then
  gatv tv-count 0= if 400 s" invalid_params" 0 0 error-result exit then
  exec arr lens nvar gatv req-grants-bounded? 0= if
    403 s" scope_exceeds_authority" 0 0 error-result exit then
  aa au gatv mint-grant-token { teu } { teaddr }
  teaddr ent-hash id-sign { su } { saddr }
  resp-inc-reset  teaddr teu resp-inc-add  id-peer resp-inc-add  saddr su resp-inc-add
  am-mark { mk }  [char] m b, 1 4 >be
  s" token" tv-text 2drop  teaddr ent-hash tv-bytes 2drop
  mk am-span  s" system/capability/grant" 2swap ent-make  200 -rot ;

\ is-hex? ( a u -- flag )  all chars are [0-9a-f].
: is-hex? { a u -- flag }
  u 0= if false exit then
  u 0 ?do  a i + c@ { c }
    c [char] 0 >= c [char] 9 <= and
    c [char] a >= c [char] f <= and or 0= if false unloop exit then
  loop  true ;
\ valid-peer-pattern? ( a u -- flag )  §4: "default", OR a 64/96-hex identity hash, OR a Base58
\ peer_id. Reject a partial-prefix (e.g. "00abc*"). We accept: "default", a full-hex string, or
\ any non-hex string WITHOUT a trailing '*' (a Base58 peer_id). Reject anything ending in '*'.
: valid-peer-pattern? { a u -- flag }
  a u s" default" compare 0= if true exit then
  u 0= if false exit then
  a u 1- + c@ [char] * = if false exit then          \ partial-prefix wildcard -> reject
  true ;

\ cap-abs2 ( pre-a pre-u sub-a sub-u -- p-a p-u )  build /<local>/system/capability/<pre><sub>
\ into a dedicated durable buffer (no reliance on the shared pad).
create cap-abs2-buf 1024 allot
: cap-abs2 { prea preu suba subu -- pa pu }
  0 { c }
  [char] / cap-abs2-buf c! 1 to c
  id-peerid cap-abs2-buf c + swap dup { l } move  c l + to c
  s" /system/capability/" cap-abs2-buf c + swap dup { s2 } move  c s2 + to c
  prea cap-abs2-buf c + preu move  c preu + to c
  suba cap-abs2-buf c + subu move  c subu + to c
  cap-abs2-buf c ;

\ cap-configure ( exec -- status raddr ru )  write a policy entry at policy/<peer_pattern>.
: cap-configure { exec -- status raddr ru }
  exec params-of dup 0= if drop 400 s" invalid_params" 0 0 error-result exit then { p }
  p s" peer_pattern" ent-text dup 0= if 2drop 400 s" invalid_params" 0 0 error-result exit then { ppa ppu }
  ppa ppu valid-peer-pattern? 0= if 400 s" invalid_params" 0 0 error-result exit then
  p s" grants" ent-field dup 0= if drop 400 s" invalid_params" 0 0 error-result exit then
    dup c@ [char] a <> if drop 400 s" invalid_params" 0 0 error-result exit then
    tv-count 0= if 400 s" invalid_params" 0 0 error-result exit then
  s" policy/" ppa ppu cap-abs2  p p ent-len store-bind
  200 p p ent-len ;

\ cap-revoke ( exec -- status raddr ru )  write a revocation marker at revocations/<hex(token)>.
create revhex 160 allot
: cap-revoke { exec -- status raddr ru }
  exec params-of dup 0= if drop 400 s" invalid_params" 0 0 error-result exit then { p }
  p s" token" ent-text dup 0= if 2drop 400 s" invalid_params" 0 0 error-result exit then { tka tku }
  tka tku all-zero? if 400 s" invalid_params" 0 0 error-result exit then   \ §10: token MUST be non-zero
  am-mark { mk }  [char] m b, 3 4 >be
  s" token"      tv-text 2drop  tka tku tv-bytes 2drop
  s" reason"     tv-text 2drop  s" revoked" tv-text 2drop
  s" revoked_at" tv-text 2drop  utime d>s 1000 / tv-uint 2drop   \ §2a: handler-set wall-clock ms
  mk am-span  s" system/capability/revocation" 2swap ent-make { maddr mu }
  \ path = revocations/<hex(token)>
  tka tku  revhex  hexlc { ha hu }
  s" revocations/" ha hu cap-abs2 { pa pu }
  pa pu maddr mu store-bind
  200 maddr mu ;                                       \ ( status result-eaddr result-eu )

: hnd-capability { conn exec arr lens nvar -- status result-eaddr result-eu }
  exec s" request"   op-eq if exec arr lens nvar  exec s" author" ent-text  cap-request exit then
  exec s" configure" op-eq if exec cap-configure exit then
  exec s" revoke"    op-eq if exec cap-revoke exit then
  exec s" delegate"  op-eq if 501 s" unsupported_operation" 0 0 error-result exit then
  501 s" unsupported_operation" 0 0 error-result ;

: hnd-type { conn exec arr lens nvar -- status result-eaddr result-eu }
  501 s" unsupported_operation" 0 0 error-result ;

\ ── §6.2 system/handler:register / :unregister — the L0 peer-owner-write protocol ──
\ Behavioral presence is NORMATIVE under --profile core (§6.2 v7.74): the register op MUST
\ execute the five spec writes; a 501 stub is non-conformant. Byte-parity with the Rexx
\ cohort peer's _handlers_register / _handlers_unregister.

\ peer-abs ( sub-a sub-u -- p-a p-u )  build /<local>/<sub> into a dedicated durable buffer
\ (the peer-rooted absolute form a tree.get canonicalizes to — so a register write and a
\ subsequent validator TreeGet resolve to the SAME path).
create peer-abs-buf 1024 allot
: peer-abs { sa su -- pa pu }
  0 { c }
  [char] / peer-abs-buf c! 1 to c
  id-peerid peer-abs-buf c + swap dup { l } move  c l + to c
  [char] / peer-abs-buf c + c!  c 1+ to c
  sa peer-abs-buf c + su move  c su + to c
  peer-abs-buf c ;

\ reg-pattern ( exec -- pa pu | 0 0 )  the register/unregister pattern = resource.targets[0]
\ with the leading "system/handler/" stripped (§3.2 path-as-resource). 0 0 if the target is
\ missing or not under system/handler/.
: reg-pattern { exec -- pa pu }
  exec tree-target dup 0= if 2drop 0 0 exit then { ta tu }
  s" system/handler/" nip { pfxu }
  tu pfxu <= if 0 0 exit then                          \ too short to carry a pattern
  ta pfxu  s" system/handler/" compare 0<> if 0 0 exit then   \ prefix must match exactly
  ta pfxu +  tu pfxu -  dup 0<= if 2drop 0 0 exit then ;

create reg-sighex 160 allot            \ hex-encode scratch for the grant-hash signature path
create reg-typebuf 256 allot           \ system/type/<name> path scratch

\ cap-cat ( pre-a pre-u sub-a sub-u -- ca cu )  concatenate two spans into a durable scratch
\ buffer (a relative path like "system/capability/grants/" + pattern), returning the joined
\ span (still RELATIVE — the caller peer-abs's it).
create cap-cat-buf 1024 allot
: cap-cat { prea preu suba subu -- ca cu }
  prea cap-cat-buf preu move
  suba cap-cat-buf preu + subu move
  cap-cat-buf preu subu + ;

\ manifest-interface-rel ( pat-a pat-u -- ra ru )  the interface path "system/handler/<pattern>"
\ (relative form, used as the handler entity's `interface` field value + the interface bind key).
create reg-ifacebuf 512 allot
: manifest-interface-rel { pa pu -- ra ru }
  s" system/handler/" reg-ifacebuf swap dup { pfxu } move
  pa reg-ifacebuf pfxu + pu move
  reg-ifacebuf pfxu pu + ;

\ bind-type-entry ( key-a key-u val-tv -- )  install ONE associated type at
\ /<local>/system/type/<name> as a system/type entity (data = the value map, or {def: value}
\ for a non-map). All locals per-CALL (a delegated loop body — A-FT-019).
: bind-type-entry { tka tku tvp -- }
  s" system/type/" reg-typebuf swap dup { pfxu } move
  tka reg-typebuf pfxu + tku move
  reg-typebuf pfxu tku +  peer-abs { tpa tpu }
  tvp c@ [char] m = if
    s" system/type" tvp tvp tv-node-len ent-make
  else
    am-mark { dmk }  [char] m b, 1 4 >be
      s" def" tv-text 2drop  tvp tvp tv-node-len bytes,
    dmk am-span  s" system/type" 2swap ent-make
  then { tea teu }                                    \ ( eaddr eu ) stack-order (A-FT-012)
  tpa tpu  tea teu store-bind ;

\ bind-associated-types ( types-mtv -- )  walk a {name -> type-def} map, binding each entry.
: bind-associated-types { m -- }
  m 0= if exit then  m c@ [char] m <> if exit then
  m tv-count { n }
  m 5 + { p }                                       \ first pair after the 4-byte map header
  n 0 ?do
    p c@ [char] t = if                              \ text key (a type name)
      p tv-payload { ku } { ka }                    \ key span
      p tv-node-len p + { vp }                      \ value TV addr
      ka ku vp bind-type-entry
      vp tv-node-len vp + to p                       \ advance past value -> next pair
    else
      p tv-node-len p +  dup tv-node-len + to p      \ skip a non-text key + its value
    then
  loop ;

\ mtv-text ( mtv key-a key-u -- v-a v-u | 0 0 )  a text/bytes field's payload off a RAW map TV
\ (the register-request/manifest fields are plain CBOR maps, NOT nested {type,data,hash} entities).
: mtv-text { m ka ku -- va vu }
  m 0= if 0 0 exit then  m c@ [char] m <> if 0 0 exit then
  m ka ku tv-map-get dup 0= if drop 0 0 exit then  tv-payload ;
\ mtv-field ( mtv key-a key-u -- vtv | 0 )  a raw value TV off a raw map TV.
: mtv-field { m ka ku -- vtv }
  m 0= if 0 exit then  m c@ [char] m <> if 0 exit then  m ka ku tv-map-get ;

\ ── register WRITEs, factored into small words (each stays under gforth's per-word locals cap) ──
\ reg-write-handler ( pa pu manifest-mtv -- )  WRITE 1 + 5: the dispatch handler entity at
\ <pattern> (system/handler {interface, expression_path?}) AND the interface entity
\ (system/handler/interface {name, operations, pattern}) at system/handler/<pattern>. `manifest`
\ is the RAW manifest map TV (register-request.manifest is inline CBOR, not a wire entity).
: reg-write-handler { pa pu manifest -- }
  pa pu manifest-interface-rel { ifacea ifaceu }
  manifest s" expression_path" mtv-text { xpa xpu }
  \ WRITE 1: system/handler {interface, expression_path?} at <pattern>
  am-mark { hmk }  [char] m b,  xpu 0<> if 2 else 1 then 4 >be
    s" interface"       tv-text 2drop  ifacea ifaceu tv-text 2drop
    xpu 0<> if s" expression_path" tv-text 2drop  xpa xpu tv-text 2drop then
  hmk am-span  s" system/handler" 2swap ent-make { hea heu }   \ ( eaddr eu ) stack-order (A-FT-012)
  pa pu peer-abs  hea heu store-bind
  \ WRITE 5: system/handler/interface {name, operations, pattern} at system/handler/<pattern>
  manifest s" name" mtv-text { nma nmu }
  nmu 0= if pa to nma pu to nmu then
  manifest s" operations" mtv-field { ops-mtv }
  am-mark { imk }  [char] m b,  3 4 >be
    s" name"       tv-text 2drop  nma nmu tv-text 2drop
    s" operations" tv-text 2drop
      ops-mtv 0<> ops-mtv c@ [char] m = and if ops-mtv ops-mtv tv-node-len bytes, drop
      else am-mark [char] m b, 0 4 >be drop then
    s" pattern"    tv-text 2drop  pa pu tv-text 2drop
  imk am-span  s" system/handler/interface" 2swap ent-make { iea ieu }   \ ( eaddr eu ) (A-FT-012)
  ifacea ifaceu peer-abs  iea ieu store-bind ;

\ reg-write-grant ( pa pu req manifest -- grant-eaddr )  WRITE 3 + 4: mint the handler grant
\ token (grantee=us, grants=requested_scope|internal_scope) at system/capability/grants/<pattern>,
\ then bind its §3.5 signature at system/signature/<hex(grant_hash)>. Returns the grant entity.
: reg-write-grant { pa pu req manifest -- gta }
  req s" requested_scope" ent-field dup 0= if drop
    manifest s" internal_scope" mtv-field
  then { scope-atv }
  am-mark { gmk }
  [char] m b,  4 4 >be
  s" grantee"    tv-text 2drop  id-idhash tv-bytes 2drop
  s" granter"    tv-text 2drop  id-idhash tv-bytes 2drop
  s" grants"     tv-text 2drop
    scope-atv 0<> scope-atv c@ [char] a = and if scope-atv scope-atv tv-node-len bytes, drop
    else am-mark [char] a b, 0 4 >be drop then
  s" created_at" tv-text 2drop  hnd-now-ms tv-uint 2drop
  gmk am-span  s" system/capability/token" 2swap ent-make drop { gta }
  s" system/capability/grants/" pa pu cap-cat  peer-abs  gta gta ent-len store-bind
  \ WRITE 4: signature at /<local>/system/signature/<hex(grant_hash)>
  gta ent-hash reg-sighex hexlc { sha shu }
  s" system/signature/" sha shu cap-cat  peer-abs { spa spu }
  gta ent-hash id-sign  spa spu 2swap store-bind
  gta ;

\ reserved-pattern? ( pa pu -- flag )  §6.2: true iff pattern == "system" or pattern starts
\ with "system/" -- user-installed handlers MUST NOT register there.
: reserved-pattern? { pa pu -- flag }
  pa pu s" system" compare 0= if true exit then
  pu 7 < if false exit then
  pa 7 s" system/" compare 0= ;

create reg-reservedmsg-buf 512 allot
\ reserved-msg ( pa pu -- ma mu )  the §6.2 refusal message, with the offending pattern
\ appended (durable scratch buffer, same shape as cap-cat/manifest-interface-rel above).
: reserved-msg { pa pu -- ma mu }
  s" §6.2: user-installed handlers MUST NOT register at system/* paths: " { la lu }
  la reg-reservedmsg-buf lu move
  pa reg-reservedmsg-buf lu + pu move
  reg-reservedmsg-buf lu pu + ;

: hnd-handlers-register { conn exec arr lens nvar -- status raddr ru }
  exec reg-pattern dup 0= if 2drop
    exec tree-target 0= if 400 s" ambiguous_resource" 0 0 error-result exit then
    400 s" invalid_resource" 0 0 error-result exit then { pa pu }
  pa pu reserved-pattern? if
    pa pu reserved-msg { ma mu }
    403 s" forbidden_pattern" ma mu error-result exit
  then
  exec params-of dup 0= if drop 400 s" unexpected_params" 0 0 error-result exit then { req }
  req ent-type s" system/handler/register-request" compare 0<> if
    400 s" unexpected_params" 0 0 error-result exit then
  req s" manifest" ent-field { manifest }          \ the RAW manifest map TV (inline CBOR)
  pa pu manifest reg-write-handler                 \ WRITEs 1 + 5
  req s" types" ent-field bind-associated-types     \ WRITE 2
  pa pu req manifest reg-write-grant { gta }         \ WRITEs 3 + 4
  \ result: system/handler/register-result {grant: <grant token data>, pattern}
  am-mark { rmk }  [char] m b,  2 4 >be
    s" grant"   tv-text 2drop  gta ent-data bytes,
    s" pattern" tv-text 2drop  pa pu tv-text 2drop
  rmk am-span  s" system/handler/register-result" 2swap ent-make  200 -rot ;

: hnd-handlers-unregister { conn exec arr lens nvar -- status raddr ru }
  exec reg-pattern dup 0= if 2drop
    exec tree-target 0= if 400 s" ambiguous_resource" 0 0 error-result exit then
    400 s" invalid_resource" 0 0 error-result exit then { pa pu }
  \ remove the grant signature (via the grant's current hash) + grant, then handler + interface.
  s" system/capability/grants/" pa pu cap-cat  peer-abs { gpa gpu }
  gpa gpu store-get-at ?dup if
    ent-hash reg-sighex hexlc { sha shu }
    s" system/signature/" sha shu cap-cat  peer-abs  store-unbind
    gpa gpu store-unbind
  then
  pa pu peer-abs store-unbind                              \ handler entity at <pattern>
  pa pu manifest-interface-rel peer-abs store-unbind       \ interface at system/handler/<pattern>
  \ result: empty-params (primitive/any {})
  am-mark { mk }  [char] m b, 0 4 >be  mk am-span
  TYPE-ANY 2swap ent-make  200 -rot ;

: hnd-handlers { conn exec arr lens nvar -- status result-eaddr result-eu }
  exec s" register"   op-eq if conn exec arr lens nvar hnd-handlers-register   exit then
  exec s" unregister" op-eq if conn exec arr lens nvar hnd-handlers-unregister exit then
  501 s" unsupported_operation" 0 0 error-result ;

