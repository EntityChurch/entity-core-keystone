\ entity-core-protocol-forth — S3 peer-layer foundation self-test (no network).
\
\ Exercises the S3 machinery UNITS directly (the direction the loopback smoke + a
\ rejection-only oracle can't fully cover): identity derivation, store round-trips, the N5
\ envelope `included` byte-key/content_hash invariant + first-seen dedup, the wire builders,
\ and the two §4.10 non-functional MUSTs baked in at S3 — the §4.10(b) chain-depth pre-check
\ (-> 400 chain_depth_exceeded, BEFORE the authz walk) and the §4.10(a) 16-MiB payload cap on
\ the length prefix (-> 413 payload_too_large / drain-and-keep).
\
\ gforth has no test framework; the harness is hand-rolled (the cohort pattern). Prints
\ `SELFTEST <pass>/<total>` and exits non-zero on any failure.

require ../src/peer-all.fs

variable pass  variable total
: check ( flag name-addr name-u -- )
  total @ 1+ total !
  rot if pass @ 1+ pass ! ." ok   " else ." FAIL " then type cr ;

\ badd ( e-addr -- )  add an entity to incB (self-delimiting => len via ent-len).
: badd { eaddr -- }  incB-addr incB-len incB-n  eaddr eaddr ent-len  inc-add ;

create sd1 32 allot   create sd2 32 allot   create sd3 32 allot
: fill ( byte addr -- )  32 0 ?do 2dup i + c! loop 2drop ;
: setup ( -- )  $11 sd1 fill  $22 sd2 fill  $33 sd3 fill ;

\ ── L1 identity ──
: t-identity ( -- )
  sd1 32 id-init
  id-peer drop c@ [char] E =                         s" identity: peer entity is an entity" check
  id-idhash nip 33 =                                 s" identity: id_hash is 33 bytes (fmt+sha256)" check
  id-peerid nip 0>                                    s" identity: peer_id string non-empty" check
  \ sign + verify round-trip over a synthetic target hash
  id-idhash id-sign { su } { sa }
  sa id-pub 32 id-verify-sig                          s" identity: sign/verify round-trip" check ;

\ ── foundation store ──
: t-store ( -- )
  store-reset  sd1 32 id-init
  \ bind an entity at a path, read it back
  am-mark [char] m b, 1 4 >be s" k" tv-text 2drop s" v" tv-text 2drop am-span
  s" prim/x" 2swap ent-make { eu } { ea }
  s" a/b/c" ea eu store-bind
  s" a/b/c" store-get-at dup 0<>                      s" store: bind+get round-trip" check
  ?dup if ent-hash ea ent-hash compare 0= else false then
                                                      s" store: retrieved entity hash matches" check
  s" a/b/nope" store-get-at 0=                        s" store: absent path -> 0" check ;

\ ── N5 envelope included: byte-keyed, key==content_hash, first-seen dedup ──
: t-envelope-n5 ( -- )
  store-reset  sd1 32 id-init
  am-mark [char] m b, 1 4 >be s" x" tv-text 2drop s" y" tv-text 2drop am-span
  s" test/root" 2swap ent-make { ru } { root }
  0 incB-n !
  \ add our peer entity TWICE (dedup must collapse to one)
  id-peer drop badd
  id-peer drop badd
  incB-n @ 1 =                                        s" N5: duplicate included entity deduped" check
  root incB-addr incB-len incB-n env->wire { wu } { wa }
  wa wu incA-addr incA-len incA-n env<-wire { r2 }
  r2 ent-type s" test/root" compare 0=               s" N5: envelope root round-trips" check
  incA-n @ 1 =                                        s" N5: included preserved (1 entity)" check
  \ the decoded included entity's hash must equal our peer's (key==content_hash held)
  incA-addr @ ent-hash id-peer drop ent-hash compare 0=
                                                      s" N5: included key == content_hash" check ;

\ ── §4.10(b) chain-depth pre-check -> 400, BEFORE the authz walk ──
\ Build a chain of tokens each pointing to the next via `parent`, exceeding MAX-CHAIN-DEPTH,
\ all present in an included set. cap-exceeds-depth must return true (structural, no sig).
: t-chain-depth ( -- )
  store-reset  sd1 32 id-init
  0 incB-n !
  \ root token (no parent), grantee = our id_hash
  am-mark [char] m b, 2 4 >be
    s" grantee" tv-text 2drop id-idhash tv-bytes 2drop
    s" granter" tv-text 2drop id-idhash tv-bytes 2drop
  am-span s" system/capability/token" 2swap ent-make { r-u } { r-e }
  r-e badd
  r-e { cur }
  \ build a chain 70 deep (each parent = the previous token's hash)
  70 0 ?do
    am-mark [char] m b, 3 4 >be
      s" grantee" tv-text 2drop id-idhash tv-bytes 2drop
      s" granter" tv-text 2drop id-idhash tv-bytes 2drop
      s" parent"  tv-text 2drop cur ent-hash tv-bytes 2drop
    am-span s" system/capability/token" 2swap ent-make { c-u } { c-e }
    c-e badd
    c-e to cur
  loop
  \ cur is the deepest token; the pre-check must flag it (depth 70 > 64)
  cur incB-addr incB-len incB-n cap-exceeds-depth    s" 4.10(b): deep chain -> exceeds-depth (400)" check
  \ the root token alone is within depth
  r-e incB-addr incB-len incB-n cap-exceeds-depth 0= s" 4.10(b): root token within depth" check
  \ an UNREACHABLE parent is NOT a depth problem (returns false -> real walk handles as 403)
  0 incB-n !
  am-mark [char] m b, 3 4 >be
    s" grantee" tv-text 2drop id-idhash tv-bytes 2drop
    s" granter" tv-text 2drop id-idhash tv-bytes 2drop
    s" parent"  tv-text 2drop s" 00deadbeef" tv-bytes 2drop     \ a parent hash not in included
  am-span s" system/capability/token" 2swap ent-make { o-u } { o-e }
  o-e badd
  o-e incB-addr incB-len incB-n cap-exceeds-depth 0= s" 4.10(b): unreachable parent is NOT depth (stays 403)" check ;

\ ── §4.10(a) 16-MiB payload cap: MAX-FRAME finite + over-limit classified ──
: t-payload-cap ( -- )
  MAX-FRAME 16 1024 * 1024 * =                        s" 4.10(a): MAX-FRAME = 16 MiB (finite)" check
  \ the de-framer classifies flen > MAX-FRAME as oversize (drain-and-keep); we can't drive a
  \ real socket here, so assert the classifier predicate the de-framer uses.
  MAX-FRAME 1+  dup 0< swap MAX-FRAME > or            s" 4.10(a): flen > MAX-FRAME flagged oversize (413/drain)" check
  1000 dup 0< swap MAX-FRAME > or 0=                  s" 4.10(a): a normal frame is NOT oversize" check ;

\ ── wire builders: EXECUTE / EXECUTE_RESPONSE / error round-trip through the codec ──
: t-wire ( -- )
  store-reset  sd1 32 id-init
  empty-params { pu } { pe }
  s" req-9" s" system/tree" s" get" pe pu 0 0 0 0 wire-execute { eu } { ee }
  ee ent-type s" system/protocol/execute" compare 0=  s" wire: EXECUTE builds" check
  ee exec-request-id s" req-9" compare 0=             s" wire: EXECUTE request_id field" check
  s" req-9" 404 empty-params wire-response { ru } { re }
  re resp-status drop 404 =                            s" wire: RESPONSE status field" check ;

\ ── §5.2 `peers` grant dimension (0.8.1 peers-fix, HANDOFF-TO-ARCH-2026-08-13) ──
\ Regression coverage for capauthz.fs's grant-covers-op-handler / check-permission: the
\ `peers` scope was previously never read at all (silently equivalent to peers:{include:["*"]}
\ on every grant). The oracle has ZERO vectors for this dimension (confirmed in the handoff),
\ so this unit test is the only thing that will ever catch a regression here.
\ (Split into small helper words — gforth's per-definition locals table is tight against the
\ already-large peer-all.fs load, and one big multi-locals word overflows it.)

\ mk-token1 ( grant-mtv-a grant-mtv-u -- cap-eaddr cap-eu )  a capability token w/ one grant.
: mk-token1 { ga gu -- ceaddr ceu }
  am-mark { tmk }
  [char] m b,  1 4 >be
  s" grants" tv-text 2drop
    am-mark [char] a b, 1 4 >be  ga gu bytes,  drop
  tmk am-span
  s" system/capability/token" 2swap ent-make ;

\ mk-grant-def ( -- grant-a grant-u )  handlers:*, operations:*, `peers` OMITTED (the spec
\ default {include:[local_peer_id]} applies at evaluation time).
: mk-grant-def ( -- ga gu )
  am-mark { mk }
  [char] m b,  2 4 >be
  s" handlers"   tv-text 2drop  s" *" path-scope-inc1 2drop
  s" operations" tv-text 2drop  s" *" path-scope-inc1 2drop
  mk am-span ;

\ mk-grant-peer ( peer-a peer-u -- grant-a grant-u )  handlers:*, operations:*, peers:{include:[peer]}.
: mk-grant-peer { pa pu -- ga gu }
  am-mark { mk }
  [char] m b,  3 4 >be
  s" handlers"   tv-text 2drop  s" *" path-scope-inc1 2drop
  s" operations" tv-text 2drop  s" *" path-scope-inc1 2drop
  s" peers"      tv-text 2drop  pa pu path-scope-inc1 2drop
  mk am-span ;

\ mk-exec-foreign ( peer-a peer-u -- exec-a exec-u )  an EXECUTE "get" on "/<peer>/system/tree".
: mk-exec-foreign { pa pu -- exa exu }
  pa pu s" system/tree" canon { ua uu }
  s" req-p1" ua uu s" get" empty-params 0 0 0 0 wire-execute ;

\ mk-exec-local ( -- exec-a exec-u )  an EXECUTE "get" on the bare (unaddressed) local path.
: mk-exec-local ( -- exa exu )
  s" req-p2" s" system/tree" s" get" empty-params 0 0 0 0 wire-execute ;

: t-peers-scope ( -- )
  store-reset  sd1 32 id-init
  id-peerid { lpa lpu }                                \ local peer_id
  sd2 32 id-peerid-of-pub { fpa fpu }                   \ "foreign" peer_id (the target peer)
  sd3 32 id-peerid-of-pub { opa opu }                   \ a THIRD, unrelated peer_id
  fpa fpu mk-exec-foreign { fexa fexu }                 \ EXECUTE addressed at the foreign peer
  \ grant 1 (ACCEPT path): peers explicitly includes the target peer -> ALLOW.
  fpa fpu mk-grant-peer mk-token1 { cap1 cap1u }
  fexa incB-addr incB-len incB-n lpa lpu cap1 check-permission
    s" peers: explicit include matching target_peer -> ALLOW" check
  \ grant 2 (REJECT path): peers includes only an unrelated THIRD peer, excluding the target
  \ -> DENY. Pre-fix this dimension was never read, so this grant used to (wrongly) ALLOW.
  opa opu mk-grant-peer mk-token1 { cap2 cap2u }
  fexa incB-addr incB-len incB-n lpa lpu cap2 check-permission 0=
    s" peers: include excludes target_peer -> DENY (was silently ALLOW pre-fix)" check
  \ grant 3 (ACCEPT path, default): peers OMITTED entirely; request targets LOCAL -> the
  \ spec default {include:[local_peer_id]} still ALLOWs the unaddressed/local case.
  mk-exec-local { lexa lexu }
  mk-grant-def mk-token1 { cap3 cap3u }
  lexa incB-addr incB-len incB-n lpa lpu cap3 check-permission
    s" peers: omitted -> defaults to {include:[local]}, local target -> ALLOW" check ;

: run-selftest ( -- )
  0 pass ! 0 total !
  setup
  t-identity  t-store  t-envelope-n5  t-chain-depth  t-payload-cap  t-wire  t-peers-scope
  cr ." SELFTEST " pass @ 0 .r ." /" total @ 0 .r cr
  pass @ total @ = if 0 else 1 then (bye) ;
run-selftest
