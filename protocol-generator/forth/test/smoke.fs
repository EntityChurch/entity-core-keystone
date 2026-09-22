\ entity-core-protocol-forth — S3 two-peer loopback smoke (the initiator side).
\
\ Boots as: gforth test/smoke.fs <responder-port>
\ Dials the responder (a bin/peer.fs process on 127.0.0.1:<port>) and drives the §4.1
\ handshake + the post-handshake checks, asserting each leg. Prints `SMOKE <pass>/<total>`.
\
\ Scenario (the cohort shape — study rexx status/PHASE-S3.md 8/8):
\   1. connect:hello        -> 200, responder hello carries a peer_id + nonce
\   2. connect:authenticate -> 200, result is a system/capability/grant with a token
\   3. connection established (the grant proves it)
\   4. EXECUTE unregistered path -> EXECUTE_RESPONSE status 404 handler_not_found
\   5. request_id demux: two EXECUTEs issued, replies correlate by request_id (out-of-order)
\   6. clean teardown

require ../src/peer-all.fs

: arg-uint ( c-addr u -- n )  0 0 2swap >number 2drop drop ;

\ ── the initiator's own identity (a distinct seed) ──
create init-seed 32 allot
: init-identity ( -- )  32 0 ?do $22 init-seed i + c! loop  init-seed 32 id-init ;

\ ── a dialed connection ──
variable dfd
variable rid-ctr   0 rid-ctr !
create rid-buf 32 allot
: next-rid ( -- addr u )  \ "req-N" as a text request_id, built into rid-buf
  s" req-" { p4a p4u }                             \ "req-" span
  p4a rid-buf p4u move                             \ copy prefix
  rid-ctr @ 1+ dup rid-ctr !                       \ next counter
  s>d <# #s #> { dna dnu }                          \ decimal digits span (double for <#)
  dna  rid-buf p4u +  dnu move                     \ append digits
  rid-buf  p4u dnu + ;

\ iadd ( e-addr -- )  add an entity to the initiator's outbound included set (incB).
: iadd { eaddr -- }  incB-addr incB-len incB-n  eaddr eaddr ent-len  inc-add ;

\ ── send an EXECUTE, receive its EXECUTE_RESPONSE (blocking, correlated by request_id) ──
\ send-exec ( exec-eaddr  arr lens nvar -- )  frame + send on dfd.
: send-exec { exec arr lens nvar -- }
  exec arr lens nvar env->wire { wu } { waddr }
  dfd @ waddr wu frame-out ;

\ recv-response ( -- root-eaddr | 0 )  read one frame, decode, return the root entity (uses
\ incA as the decode included set). Blocks via a select gate + recv-exact.
: recv-response ( -- root )
  dfd @ net-read-frame { faddr flen }        \ ( addr len ): locals bind stack-order
  faddr -1 = if 0 exit then
  faddr 0= flen 0= and if 0 exit then
  faddr flen  incA-addr incA-len incA-n  env<-wire ;

\ ── test bookkeeping ──
variable pass  variable total
: check ( flag name-addr name-u -- )
  total @ 1+ total !
  rot if pass @ 1+ pass ! ." ok   " else ." FAIL " then type cr ;

\ ── build + send hello ──
: do-hello ( -- root )
  am-mark drop
  \ hello params: {peer_id, nonce, protocols, timestamp}
  am-mark { pmk }
  [char] m b,  4 4 >be
  s" peer_id"   tv-text 2drop  id-peerid tv-text 2drop
  s" nonce"     tv-text 2drop  init-seed 32 tv-bytes 2drop     \ a fixed 32-byte nonce
  \ §8.4's protocol version identifier, and it must be the one the responder accepts:
  \ "entity-core/0.8" is a SPEC-LINE name, not an identifier, and §4.5's negotiation
  \ answers 400 incompatible_protocol for it. This read as green only while nothing
  \ compared the field (F56 is the same confusion reached from the probe side).
  s" protocols" tv-text 2drop  s" entity-core/1.0" text-array1 2drop
  s" timestamp" tv-text 2drop  0 tv-uint 2drop
  pmk am-span
  s" system/protocol/connect/hello" 2swap ent-make { pu } { paddr }
  next-rid { ru } { raddr }
  raddr ru  s" system/protocol/connect"  s" hello"  paddr pu  0 0  0 0  wire-execute { eu } { eaddr }
  0 incB-n !                                          \ no included on hello
  eaddr incB-addr incB-len incB-n send-exec
  recv-response ;

\ authenticate: sign the authenticate params entity's content_hash, carry the signature +
\ our peer entity in included. Echo the responder's issued nonce (from the hello response).
create resp-nonce 32 allot   variable have-resp-nonce
\ the nonce is inside the response's `result` entity (the responder's hello), not at the
\ response root — navigate result -> hello entity -> nonce.
: capture-resp-nonce ( response-root -- )
  s" result" ent-field ?dup 0= if exit then       \ result value TV (a wire entity map)
  ent<-wire { hello }                              \ the hello result entity
  hello s" nonce" ent-field ?dup if
    dup c@ [char] b = if tv-payload 32 min resp-nonce swap move 1 have-resp-nonce !
    else drop then
  else drop then ;

: do-authenticate ( -- root )
  \ params entity {peer_id, public_key, key_type, nonce(echo)}
  am-mark { pmk }
  [char] m b,  4 4 >be
  s" peer_id"    tv-text 2drop  id-peerid tv-text 2drop
  s" public_key" tv-text 2drop  id-pub 32 tv-bytes 2drop
  s" key_type"   tv-text 2drop  s" ed25519" tv-text 2drop
  s" nonce"      tv-text 2drop  resp-nonce 32 tv-bytes 2drop
  pmk am-span
  s" system/protocol/connect/authenticate" 2swap ent-make { pu } { paddr }
  \ sign the params content_hash
  paddr ent-hash id-sign { sigu } { sigaddr }         \ system/signature entity
  next-rid { ru } { raddr }
  raddr ru  s" system/protocol/connect"  s" authenticate"  paddr pu  0 0  0 0  wire-execute { eu } { eaddr }
  0 incB-n !
  paddr iadd            \ authenticate params (harmless; already in exec)
  sigaddr iadd          \ the signature
  id-peer drop iadd     \ our peer entity
  eaddr incB-addr incB-len incB-n send-exec
  recv-response ;

\ an EXECUTE to an unregistered path (no auth needed to reach the 404 — resolution-first).
\ But a non-connect EXECUTE runs verify first; without a cap it is 401/403 BEFORE 404. To
\ isolate the §6.6 resolution-miss 404 we must present a valid signature + capability. For
\ the S3 smoke we assert the 404 path via a connect-authenticated request carrying the seed
\ grant. Simpler and still spec-faithful: after authenticate we hold the granted token; a
\ request to an unregistered path with that token resolves-first to 404.
\ (The seed grant does not cover arbitrary paths, but §6.6 resolution precedes §5.2 perms,
\ so an UNREGISTERED path returns 404 regardless — resolution-first, §6.6 informative.)
create grant-token-h 64 allot  variable grant-token-hlen  0 grant-token-hlen !
: capture-grant ( auth-root -- )
  s" token" ent-field ?dup if
    dup c@ [char] b = if tv-payload dup 64 min grant-token-hlen ! grant-token-h swap move
    else drop then
  else drop then ;

: do-unregistered ( -- root )
  empty-params { pu } { paddr }
  next-rid { ru } { raddr }
  \ author = our id_hash; capability = the granted token hash (from authenticate).
  id-idhash { authu } { authaddr }
  raddr ru  s" local/does-not-exist"  s" get"  paddr pu
    authaddr authu  grant-token-h grant-token-hlen @  wire-execute { eu } { eaddr }
  \ sign the exec + carry our peer entity + the signature; the token/granter travel too but
  \ for the resolution-miss 404 the dispatcher returns 404 before deep chain checks anyway.
  eaddr ent-hash id-sign { sigu } { sigaddr }
  0 incB-n !
  sigaddr iadd          \ the signature
  id-peer drop iadd     \ our peer entity
  eaddr incB-addr incB-len incB-n send-exec
  recv-response ;

\ send-unregistered-with-rid ( rid-addr rid-u -- )  send one authenticated EXECUTE to an
\ unregistered path with the given request_id (no reply read here — pipelined).
: send-unregistered-with-rid { raddr ru -- }
  empty-params { pu } { paddr }
  id-idhash { authu } { authaddr }
  raddr ru  s" local/does-not-exist"  s" get"  paddr pu
    authaddr authu  grant-token-h grant-token-hlen @  wire-execute { eu } { eaddr }
  eaddr ent-hash id-sign { sigu } { sigaddr }
  0 incB-n !
  sigaddr iadd          \ the signature
  id-peer drop iadd     \ our peer entity
  eaddr incB-addr incB-len incB-n send-exec ;

\ two distinct request_ids stored durably (they must outlive the arena churn of send/recv).
create ridA 16 allot  variable ridA-len
create ridB 16 allot  variable ridB-len
: pipeline-two-check ( -- )
  next-rid dup ridA-len ! ridA swap move
  next-rid dup ridB-len ! ridB swap move
  \ send BOTH before reading either (the pipeline that forces demux, not wire order)
  ridA ridA-len @ send-unregistered-with-rid
  ridB ridB-len @ send-unregistered-with-rid
  \ read two replies; collect their request_ids
  recv-response { p1 }  p1 0<> if p1 resp-request-id else 0 0 then { g1u } { g1a }
  recv-response { p2 }  p2 0<> if p2 resp-request-id else 0 0 then { g2u } { g2a }
  \ each sent id must appear among the two returned ids (order-independent match)
  g1a g1u ridA ridA-len @ compare 0=  g2a g2u ridA ridA-len @ compare 0= or { hasA }
  g1a g1u ridB ridB-len @ compare 0=  g2a g2u ridB ridB-len @ compare 0= or { hasB }
  hasA hasB and  s" pipelined replies correlate by request_id (§6.11 demux)" check ;

\ ── the run ──
: run-smoke { port -- }
  0 pass ! 0 total !
  init-identity
  ." (dialing 127.0.0.1:" port . ." )" cr
  port net-dial dfd !
  \ 1. hello
  do-hello { hroot }
  hroot 0<> hroot if hroot resp-status drop 200 = else false then and
    s" hello -> 200" check
  hroot 0<> if hroot capture-resp-nonce then
  have-resp-nonce @  s" responder issued a nonce" check
  \ 2. authenticate
  do-authenticate { aroot }
  aroot 0<> aroot if aroot resp-status drop 200 = else false then and
    s" authenticate -> 200 (grant)" check
  \ 3. established (a grant result with a token)
  aroot 0<> if
    aroot s" result" ent-field ?dup if ent<-wire capture-grant then
  then
  grant-token-hlen @ 0>  s" grant carries a capability token" check
  \ 4. unregistered path -> 404
  do-unregistered { uroot }
  uroot 0<> uroot if uroot resp-status drop 404 = else false then and
    s" unregistered path -> 404" check
  \ 5. request_id demux (§6.11): PIPELINE two EXECUTEs (both sent before any reply is read),
  \ then read both replies and assert each reply's request_id equals its own request's — the
  \ demux is by request_id, not by wire order. We capture both request_ids, send both, then
  \ match each returned reply to a sent id.
  pipeline-two-check
  dfd @ net-close
  cr ." SMOKE " pass @ 0 .r ." /" total @ 0 .r cr ;

\ ── main: read the responder port from argv, run, exit non-zero on any failure ──
: smoke-main ( -- )
  next-arg dup 0= if 2drop ." usage: smoke.fs <port>" cr 2 (bye) then
  arg-uint run-smoke
  pass @ total @ = if 0 else 1 then (bye) ;
smoke-main
