\ entity-core-protocol-forth — L2/L4: the dispatch chain, the select event loop, the
\ §6.11 request_id demux + the manual reentry pump.
\
\ The peer is a SINGLE-THREAD SELECT LOOP (the COBOL/Rexx family; §7b store-safety
\ structural). One inbound frame is dispatched to completion before the next select() wake.
\ The §6.11 handler-initiated outbound reentry is a MANUAL correlation pump: a handler that
\ originates an outbound EXECUTE sends it, then RE-ENTERS a bounded select/recv loop that
\ keeps serving other inbound frames until the correlated reply (matched by request_id)
\ arrives — no thread; the correlation-map tax the non-actor/non-CSP peers pay.
\
\ Wire roots (§3.3): ONLY system/protocol/execute and .../execute/response. An EXECUTE is
\ dispatched; an EXECUTE_RESPONSE is correlated to a pending outbound by request_id; ANY
\ other root type closes the connection.

\ ── the pending-reply table (request_id -> parked reply root + done flag) ──
32 constant MAX-PENDING
create pend-rid-addr  MAX-PENDING cells allot
create pend-rid-len   MAX-PENDING cells allot
create pend-done      MAX-PENDING cells allot     \ 0 waiting / 1 arrived
create pend-root      MAX-PENDING cells allot     \ parked reply root entity addr (durable)
variable pend-count
: pend-reset ( -- )  0 pend-count ! ;
pend-reset
: pend-new { ridaddr ridu -- idx }
  pend-count @ dup MAX-PENDING >= if drop -1 exit then { i }
  ridaddr ridu store-dup  pend-rid-len i cells + !  pend-rid-addr i cells + !
  0 pend-done i cells + !  0 pend-root i cells + !
  i 1+ pend-count !
  i ;                                     \ return the NEW slot index (was missing: a stale-stack
  \ 0 slipped through, so every concurrent reentry aliased slot 0 -> all awaits read o1's reply,
  \ the §6.11(b) cross-talk. Latent at S3: a single reentry's stale value happened to be 0.
: pend-find { ridaddr ridu -- idx }
  pend-count @ 0 ?do
    pend-rid-addr i cells + @  pend-rid-len i cells + @  ridaddr ridu compare 0= if
      i unloop exit then
  loop  -1 ;

\ ── the active-connection fd set (for select) ──
\ conn-fd[] already holds every connection fd (handlers.fs); we add the listen fd.
variable listen-fd
create select-fds  MAX-CONNS 2 + cells allot   \ listen + all conns
: gather-fds ( -- addr n )
  listen-fd @ select-fds !
  1 { n }
  conn-count @ 0 ?do
    conn-fd i cells + @ dup 0>= if select-fds n cells + ! n 1+ to n else drop then
  loop
  select-fds n ;

\ conn-close ( conn fd -- )  close the fd + tombstone the slot (reusable by conn-new). Defined
\ here (before on-frame) so both the §3.3 non-EXECUTE close and the serve-loop EOF path use it.
: conn-close ( conn fd -- )  net-close conn-drop ;

\ ── the inbound request's included set is incA; the outbound builder is incB ──
\ (Both from envelope.fs / handlers.fs.)

\ cap-verdict-error ( verdict request_id$ -- status result-eaddr result-eu )  map a non-ALLOW
\ capability verdict to a coded EXECUTE_RESPONSE payload (status + error result).
: cap-verdict-error { verdict -- status raddr ru }
  verdict VERDICT-AUTHN = if 401 s" authentication_failed" 0 0 error-result exit then
  verdict VERDICT-AUTHZ = if 403 s" capability_denied"     0 0 error-result exit then
  verdict VERDICT-UNRES = if 401 s" unresolvable_grantee"  0 0 error-result exit then
  verdict VERDICT-DEPTH = if 400 s" chain_depth_exceeded"  0 0 error-result exit then
  500 s" internal_error" 0 0 error-result ;

\ ── the dispatch chain (§6.5) for a decoded inbound EXECUTE ──
\ dispatch-execute ( conn exec-eaddr -- status result-eaddr result-eu )  (incA holds the
\ request's included set.) Connect is pre-auth; everything else runs verify -> resolve ->
\ dispatch. A §6.6 resolution miss is 404 (resolution-first: 404 beats 403).
: is-connect? ( exec-eaddr -- flag )
  exec-uri s" system/protocol/connect" compare 0= ;

\ uri->handler-path ( uri-a uri-u -- p-a p-u )  strip the addressing prefix so the §6.6
\ tree-walk sees a bare handler path. The addressed forms are "entity://<peer-id>/<path>" and
\ "/<peer-id>/<path>"; the first segment there is a peer_id to drop. A BARE "<path>" (e.g.
\ "system/protocol/connect") is already a handler path and MUST NOT have its first segment
\ stripped (that would turn system/protocol/connect into protocol/connect). So we only drop the
\ leading peer segment when the URI carried the entity:// scheme or a leading '/'.
variable uri-addressed
: uri->handler-path { ua uu -- pa pu }
  false uri-addressed !
  ua uu s" entity://" str-starts if ua 9 + uu 9 - to uu to ua true uri-addressed ! then
  ua uu s" /" str-starts if ua 1+ uu 1- to uu to ua true uri-addressed ! then   \ leading '/'
  uri-addressed @ 0= if ua uu exit then
  ua uu 0 slash-from dup 0< if drop ua uu exit then  \ no '/': one segment, keep
  { i } ua i 1+ +  uu i 1+ - ;                       \ drop "<peer>/"

: dispatch-execute { conn exec -- status raddr ru }
  exec exec-uri uri->handler-path { hpa hpu }
  hpa hpu s" system/protocol/connect" str-starts if
    conn exec  incA-addr incA-len incA-n  hnd-connect exit
  then
  \ authenticated path (§6.5 order): AUTHN → resolve (404) → AUTHZ (403) → dispatch.
  \ 1. integrity/authn first (an unsigned request is 401 whatever the path).
  exec incA-addr incA-len incA-n cap-verify-authn { averdict }
  averdict VERDICT-ALLOW <> if averdict cap-verdict-error exit then
  \ 2. resolve the handler by the URI (§6.6 tree-walk); miss -> 404 (resolution-first: 404
  \    beats 403 for an unregistered path).
  hpa hpu resolve-handler dup 0= if 2drop 404 s" handler_not_found" 0 0 error-result exit then
    { rpaddr rpu }                        \ ( rpaddr rpu -- ) single locals group (stack order)
  rpaddr rpu hnd-lookup dup 0= if drop 404 s" handler_not_found" 0 0 error-result exit then
    { xt }
  \ 3. permission/authz on the resolved handler (§5.5 chain verify + §5.2 scope + §4.10(b) depth).
  exec incA-addr incA-len incA-n cap-authorize { zverdict }
  zverdict VERDICT-ALLOW <> if zverdict cap-verdict-error exit then
  conn exec  incA-addr incA-len incA-n  xt execute ;

\ ── frame in -> response out ──
\ handle-execute-frame ( conn exec-eaddr -- )  dispatch + send the EXECUTE_RESPONSE on conn.
: send-response { conn ridaddr ridu status raddr ru -- }
  \ build the response envelope (root=response entity; included=incB, which a handler may
  \ have populated — e.g. authenticate's grant). If no handler touched incB, it's whatever
  \ the previous op left; connect handlers reset it, others should too. We reset here for
  \ non-connect ops via a flag set by the handler; simplest: only authenticate populates it.
  ridaddr ridu status raddr ru wire-response { respu } { respaddr }
  respaddr  incB-addr incB-len incB-n  env->wire { wu } { waddr }
  conn conn-fd@  waddr wu  frame-out ;

\ salvage-request-id ( faddr fu -- rid-a rid-u | 0 0 )  §6.3: recover ONLY the request_id
\ from a frame the strict decoder rejected. The frame stays rejected -- nothing else is read
\ out of it. The envelope and entity-wrapper shapes are fixed maps with no legal tag position
\ (§6.3), so a frame whose ONLY defect is a tag inside some entity's `data` still has a
\ structurally sound root, which is exactly the case this recovers.
: salvage-request-id { faddr fu -- ra ru }
  faddr fu cbor-decode-salvage drop { v }
  v s" root" tv-map-get dup 0= if drop 0 0 exit then { rootv }
  rootv s" data" tv-map-get dup 0= if drop 0 0 exit then { datav }
  datav s" request_id" tv-map-get dup 0= if drop 0 0 exit then { ridv }
  ridv c@ [char] t <> if 0 0 exit then
  ridv tv-payload ;

\ reject-frame ( conn faddr fu -- )  answer a rejected frame with 400 non_canonical_ecf,
\ correlated by the salvaged request_id. Runs under `catch` at the call site, so a further
\ throw degrades to the silence this exists to remove -- no worse than the old behaviour.
: reject-frame { conn faddr fu -- }
  faddr fu salvage-request-id { ru } { ra }
  ru 0= if exit then
  resp-inc-reset
  s" non_canonical_ecf" 0 0 error-result { eu } { ea }
  conn ra ru 400 ea eu send-response ;


\ dispatch-guarded ( conn exec -- status raddr ru )  run dispatch-execute; if it THROWs
\ (a bug or a hostile-shaped-but-decodable EXECUTE), map the throw to a 500 error result
\ rather than letting it propagate — a decodable EXECUTE MUST always get an EXECUTE_RESPONSE,
\ never a silent drop (a silent drop shows up as a 20s validator per-request timeout, which
\ is worse than any wrong-but-present status). §4.9 deliver-or-signal.
: dispatch-guarded { conn exec -- status raddr ru }
  conn exec ['] dispatch-execute catch    \ ok: ( status raddr ru 0 ) ; throw: ( conn exec code )
  ?dup if
    drop 2drop                            \ throw: discard code (already ?dup-dropped) + conn exec
    500 s" internal_error" 0 0 error-result
  then ;                                    \ success: 0 consumed by ?dup-if-else; results remain

: handle-execute { conn exec -- }
  \ Always start the outbound included set EMPTY, then dispatch (a handler — e.g.
  \ authenticate — re-adds the token/granter/signature it wants carried). This keeps a stale
  \ set from a previous op (or from bootstrap) out of an unrelated response.
  resp-inc-reset
  exec exec-request-id { ridu } { ridaddr }
  conn exec dispatch-guarded { status raddr ru }
  conn ridaddr ridu status raddr ru send-response ;

\ park-reply ( response-root -- )  correlate an EXECUTE_RESPONSE root to a pending outbound by
\ request_id (§6.11 demux). DURABLY copy the reply into the store heap so it survives arena churn
\ across the (nested, concurrent) reentry pump — the awaiting handler reads an epoch-independent
\ copy, never a bare arena addr. Each pending slot gets its OWN durable copy (A-FT-025: the
\ per-outbound pend slot index MUST be distinct — a stale-stack 0 aliased every reentry to slot 0
\ and cross-talked all replies to o1; see pend-new).
: park-reply { root -- }
  root resp-request-id pend-find dup 0>= if
    { idx }
    root  root ent-len  store-dup drop { rdup }
    1     pend-done idx cells + !
    rdup  pend-root idx cells + !
  else drop then ;

\ on-frame ( conn frame-addr frame-u -- )  decode a frame, route by root type. incA is the
\ inbound included set. Any decode error (a THROW) is caught by the caller (serve loop) —
\ a malformed frame does not crash the peer (§4.9). A non-EXECUTE/RESPONSE root closes conn.
: on-frame { conn faddr fu -- }
  0 tv-depth !                                     \ reset the TV recursion guard per frame
  faddr fu  incA-addr incA-len incA-n  env<-wire { root }
  root ent-type s" system/protocol/execute" compare 0= if
    conn root handle-execute exit
  then
  root ent-type s" system/protocol/execute/response" compare 0= if
    root park-reply exit
  then
  \ any other root type: close the connection (§3.3).
  conn conn conn-fd@ conn-close ;

\ conn-of-fd ( fd -- conn-idx | -1 )
: conn-of-fd { fd -- idx }
  conn-count @ 0 ?do  conn-fd i cells + @ fd = if i unloop exit then  loop  -1 ;

\ ── one select tick: drain every ready fd ──
\ pump-once ( timeout-sec timeout-usec -- got-event? )  select over listen + conns; accept a
\ new connection or read+dispatch one frame per ready conn. Returns true if anything fired.
\ A per-frame THROW (malformed input) is CAUGHT here so a hostile frame never crashes the
\ peer (§4.9 keep-serving); the connection is simply dropped on a hard transport error.
: accept-new ( -- )
  listen-fd @ net-accept dup 0< if drop exit then    ( fd )
  dup conn-new 0< if net-close else drop then ;        \ no slot: close the fd (don't leak)

\ serve-conn ( fd -- )  read one frame from a ready connection and dispatch it. net-read-frame
\ returns ( addr len ): (-1 -1) EOF/error -> close; (0 0) oversize drained -> keep serving;
\ else a valid frame. A malformed-frame THROW from on-frame is swallowed (§4.9 keep-serving).
: serve-conn { fd -- }
  fd conn-of-fd { conn }
  conn 0< if fd net-close exit then
  fd net-read-frame { faddr flen }           \ ( addr len ): locals bind in stack order
  faddr -1 = if conn fd conn-close exit then  \ EOF/error
  faddr 0= flen 0= and if exit then          \ oversize drained, keep serving
  conn faddr flen ['] on-frame catch if
    \ §6.3: "Rejection returns 400 non_canonical_ecf" -- a rejected frame is owed a STATUS,
    \ not silence. The bare `catch drop` here rejected the frame (correct) and then dropped
    \ it on the floor (wrong): the sender saw no response at all and blocked until its own
    \ timeout, violating §6.3's second sentence and §4.9(c) deliver-or-signal. It also made
    \ a refusal indistinguishable from a dead peer, and on a single-connection oracle run
    \ it poisons every later request on the same connection.
    \
    \ The frame is still REJECTED -- only enough is salvaged to correlate the response. If
    \ even the request_id is unrecoverable the frame is unattributable and silence is the
    \ only option left, which is what the inner catch leaves in place.
    2drop drop                              \ catch left ( conn faddr flen code ) minus code
    conn faddr flen ['] reject-frame catch drop
  then ;

: pump-once { sec usec -- fired }
  gather-fds { n } { fds }
  fds n sec usec net-select { nready }
  nready 0<= if false exit then
  listen-fd @ net-ready? if accept-new then
  conn-count @ 0 ?do
    conn-fd i cells + @ { f }
    f 0>= f net-ready? and if f serve-conn then
  loop
  true ;

\ ── the top-level serve loop ── serve-forever ( -- )  arena-reset per tick.
variable serving
: serve-forever ( -- )
  true serving !
  begin serving @ while
    arena-reset scratch-reset  0 tv-depth !
    1 0 pump-once drop           \ 1s select timeout
  repeat ;

\ ── §6.11 the reentry pump (handler-originated outbound) ──
\ CONCURRENT-REENTRY (§6.11(b), t1_2): the validator multiplexes N concurrent dispatch-outbound
\ EXECUTEs on ONE shared connection. Each handler that originates an outbound EXECUTE re-enters
\ the general select pump to keep serving the OTHER inbound EXECUTEs while it awaits its own reply
\ (§6.11(a): fast not gated behind slow). That re-entry recurses (dispatch-outbound → pump →
\ on-frame → handle-execute → dispatch-outbound …), N deep for N concurrent probes. Correctness
\ rests on two invariants:
\   (1) every outbound gets a DISTINCT pending-table slot (A-FT-025 — pend-new MUST return the new
\       index; a missing return left a stale 0 that aliased every reentry to slot 0 and cross-talked
\       every reply to o1), and each reply is store-dup'd durable so it survives arena churn;
\   (2) the recursion has stack headroom — a single-thread manual-pump substrate legitimately needs
\       enlarged gforth stacks (run-s4.sh -d/-r/-l), and the codec walk carries a §4.9 depth+count
\       cap so a MALFORMED frame throws-and-recovers instead of overflowing.
\ REENTRY-DEPTH-CAP is a belt-and-suspenders shed valve: past the cap a new reentry returns 0 ->
\ 503 no_outbound_seam rather than nesting further (a coded refusal is conformant per §4.9).
variable reentry-depth
64 constant REENTRY-DEPTH-CAP
\ await-reply ( pend-idx conn -- reply-root | 0 )  keep serving inbound frames via the general
\ pump until OUR reply correlates (pend-done). Bounded by a retry budget (§4.9).
: await-reply { idx conn -- root }
  200 { budget }
  begin
    pend-done idx cells + @ if pend-root idx cells + @ exit then
    budget 0<= if 0 exit then
    0 50000 pump-once drop                  \ 50ms select ticks; keeps serving other frames
    budget 1- to budget
  again ;

\ dispatch-outbound ( conn exec-eaddr  arr lens nvar -- reply-root | 0 )  send an outbound
\ EXECUTE on a connection and await its correlated reply (§6.11). The included set (arr..)
\ carries the outbound authority chain. Used by the §7a validate dispatch-outbound handler.
: dispatch-outbound { conn exec arr lens nvar -- root }
  reentry-depth @ REENTRY-DEPTH-CAP >= if 0 exit then     \ shed rather than overflow the stack
  reentry-depth @ 1+ reentry-depth !
  exec exec-request-id pend-new dup 0< if drop -1 reentry-depth +! 0 exit then { idx }
  exec  arr lens nvar  env->wire { wu } { waddr }
  conn conn-fd@ waddr wu frame-out
  idx conn await-reply
  -1 reentry-depth +! ;
