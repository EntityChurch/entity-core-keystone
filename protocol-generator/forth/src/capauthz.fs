\ entity-core-protocol-forth — L3 capability chain verification (§5.2 / §5.5 / §PR-8),
\ the AUTHZ interior beyond the S3 depth/grantee primitives (capability.fs). Ported from the
\ Rexx cohort peer's Cap_VerifyChain / Cap_CheckPermission / _verify_multisig_root, the
\ already-converged §5.5 logic. The S3 capability.fs supplies the trichotomy scaffold + the
\ §4.10(b) depth pre-check; THIS file adds the full chain walk (root single-sig + multisig
\ M3/M4/M6), per-link signature + attenuation + grantee/expiry, permission scope matching, and
\ the §5.2 verdict the dispatcher maps to a status.
\
\ Peer-local string work uses the SCRATCH stack (independent of the value arena) so a canon
\ path never contaminates the response being built. Patterns/paths are (addr,len) spans.

\ ── small string predicates over (addr,len) spans ──
\ str-starts ( a u p pu -- flag )  does span (a,u) start with prefix (p,pu)?
: str-starts { a u p pu -- flag }
  u pu < if false exit then  a pu p pu compare 0= ;   \ compare the first pu bytes of a with p
\ str-ends ( a u p pu -- flag )  does span (a,u) end with suffix (p,pu)?
: str-ends { a u p pu -- flag }
  u pu < if false exit then  a u pu - +  pu  p pu compare 0= ;  \ last pu bytes of a vs p
\ span-eq ( a u b bu -- flag )  byte-equal? Null-safe: a 0 address (an unresolved span) is never
\ equal to a real span (guards `compare` against dereferencing a NULL addr).
: span-eq { a u b bu -- flag }
  a 0= b 0= or if false exit then
  a u b bu compare 0= ;
\ index-of-slash-from ( a u start -- idx | -1 )  first '/' at or after start (0-based), or -1.
: slash-from { a u start -- idx }
  u start ?do  a i + c@ [char] / = if i unloop exit then  loop  -1 ;

\ ── §5.4 canonicalization: a bare (non-absolute) path is peer-rooted "/<local>/<path>".
\ We render the canonical form into the scratch stack and return its span. THROWs on a
\ reserved-relative / bare-peer-wildcard path (→ 400 at the dispatch boundary).
-25400 constant E-RESERVED-RELATIVE
-25401 constant E-AMBIGUOUS-WILDCARD
\ canon ( local-a local-u path-a path-u -- ca cu )  canonicalized span in scratch.
: canon { la lu pa pu -- ca cu }
  pa pu s" ./"  str-starts if E-RESERVED-RELATIVE throw then
  pa pu s" ../" str-starts if E-RESERVED-RELATIVE throw then
  pa pu s" */"  str-starts if E-AMBIGUOUS-WILDCARD throw then
  pa pu s" /"   str-starts if pa pu exit then          \ already absolute
  \ build "/" + local + "/" + path into scratch
  1 lu + 1 + pu + sc-alloc { dst }
  [char] / dst c!
  la  dst 1 +  lu move
  [char] /  dst 1 + lu +  c!
  pa  dst 1 + lu + 1 +  pu move
  dst  1 lu + 1 + pu + ;

\ ── §5.4 pattern matching (recursive /*/ + /* suffix) ──
\ matches-pattern ( path-a path-u pat-a pat-u -- flag )
: matches-pattern { pa pu qa qu -- flag }
  qu 1 = qa c@ [char] * = and if true exit then      \ pattern "*" matches all
  \ pattern begins "/*/" : strip a "/<seg>" from path, recurse on the remainder.
  qa qu s" /*/" str-starts if
    pu 0= if false exit then
    pa pu 1 slash-from dup 0< if drop false exit then { i }   \ next '/' at/after index 1
    pa i 1+ +  pu i 1+ -  qa 3 +  qu 3 -  recurse exit
  then
  \ pattern ends "/*" : path must start with pattern-minus-the-'*'.
  qu 2 >= qa qu s" /*" str-ends and if
    pa pu  qa qu 1-  str-starts exit
  then
  pa pu qa qu span-eq ;

\ ── §5.2 id-scope literal match (0.8.1, F40) — `operations` and `peers`. Literal compare
\ with exactly two wildcard forms: bare "*" and a trailing slash-star segment-prefix. None
\ of the §5.4 path transforms apply — no leading-slash universal reading, no interior
\ peer-wildcard, no peer-relative qualification — so a pattern carrying path syntax is
\ matched as a literal string: a non-match, never a fault.
\ matches-id-pattern ( val-a val-u pat-a pat-u -- flag )
: matches-id-pattern { va vu pa pu -- flag }
  pu 1 = pa c@ [char] * = and if true exit then       \ bare "*" matches any value
  pu 2 >= pa pu s" /*" str-ends and if
    va vu  pa pu 1-  str-starts exit                   \ keep the "/", drop the "*"
  then
  va vu pa pu span-eq ;

\ §5.2 scope kind (0.8.1, F40) — REQUIRED at every matches-scope call site, no default, so
\ a new call site cannot silently inherit the wrong matcher (the F40 defect, re-introduced).
0 constant SCOPE-PATH
1 constant SCOPE-ID

\ ── scope reads (a system/capability/*-scope map {include:[...], exclude:[...]}) ──
\ We read the include/exclude arrays straight off the grant's scope TV (no pre-parse).
\ scope-array ( scope-mtv key-a key-u -- atv | 0 )  the include/exclude array TV, or 0.
: scope-array { m ka ku -- atv }
  m 0= if 0 exit then
  m c@ [char] m <> if 0 exit then
  m ka ku tv-map-get ;

\ covered-by-array ( frame-a frame-u val-a val-u atv -- flag )  is canonicalized `val`
\ (already canonicalized against the CALLER frame) matched by any pattern in the array TV,
\ each pattern canonicalized against `frame`? (atv 0 -> no patterns -> false.) PATH-scope only.
: covered-by-array { fa fu va vu atv -- flag }
  atv 0= if false exit then
  atv c@ [char] a <> if false exit then
  atv tv-count { n }
  n 0 ?do
    atv i tv-array-elem dup c@ [char] t = if
      tv-payload { pa pu }                            \ pattern text
      sc-mark { mk }
      fa fu pa pu canon { ca cu }                     \ canonicalize the pattern vs frame
      va vu  ca cu  matches-pattern
      mk sc-free
      if true unloop exit then
    else drop then
  loop  false ;

\ covered-by-id-array ( val-a val-u atv -- flag )  is the RAW (uncanonicalized) `val` matched
\ literally by any pattern in the array TV? (§5.2 id-scope, 0.8.1 F40 — no frame, no canon.)
: covered-by-id-array { va vu atv -- flag }
  atv 0= if false exit then
  atv c@ [char] a <> if false exit then
  atv tv-count { n }
  n 0 ?do
    atv i tv-array-elem dup c@ [char] t = if
      tv-payload { pa pu }                            \ pattern text (literal, no canon)
      va vu pa pu matches-id-pattern
      if true unloop exit then
    else drop then
  loop  false ;

\ matches-scope ( frame-a frame-u val-a val-u scope-mtv kind -- flag )  §5.2, typed (0.8.1
\ F40): kind == SCOPE-ID (operations, peers) compares literally, no canonicalization; kind ==
\ SCOPE-PATH (handlers, resources) is the original §5.4 covered-by-include-AND-NOT-exclude,
\ unchanged. `kind` has no default — every caller names its dimension explicitly.
: matches-scope { fa fu va vu s kind -- flag }
  kind SCOPE-ID = if
    va vu s s" include" scope-array covered-by-id-array 0= if false exit then
    va vu s s" exclude" scope-array covered-by-id-array 0= exit
  then
  sc-mark { mk }
  fa fu va vu canon { ca cu }                         \ canonicalize the value
  fa fu  ca cu  s s" include" scope-array covered-by-array 0= if mk sc-free false exit then
  fa fu  ca cu  s s" exclude" scope-array covered-by-array                    \ excluded?
  mk sc-free  0= ;                                     \ ALLOW iff NOT excluded

\ ── §PR-8 granter-peer resolution (frames a cap's resource patterns) ──
\ resolve-peer-of-hash ( arr lens nvar h-a h-u -- pid-a pid-u | 0 0 )  peer_id of the peer
\ entity at content-hash h (from included, else store), via its public_key. 0 0 if absent.
: resolve-peer-of-hash { arr lens nvar ha hu -- pa pu }
  hu 0= if 0 0 exit then
  arr lens nvar ha hu inc-get dup 0= if
    drop ha hu store-get-by-hash dup 0= if drop 0 0 exit then
  then { pe }
  pe s" public_key" ent-field dup 0= if drop 0 0 exit then tv-payload { pka pku }
  pku 32 <> if 0 0 exit then
  pka pku id-peerid-of-pub ;

\ cap-granter-tv ( cap -- gtv | 0 )  the raw `granter` value TV (a 'b' single-sig hash or an
\ 'm' multi-granter map), or 0 if absent.
: cap-granter-tv ( cap -- gtv )  s" granter" ent-field ;
\ cap-is-multisig ( cap -- flag )  granter present AND a map ('m').
: cap-is-multisig ( cap -- flag )  cap-granter-tv dup 0= if drop false exit then c@ [char] m = ;

\ granter-peer-of-cap ( arr lens nvar local-a local-u cap -- pid-a pid-u )  the frame peer for
\ a link: the cap's single-sig granter peer_id; a rootless (no-granter) cap frames as `local`;
\ a multisig granter frames as `local` (root-at-local); an unresolvable granter frames as 0 0.
: granter-peer-of-cap { arr lens nvar la lu cap -- pa pu }
  cap cap-granter-tv dup 0= if drop la lu exit then { gtv }   \ no granter -> local frame
  gtv c@ [char] b <> if la lu exit then                       \ multisig granter (map) -> local
  arr lens nvar gtv tv-payload resolve-peer-of-hash ;

\ ── wall clock (ms) for §5.6 validity windows ──
: now-ms ( -- ms )  utime d>s  1000 / ;   \ microseconds (fits one 64-bit cell) -> ms

\ ── the chain: collect parent pointers into a scratch array of cap addrs (root last) ──
64 constant CHAIN-CAP
create chain-arr  CHAIN-CAP cells allot
variable chain-n
\ collect-chain ( cap arr lens nvar -- ok? )  fill chain-arr[0..chain-n) = [cap..root]. false if
\ a parent is unreachable or depth exceeds MAX (structural). No signature work here.
: collect-chain { cap arr lens nvar -- ok }
  0 chain-n !  cap { cur }  0 { depth }
  begin
    depth MAX-CHAIN-DEPTH > if false exit then
    cur chain-arr chain-n @ cells + !  chain-n @ 1+ chain-n !
    cur cap-parent dup 0= if 2drop true exit then       \ no parent -> root reached
    { pu } { pa }  arr lens nvar pa pu inc-get dup 0= if drop false exit then
    to cur  depth 1+ to depth
  again ;
: chain-root ( -- cap )  chain-arr chain-n @ 1- cells + @ ;

\ ── §5.5 M4 quorum count for a multisig root ──
\ multisig-quorum-ok ( root arr lens nvar local-a local-u -- flag )  M3 structure + M6
\ local∈signers + M4 threshold distinct valid signatures. (Ported from _verify_multisig_root.)
: signer-hash-at ( gmap idx -- h-a h-u | 0 0 )  \ the idx-th signer hash from {signers:[b..]}
  { gmap idx }
  gmap s" signers" tv-map-get dup 0= if drop 0 0 exit then { arr }
  arr c@ [char] a <> if 0 0 exit then
  idx arr tv-count >= if 0 0 exit then
  arr idx tv-array-elem dup c@ [char] b <> if drop 0 0 exit then tv-payload ;
: multisig-signers-count ( gmap -- n )
  s" signers" tv-map-get dup 0= if drop 0 exit then
  dup c@ [char] a <> if drop 0 exit then tv-count ;
: multisig-threshold ( gmap -- k )
  s" threshold" tv-map-get dup 0= if drop 0 exit then
  dup c@ [char] i <> if drop 0 exit then tv-int-value ;
\ signer-local-at? ( gmap arr lens nvar local-a local-u idx -- flag )  is signer[idx]'s peer_id
\ == local?  Extracted so the loop body carries no locals (gforth locals-in-loop hazard).
: signer-local-at? { gmap arr lens nvar la lu idx -- flag }
  gmap idx signer-hash-at { ha hu }
  hu 0= if false exit then
  arr lens nvar ha hu resolve-peer-of-hash la lu span-eq ;
\ signer-is-local ( gmap arr lens nvar local-a local-u -- flag )  M6: some signer's peer_id==local.
: signer-is-local { gmap arr lens nvar la lu -- flag }
  gmap multisig-signers-count 0 ?do
    gmap arr lens nvar la lu i signer-local-at? if true unloop exit then
  loop  false ;
\ dup-of? ( gmap idx -- flag )  is signer[idx] equal to any LATER signer? (per-call locals)
: dup-of? { gmap idx -- flag }
  gmap idx signer-hash-at { ia iu }
  gmap multisig-signers-count idx 1+ ?do
    gmap i signer-hash-at ia iu span-eq if true unloop exit then
  loop  false ;
\ dup-signers? ( gmap -- flag )  M3: any two signer hashes equal.
: dup-signers? { gmap -- flag }
  gmap multisig-signers-count 0 ?do
    gmap i dup-of? if true unloop exit then
  loop  false ;
\ count-valid-sigs ( root gmap arr lens nvar -- count )  distinct signers with a valid sig over
\ root's content_hash (each signer counted once). §5.5 M4.
create seen-arr  CHAIN-CAP cells allot   create seen-len CHAIN-CAP cells allot
variable seen-n
: seen-has? { ha hu -- flag }
  seen-n @ 0 ?do  seen-arr i cells + @  seen-len i cells + @  ha hu span-eq if true unloop exit then  loop  false ;
: seen-add { ha hu -- }  ha seen-arr seen-n @ cells + !  hu seen-len seen-n @ cells + !  seen-n @ 1+ seen-n ! ;
\ sig-for-signer ( tha thu sgn-a sgn-u pk-a pk-u arr lens nvar -- flag )  is there a
\ system/signature in `included` whose target==th, signer==sgn, valid under public key pk?
\ (cap-find-signature returns only the FIRST sig on a target; a multisig root carries several,
\ so we scan the full set here matching on signer.)
\ ent-bytes-eq? ( e key-a key-u cmp-a cmp-u -- flag )  is entity e's byte-field `key` == cmp?
: ent-bytes-eq? { e ka ku ca cu -- flag }
  e ka ku ent-field dup 0= if drop false exit then
  dup c@ [char] b <> if drop false exit then
  tv-payload ca cu compare 0= ;
\ is-sig-by? ( e tha thu sgna sgnu pka pku -- flag )  is included-entity e a system/signature on
\ target th, signed by sgn, valid under pk? (per-call locals — no loop-body locals.)
: is-sig-by? { e tha thu sgna sgnu pka pku -- flag }
  e ent-type s" system/signature" compare 0<> if false exit then
  e s" target" tha thu ent-bytes-eq? 0= if false exit then    \ target == th
  e s" signer" sgna sgnu ent-bytes-eq? 0= if false exit then   \ signer == sgn
  e pka pku id-verify-sig ;
\ sig-for-signer ( tha thu sgn-a sgn-u pk-a pk-u arr lens nvar -- flag )  any valid signature in
\ `included` on target th by signer sgn under pk?
: sig-for-signer { tha thu sgna sgnu pka pku arr lens nvar -- flag }
  nvar @ 0 ?do
    arr i cells + @  tha thu sgna sgnu pka pku is-sig-by? if true unloop exit then
  loop  false ;
\ count-sig-at ( root gmap arr lens nvar rha rhu idx -- 1|0 )  1 iff signer[idx] is a distinct
\ (not-yet-seen) signer with a valid signature on root; records it in the seen set. Per-call.
: count-sig-at { gmap arr lens nvar rha rhu idx -- n }
  gmap idx signer-hash-at { sa su }
  su 0= if 0 exit then
  sa su seen-has? if 0 exit then
  arr lens nvar sa su inc-get { speer }
  speer 0= if 0 exit then
  speer s" public_key" ent-field dup 0= if drop 0 exit then tv-payload { pka pku }
  rha rhu sa su pka pku arr lens nvar sig-for-signer 0= if 0 exit then
  sa su seen-add  1 ;
: count-valid-sigs { root gmap arr lens nvar -- count }
  0 seen-n !  root ent-hash { rha rhu }
  0                                                     \ accumulator
  gmap multisig-signers-count 0 ?do
    gmap arr lens nvar rha rhu i count-sig-at +
  loop ;

\ verify-multisig-root ( root arr lens nvar local-a local-u -- flag )  §3.6 M3 + §5.5 M4/M6.
: verify-multisig-root { root arr lens nvar la lu -- flag }
  root cap-granter-tv dup 0= if drop false exit then { gmap }
  gmap c@ [char] m <> if false exit then
  root cap-parent nip 0<> if false exit then           \ M3: multisig cap MUST be root (no parent)
  gmap multisig-signers-count { n }
  n 2 < if false exit then                              \ M3: N >= 2
  gmap multisig-threshold { k }
  k 2 < if false exit then  k n > if false exit then    \ M3: K in [2, N]
  gmap dup-signers? if false exit then                  \ M3: distinct signers
  gmap arr lens nvar la lu signer-is-local 0= if false exit then   \ M6: local in signers
  \ §5.6 validity: reject if now < not_before, or now > expires_at (i.e. expires_at < now).
  root s" not_before" ent-uint if now-ms > if false exit then else drop then       \ not_before > now
  root s" expires_at" ent-uint if now-ms < if false exit then else drop then       \ expires_at < now
  \ grantee resolvable
  root cap-grantee dup 0= if 2drop false exit then { ga gu }
  arr lens nvar ga gu inc-get 0= if false exit then
  \ M4: >= K distinct valid signatures
  root gmap arr lens nvar count-valid-sigs k >= ;

\ verify-single-root ( root arr lens nvar local-a local-u -- flag )  §5.5 root-at-local: the
\ single-sig granter's peer_id == local.
: verify-single-root { root arr lens nvar la lu -- flag }
  arr lens nvar la lu root granter-peer-of-cap { pa pu }
  pu 0= if false exit then                             \ unresolvable granter -> not root-at-local
  pa pu la lu span-eq ;

\ ── per-link attenuation (§5.5): a child's grants MUST be a subset of the parent's. We take
\ the pragmatic subset check the cohort converged on: each child grant's include patterns are
\ covered by some parent grant, framed by the respective granter peers. (Full caveat/exclude
\ subset is folded in via matches-scope semantics.) ──
\ grant-scope ( grant-mtv key-a key-u -- scope-mtv | 0 )  a grant's handlers/resources/operations map.
: grant-scope { g ka ku -- s }  g 0= if 0 exit then g c@ [char] m <> if 0 exit then g ka ku tv-map-get ;
\ token-grants ( cap -- arr-tv | 0 )  the {grants:[...]} array TV.
: token-grants ( cap -- atv )  s" grants" ent-field dup 0= if exit then dup c@ [char] a <> if drop 0 then ;

\ scope-subset ( child-frame-a child-frame-u parent-frame-a parent-frame-u child-scope parent-scope -- flag )
\ every child include pattern is covered by the parent include set.
: scope-subset { cfa cfu pfa pfu cs ps -- flag }
  cs s" include" scope-array { cinc }
  cinc 0= if true exit then                             \ no child includes -> vacuously subset
  cinc c@ [char] a <> if true exit then
  cinc tv-count { n }
  n 0 ?do
    cinc i tv-array-elem dup c@ [char] t = if
      tv-payload { pa pu }                              \ child include pattern
      sc-mark { mk }
      cfa cfu pa pu canon { ca cu }                     \ canonicalize vs child frame
      pfa pfu  ca cu  ps s" include" scope-array covered-by-array   \ covered by parent includes?
      mk sc-free
      0= if false unloop exit then
    else drop then
  loop  true ;

\ grant-subset ( local-a local-u child-frame-a child-frame-u parent-frame-a parent-frame-u child-grant parent-grant -- flag )
: grant-subset { la lu cfa cfu pfa pfu cg pg -- flag }
  la lu la lu  cg s" handlers"   grant-scope pg s" handlers"   grant-scope scope-subset 0= if false exit then
  la lu la lu  cg s" operations" grant-scope pg s" operations" grant-scope scope-subset 0= if false exit then
  cfa cfu pfa pfu  cg s" resources" grant-scope pg s" resources" grant-scope scope-subset ;

\ cg-covered-by-some? ( la lu cfa cfu pfa pfu cg pga -- flag )  is child grant cg a subset of
\ SOME grant in the parent's grants array pga?  (Extracted so the outer attenuation loop carries
\ no loop-body locals — the gforth locals-in-loop hazard.)
: cg-covered-by-some? { la lu cfa cfu pfa pfu cg pga -- flag }
  pga tv-count 0 ?do
    la lu cfa cfu pfa pfu cg  pga i tv-array-elem  grant-subset if true unloop exit then
  loop  false ;
\ is-attenuated ( arr lens nvar local-a local-u child parent -- flag )  every child grant is a
\ subset of some parent grant; child expiry <= parent expiry (if parent bounded).
: is-attenuated { arr lens nvar la lu child parent -- flag }
  arr lens nvar la lu child granter-peer-of-cap { cfa cfu }
  arr lens nvar la lu parent granter-peer-of-cap { pfa pfu }
  cfu 0= if false exit then  pfu 0= if false exit then
  child token-grants { cga }
  cga 0= if true exit then
  parent token-grants { pga }
  pga 0= if false exit then
  cga tv-count 0 ?do
    la lu cfa cfu pfa pfu  cga i tv-array-elem  pga  cg-covered-by-some? 0= if false unloop exit then
  loop
  \ expiry attenuation
  parent s" expires_at" ent-uint if { pe }
    child s" expires_at" ent-uint 0= if drop false exit then pe > if false exit then
  else drop then
  true ;

\ ── per-link checks (split out to stay under gforth's per-word locals cap) ──
\ link-sig-ok ( cur arr lens nvar -- flag )  §5.5: cur's single-sig granter signed cur's hash.
: link-sig-ok { cur arr lens nvar -- flag }
  cur cap-granter-tv dup 0= if drop false exit then { gtv }
  gtv c@ [char] b <> if false exit then  gtv tv-payload { gha ghu }
  cur ent-hash arr lens nvar cap-find-signature dup 0= if drop false exit then { sig }
  sig s" signer" ent-field dup 0= if drop false exit then tv-payload gha ghu compare 0<> if false exit then
  arr lens nvar gha ghu inc-get dup 0= if drop false exit then { granter }
  granter s" public_key" ent-field dup 0= if drop false exit then tv-payload { gpku } { gpka }
  sig gpka gpku id-verify-sig ;
\ temporal-representable? ( eaddr -- flag )  §6.2 CAP-6a: true iff every temporal field on
\ a RECEIVED token is either absent (legal) or representable as a uint64.
\
\ This is the reader-side half of CAP-6 and it is where a peer fails OPEN. `ent-uint`
\ answers ( 0 false ) for an ABSENT field, and for a PRESENT one it hands back
\ `tv-int-value` -- which applies the TV's SIGN byte and therefore returns a NEGATIVE cell
\ quite happily. So the range tests below did not skip; they RAN and answered wrong: for a
\ negative not_before, `not_before > now` is false and the capability passed. §6.2 CAP-6a:
\ such a token "is malformed. A verifier MUST refuse it and MUST NOT treat the
\ unrepresentable field as absent." An absent field stays legal and is NOT rejected here.
\
\ The check reads the TV directly rather than through ent-uint, because the sign byte is
\ exactly the bit ent-uint discards. A >2^64 magnitude cannot reach here at all: the TV int
\ carries an 8-byte argument, and a bignum arrives as a major-type-6 tag, rejected at decode.
: temporal-field-ok? { eaddr kaddr ku -- flag }
  eaddr kaddr ku ent-field dup 0= if drop true exit then   \ absent is legal
  dup c@ [char] i <> if drop false exit then               \ present but not an int
  1+ c@ 0= ;                                                \ sign byte 0 => non-negative
: temporal-representable? { eaddr -- flag }
  eaddr s" expires_at" temporal-field-ok? 0= if false exit then
  eaddr s" not_before" temporal-field-ok? 0= if false exit then
  eaddr s" created_at" temporal-field-ok? 0= if false exit then
  true ;

\ link-validity-ok ( cur -- flag )  §5.6 not_before/expires_at window.
: link-validity-ok { cur -- flag }
  \ CAP-6a FIRST: the two range tests below cannot tell absent from unrepresentable, so on
  \ their own they skip the check and honor the token (fail-open).
  cur temporal-representable? 0= if false exit then
  cur s" not_before" ent-uint if now-ms > if false exit then else drop then   \ not_before > now -> not yet valid
  cur s" expires_at" ent-uint if now-ms < if false exit then else drop then   \ expires_at < now -> expired
  true ;
\ link-grantee-resolvable ( cur arr lens nvar -- flag )  §5.2/PR-3: grantee present AND resolves
\ to a system/peer entity (a grantee that resolves to a non-peer, or not at all, is UNRESOLVABLE
\ -> the 401 unresolvable_grantee carve-out).
: link-grantee-resolvable { cur arr lens nvar -- flag }
  cur cap-grantee dup 0= if 2drop false exit then { gea geu }
  arr lens nvar gea geu inc-get dup 0= if drop false exit then    \ resolved entity
  ent-type s" system/peer" compare 0= ;                            \ MUST be a system/peer
\ ── §5.7 delegation caveats (a parent grant may bound its children) ──
\ tv-map-uint ( mtv key-a key-u -- u present? )  read an unsigned int field off a raw map TV.
: tv-map-uint { m ka ku -- u present }
  m 0= if 0 false exit then  m c@ [char] m <> if 0 false exit then
  m ka ku tv-map-get dup 0= if drop 0 false exit then
  dup c@ [char] i <> if drop 0 false exit then  tv-int-value true ;
\ tv-map-bool-true? ( mtv key-a key-u -- flag )  is the boolean field present AND true?
: tv-map-bool-true? { m ka ku -- flag }
  m 0= if false exit then  m c@ [char] m <> if false exit then
  m ka ku tv-map-get dup 0= if drop false exit then  c@ [char] T = ;
\ caveats-ok? ( parent child depth -- flag )  §5.7: honor parent.delegation_caveats bounding the
\ child link. no_delegation -> deny; max_delegation_depth -> depth < mdd; max_delegation_ttl ->
\ (child.expires_at - child.created_at) <= ttl (a child with no expiry fails a ttl cap).
: caveats-ok? { parent child depth -- flag }
  parent s" delegation_caveats" ent-field { cav }
  cav 0= if true exit then  cav c@ [char] m <> if true exit then
  cav s" no_delegation" tv-map-bool-true? if false exit then
  cav s" max_delegation_depth" tv-map-uint if depth swap >= if false exit then else drop then
  cav s" max_delegation_ttl" tv-map-uint if { maxttl }
    child s" expires_at" ent-uint 0= if drop false exit then { cex }
    child s" created_at" ent-uint 0= if drop 0 then { ccr }
    cex ccr - maxttl > if false exit then
  else drop then
  true ;

\ link-parent-ok ( cur parent idx arr lens nvar local-a local-u -- flag )  parent.grantee==child.
\ granter AND child attenuates parent AND the parent's §5.7 delegation caveats permit the link.
: link-parent-ok { cur parent idx arr lens nvar la lu -- flag }
  parent cap-grantee { pga pgu }
  cur cap-granter-tv dup 0= if drop false exit then { cgtv }
  cgtv c@ [char] b <> if false exit then  cgtv tv-payload { cga cgu }
  pgu 0= if false exit then
  pga pgu cga cgu span-eq 0= if false exit then          \ parent.grantee == child.granter (null-safe)
  arr lens nvar la lu cur parent is-attenuated 0= if false exit then
  parent cur idx caveats-ok? ;

\ verify-link ( idx cur arr lens nvar local-a local-u -- verdict )  one chain link's verdict
\ (ALLOW to continue). idx is the chain position; the last position is the root.
: verify-link { idx cur arr lens nvar la lu -- verdict }
  cur cap-is-multisig if
    idx chain-n @ 1- <> if VERDICT-AUTHZ exit then       \ multisig only at the root
  else
    cur arr lens nvar link-sig-ok 0= if VERDICT-AUTHZ exit then
  then
  cur arr lens nvar link-grantee-resolvable 0= if VERDICT-UNRES exit then
  cur link-validity-ok 0= if VERDICT-AUTHZ exit then
  idx chain-n @ 1- < if
    cur  chain-arr idx 1+ cells + @  idx arr lens nvar la lu link-parent-ok 0= if VERDICT-AUTHZ exit then
  then
  VERDICT-ALLOW ;

\ ── §5.5 full chain verification -> VERDICT-ALLOW / VERDICT-AUTHZ / VERDICT-UNRES ──
\ verify-chain ( cap arr lens nvar local-a local-u -- verdict )
: verify-chain { cap arr lens nvar la lu -- verdict }
  cap arr lens nvar collect-chain 0= if VERDICT-AUTHZ exit then
  chain-root { root }
  root cap-is-multisig if
    root arr lens nvar la lu verify-multisig-root 0= if VERDICT-AUTHZ exit then
  else
    root arr lens nvar la lu verify-single-root 0= if VERDICT-AUTHZ exit then
  then
  chain-n @ 0 ?do
    i  chain-arr i cells + @  arr lens nvar la lu  verify-link { v }
    v VERDICT-ALLOW <> if v unloop exit then
  loop
  VERDICT-ALLOW ;

\ ── §5.2 permission scope check (the resolved cap covers op + handler) ──

\ exec-handler-path ( exec -- ha hu )  the exec.uri stripped of "entity://<peer>/" (or a
\ leading "/<peer>/") down to the bare handler path — the §6.6 resolved handler pattern.
2variable ehp-span
: exec-handler-path { exec -- ha hu }
  exec exec-uri ehp-span 2!
  ehp-span 2@ s" entity://" str-starts if ehp-span 2@ 9 /string ehp-span 2! then
  ehp-span 2@ s" /" str-starts if ehp-span 2@ 1 /string ehp-span 2! then
  ehp-span 2@ 0 slash-from { i }
  i 0< if ehp-span 2@ exit then
  ehp-span 2@ i 1+ /string ;

\ ── §5.2 `peers` grant dimension (0.8.1, peers-grant-dimension-oracle-gap remediation) ──
\ extract-peer ( uri-a uri-u local-a local-u -- peer-a peer-u )  target_peer per spec line
\ 2196: the EXECUTE's own dispatch URI's first path segment IF it's a valid peer_id (§1.4
\ seg-is-peerid?, Base58 >=46 chars), else local_peer_id. Strips a leading "entity://" scheme,
\ then a leading "/", then takes up to the next "/" (or the whole remainder if none) — mirrors
\ the reference `first_segment`/`extract_peer` byte-for-byte (rust/src/peer/capability.rs
\ lines 195-213; python/src/entity_core/peer/capability.py).
2variable ep-span
: extract-peer { ua uu la lu -- pa pu }
  ua uu ep-span 2!
  ep-span 2@ s" entity://" str-starts if ep-span 2@ 9 /string ep-span 2! then
  ep-span 2@ s" /" str-starts if ep-span 2@ 1 /string ep-span 2! then
  ep-span 2@ 0 slash-from { i }
  i 0< if ep-span 2@ else ep-span 2@ drop i then
  2dup seg-is-peerid? if exit then
  2drop la lu ;

\ grant-peers-ok? ( exec local-a local-u grant-mtv -- flag )  §5.2 peers dimension: a genuine
\ MUST-gate, checked exactly like operations/handlers/resources — a grant that fails this check
\ does NOT cover the request. `grant.peers` defaults to {include:[local_peer_id]} when absent
\ (spec line 1040/2378) — NOT "no restriction" — so the absent case is target_peer==local_peer_id
\ literally (identical to what SCOPE-ID matches-scope would compute against that synthetic
\ default, since it carries no exclude and its sole include pattern is the literal local id).
: grant-peers-ok? { exec la lu grant -- flag }
  exec exec-uri la lu extract-peer { tpa tpu }
  grant s" peers" grant-scope { ps }
  ps 0= if tpa tpu la lu span-eq exit then
  la lu tpa tpu ps SCOPE-ID matches-scope ;

\ ── §5.2 resource-scope check (§PR-8 granter-framed) ──
\ exec-resource-tv ( exec -- rtv | 0 )  the exec.resource map TV, or 0.
: exec-resource-tv ( exec -- rtv )  s" resource" ent-field ;
\ resource-target-covered? ( local-a local-u granter-a granter-u grant-mtv target-a target-u -- flag )
\ is one canonicalized resource target covered by the grant's resources INCLUDE (framed by the
\ granter peer) AND not by its EXCLUDE?  (Rexx Cap_CheckResourceScope per-target body.)
: resource-target-covered? { la lu ga gu grant ta tu -- flag }
  grant s" resources" grant-scope { rs }
  rs 0= if false exit then
  sc-mark { mk }
  la lu ta tu canon { ca cu }                          \ canonicalize the target vs local
  ga gu  ca cu  rs s" include" scope-array covered-by-array 0= if mk sc-free false exit then
  ga gu  ca cu  rs s" exclude" scope-array covered-by-array   \ excluded by the grant?
  mk sc-free  0= ;
\ grant-covers-resource? ( exec local-a local-u granter-a granter-u grant-mtv -- flag )  §5.2
\ resource dimension: if the exec carries a resource with targets, EVERY target MUST be covered
\ by this grant's resources (granter-framed). An exec with NO resource is handler+op only (the
\ path-less §4.4 request shape) -> vacuously covered.
: grant-covers-resource? { exec la lu ga gu grant -- flag }
  exec exec-resource-tv dup 0= if drop true exit then { rtv }
  rtv s" targets" tv-map-get dup 0= if drop true exit then { tgts }   \ no targets -> handler-only
  tgts c@ [char] a <> if true exit then
  tgts tv-count dup 0= if drop true exit then { tn }
  tn 0 ?do
    tgts i tv-array-elem dup c@ [char] t = if
      tv-payload { xa xu }
      exec la lu ga gu grant xa xu resource-target-covered? 0= if false unloop exit then
    else drop then
  loop  true ;

\ grant-covers-op-handler ( exec local-a local-u granter-a granter-u grant-mtv -- flag )  does
\ one grant cover the exec's operation + resolved handler path + target peer + resource targets
\ (§PR-8 frame)? §5.2/0.8.1 F40: `operations`/`peers` are id-scope (literal), `handlers` is
\ path-scope (canonicalized). `peers` (0.8.1 peers-fix): the target_peer dimension — MUST-gate,
\ same as the other three; previously unchecked entirely
\ (protocol-generator/shared/findings/peers-grant-dimension-oracle-gap.md).
: grant-covers-op-handler { exec la lu ga gu grant -- flag }
  exec exec-operation { opa opu }
  la lu opa opu grant s" operations" grant-scope SCOPE-ID matches-scope 0= if false exit then
  exec exec-handler-path { ha hu }
  la lu ha hu grant s" handlers" grant-scope SCOPE-PATH matches-scope 0= if false exit then
  exec la lu grant grant-peers-ok? 0= if false exit then
  exec la lu ga gu grant grant-covers-resource? ;

\ check-permission ( exec arr lens nvar local-a local-u cap -- flag )  ALLOW iff some grant of
\ the resolved LEAF cap covers operation + handler + resource targets. Resources are framed by
\ the cap's granter peer (§PR-8). This is the §5.2 dispatch-authorization gate (a resolved+
\ verified cap that does not cover the request is the default-DENY -> 403 capability_denied).
: check-permission { exec arr lens nvar la lu cap -- flag }
  cap token-grants { ga }
  ga 0= if false exit then
  arr lens nvar la lu cap granter-peer-of-cap { gpa gpu }   \ §PR-8 granter frame for resources
  ga tv-count { n }
  n 0 ?do
    ga i tv-array-elem { grant }
    exec la lu gpa gpu grant grant-covers-op-handler if true unloop exit then
  loop  false ;

\ ── the §5.2 dispatch authorization gate (replaces the S3 cap-verify-authz stub) ──
\ cap-authorize ( exec arr lens nvar -- verdict )  runs AFTER §6.6 handler resolution: resolve
\ the presented cap, run the §4.10(b) depth pre-check, verify the chain (root trust + per-link
\ sig/grantee/expiry/attenuation), bind grantee==author, then check the grant scope covers the
\ operation+handler. A resolved+verified cap that does not cover the op is the default DENY
\ (VERDICT-AUTHZ -> 403 capability_denied).
\ cap-revoked? ( cap arr lens nvar -- flag )  §5.1 is_revoked: deny iff a revocation marker is
\ bound at /<local>/system/capability/revocations/<hex(H)> for H ∈ {leaf cap hash, chain-root
\ hash}. Byte-parity with the Rexx cohort's Cap_IsRevoked (leaf OR root). Scoping to these two
\ SPECIFIC hashes — never anything connection-scoped — is what keeps a single revoke from
\ cascading across the shared conformance connection (A-FT-023 resolution): each revoke denies
\ exactly the revoked token (and its delegated children, caught by the shared root hash).
create revchk-hex 160 allot
\ marker-at-hash? ( h-a h-u -- flag )  is a revocation marker bound for content-hash H?
: marker-at-hash? { ha hu -- flag }
  hu 0= if false exit then
  ha hu revchk-hex hexlc { xa xu }
  s" revocations/" xa xu cap-abs2 store-get-at 0<> ;
: cap-revoked? { cap arr lens nvar -- flag }
  cap ent-hash marker-at-hash? if true exit then            \ leaf cap revoked
  cap arr lens nvar collect-chain if                        \ else check the chain root
    chain-root ent-hash marker-at-hash? exit
  then false ;

\ ── §6.2 request/delegate mint-bounded check (fills the handlers.fs deferred word) ──
\ one-grant-bounded? ( local-a local-u child-grant parent-grants-atv -- flag )  is child-grant a
\ subset of SOME grant in the presented cap's grants array? (Frames all local — Rexx parity.)
: one-grant-bounded? { la lu cg pga -- flag }
  pga 0= if false exit then  pga c@ [char] a <> if false exit then
  pga tv-count 0 ?do
    la lu la lu la lu  cg  pga i tv-array-elem  grant-subset if true unloop exit then
  loop  false ;
\ mint-bounded? ( exec arr lens nvar grants-atv -- flag )  every requested grant is bounded by
\ the presented cap. No presented cap -> allow (connection-seed bounded). This is the accept-path
\ the oracle's rejection-only capability vectors cannot cover (the keystone payoff): a narrow
\ presented cap that asks to WIDEN is refused; a within-authority ask is granted.
: mint-bounded? { exec arr lens nvar gatv -- flag }
  exec s" capability" ent-field dup 0= if drop true exit then      \ no cap presented -> seed-bounded
    tv-payload { cu } { ca }  arr lens nvar ca cu inc-get { cap }
  cap 0= if true exit then                                         \ unresolved -> defer to authz
  cap token-grants { pga }
  pga 0= if false exit then
  gatv tv-count 0 ?do
    id-peerid  gatv i tv-array-elem  pga  one-grant-bounded? 0= if false unloop exit then
  loop  true ;
' mint-bounded? is req-grants-bounded?

: cap-authorize { exec arr lens nvar -- verdict }
  exec s" capability" ent-field dup 0= if drop VERDICT-AUTHZ exit then
    tv-payload { cu } { ca }  arr lens nvar ca cu inc-get { cap }
  cap 0= if VERDICT-AUTHZ exit then
  \ §5.1 revoked-cap check (A-FT-023 RESOLVED, re-enabled): deny a cap whose leaf OR chain-root
  \ hash carries a revocation marker. Scoped to those specific hashes — NOT connection-scoped —
  \ so one revoke denies exactly the revoked token + its children, with no cross-cap cascade.
  cap arr lens nvar cap-revoked? if VERDICT-AUTHZ exit then
  cap arr lens nvar cap-exceeds-depth if VERDICT-DEPTH exit then   \ §4.10(b) BEFORE the walk
  cap arr lens nvar id-peerid verify-chain { v }
  v VERDICT-ALLOW <> if v exit then
  \ grantee binding: the leaf cap's grantee == the request author (§5.2).
  exec s" author" ent-field dup 0= if drop VERDICT-AUTHZ exit then tv-payload { au } { aa }
  cap cap-grantee dup 0= if 2drop VERDICT-AUTHZ exit then aa au compare 0<> if VERDICT-AUTHZ exit then
  \ scope: some grant covers operation + handler.
  exec arr lens nvar id-peerid cap check-permission 0= if VERDICT-AUTHZ exit then
  VERDICT-ALLOW ;
