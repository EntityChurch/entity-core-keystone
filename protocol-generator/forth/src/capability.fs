\ entity-core-protocol-forth — L3 capability (§5): the system/capability/token shape, the
\ chain-walk + signature verification (the Layer-1 verdict, §5.10), and — the ONE net-new
\ bit of peer code across the whole cohort — the §4.10(b) chain-depth PRE-CHECK that maps an
\ over-deep chain to 400 chain_depth_exceeded BEFORE the per-link authz walk (structural
\ excess ≠ authz denial; an *unreachable* parent is NOT a depth problem and stays 403).
\
\ Verdict trichotomy (§5.2 / §5.2a), mapped to status once at the dispatch boundary:
\   VERDICT-AUTHN   -> 401 authentication_failed   (bad/absent request signature)
\   VERDICT-AUTHZ   -> 403 capability_denied        (chain invalid / grantee mismatch / scope)
\   VERDICT-UNRES   -> 401 unresolvable_grantee     (a grantee peer entity is absent)
\   VERDICT-DEPTH   -> 400 chain_depth_exceeded      (§4.10(b) structural pre-check)
\   VERDICT-ALLOW   -> proceed
\
\ At S3 the capability layer is wired structurally (the seed grant from the handshake is a
\ root single-sig token). Full attenuation/multisig/revocation depth is exercised by the
\ S4 validate-peer chain-construction categories; here we build the primitives + the two
\ MUSTs (depth pre-check ordering + the trichotomy) so they are NOT rediscovered at S4.

64 constant MAX-CHAIN-DEPTH        \ §4.10(b) informative default

0 constant VERDICT-ALLOW
1 constant VERDICT-AUTHN
2 constant VERDICT-AUTHZ
3 constant VERDICT-UNRES
4 constant VERDICT-DEPTH

\ ── token field reads (a system/capability/token data map) ──
: cap-grantee ( token-eaddr -- h-addr h-u | 0 0 )  s" grantee" ent-text ;
: cap-granter ( token-eaddr -- v-addr v-u | 0 0 )  s" granter" ent-text ;
: cap-parent  ( token-eaddr -- h-addr h-u | 0 0 )  s" parent" ent-text ;

\ cap-find-signature ( target-h-addr target-h-u  arr lens n-var -- sig-eaddr | 0 )
\ scan an included set for a system/signature whose `target` == the given content hash.
: cap-find-signature { thaddr thu arr lens nvar -- sigent }
  nvar @ 0 ?do
    arr i cells + @ { e }
    e ent-type s" system/signature" compare 0= if
      e s" target" ent-field ?dup if
        dup c@ [char] b = if tv-payload thaddr thu compare 0= if e unloop exit then
        else drop then
      then
    then
  loop  0 ;

\ ── §4.10(b) chain-depth PRE-CHECK (BEFORE any signature verification) ──
\ cap-exceeds-depth ( token-eaddr  arr lens n-var -- flag )  follow parent pointers WITHOUT
\ verifying signatures, counting depth. Returns true iff depth > MAX-CHAIN-DEPTH. An
\ unreachable parent is NOT a depth problem (stops the count, returns false — the real walk
\ handles the resolution failure as 403/401). This is the structural pre-check the whole
\ v7.75 cohort was missing (all nine returned 403 before the ruling).
: cap-exceeds-depth { token arr lens nvar -- flag }
  token 1 { cur depth }
  begin
    cur cap-parent dup 0= if 2drop false exit then    \ no parent -> root, within depth
    { paddr pu }  arr lens nvar paddr pu inc-get       \ resolve parent token in included
    dup 0= if drop false exit then                     \ unreachable parent: NOT a depth issue
    to cur
    depth 1+ to depth
    depth MAX-CHAIN-DEPTH > if true exit then
  again ;

\ ── the request verdict (§5.2) ──
\ cap-verify-request ( exec-eaddr  arr lens n-var -- verdict )  the trichotomy gate for an
\ authenticated (non-connect) EXECUTE:
\   1. find + verify the request signature (author's) over exec.content_hash  -> AUTHN
\   2. resolve the capability token from included                              -> AUTHZ
\   3. §4.10(b) depth PRE-CHECK                                                -> DEPTH
\   4. structural chain walk + grantee binding                                -> AUTHZ/UNRES
\ At S3 the seed grant is a root single-sig token, so steps 3-4 are the root case; the
\ deep-chain and attenuation legs are S4 (validate-peer chain-construction).
\ cap-verify-authn ( exec-eaddr arr lens nvar -- verdict )  §6.5 step "verify integrity":
\ the AUTHN leg only (author's request signature over exec.content_hash). This runs BEFORE
\ handler resolution so a signed request to an unregistered path resolves-first to 404, and
\ an UNSIGNED request is 401 regardless of the path (§6.5 integrity precedes resolution).
: cap-verify-authn { exec arr lens nvar -- verdict }
  exec ent-hash arr lens nvar cap-find-signature { sig }
  sig 0= if VERDICT-AUTHN exit then
  sig s" signer" ent-field dup 0= if drop VERDICT-AUTHN exit then
    tv-payload { sa su }
  \ §3.5 / §5.1: the exec MUST carry an `author`, and the request signature's signer MUST
  \ equal that author (a signer≠author or missing-author request is unauthenticated).
  exec s" author" ent-field dup 0= if drop VERDICT-AUTHN exit then
    tv-payload sa su compare 0<> if VERDICT-AUTHN exit then
  arr lens nvar sa su inc-get { signer-peer }
  signer-peer 0= if VERDICT-AUTHN exit then
  signer-peer s" public_key" ent-field dup 0= if drop VERDICT-AUTHN exit then
    tv-payload { pkaddr pku }
  sig pkaddr pku id-verify-sig 0= if VERDICT-AUTHN exit then
  VERDICT-ALLOW ;

\ cap-verify-authz ( exec-eaddr arr lens nvar -- verdict )  §6.5 step "check permission":
\ the AUTHZ leg (capability token resolve + §4.10(b) depth pre-check + grantee binding). Runs
\ AFTER handler resolution (§6.6 resolution-first: a 404 on an unregistered path beats a 403).
: cap-verify-authz { exec arr lens nvar -- verdict }
  exec s" capability" ent-field dup 0= if drop VERDICT-AUTHZ exit then
    tv-payload { cu } { ca }  arr lens nvar ca cu inc-get { token }
  token 0= if VERDICT-AUTHZ exit then
  token arr lens nvar cap-exceeds-depth if VERDICT-DEPTH exit then   \ §4.10(b) BEFORE the walk
  token cap-grantee dup 0= if 2drop VERDICT-UNRES exit then
    { gu } { ga }  arr lens nvar ga gu inc-get 0= if VERDICT-UNRES exit then
  VERDICT-ALLOW ;

\ cap-verify-request ( exec arr lens nvar -- verdict )  the composite (authn then authz),
\ kept for callers that don't interleave resolution.
: cap-verify-request { exec arr lens nvar -- verdict }
  exec arr lens nvar cap-verify-authn dup VERDICT-ALLOW <> if exit then drop
  exec arr lens nvar cap-verify-authz ;

\ verdict->status maps at the dispatch boundary (see dispatch.fs cap-verdict-error).
