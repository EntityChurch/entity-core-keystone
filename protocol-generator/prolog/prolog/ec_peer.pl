% ec_peer.pl — Peer assembly: bootstrap, the four MUST system handlers (§6.2:
% connect, tree, capability, handler), the §6.5 dispatch chain, §6.6 resolution,
% §6.9/§6.9a bootstrap, §7a conformance handlers.
%
% THE IDIOM (profile [idiom].clause_head_dispatch): operation dispatch is a set of
% MULTI-HEAD CLAUSES — handle_op(HandlerPattern, OpKeyword, Ctx, Outcome). Each
% (handler, operation) pair is its OWN clause head; the §6.6 resolver picks the
% handler pattern, the operation rides as a ground atom, and Prolog's first-argument
% indexing selects the clause. The "unknown (handler, op) → 501" arm is the FINAL
% catch-all clause — the analogue of CL's CLOS default method / the other peers'
% `| other ->`. Where C#/TS/OCaml write a match-ladder inside one function and CL
% externalizes it to the metaobject method table, Prolog externalizes it to the
% CLAUSE DATABASE: the router is the predicate's clause set, selected by unification
% + indexing. Adding an operation = adding a clause, not editing a ladder.
%
% Per-connection + per-peer state lives in the clause DB keyed by ids (peer_fact/2,
% conn_fact/2) — consistent with the store-as-clause-DB idiom.

:- module(ec_peer,
          [ make_peer/2,             % +Options(list: seed=Bytes, open_grants=Bool, conformance=Bool), -Peer
            peer_local_peer/2,       % +Peer, -PeerIdString
            peer_store/2,            % +Peer, -StoreId
            peer_identity/2,         % +Peer, -Identity
            dispatch/4,              % +Peer, +Env, +Outbound/2, -RespEnv   (the §6.5 chain)
            serve_goal/4,            % +Peer, +Env, +Outbound, -RespEnv     (transport entry)
            conn_forget/1            % +ConnId — drop a closed connection's handshake state
          ]).

:- use_module(ec_codec).
:- use_module(ec_cbor).
:- use_module(ec_entity).
:- use_module(ec_identity).
:- use_module(ec_store).
:- use_module(ec_capability).
:- use_module(ec_wire).
:- use_module(ec_types).
:- use_module(library(lists)).

:- dynamic peer_fact/2.       % PeerId, peer(Identity, StoreId, OpenGrants, Conformance)
:- dynamic conn_state_f/2.    % ConnKey, conn(Established, IssuedNonce, HelloPeerId)
:- dynamic conn_ctr/1.

% the §6.6 handler clause table (handle_op/4) is interleaved with its helper
% predicates by handler section (tree near cas_ok/path_flex_ok, capability near
% peer_pattern_ok, …) for readability — declare it discontiguous.
:- discontiguous handle_op/4.
:- discontiguous handle_connect/6.

% Peer is peer(PeerId) — a handle; the heavy state is in peer_fact/2.

make_peer(Opts, peer(PeerId)) :-
    ( memberchk(seed=Seed, Opts) -> true ; throw(error(ec_peer(seed_required), _)) ),
    ( memberchk(open_grants=OG, Opts) -> true ; OG = false ),
    ( memberchk(conformance=CF, Opts) -> true ; CF = false ),
    make_identity(Seed, Identity),
    identity_peer_id(Identity, PeerId),
    store_new(StoreId),
    assertz(peer_fact(PeerId, peer(Identity, StoreId, OG, CF))),
    % local identity entity in the store (root-granter resolution).
    identity_peer_entity(Identity, PeerEntity),
    store_put_entity(StoreId, PeerEntity),
    % publish the 53 core types (§9.5 floor, render-from-model).
    publish_core_types(StoreId, PeerId),
    % bootstrap the MUST handler tree entities + §6.9a owner authority.
    bootstrap_handlers(PeerId, Identity, StoreId, CF),
    bootstrap_authority(PeerId, Identity, StoreId, OG).

peer_local_peer(peer(PeerId), PeerId).
peer_store(peer(PeerId), StoreId) :- peer_fact(PeerId, peer(_, StoreId, _, _)).
peer_identity(peer(PeerId), Id) :- peer_fact(PeerId, peer(Id, _, _, _)).
peer_open_grants(peer(PeerId), OG) :- peer_fact(PeerId, peer(_, _, OG, _)).
peer_conformance(peer(PeerId), CF) :- peer_fact(PeerId, peer(_, _, _, CF)).

% ── core type publication (§9.5) ───────────────────────────────────────────────
publish_core_types(StoreId, PeerId) :-
    core_type_names(Names),
    forall(member(Name, Names),
           ( core_type_model(Name, Data),
             make_entity("system/type", Data, E),
             atomics_to_string(["/", PeerId, "/system/type/", Name], Path),
             store_bind(StoreId, Path, E) )).

% ── grant construction (§4.4 / §5.4) ────────────────────────────────────────────
scope(Incl, map(["include"-Incl])).
scope(Incl, Excl, map(["include"-Incl, "exclude"-Excl])).

grant(Handlers, Resources, Operations, map(Pairs)) :-
    scope(Handlers, HS), scope(Resources, RS), scope(Operations, OS),
    Pairs = ["handlers"-HS, "resources"-RS, "operations"-OS].
grant(Handlers, Resources, Operations, Peers, map(Pairs)) :-
    scope(Handlers, HS), scope(Resources, RS), scope(Operations, OS), scope(Peers, PS),
    Pairs = ["handlers"-HS, "resources"-RS, "operations"-OS, "peers"-PS].

% §4.4 discovery floor: every authenticated identity gets at least this.
discovery_floor([G1, G2]) :-
    grant(["system/tree"], ["system/type/*", "system/handler/*"], ["get"], G1),
    grant(["system/capability"], [], ["request"], G2).

open_grants_scope([G]) :- grant(["*"], ["*", "/*/*"], ["*"], ["*"], G).
owner_grants(PeerId, [G]) :- grant(["*"], ["*"], ["*"], [PeerId], G).

% ── token mint (§4.4 / §6.9a) ────────────────────────────────────────────────────
now_ms(Ms) :- get_time(T), Ms is integer(T * 1000).

mint_token(Identity, GranteeHash, Grants, Token, Sig) :-
    mint_token(Identity, GranteeHash, Grants, (-), Token, Sig).
mint_token(Identity, GranteeHash, Grants, Parent, Token, Sig) :-
    % No §5.6 ceiling: the self-issued paths (bootstrap, handler registration, the
    % §4.4 handshake) mint from local authority, where no MIN_DEFINED term is in play.
    now_ms(Created),
    mint_token_at(Identity, Created, GranteeHash, Grants, Parent, (-), Token, Sig).

% Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
%
% Expires == (-) means no term was defined and the token genuinely has no expiry (the
% ONLY "no bound" spelling). A present value is emitted verbatim -- including one equal
% to Created, which §5.6 rule 2 requires for ttl_ms == 0 and which means "already
% expired at every observable instant", not "unbounded".
%
% Created is supplied rather than sampled here so a computed expiry is guaranteed to be
% relative to the SAME instant that lands in the token; sampling the clock twice skews
% the two.
mint_token_at(Identity, Created, GranteeHash, Grants, Parent, Expires, Token, Sig) :-
    identity_hash(Identity, GranterHash),
    string_codes(GranterHash, GHC), string_codes(GranteeHash, GeC),
    Base = ["granter"-bytes(GHC), "grantee"-bytes(GeC), "grants"-Grants, "created_at"-int(Created)],
    ( Expires == (-) -> Base1 = Base
    ; append(Base, ["expires_at"-int(Expires)], Base1) ),
    ( Parent == (-) -> Pairs = Base1
    ; string_codes(Parent, PC), append(Base1, ["parent"-bytes(PC)], Pairs) ),
    make_entity("system/capability/token", map(Pairs), Token),
    sign_entity(Identity, Token, Sig).

% ── §5.6 temporal ceiling (CAP-5 / CAP-6) ────────────────────────────────────────
%
% add_ttl converts a DURATION term to an absolute timestamp, FAILING when it
% contributes no term. §5.6 rule 3: a conversion that is not representable is treated
% as ABSENT, exactly as a null term is -- it MUST NOT wrap and MUST NOT saturate to a
% representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
% bound no reader can distinguish from a deliberate one. Prolog integers are
% arbitrary-precision, so this is a DELIBERATE range check rather than an overflow trap.
%
% Ttl == 0 is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
% yielding Created (expire immediately). The absent field is the only "no bound"
% spelling, and falling out of the arithmetic is what keeps the two from collapsing.
add_ttl(Created, Ttl, Abs) :-
    integer(Ttl), Ttl >= 0,
    Abs is Created + Ttl,
    Abs < 18446744073709551616.

% MIN over the DEFINED terms only (§5.6). Terms arrive already shaped: absolute
% timestamps enter directly, durations MUST be converted with add_ttl first. Mixing a
% duration in unconverted yields a timestamp near the epoch and silently clamps every
% token to already-expired -- the failure mode §5.6 calls out by name.
min_defined([], (-)).
min_defined(Terms, Min) :- Terms \== [], min_list(Terms, Min).

% ── §6.9a seed policy (authenticate-time grant derivation) ───────────────────────
derive_seed_grants(PeerId, StoreId, _RemotePeer, RemotePeerId, Grants) :-
    discovery_floor(Floor),
    atomics_to_string(["/", PeerId, "/system/capability/policy/", RemotePeerId], P1),
    atomics_to_string(["/", PeerId, "/system/capability/policy/default"], PDef),
    ( store_get_at(StoreId, P1, Entry) -> true
    ; store_get_at(StoreId, PDef, Entry) -> true
    ; Entry = (-) ),
    ( Entry == (-) -> Grants = Floor
    ; ( ent_field(Entry, "grants", G), is_list(G) -> append(Floor, G, Grants) ; Grants = Floor ) ).

% ═══════════════════════════════════════════════════════════════════════════
% DISPATCH CHAIN (§6.5) — returns an EXECUTE_RESPONSE envelope, or (-) for a
% non-EXECUTE root (server ignores non-EXECUTE).
% ═══════════════════════════════════════════════════════════════════════════
serve_goal(Peer, Env, Outbound, Resp) :- dispatch(Peer, Env, Outbound, Resp).

dispatch(Peer, Env, Outbound, Resp) :-
    envelope_root(Env, Exec),
    ( entity_type(Exec, "system/protocol/execute") -> true ; (Resp = (-), !, fail) ),
    ( ent_text(Exec, "request_id", ReqId) -> true ; ReqId = "" ),
    catch(run_chain(Peer, Env, Exec, Outbound, Outcome),
          Err,
          chain_error_outcome(Err, Outcome)),
    Outcome = outcome(Status, Result, Included),
    make_response(ReqId, Status, Result, RespEntity),
    envelope(RespEntity, Included, Resp).
dispatch(_, _, _, (-)).   % non-execute root

chain_error_outcome(ec_capability(unresolvable_grantee), outcome(401, R, [])) :- !,
    error_result("unresolvable_grantee", "", R).
chain_error_outcome(Err, outcome(500, R, [])) :-
    ( getenv('EC_DEBUG', _) -> ( format(user_error, "EC_CHAIN_ERROR: ~q~n", [Err]), flush_output(user_error) ) ; true ),
    error_result("internal_error", "", R).

% run_chain: connect ops bypass authz; everything else runs verify → resolve →
% check_permission → handler.
run_chain(Peer, Env, Exec, Outbound, Outcome) :-
    ent_text(Exec, "uri", "system/protocol/connect"), !,
    ( ent_text(Exec, "operation", Op) -> true ; Op = "" ),
    % Outbound is threaded in ONLY to identify the CONNECTION — see conn_key/2.
    handle_connect(Peer, Env, Exec, Op, Outbound, Outcome).
run_chain(Peer, Env, Exec, Outbound, Outcome) :-
    peer_store(Peer, StoreId),
    peer_local_peer(Peer, Local),
    ingest_signatures(Peer, Env),
    % §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION. This gate used to
    % sit in authorized_dispatch/5, reachable only on the `allow` verdict, so a
    % pre-establishment EXECUTE naming a FOREIGN namespace took the 401 an unauthenticated
    % request takes. §4.7's own reason: "a 401 directs the caller to authenticate and retry,
    % and for a foreign-namespace address that retry cannot succeed at any authentication
    % state — so the 401 names a remedy that does not exist." §6.5 step 3 calls it "a gate,
    % not an ordering preference" and §1.4 makes the downstream permission check unreachable
    % here, so evaluating authentication first can only mislead.
    ( ent_text(Exec, "uri", AUri) -> true ; AUri = "" ),
    normalize_uri(AUri, ANU),
    canonicalize(Local, ANU, APath),
    (   \+ extract_peer(Local, APath, Local)
    ->  error_result("invalid_request", "not local peer", AR),
        Outcome = outcome(400, AR, [])
    ;   verify_request(Local, StoreId, Env, Verdict),
        verdict_outcome(Verdict, Peer, Env, Exec, Outbound, Outcome) ).

verdict_outcome(authn_fail, _, _, _, _, outcome(401, R, [])) :- !, error_result("authentication_failed", "", R).
verdict_outcome(authz_deny, _, _, _, _, outcome(403, R, [])) :- !, error_result("capability_denied", "", R).
verdict_outcome(chain_too_deep, _, _, _, _, outcome(400, R, [])) :- !, error_result("chain_depth_exceeded", "", R).
verdict_outcome(allow, Peer, Env, Exec, Outbound, Outcome) :-
    authorized_dispatch(Peer, Env, Exec, Outbound, Outcome).

authorized_dispatch(Peer, Env, Exec, Outbound, Outcome) :-
    peer_local_peer(Peer, Local),
    ( ent_text(Exec, "uri", Uri) -> true ; Uri = "" ),
    normalize_uri(Uri, NU),
    canonicalize(Local, NU, Path),
    % §1.4 / §6.5 step 3 — the ADDRESS gate, ahead of handler resolution and
    % check_permission: 400 invalid_request, never a handler or authz verdict
    % (§6.2, 0.8.2.2).
    %
    % This used to be `throw(not_local)` with a second authorized_dispatch/5
    % clause below answering the refusal. That clause was DEAD CODE and always
    % had been: a throw/1 does not fall through to the next clause, it unwinds to
    % dispatch/4's catch, where the generic chain_error_outcome/2 turned it into
    % 500 internal_error. So the refusal a source read finds — a tidy fallback
    % clause naming the right status — was never the answer on the wire. Measured
    % at oracle f313028: (500, "internal_error").
    % (The gate itself has moved UP into run_chain/5, ahead of verify_request/4 —
    % §4.7 0.8.2.6 orders the address before authentication. Reaching this clause at
    % all now means the path is local; the check is kept as a cheap restatement so the
    % two cannot drift apart silently.)
    ( \+ extract_peer(Local, Path, Local)
    -> error_result("invalid_request", "not local peer", R), Outcome = outcome(400, R, [])
    ;  resolve_handler(Peer, Path, Pattern)
    -> permission_then_handle(Peer, Env, Exec, Pattern, Outbound, Outcome)
    ;  error_result("handler_not_found", Path, R), Outcome = outcome(404, R, []) ).

permission_then_handle(Peer, Env, Exec, Pattern, Outbound, Outcome) :-
    peer_local_peer(Peer, Local),
    peer_store(Peer, StoreId),
    ( ent_bytes(Exec, "capability", CapH), included_get(Env, CapH, CallerCap)
    -> granter_frame(Env, StoreId, Local, CallerCap, GranterPeer),
       check_permission(Local, GranterPeer, Exec, CallerCap, Pattern, PermVerdict),
       ( PermVerdict == allow
       -> strip_local(Local, Pattern, Stripped),
          ( ent_text(Exec, "operation", Op) -> true ; Op = "" ),
          handle_op(Stripped, Op, ctx(Peer, Env, Exec, CallerCap, Outbound), Outcome)
       ;  error_result("capability_denied", "", R), Outcome = outcome(403, R, []) )
    ;  error_result("capability_denied", "", R), Outcome = outcome(403, R, []) ).

granter_frame(Env, StoreId, Local, CallerCap, GranterPeer) :-
    ( ent_bytes(CallerCap, "granter", GH),
      ( included_get(Env, GH, G) -> true ; store_get_by_hash(StoreId, GH, G) ),
      ent_bytes(G, "public_key", PK), peer_id_of_pubkey(PK, GranterPeer)
    -> true
    ;  GranterPeer = Local ).


% ═══════════════════════════════════════════════════════════════════════════
% §4.1 / §4.6 handshake (connect handler).
% ═══════════════════════════════════════════════════════════════════════════
handle_connect(Peer, _Env, Exec, "hello", Outbound, Outcome) :- !,
    peer_local_peer(Peer, Local),
    conn_key(Outbound, CK),
    ( ent_entity(Exec, "params", P) -> true ; P = (-) ),
    ( P \== (-), ent_text(P, "peer_id", HPid0) -> HPid = HPid0 ; HPid = (-) ),
    ( % ── §4.5 CONTENT checks first, then §4.7 STATE checks. ──────────────────
      %
      % THE TWO ORDERS ARE DISTINGUISHABLE AND THE ORACLE DISTINGUISHES THEM.
      % Measured at oracle 78db4a9: in a FULL core run this peer receives
      % `negotiation/format_disjoint_reject`'s disjoint hello on a HALF-OPEN
      % connection (traced: ck=conn117, established=false, hash_formats=
      % ["ecfv1-fake-disjoint-format"]), so a state-first ladder answers
      % 409 connection_sequence_error and the check wants 400
      % incompatible_hash_format. Driven as `-category negotiation` alone the same
      % hello arrives on a FRESH connection and either order passes — which is why
      % the category run is green and the full run is not.
      %
      % Content-first is the reading that satisfies both vectors, and it is the one
      % §4.5 argues for: a hello naming no common hash format is refusable on what
      % it CONTAINS, in any state, and §4.5 wants that refusal at the earliest
      % point. It is the same principle as §4.7 row 10 — an operation that "exists
      % in no state" is not an ordering defect — applied to a field rather than an
      % operation name. §4.5 and §4.7 fix no precedence between them, so both
      % orders are spec-legal and only one passes: that is a finding, not a
      % preference, and it is recorded rather than silently absorbed.
      %
      % §4.5 negotiation: an EXPLICIT hash_formats/key_types list that is DISJOINT
      % from our floor (ecfv1-sha256 / ed25519) is rejected up front (400). An
      % absent list = no constraint (admit). NEGOTIATE-FORMAT-1 / NEGOTIATE-KEYTYPE-1.
      P \== (-), ent_field(P, "hash_formats", HFs), is_list(HFs), \+ list_has_text(HFs, "ecfv1-sha256")
    -> error_result("incompatible_hash_format", "", R), Outcome = outcome(400, R, [])
    ;  P \== (-), ent_field(P, "key_types", KTs), is_list(KTs), \+ list_has_text(KTs, "ed25519")
    -> error_result("unsupported_key_type", "", R), Outcome = outcome(400, R, [])
      % §4.5 mutual verifiability, the direction that is NOT the array. `key_types`
      % is an ACCEPT-SET; the initiator's OWN key_type is not in it — it rides in
      % its `peer_id` — so a hello may advertise a perfectly good accept-set and
      % still name an identity we cannot verify. An UNPARSEABLE peer_id is left
      % alone: a malformed field, not a key_type we lack.
    ;  HPid \== (-), catch(ec_peerid_parse(HPid, HKT, _, _), _, fail), HKT =\= 1
    -> error_result("unsupported_key_type", "", R), Outcome = outcome(400, R, [])
      % §4.5 `protocols` — the one negotiated field Required with NO default, so
      % there is no floor to fall back to, and its two failure modes carry
      % different codes on purpose (§4.5 table row / §4.7 row 1):
      %
      %   absent or empty     -> 400 invalid_request       (a malformed hello)
      %   non-empty, disjoint -> 400 incompatible_protocol (we compared)
      %
      % "a caller that named no version cannot be told the comparison failed" — the
      % remedies differ (send the field vs change the version) and §4.7 exists so
      % the code selects the remedy.
      %
      % ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
      % precedence between the three, so a hello disjoint in more than one
      % dimension may be refused on any of them — but the choice is OBSERVABLE, and
      % the reference peer refuses key_types first. Checking protocols first makes
      % AGILITY-UNKNOWN-1 answer incompatible_protocol, because that probe's hello
      % carries ["entity-core/v7"] — a spec-line name, not a §8.4 identifier (F56).
    ;  \+ ( P \== (-), ent_field(P, "protocols", Ps0), is_list(Ps0), Ps0 \== [] )
    -> error_result("invalid_request", "hello: protocols absent or empty", R),
       Outcome = outcome(400, R, [])
    ;  ent_field(P, "protocols", Ps), \+ list_has_text(Ps, "entity-core/1.0")
    -> error_result("incompatible_protocol", "", R), Outcome = outcome(400, R, [])
      % ── §4.7 STATE checks, after the content is known to be acceptable. ───────
      % Rows 3/4: a hello on an ESTABLISHED connection is a state conflict.
    ;  conn_established_key(CK)
    -> error_result("connection_already_established", "", R), Outcome = outcome(409, R, [])
      % The out-of-order row + the 0.8.2.8 half-open note: a second hello on a
      % HALF-OPEN connection (hello done, authenticate not yet) is an operation we
      % implement arriving in a state that forbids it — the same class as the row
      % above, taking the same 409. A half-open connection is NOT established, so
      % the guard above cannot reach it; §4.7 names this gap explicitly because two
      % adjacent rules each look like they cover it and neither does.
    ;  conn_issued_nonce_key(CK, _)
    -> error_result("connection_sequence_error", "", R), Outcome = outcome(409, R, [])
    ;  random_nonce(Nonce), string_codes(Nonce, NC),
       conn_remember_key(CK, Nonce, HPid),
       make_entity("system/protocol/connect/hello",
                   map(["peer_id"-Local, "nonce"-bytes(NC),
                        "protocols"-["entity-core/1.0"], "timestamp"-int(0),
                        "hash_formats"-["ecfv1-sha256"], "key_types"-["ed25519"]]),
                   HelloE),
       Outcome = outcome(200, HelloE, []) ).

list_has_text(L, T) :- member(X, L), ( X == T -> true ; ( string(X), string(T), X == T ) ), !.
handle_connect(Peer, Env, Exec, "authenticate", Outbound, Outcome) :- !,
    handle_authenticate(Peer, Env, Exec, Outbound, Outcome).
% §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
% 400 invalid_request, not the 501 every other handler answers. The table separates
% a STATE conflict from an UNKNOWN operation because they select different remedies
% — "an unknown connect operation is not out of order at all; it exists in no
% state", so connection_sequence_error would point the caller at its ORDERING when
% the defect is its OPERATION NAME. Row 10 is scoped "in any state", so this clause
% covers pre-handshake AND established.
%
% SCOPED TO THIS PREDICATE DELIBERATELY. The generic registered-handler rule (§3.3's
% 501 row, §6.2) is a different contract and is separately gated; and note it is a
% CLAUSE and not a throw/1 — the ec_peer §1.4 gate above records what happens when a
% refusal is raised into a generic catch instead of answered where it is decided.
handle_connect(_, _, _, Op, _, outcome(400, R, [])) :-
    format(string(Msg), "connect: unknown operation ~w", [Op]),
    error_result("invalid_request", Msg, R).

handle_authenticate(Peer, Env, Exec, Outbound, Outcome) :-
    peer_local_peer(Peer, Local),
    peer_identity(Peer, Identity),
    peer_store(Peer, StoreId),
    conn_key(Outbound, CK),
    % RT-6 (§4.6) anti-replay: a SECOND authenticate on an already-established
    % connection must not be re-processed (it would re-verify the same
    % still-cached nonce and re-issue a grant) — the nonce is documented
    % single-use. Reject outright, before any nonce/signature work.
    ( conn_established_key(CK)
    -> error_result("invalid_nonce", "", R), Outcome = outcome(401, R, [])
    % FM-1 (§4.2, §4.7 row 6, 0.8.2.1): an authenticate arriving before any hello
    % nonce was issued is the SAME input as the replay above — a captured
    % authenticate replayed onto a fresh connection — so it is 401 invalid_nonce.
    % Without this clause the frame falls through to authenticate_ok/4 failing and
    % surfaces as 401 authentication_failed: the right STATUS reached by a later
    % check, with a code that names the wrong failure. (Absence of a guard does not
    % predict which later check catches the frame — measured, not assumed.)
    ; \+ conn_issued_nonce_key(CK, _)
    -> error_result("invalid_nonce", "", R), Outcome = outcome(401, R, [])
    ; ent_entity(Exec, "params", Auth), unsupported_key_type(Auth)
    -> error_result("unsupported_key_type", "", R), Outcome = outcome(400, R, [])
    ; ent_entity(Exec, "params", Auth)
    -> ( % §4.7 row 8 names TWO inputs and BOTH are 401 identity_mismatch, so they
         % are checked AFTER proof-of-possession and separately from it. Folding
         % them into authenticate_ok/4 made every one of the three §4.6 checks
         % collapse into a single 401 authentication_failed — the right status
         % reached by the wrong check, with a code that names the wrong failure.
         %
         %   (a) the claimed peer_id is not derived from the presented public_key
         %       — the identity is not SELF-CONSISTENT;
         %   (b) the claimed peer_id is not the one this connection GREETED as
         %       — self-consistent, and not the identity we have been negotiating
         %       with. Without (b) a caller may greet as one peer and authenticate
         %       as another, and every seed-policy lookup after it resolves against
         %       the second.
         authenticate_ok(CK, Env, Auth, Pub, Claimed)
       -> ( peer_id_of_pubkey(Pub, Derived), Derived \== Claimed
          -> error_result("identity_mismatch", "", R), Outcome = outcome(401, R, [])
          ;  conn_hello_peer_key(CK, Greeted), Greeted \== (-), Greeted \== Claimed
          -> error_result("identity_mismatch", "", R), Outcome = outcome(401, R, [])
          ;  handshake_grant(Peer, Local, Identity, StoreId, CK, Pub, Claimed, Outcome) )
       ;  error_result("authentication_failed", "", R), Outcome = outcome(401, R, []) )
    ;  error_result("authentication_failed", "", R), Outcome = outcome(401, R, []) ).

handshake_grant(_Peer, Local, Identity, StoreId, CK, Pub, Claimed, Outcome) :-
    peer_entity_of_pubkey(Pub, RemotePeer),
    entity_hash(RemotePeer, RemoteHash),
    derive_seed_grants(Local, StoreId, RemotePeer, Claimed, Grants),
    mint_token(Identity, RemoteHash, Grants, Token, Sig),
    store_put_entity(StoreId, RemotePeer),
    entity_hash(Token, TokenHash), string_codes(TokenHash, THC),
    make_entity("system/capability/grant", map(["token"-bytes(THC)]), GrantE),
    identity_peer_entity(Identity, PeerEntity),
    included_pairs([Token, PeerEntity, Sig], Included),
    conn_mark_established_key(CK),
    Outcome = outcome(200, GrantE, Included).

% §4.6 hardening / AGILITY-UNKNOWN-1: an unsupported key_type → 400 (NOT 401).
% The unsupported code can ride in the key_type field, a non-32-byte public_key,
% or the claimed peer_id's leading key_type byte (the 0xfd case — field still says
% "ed25519"). Reject all three before the authn trichotomy.
unsupported_key_type(Auth) :-
    ( ent_text(Auth, "key_type", KT), KT \== "ed25519"
    ; ent_bytes(Auth, "public_key", PK), string_length(PK, L), L =\= 32
    ; ent_text(Auth, "peer_id", PID),
      catch(ec_peerid_parse(PID, ParsedKT, _, _), _, fail), ParsedKT =\= 1
    ), !.

% The §4.6 checks that are authentication_failed when they fail: shape, nonce-echo
% and proof-of-possession. The IDENTITY-BINDING pair (§4.7 row 8) is deliberately NOT
% here — both of its inputs are identity_mismatch, and a caller told
% "authentication_failed" for a peer_id mismatch is pointed at the wrong remedy.
authenticate_ok(CK, Env, Auth, Pub, Claimed) :-
    ent_bytes(Auth, "public_key", Pub), string_length(Pub, 32),
    ent_text(Auth, "peer_id", Claimed),
    ( ent_text(Auth, "key_type", KT) -> KT == "ed25519" ; true ),
    % nonce-echo: the echoed nonce must match the one we issued for this connection.
    ent_bytes(Auth, "nonce", Echoed),
    conn_issued_nonce_key(CK, Issued),
    Echoed == Issued,
    % proof of possession: signature over auth's content_hash verifies under Pub.
    entity_hash(Auth, AuthHash),
    find_sig_for(Env, AuthHash, Sig),
    ent_bytes(Sig, "signature", SigBytes),
    catch(ec_ed25519_verify(Pub, AuthHash, SigBytes), _, fail).

find_sig_for(Env, Target, Sig) :-
    envelope_included(Env, Inc), member(_-Sig, Inc),
    entity_type(Sig, "system/signature"),
    ent_bytes(Sig, "target", T), T == Target, !.

% ── per-CONNECTION handshake state ──────────────────────────────────────────────
%
% THE KEY IS THE TRANSPORT'S CONNECTION ID, NOT A FIELD FROM THE FRAME. This used
% to be keyed on the initiator peer_id carried in the hello's own params, with a
% comment calling it "the simplest correct scheme for the smoke". It is not correct
% and the defect is not subtle once named: the state that decides whether a nonce
% was issued, and whether this connection is established, was addressed by a value
% the CALLER chooses. Two consequences, both measured at oracle 78db4a9:
%
%   - an authenticate naming a different peer_id than the hello looked up a
%     DIFFERENT key, found no state, and answered 401 invalid_nonce — so §4.7
%     row 8's greeted-vs-claimed mismatch was refused for the wrong reason, and
%     the refusal was an accident of the lookup rather than a check;
%   - two connections greeting as the same peer_id SHARE one state record, so one
%     can consume or establish the other's handshake.
%
% `Outbound` is the §6.13(b) reentry seam the transport hands the dispatcher:
% `ec_transport:outbound_via(io(ConnId, ...))`, one io per accepted socket. Reading
% ConnId off it identifies the connection without changing serve_goal/4's arity —
% and it is the transport's own identifier, so nothing on the wire can name it.
conn_key(Outbound, ConnId) :-
    nonvar(Outbound),
    Outbound = _:outbound_via(io(ConnId, _, _, _, _)), !.
% No io in scope (an in-process caller, not a served connection). Fail CLOSED to a
% single named key rather than to a wire value: a shared key can only ever refuse
% or confuse a second concurrent in-process handshake, where a caller-chosen key
% hands the choice to the caller.
conn_key(_, no_connection).

% Release this connection's handshake state when the connection goes. Without it
% one record accumulates per connection for the life of the process, which the
% oracle's 100-cycle churn and 256-connection flood make measurable.
%
% REGISTERED BY THE HOST, NOT HERE. ec_peer deliberately does not import
% ec_transport — the dependency runs the other way (the transport calls
% serve_goal/4) — so registering the hook from this module would either create a
% cycle or race the load order. ec_host imports both and wires them.
conn_forget(CK) :- retractall(conn_state_f(CK, _)).

conn_remember_key(CK, Nonce, HelloPeerId) :-
    retractall(conn_state_f(CK, _)),
    assertz(conn_state_f(CK, conn(false, Nonce, HelloPeerId))).
conn_issued_nonce_key(CK, Nonce) :- conn_state_f(CK, conn(_, Nonce, _)).

% §4.7 row 8, second input: the identity this connection GREETED as, or (-) if the
% hello named none. Fails when there is no state at all, so callers guard with the
% nonce check first.
conn_hello_peer_key(CK, HelloPeerId) :- conn_state_f(CK, conn(_, _, HelloPeerId)).

% RT-6 (§4.6): has this connection already completed a successful authenticate?
% Fails (not established) when no conn_state_f fact exists yet, so a first-time
% authenticate falls through to the normal nonce-echo/signature checks.
conn_established_key(CK) :- conn_state_f(CK, conn(true, _, _)).

conn_mark_established_key(CK) :-
    retract(conn_state_f(CK, conn(_, Nonce, HelloPeerId))),
    assertz(conn_state_f(CK, conn(true, Nonce, HelloPeerId))).

random_nonce(Nonce) :-
    length(Codes, 32),
    maplist([C]>>(C is random(256)), Codes),
    string_codes(Nonce, Codes).

% ═══════════════════════════════════════════════════════════════════════════
% §6.6 handler resolution — backward tree-walk (the longest bound prefix).
% ═══════════════════════════════════════════════════════════════════════════
resolve_handler(Peer, Path, Pattern) :-
    peer_store(Peer, StoreId),
    split_string(Path, "/", "", Segs0),
    exclude(==(""), Segs0, Segs),   % keep peer_id..tail; drop empties
    length(Segs, N),
    between_desc(N, 1, I),
    length(Prefix, I), append(Prefix, _, Segs),
    atomic_list_concat_strs(Prefix, "/", Body),
    string_concat("/", Body, Cand),
    store_get_at(StoreId, Cand, E),
    entity_type(E, "system/handler"), !,
    Pattern = Cand.

between_desc(Hi, Lo, X) :- Hi >= Lo, ( X = Hi ; H1 is Hi - 1, between_desc(H1, Lo, X) ).

atomic_list_concat_strs(List, Sep, S) :- atomic_list_concat(List, Sep, A), atom_string(A, S).

strip_local(Local, Pattern, Stripped) :-
    atomics_to_string(["/", Local, "/"], Prefix),
    ( string_concat(Prefix, Rest, Pattern) -> Stripped = Rest ; Stripped = Pattern ).

% ═══════════════════════════════════════════════════════════════════════════
% §6.5 signature ingestion — stash signatures + signer peers into the store so
% the relational chain walk can resolve them.
% ═══════════════════════════════════════════════════════════════════════════
ingest_signatures(Peer, Env) :-
    peer_store(Peer, StoreId),
    envelope_included(Env, Inc),
    forall(( member(_-E, Inc), entity_type(E, "system/signature") ),
           ingest_one(StoreId, Env, E)).
ingest_one(StoreId, Env, Sig) :-
    store_put_entity(StoreId, Sig),
    ( ent_bytes(Sig, "signer", SignerH), included_get(Env, SignerH, SignerPeer)
    -> store_put_entity(StoreId, SignerPeer),
       ( ent_bytes(Sig, "target", Target), ent_bytes(SignerPeer, "public_key", PK)
       -> peer_id_of_pubkey(PK, Pid), bytes_hex(Target, HexA), atom_string(HexA, Hex),
          atomics_to_string(["/", Pid, "/system/signature/", Hex], Path),
          store_bind(StoreId, Path, Sig)
       ;  true )
    ;  true ).

% ═══════════════════════════════════════════════════════════════════════════
% THE HANDLER CLAUSE TABLE — handle_op(HandlerPattern, Op, Ctx, Outcome).
% ctx(Peer, Env, Exec, CallerCap, Outbound). Each (handler, op) is a clause head;
% the final clause is the 501 catch-all (the §6.6 default arm).
% ═══════════════════════════════════════════════════════════════════════════

% ── tree handler (§6.3) ──
handle_op("system/tree", "get", ctx(Peer, _, Exec, _, _), Outcome) :- !,
    peer_local_peer(Peer, Local), peer_store(Peer, StoreId),
    ( exec_resource_target(Exec, Target)
    -> ( \+ path_flex_ok(Target)
       -> error_result("invalid_path", Target, R), Outcome = outcome(400, R, [])
       ;  target_is_listing(Target)
       -> canonicalize(Local, Target, P), build_listing(StoreId, P, Outcome)
       ;  canonicalize(Local, Target, Path),
          ( store_get_at(StoreId, Path, E)
          -> Outcome = outcome(200, E, [])
          ;  error_result("not_found", Path, R), Outcome = outcome(404, R, []) ) )
    ;  atomics_to_string(["/", Local, "/"], Root), build_listing(StoreId, Root, Outcome) ).

handle_op("system/tree", "put", ctx(Peer, _, Exec, _, _), Outcome) :- !,
    peer_local_peer(Peer, Local), peer_store(Peer, StoreId),
    ( exec_resource_target(Exec, Target)
    -> ( \+ path_flex_ok(Target)
       -> error_result("invalid_path", Target, R), Outcome = outcome(400, R, [])
       ;  canonicalize(Local, Target, Path),
          ( ent_entity(Exec, "params", Params), ent_field(Params, "entity", RawEntity)
          -> ( cas_ok(StoreId, Path, Params)
             -> admit_put(RawEntity, Admission),
                ( Admission = admitted(Entity)
                -> store_bind(StoreId, Path, Entity),
                   entity_hash(Entity, H), string_codes(H, HC),
                   make_entity("system/hash", map(["hash"-bytes(HC)]), HashE),
                   Outcome = outcome(200, HashE, [])
                ;  Admission = refused(Outcome) )
             ;  error_result("hash_mismatch", Path, R), Outcome = outcome(409, R, []) )
          ;  error_result("unexpected_params", "put: missing entity", R), Outcome = outcome(400, R, []) ) )
    ;  error_result("ambiguous_resource", "tree: missing resource target", R), Outcome = outcome(400, R, []) ).

% ── §6.3 put admission (normative, 0.8.2.11) ──
%
% `put` is a RECEIPT path: the submitter authors the entity, the peer validates
% what it received (§1.8 item 1) and MUST NOT author a submitted entity's
% content_hash on the submitter's behalf. Two ordered steps:
%
%   1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any
%      CBOR value; null is a legal payload), and a `content_hash` that is a
%      well-formed system/hash whose total byte length matches its format code
%      (§1.2). Any failure -> 400 invalid_request. A well-formed hash naming a
%      format code this peer cannot verify is the separate §1.2 ingest-dispatch
%      case -> 400 unsupported_content_hash_format.
%   2. HASH — carried content_hash vs content_hash({type, data}). Disagreement ->
%      400 hash_mismatch.
%
% Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
% inputs are exactly what step 1 establishes, so a submission that is both
% malformed and mis-hashed is step 1's and answers invalid_request. The clause
% order below IS that ordering — each rung cuts, so a later rung is unreachable
% once an earlier one has committed.
%
% Structural admission is not semantic validation: `data` is never checked
% against the type named by `type`.

% Digest byte length for a content_hash_format code per the §1.2 seed table.
% Fails for a code this peer cannot VERIFY — the total wire length is this plus
% the varint prefix, which is not a constant of the code (§7.3).
hash_digest_len(0, 32).
hash_digest_len(1, 48).

% Decode one multicodec LEB128 varint from a code list. FAILS (rather than
% throwing) when the prefix runs off the end, which is the truncated case.
varint_decode_codes(Codes, Value, Consumed) :-
    varint_decode_codes_(Codes, 0, 0, 0, Value, Consumed).
varint_decode_codes_([B|Rest], Shift, Acc, N, Value, Consumed) :-
    Acc1 is Acc \/ ((B /\ 0x7f) << Shift),
    N1 is N + 1,
    ( B /\ 0x80 =:= 0
    -> Value = Acc1, Consumed = N1
    ;  Shift1 is Shift + 7,
       varint_decode_codes_(Rest, Shift1, Acc1, N1, Value, Consumed) ).

put_refusal(Code, Message, refused(outcome(400, R, []))) :-
    error_result(Code, Message, R).

admit_put(V, Result) :-
    ( V = map(Pairs)
    -> admit_put_map(Pairs, Result)
    ;  put_refusal("invalid_request", "put: entity is not a map", Result) ).

admit_put_map(Pairs, Result) :-
    ( memberchk("type"-Type, Pairs), string(Type), Type \== ""
    -> ( memberchk("data"-Data, Pairs)          % PRESENCE: a CBOR null is legal
       -> ( memberchk("content_hash"-bytes(CarriedCodes), Pairs), CarriedCodes \== []
          -> admit_put_hash(Type, Data, CarriedCodes, Result)
          ;  put_refusal("invalid_request",
                         "put: entity.content_hash absent or not a byte string", Result) )
       ;  put_refusal("invalid_request", "put: entity.data absent", Result) )
    ;  put_refusal("invalid_request",
                   "put: entity.type absent, empty or not a text string", Result) ).

admit_put_hash(Type, Data, CarriedCodes, Result) :-
    ( varint_decode_codes(CarriedCodes, FormatCode, Consumed)
    -> ( hash_digest_len(FormatCode, DigestLen)
       -> length(CarriedCodes, Total),
          ( Total =:= Consumed + DigestLen
          -> string_codes(Carried, CarriedCodes),
             cbor_encode_bytes(Data, DataBytes),
             ec_content_hash_with_format(Type, DataBytes, FormatCode, Computed),
             ( Computed == Carried
             -> % The carried hash IS the entity's address; recomputing it into
                % the store would be the authoring arm §6.3 forbids.
                Result = admitted(entity(Type, Data, Carried))
             ;  put_refusal("hash_mismatch",
                            "put: content_hash does not match content_hash({type, data})",
                            Result) )
          ;  put_refusal("invalid_request",
                         "put: content_hash length does not match its format code", Result) )
       %  §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
       %  invalid_request: the shape is fine, the algorithm is what we lack.
       ;  put_refusal("unsupported_content_hash_format",
                      "put: unsupported content_hash_format", Result) )
    ;  put_refusal("invalid_request",
                   "put: entity.content_hash is not a well-formed system/hash", Result) ).

% §3.9 compare-and-swap. expected_hash absent → always admit. A 33-byte zero hash
% is create-only (admit iff the path is currently unbound). A non-zero hash must
% equal the current binding hash (else 409 hash_mismatch).
cas_ok(StoreId, Path, Params) :-
    ( ent_bytes(Params, "expected_hash", Expected)
    -> ( all_zero(Expected)
       -> \+ store_hash_at(StoreId, Path, _)
       ;  store_hash_at(StoreId, Path, CurHex),
          string_codes(Expected, EC), string_codes(ExpBytes, EC),
          bytes_hex(ExpBytes, ExpHexA), atom_string(ExpHexA, ExpHexS),
          atom_string(CurHexAtom, CurHex), atom_string(CurHexAtom, CurHexS),
          ExpHexS == CurHexS )
    ;  true ).

% §1.4 / §5.4 / CORE-TREE-PATH-FLEX-1: validate a caller-supplied resource target
% before canonicalize. Reject null byte, a leading slash whose first segment is
% NOT a peer_id, ./ ../ and interior empty segments (//). A single trailing "/" is
% the listing marker (allowed). Mirrors the OCaml/Ruby cohort path-flex predicate.
path_flex_ok("") :- !.                          % local-root listing marker
path_flex_ok("/") :- !.                          % local-root listing marker (absolute)
path_flex_ok(Target) :-
    string_codes(Target, TCodes),
    \+ memberchk(0, TCodes),                    % no null byte in any segment
    split_string(Target, "/", "", Segs0),
    ( Segs0 = ["" | BodyAbs]                      % absolute: leading "" then a peer_id
    -> BodyAbs = [First | _], is_peer_id(First), Body0 = BodyAbs
    ;  Body0 = Segs0 ),                           % relative
    % drop ONE trailing "" (the listing marker), then reject empties + . / ..
    ( append(Body, [""], Body0) -> true ; Body = Body0 ),
    forall(member(S, Body), ( S \== "", S \== ".", S \== ".." )).

% ── capability handler (§6.2) ──
handle_op("system/capability", "request", ctx(Peer, Env, Exec, CallerCap, _), Outcome) :- !,
    ( ent_bytes(Exec, "author", Author)
    -> % Bind Params to the (-) sentinel when absent rather than leaving it a fresh
       % variable: the §5.6 ceiling reads ttl_ms off it, and an unbound term would
       % UNIFY with whatever it was asked for instead of failing cleanly.
       ( ent_entity(Exec, "params", P0) -> Params = P0 ; Params = (-) ),
       ( Params \== (-), ent_field(Params, "grants", RG), is_list(RG)
       -> ReqGrants = RG ; ReqGrants = [] ),
       mint_bounded(Peer, Env, CallerCap, Params, ReqGrants, Author, (-), Outcome)
    ;  error_result("capability_denied", "", R), Outcome = outcome(403, R, []) ).

% delegate (§6.2 / v7.62 §9): mint a bounded child cap under an explicit parent.
% parent MUST be present and non-zero (else 400, before the same-peer gate so a
% malformed delegate is 400 not 501). delegate is same-peer-only in v1 (closeout
% F1): a remote author (author != local identity hash) → 501, not 403.
handle_op("system/capability", "delegate", ctx(Peer, Env, Exec, CallerCap, _), Outcome) :- !,
    peer_identity(Peer, Identity), identity_hash(Identity, LocalHash),
    ( ent_entity(Exec, "params", Params), ent_bytes(Params, "parent", ParentH), \+ all_zero(ParentH)
    -> ( ent_bytes(Exec, "author", Author)
       -> ( Author == LocalHash
          -> ( ent_field(Params, "grants", ReqGrants), is_list(ReqGrants) -> true ; ReqGrants = [] ),
             mint_bounded(Peer, Env, CallerCap, Params, ReqGrants, Author, ParentH, Outcome)
          ;  error_result("unsupported_operation", "delegate: same-peer-only in v1", R),
             Outcome = outcome(501, R, []) )
       ;  error_result("capability_denied", "", R), Outcome = outcome(403, R, []) )
    ;  error_result("unexpected_params", "delegate: parent required", R), Outcome = outcome(400, R, []) ).

handle_op("system/capability", "revoke", ctx(Peer, _, Exec, _, _), Outcome) :- !,
    peer_local_peer(Peer, Local), peer_store(Peer, StoreId),
    ( ent_entity(Exec, "params", Params), ent_bytes(Params, "token", TokenH), \+ all_zero(TokenH)
    -> now_ms(Now), string_codes(TokenH, TC),
       make_entity("system/capability/revocation",
                   map(["token"-bytes(TC), "revoked_at"-int(Now)]), Marker),
       bytes_hex(TokenH, HexA), atom_string(HexA, Hex),
       atomics_to_string(["/", Local, "/system/capability/revocations/", Hex], Path),
       store_bind(StoreId, Path, Marker),
       empty_params(EP), Outcome = outcome(200, EP, [])
    ;  error_result("unexpected_params", "revoke: missing token", R), Outcome = outcome(400, R, []) ).

handle_op("system/capability", "configure", ctx(Peer, _, Exec, _, _), Outcome) :- !,
    peer_local_peer(Peer, Local), peer_store(Peer, StoreId),
    ( ent_entity(Exec, "params", Params), ent_text(Params, "peer_pattern", PP)
    -> ( peer_pattern_ok(PP)
       -> atomics_to_string(["/", Local, "/system/capability/policy/", PP], Path),
          store_bind(StoreId, Path, Params),
          empty_params(EP), Outcome = outcome(200, EP, [])
       ;  error_result("invalid_peer_pattern", PP, R), Outcome = outcome(400, R, []) )
    ;  error_result("unexpected_params", "configure: missing peer_pattern", R), Outcome = outcome(400, R, []) ).

% §6.2 / F8: peer_pattern MUST be the literal "default", a full hex hash (66 hex
% chars incl. format byte), or a full Base58 peer_id. Partial prefixes are rejected.
peer_pattern_ok("default") :- !.
peer_pattern_ok(PP) :- is_full_hex_hash(PP), !.
peer_pattern_ok(PP) :- is_peer_id(PP).

is_full_hex_hash(PP) :-
    string_length(PP, 66),
    string_codes(PP, Cs),
    forall(member(C, Cs), ( (C >= 0'0, C =< 0'9) ; (C >= 0'a, C =< 0'f) )).

% ── handlers handler (§6.2 / §6.13(a) register live-hook) ──
handle_op("system/handler", "register", ctx(Peer, _, Exec, _, _), Outcome) :- !,
    handle_register(Peer, Exec, Outcome).
handle_op("system/handler", "unregister", ctx(Peer, _, Exec, _, _), Outcome) :- !,
    handle_unregister(Peer, Exec, Outcome).

% ── §7a conformance handlers (only reachable when bootstrapped under --validate) ──
handle_op("system/validate/echo", "echo", ctx(_, _, Exec, _, _), Outcome) :- !,
    ( ent_entity(Exec, "params", P) -> Outcome = outcome(200, P, [])
    ; error_result("invalid_params", "echo requires a params entity", R), Outcome = outcome(400, R, []) ).

% system/validate/dispatch-outbound (§7a / §6.13(b) / §6.11): originate exactly
% ONE outbound EXECUTE back to the caller over the SAME inbound connection (the
% reentry seam, ctx's Outbound), then return the downstream {status, result}. The
% reentry direction can only be authorized by the caller, who carries the cap it
% minted for this peer in-band (reentry_capability + its granter peer + its sig).
handle_op("system/validate/dispatch-outbound", "dispatch",
          ctx(Peer, _, Exec, _, Outbound), Outcome) :- !,
    ( ent_entity(Exec, "params", P),
      ent_text(P, "target", Target), ent_text(P, "operation", Op),
      ent_field(P, "value", Value),
      ent_entity(P, "reentry_capability", Cap),
      ent_entity(P, "reentry_granter", GranterPeer),
      ent_entity(P, "reentry_cap_signature", CapSig)
    -> ( dispatch_outbound(Peer, Outbound, Target, Op, Value, Cap, GranterPeer, CapSig, RespEnv)
       -> envelope_root(RespEnv, RRoot),
          ( ent_uint(RRoot, "status", St) -> true ; St = 0 ),
          ( ent_field(RRoot, "result", ResultV) -> true ; ResultV = map([]) ),
          make_entity("primitive/any", map(["status"-int(St), "result"-ResultV]), ResultE),
          Outcome = outcome(200, ResultE, [])
       ;  error_result("no_outbound_seam", "no live §6.11 reentry connection", R),
          Outcome = outcome(503, R, []) )
    ;  error_result("invalid_params", "dispatch-outbound requires value + reentry authority", R),
       Outcome = outcome(400, R, []) ).

% build, sign (as the local peer), and send an outbound EXECUTE through the §6.11
% reentry seam (Outbound = call(Outbound, ReqEnv, RespEnv)). The downstream cap is
% the one the caller minted for us; we author as ourselves under it.
dispatch_outbound(Peer, Outbound, Target, Op, Value, Cap, GranterPeer, CapSig, RespEnv) :-
    Outbound \== no_outbound,
    peer_identity(Peer, Identity),
    identity_hash(Identity, AuthorHash),
    identity_peer_entity(Identity, AuthorPeer),
    entity_hash(Cap, CapHash),
    % the §7a value IS the outbound params data — pass it through verbatim.
    make_entity("primitive/any", Value, InnerParams),
    resource_target([Target], Resource),   % NB: target rides as a handler-relative pattern
    out_request_id(ReqId),
    make_execute(ReqId, Target, Op, InnerParams,
                 [author=AuthorHash, capability=CapHash, resource=Resource], Exec),
    sign_entity(Identity, Exec, ExecSig),
    included_pairs([Cap, GranterPeer, AuthorPeer, CapSig, ExecSig], Included),
    envelope(Exec, Included, ReqEnv),
    call(Outbound, ReqEnv, RespEnv),
    RespEnv \== (-).

:- dynamic out_ctr/1.
:- ( catch(mutex_create(ec_peer_outctr), _, true) -> true ; true ).
out_request_id(ReqId) :-
    with_mutex(ec_peer_outctr,
        ( ( retract(out_ctr(N)) -> true ; N = 0 ), N1 is N + 1, assertz(out_ctr(N1)) )),
    format(string(ReqId), "out-~d", [N1]).

% ── the §6.6 DEFAULT ARM: unknown (handler, op) → 501 (the catch-all clause) ──
handle_op(_Pattern, Op, _Ctx, outcome(501, R, [])) :- error_result("unsupported_operation", Op, R).

% ── capability mint (§6.2 subset-bounded) ──
mint_bounded(Peer, CallerCap, ReqGrants, GranteeHash, Parent, Outcome) :-
    mint_bounded(Peer, (-), CallerCap, (-), ReqGrants, GranteeHash, Parent, Outcome).

mint_bounded(Peer, Env, CallerCap, Params, ReqGrants, GranteeHash, Parent, Outcome) :-
    peer_identity(Peer, Identity),
    peer_local_peer(Peer, Local),
    ( CallerCap \== (-),
      ( ent_field(CallerCap, "grants", ParentGrants), is_list(ParentGrants) -> true ; ParentGrants = [] ),
      forall(member(CG, ReqGrants),
             once(( member(PG, ParentGrants), grant_subset(Local, Local, Local, CG, PG) )))
    -> % §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at ONCE and
       % convert the duration term against that same instant.
       %
       % Note what this is NOT: an authorization decision. An over-long ttl_ms from a
       % bounded caller MINTS a clamped token and returns 200 -- "rejecting it is
       % non-conformant" (§5.6). The bound exists because `request` mints a ROOT token
       % (parent: null), so §5.6's parent-child attenuation never reaches it; without
       % this clamp, temporal attenuation is the one dimension a requester could
       % escape, and policy withdrawal would have no bounded latency.
       now_ms(Created),
       findall(T, mint_ceiling_term(Peer, Env, CallerCap, Params, Parent, Created, T), Terms),
       min_defined(Terms, Expires),
       mint_token_at(Identity, Created, GranteeHash, ReqGrants, Parent, Expires, Token, Sig),
       entity_hash(Token, TokenHash), string_codes(TokenHash, THC),
       make_entity("system/capability/grant", map(["token"-bytes(THC)]), GrantE),
       identity_peer_entity(Identity, PeerEntity),
       included_pairs([Token, PeerEntity, Sig], Included),
       Outcome = outcome(200, GrantE, Included)
    ;  error_result("scope_exceeds_authority", "", R), Outcome = outcome(403, R, []) ).

% One DEFINED term of the §5.6 MIN_DEFINED ceiling. Enumerated by findall, so a term
% that does not apply simply fails rather than contributing a sentinel.
mint_ceiling_term(Peer, Env, _CallerCap, _Params, Parent, _Created, T) :-   % absolute
    Parent \== (-), Env \== (-),
    peer_store(Peer, StoreId),
    cap_resolve(Env, StoreId, Parent, ParentTok),
    ent_uint(ParentTok, "expires_at", T).
mint_ceiling_term(_Peer, _Env, CallerCap, _Params, _Parent, _Created, T) :- % absolute
    CallerCap \== (-),
    ent_uint(CallerCap, "expires_at", T).
mint_ceiling_term(_Peer, _Env, _CallerCap, Params, _Parent, Created, T) :-  % duration
    Params \== (-),
    ent_uint(Params, "ttl_ms", Ttl),
    add_ttl(Created, Ttl, T).

% §6.2: user-installed handlers MUST NOT register at reserved system/* patterns.
is_reserved_system_pattern(Pattern) :-
    ( Pattern == "system" ; string_concat("system/", _, Pattern) ), !.

% ── register live-hook: write the five normative entities (§6.13(a)) ──
handle_register(Peer, Exec, Outcome) :-
    peer_local_peer(Peer, Local), peer_store(Peer, StoreId), peer_identity(Peer, Identity),
    ( exec_resource_target(Exec, Target), string_concat("system/handler/", Pattern, Target), Pattern \== ""
    -> ( is_reserved_system_pattern(Pattern)
       -> atomics_to_string(["§6.2: user-installed handlers MUST NOT register at system/* paths: ", Pattern], ForbiddenMsg),
          error_result("forbidden_pattern", ForbiddenMsg, R), Outcome = outcome(403, R, [])
       ;  ( ent_entity(Exec, "params", Req), entity_type(Req, "system/handler/register-request")
          -> ( ent_field(Req, "manifest", map(M)) -> true ; M = [] ),
             ( memberchk("name"-Name, M), string(Name) -> true ; Name = Pattern ),
             ( memberchk("operations"-Ops, M) -> true ; Ops = map([]) ),
             atomics_to_string(["/", Local, "/", Pattern], HandlerPath),
             atomics_to_string(["system/handler/", Pattern], InterfaceRel),
             make_entity("system/handler", map(["interface"-InterfaceRel]), HandlerE),
             store_bind(StoreId, HandlerPath, HandlerE),
             % self-issued signed handler grant + signature at §3.5 pointer.
             identity_hash(Identity, IdHash),
             mint_token(Identity, IdHash, [], GrantToken, GrantSig),
             atomics_to_string(["/", Local, "/system/capability/grants/", Pattern], GrantPath),
             store_bind(StoreId, GrantPath, GrantToken),
             entity_hash(GrantToken, GTH), bytes_hex(GTH, GTHHexA), atom_string(GTHHexA, GTHHex),
             atomics_to_string(["/", Local, "/system/signature/", GTHHex], SigPath),
             store_bind(StoreId, SigPath, GrantSig),
             % interface entity (discovery index).
             atomics_to_string(["/", Local, "/system/handler/", Pattern], IfacePath),
             make_entity("system/handler/interface",
                         map(["pattern"-Pattern, "name"-Name, "operations"-Ops]), IfaceE),
             store_bind(StoreId, IfacePath, IfaceE),
             make_entity("system/handler/register-result",
                         map(["pattern"-Pattern, "grant"-map([])]), ResultE),
             Outcome = outcome(200, ResultE, [])
          ;  error_result("unexpected_params", "register expects register-request", R), Outcome = outcome(400, R, []) )
       )
    ;  error_result("invalid_resource", "resource target MUST be system/handler/{pattern}", R), Outcome = outcome(400, R, []) ).

handle_unregister(Peer, Exec, Outcome) :-
    peer_local_peer(Peer, Local), peer_store(Peer, StoreId),
    ( exec_resource_target(Exec, Target), string_concat("system/handler/", Pattern, Target), Pattern \== ""
    -> atomics_to_string(["/", Local, "/", Pattern], HandlerPath),
       atomics_to_string(["/", Local, "/system/handler/", Pattern], IfacePath),
       atomics_to_string(["/", Local, "/system/capability/grants/", Pattern], GrantPath),
       % writer/unregister symmetry (§6.13(a)): remove EVERY entity register wrote —
       % the handler, the interface index, the self-issued grant token, AND its
       % detached §3.5 signature at /Local/system/signature/{grantTokenHash}.
       ( store_get_at(StoreId, GrantPath, GrantToken)
       -> entity_hash(GrantToken, GTH), bytes_hex(GTH, GTHHexA), atom_string(GTHHexA, GTHHex),
          atomics_to_string(["/", Local, "/system/signature/", GTHHex], SigPath),
          store_unbind(StoreId, SigPath)
       ;  true ),
       store_unbind(StoreId, HandlerPath),
       store_unbind(StoreId, IfacePath),
       store_unbind(StoreId, GrantPath),
       empty_params(EP), Outcome = outcome(200, EP, [])
    ;  error_result("invalid_resource", "unregister target MUST be system/handler/{pattern}", R), Outcome = outcome(400, R, []) ).

% ── tree listing build (§3.9) ──
target_is_listing(Target) :- ( Target == "" -> true ; sub_atom_suffix(Target, "/") ).
sub_atom_suffix(S, Suf) :- string_length(Suf, SL), string_length(S, L), L >= SL,
                           Start is L - SL, sub_string(S, Start, SL, 0, Suf).

build_listing(StoreId, Path, outcome(200, ListingE, [])) :-
    store_listing(StoreId, Path, Entries0),
    % CORE-TREE-DELETE-1 / §6.3: omit leaf entries bound to a system/deletion-marker
    % (a delete is a put of a deletion-marker; the listing must not show the path).
    include(visible_entry(StoreId), Entries0, Entries),
    findall(Seg-EntryV, ( member(entry(Seg, Hash, Deeper), Entries),
                          listing_entry_value(Hash, Deeper, EntryV) ), Pairs),
    length(Entries, Count),
    make_entity("system/tree/listing",
                map(["path"-Path, "entries"-map(Pairs), "count"-int(Count), "offset"-int(0)]),
                ListingE).

% an entry is visible unless it is a bound leaf whose entity is a deletion-marker.
visible_entry(_, entry(_, _, true)) :- !.            % has children → keep (prefix)
visible_entry(_, entry(_, (-), _)) :- !.             % no bound hash → keep
visible_entry(StoreId, entry(_, HashHex, false)) :-
    ( hex_to_bytes(HashHex, Codes), string_codes(H, Codes),
      store_get_by_hash(StoreId, H, E), entity_type(E, "system/deletion-marker")
    -> fail ; true ).
listing_entry_value(-, Deeper, EV) :- !,
    make_entity("system/tree/listing-entry", map(["has_children"-bool(Deeper)]), E),
    entity_to_cbor(E, EV).
listing_entry_value(HashHex, Deeper, EV) :-
    hex_to_bytes(HashHex, Codes),
    make_entity("system/tree/listing-entry",
                map(["has_children"-bool(Deeper), "hash"-bytes(Codes)]), E),
    entity_to_cbor(E, EV).

exec_resource_target(Exec, Target) :-
    ent_field(Exec, "resource", map(R)),
    memberchk("targets"-Tgs, R), Tgs = [Target|_], string(Target).

all_zero(ByteString) :- string_codes(ByteString, Cs), forall(member(C, Cs), C =:= 0).

hex_to_bytes(Hex, Codes) :- bytes_hex(Bytes, Hex), string_codes(Bytes, Codes).

included_pairs(Entities, Pairs) :-
    findall(H-E, ( member(E, Entities), entity_hash(E, H) ), Pairs).

% ── bootstrap (§6.9) ─────────────────────────────────────────────────────────────
% Each MUST handler declares its OPERATIONS map (§9.5): the oracle's
% handler_*_operations_match reads the interface entity's operations keys and
% checks the required set is present. Op spec value = {input_type?, output_type?}.
core_handler_spec("system/protocol/connect", "Connect",
                  ["hello"-op(-, -), "authenticate"-op(-, -)]).
core_handler_spec("system/tree", "Tree",
                  ["get"-op(-, -), "put"-op(-, -)]).
core_handler_spec("system/handler", "Handlers",
                  ["register"-op("system/handler/register-request", "system/handler/register-result"),
                   "unregister"-op("system/handler/unregister-request", -)]).
core_handler_spec("system/type", "Types",
                  ["validate"-op("system/type/validate-request", "system/type/validate-result")]).
core_handler_spec("system/capability", "Capability",
                  ["request"-op("system/capability/request", "system/capability/grant"),
                   "revoke"-op("system/capability/revoke-request", -),
                   "configure"-op("system/capability/policy-entry", -),
                   "delegate"-op("system/capability/delegate-request", "system/capability/grant")]).

% §7a conformance handlers (only bootstrapped under --validate).
conformance_handler_spec("system/validate/echo", "validate-echo",
                         ["echo"-op(-, -)]).
conformance_handler_spec("system/validate/dispatch-outbound", "validate-dispatch-outbound",
                         ["dispatch"-op(-, -)]).

bootstrap_handlers(PeerId, Identity, StoreId, CF) :-
    forall(core_handler_spec(Pattern, Name, Ops),
           bootstrap_handler_entities(PeerId, Identity, StoreId, Pattern, Name, Ops)),
    ( CF == true
    -> forall(conformance_handler_spec(Pattern, Name, Ops),
              bootstrap_handler_entities(PeerId, Identity, StoreId, Pattern, Name, Ops))
    ;  true ).

bootstrap_handler_entities(PeerId, Identity, StoreId, Pattern, Name, Ops) :-
    atomics_to_string(["/", PeerId, "/", Pattern], HandlerPath),
    atomics_to_string(["system/handler/", Pattern], InterfaceRel),
    make_entity("system/handler", map(["interface"-InterfaceRel]), HandlerE),
    store_bind(StoreId, HandlerPath, HandlerE),
    atomics_to_string(["/", PeerId, "/system/handler/", Pattern], IfacePath),
    operations_map(Ops, OpsMap),
    make_entity("system/handler/interface",
                map(["pattern"-Pattern, "name"-Name, "operations"-OpsMap]), IfaceE),
    store_bind(StoreId, IfacePath, IfaceE),
    identity_hash(Identity, IdHash),
    mint_token(Identity, IdHash, [], Token, _Sig),
    atomics_to_string(["/", PeerId, "/system/capability/grants/", Pattern], GrantPath),
    store_bind(StoreId, GrantPath, Token).

% operations: map of OpName → {input_type?, output_type?} (absent fields omitted).
operations_map(Ops, map(Pairs)) :-
    findall(Op-Spec, ( member(Op-op(In, Out), Ops), op_spec_map(In, Out, Spec) ), Pairs).
op_spec_map(In, Out, map(SPairs)) :-
    findall(K-V, ( member(K-Field, ["input_type"-In, "output_type"-Out]),
                   Field \== (-), V = Field ), SPairs).

% §6.9a Peer Authority Bootstrap (L0): self-owner cap at the hex policy path + its
% signature at §3.5, plus the default scope-template entry (discovery floor, or the
% degenerate open-grants wildcard under --debug-open-grants).
bootstrap_authority(PeerId, Identity, StoreId, OG) :-
    identity_hash(Identity, IdHash),
    owner_grants(PeerId, OwnerGrants),
    mint_token(Identity, IdHash, OwnerGrants, OwnerToken, OwnerSig),
    bytes_hex(IdHash, IdHexA), atom_string(IdHexA, IdHex),
    atomics_to_string(["/", PeerId, "/system/capability/policy/", IdHex], PolPath),
    store_bind(StoreId, PolPath, OwnerToken),
    entity_hash(OwnerToken, OTH), bytes_hex(OTH, OTHHexA), atom_string(OTHHexA, OTHHex),
    atomics_to_string(["/", PeerId, "/system/signature/", OTHHex], SigPath),
    store_bind(StoreId, SigPath, OwnerSig),
    ( OG == true -> open_grants_scope(DefaultGrants) ; discovery_floor(DefaultGrants) ),
    make_entity("system/capability/policy-entry",
                map(["peer_pattern"-"default", "grants"-DefaultGrants]), DefEntry),
    atomics_to_string(["/", PeerId, "/system/capability/policy/default"], DefPath),
    store_bind(StoreId, DefPath, DefEntry).

atomics_to_string(List, S) :- atomic_list_concat(List, A), atom_string(A, S).
