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
            serve_goal/4             % +Peer, +Env, +Outbound, -RespEnv     (transport entry)
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
:- discontiguous handle_connect/5.

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
    identity_hash(Identity, GranterHash),
    string_codes(GranterHash, GHC), string_codes(GranteeHash, GeC),
    now_ms(Created),
    Base = ["granter"-bytes(GHC), "grantee"-bytes(GeC), "grants"-Grants, "created_at"-int(Created)],
    ( Parent == (-) -> Pairs = Base
    ; string_codes(Parent, PC), append(Base, ["parent"-bytes(PC)], Pairs) ),
    make_entity("system/capability/token", map(Pairs), Token),
    sign_entity(Identity, Token, Sig).

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
run_chain(Peer, Env, Exec, _Outbound, Outcome) :-
    ent_text(Exec, "uri", "system/protocol/connect"), !,
    ( ent_text(Exec, "operation", Op) -> true ; Op = "" ),
    handle_connect(Peer, Env, Exec, Op, Outcome).
run_chain(Peer, Env, Exec, Outbound, Outcome) :-
    peer_store(Peer, StoreId),
    peer_local_peer(Peer, Local),
    ingest_signatures(Peer, Env),
    verify_request(Local, StoreId, Env, Verdict),
    verdict_outcome(Verdict, Peer, Env, Exec, Outbound, Outcome).

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
    ( extract_peer(Local, Path, Local)
    -> true
    ;  throw(not_local) ),
    ( resolve_handler(Peer, Path, Pattern)
    -> permission_then_handle(Peer, Env, Exec, Pattern, Outbound, Outcome)
    ;  error_result("handler_not_found", Path, R), Outcome = outcome(404, R, []) ).
authorized_dispatch(_, _, _, _, outcome(404, R, [])) :- error_result("handler_not_found", "not local peer", R).

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
handle_connect(Peer, Env, Exec, "hello", Outcome) :- !,
    peer_local_peer(Peer, Local),
    % §4.5 negotiation: an EXPLICIT hash_formats/key_types list that is DISJOINT
    % from our floor (ecfv1-sha256 / ed25519) is rejected up front (400). An absent
    % list = no constraint (admit). NEGOTIATE-FORMAT-1 / NEGOTIATE-KEYTYPE-1.
    ( ent_entity(Exec, "params", P) -> true ; P = (-) ),
    ( P \== (-), ent_field(P, "hash_formats", HFs), is_list(HFs), \+ list_has_text(HFs, "ecfv1-sha256")
    -> error_result("incompatible_hash_format", "", R), Outcome = outcome(400, R, [])
    ;  P \== (-), ent_field(P, "key_types", KTs), is_list(KTs), \+ list_has_text(KTs, "ed25519")
    -> error_result("unsupported_key_type", "", R), Outcome = outcome(400, R, [])
    ;  random_nonce(Nonce), string_codes(Nonce, NC),
       conn_remember(Env, hello, Nonce),
       make_entity("system/protocol/connect/hello",
                   map(["peer_id"-Local, "nonce"-bytes(NC),
                        "protocols"-["entity-core/1.0"], "timestamp"-int(0),
                        "hash_formats"-["ecfv1-sha256"], "key_types"-["ed25519"]]),
                   HelloE),
       Outcome = outcome(200, HelloE, []) ).

list_has_text(L, T) :- member(X, L), ( X == T -> true ; ( string(X), string(T), X == T ) ), !.
handle_connect(Peer, Env, Exec, "authenticate", Outcome) :- !,
    handle_authenticate(Peer, Env, Exec, Outcome).
handle_connect(_, _, _, Op, outcome(501, R, [])) :- error_result("unsupported_operation", Op, R).

handle_authenticate(Peer, Env, Exec, Outcome) :-
    peer_local_peer(Peer, Local),
    peer_identity(Peer, Identity),
    peer_store(Peer, StoreId),
    ( ent_entity(Exec, "params", Auth), unsupported_key_type(Auth)
    -> error_result("unsupported_key_type", "", R), Outcome = outcome(400, R, [])
    ; ent_entity(Exec, "params", Auth)
    -> ( authenticate_ok(Env, Auth, Pub, Claimed)
       -> peer_entity_of_pubkey(Pub, RemotePeer),
          entity_hash(RemotePeer, RemoteHash),
          derive_seed_grants(Local, StoreId, RemotePeer, Claimed, Grants),
          mint_token(Identity, RemoteHash, Grants, Token, Sig),
          store_put_entity(StoreId, RemotePeer),
          entity_hash(Token, TokenHash), string_codes(TokenHash, THC),
          make_entity("system/capability/grant", map(["token"-bytes(THC)]), GrantE),
          identity_peer_entity(Identity, PeerEntity),
          included_pairs([Token, PeerEntity, Sig], Included),
          Outcome = outcome(200, GrantE, Included)
       ;  error_result("authentication_failed", "", R), Outcome = outcome(401, R, []) )
    ;  error_result("authentication_failed", "", R), Outcome = outcome(401, R, []) ).

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

% §4.6 three checks: nonce-echo, proof-of-possession, identity binding.
authenticate_ok(Env, Auth, Pub, Claimed) :-
    ent_bytes(Auth, "public_key", Pub), string_length(Pub, 32),
    ent_text(Auth, "peer_id", Claimed),
    ( ent_text(Auth, "key_type", KT) -> KT == "ed25519" ; true ),
    % nonce-echo: the echoed nonce must match the one we issued for this connection.
    ent_bytes(Auth, "nonce", Echoed),
    conn_issued_nonce(Env, Issued),
    Echoed == Issued,
    % proof of possession: signature over auth's content_hash verifies under Pub.
    entity_hash(Auth, AuthHash),
    find_sig_for(Env, AuthHash, Sig),
    ent_bytes(Sig, "signature", SigBytes),
    catch(ec_ed25519_verify(Pub, AuthHash, SigBytes), _, fail),
    % identity binding: claimed peer_id == peer_id_of(Pub).
    peer_id_of_pubkey(Pub, Derived), Derived == Claimed.

find_sig_for(Env, Target, Sig) :-
    envelope_included(Env, Inc), member(_-Sig, Inc),
    entity_type(Sig, "system/signature"),
    ent_bytes(Sig, "target", T), T == Target, !.

% per-connection nonce memory keyed by the issued nonce's first occurrence. The
% loopback uses one connection per handshake; we key on the initiator's hello
% peer_id present in the env's root params. Simplest correct scheme for the smoke:
% remember the last nonce we issued globally per process is unsafe under 8-way; so
% we key by the claimed initiator peer_id from the hello params.
conn_remember(Env, hello, Nonce) :-
    envelope_root(Env, Exec),
    ( ent_entity(Exec, "params", P), ent_text(P, "peer_id", InitId) -> true ; InitId = "anon" ),
    retractall(conn_state_f(InitId, _)),
    assertz(conn_state_f(InitId, conn(false, Nonce, InitId))).
conn_issued_nonce(Env, Nonce) :-
    envelope_root(Env, Exec),
    ent_entity(Exec, "params", P),
    ent_text(P, "peer_id", InitId),
    conn_state_f(InitId, conn(_, Nonce, _)).

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
          ( ent_entity(Exec, "params", Params), ent_entity(Params, "entity", Entity)
          -> ( cas_ok(StoreId, Path, Params)
             -> store_bind(StoreId, Path, Entity),
                entity_hash(Entity, H), string_codes(H, HC),
                make_entity("system/hash", map(["hash"-bytes(HC)]), HashE),
                Outcome = outcome(200, HashE, [])
             ;  error_result("hash_mismatch", Path, R), Outcome = outcome(409, R, []) )
          ;  error_result("unexpected_params", "put: missing entity", R), Outcome = outcome(400, R, []) ) )
    ;  error_result("ambiguous_resource", "tree: missing resource target", R), Outcome = outcome(400, R, []) ).

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
handle_op("system/capability", "request", ctx(Peer, _, Exec, CallerCap, _), Outcome) :- !,
    ( ent_bytes(Exec, "author", Author)
    -> ( ent_entity(Exec, "params", Params), ent_field(Params, "grants", ReqGrants), is_list(ReqGrants)
       -> true ; ReqGrants = [] ),
       mint_bounded(Peer, CallerCap, ReqGrants, Author, (-), Outcome)
    ;  error_result("capability_denied", "", R), Outcome = outcome(403, R, []) ).

% delegate (§6.2 / v7.62 §9): mint a bounded child cap under an explicit parent.
% parent MUST be present and non-zero (else 400, before the same-peer gate so a
% malformed delegate is 400 not 501). delegate is same-peer-only in v1 (closeout
% F1): a remote author (author != local identity hash) → 501, not 403.
handle_op("system/capability", "delegate", ctx(Peer, _, Exec, CallerCap, _), Outcome) :- !,
    peer_identity(Peer, Identity), identity_hash(Identity, LocalHash),
    ( ent_entity(Exec, "params", Params), ent_bytes(Params, "parent", ParentH), \+ all_zero(ParentH)
    -> ( ent_bytes(Exec, "author", Author)
       -> ( Author == LocalHash
          -> ( ent_field(Params, "grants", ReqGrants), is_list(ReqGrants) -> true ; ReqGrants = [] ),
             mint_bounded(Peer, CallerCap, ReqGrants, Author, ParentH, Outcome)
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
    peer_identity(Peer, Identity),
    peer_local_peer(Peer, Local),
    ( CallerCap \== (-),
      ( ent_field(CallerCap, "grants", ParentGrants), is_list(ParentGrants) -> true ; ParentGrants = [] ),
      forall(member(CG, ReqGrants),
             once(( member(PG, ParentGrants), grant_subset(Local, Local, Local, CG, PG) )))
    -> mint_token(Identity, GranteeHash, ReqGrants, Parent, Token, Sig),
       entity_hash(Token, TokenHash), string_codes(TokenHash, THC),
       make_entity("system/capability/grant", map(["token"-bytes(THC)]), GrantE),
       identity_peer_entity(Identity, PeerEntity),
       included_pairs([Token, PeerEntity, Sig], Included),
       Outcome = outcome(200, GrantE, Included)
    ;  error_result("scope_exceeds_authority", "", R), Outcome = outcome(403, R, []) ).

% ── register live-hook: write the five normative entities (§6.13(a)) ──
handle_register(Peer, Exec, Outcome) :-
    peer_local_peer(Peer, Local), peer_store(Peer, StoreId), peer_identity(Peer, Identity),
    ( exec_resource_target(Exec, Target), string_concat("system/handler/", Pattern, Target), Pattern \== ""
    -> ( ent_entity(Exec, "params", Req), entity_type(Req, "system/handler/register-request")
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
