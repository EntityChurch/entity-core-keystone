% smoke.pl — S3 two-peer loopback smoke test (the phase exit GATE, 11/11).
%
% Two Prolog peers talk over real loopback TCP through the full §6.5 dispatch
% chain: a RESPONDER peer listens; an INITIATOR peer (a second peer identity) dials
% it and drives the §4.1 forward handshake (hello → authenticate), then core ops:
%   Scenario 1 (default seed): handshake, 404 on unregistered path, authority-gated
%     tree get (200), capability request (200), 8-way request_id demux (N7/§6.11).
%   Scenario 2 (open-grants + --validate): register live-hook (200 not 501), emit
%     hook fires on register's tree writes, §7a echo (200), echo returns verbatim.
% Then teardown. Proving transport + handshake + register/dispatch/emit + capability
% gating + request_id demux end-to-end. Run in-container, --network=none, loopback.

:- module(smoke, [run_smoke/0, run_smoke_main/0]).

:- use_module('../prolog/ec_codec').
:- use_module('../prolog/ec_cbor').
:- use_module('../prolog/ec_entity').
:- use_module('../prolog/ec_identity').
:- use_module('../prolog/ec_store').
:- use_module('../prolog/ec_capability').
:- use_module('../prolog/ec_wire').
:- use_module('../prolog/ec_transport').
:- use_module('../prolog/ec_peer').
:- use_module('../prolog/ec_client').
:- use_module('../prolog/ec_types').
:- use_module(library(lists)).

:- dynamic result/2.
:- dynamic emit_count/1.   % thread-SHARED (global vars are thread-local in SWI; the
                          % emit consumer fires on the dispatch worker thread).

check(Name, Goal) :-
    slog(start(Name)),
    ( catch(Goal, E, (print_message(warning, E), fail)) -> OK = true ; OK = false ),
    assertz(result(Name, OK)),
    ( OK == true -> format("  [PASS] ~w~n", [Name]) ; format("  [FAIL] ~w~n", [Name]) ),
    flush_output,
    slog(done(Name, OK)).

% optional file-based progress log (stdout is block-buffered under a pipe).
slog(X) :- ( getenv('EC_SMOKELOG', F)
           -> setup_call_cleanup(open(F, append, S), (write(S, X), nl(S)), close(S))
           ; true ).

fixed_seed(Byte, Seed) :- length(Codes, 32), maplist(=(Byte), Codes), string_codes(Seed, Codes).

run_smoke_main :- ( run_smoke -> halt(0) ; halt(1) ).

run_smoke :-
    retractall(result(_,_)),
    scenario1,
    scenario2,
    scenario3,
    findall(N, result(N, false), Fails),
    findall(N, result(N, _), All),
    length(All, Total), length(Fails, NF), Pass is Total - NF,
    ( NF =:= 0 -> Verdict = 'PASS' ; Verdict = 'FAIL' ),
    format("~nTeardown clean.   ->   SMOKE: ~w (~d/~d)~n", [Verdict, Pass, Total]),
    NF =:= 0.

% ── Scenario 1: core ops, default-seed responder ─────────────────────────────────
scenario1 :-
    fixed_seed(0x11, RSeed), fixed_seed(0x22, ISeed),
    make_peer([seed=RSeed], Responder),
    make_identity(ISeed, Initiator),
    peer_local_peer(Responder, RPeerId),
    start_listener(serve_goal(Responder), 0, Sock-Port),
    format("Responder on 127.0.0.1:~d (peer ~w)~n", [Port, RPeerId]),
    setup_call_cleanup(
        dial("127.0.0.1", Port, CC),
        ( client_handshake(CC, Initiator, Session),
          session_remote_peer(Session, Remote),
          format("Handshake:~n", []),
          check("session established (capability minted)",
                session_capability(Session, _)),
          check("remote peer_id matches responder", Remote == RPeerId),

          format("Dispatch:~n", []),
          % 404 on an unregistered path
          atomics_to_string(["/", Remote, "/does/not/exist"], BadUri),
          empty_params(EP),
          check("unregistered path -> 404",
                ( client_execute_as(CC, Initiator, Session, BadUri, "noop", EP, R404),
                  response_status(R404, 404) )),
          % authority-gated tree get (200) over the discovery floor — probe a
          % handler-interface entity inside the granted system/handler/* scope.
          atomics_to_string(["/", Remote, "/system/tree"], TreeUri),
          resource_target(["system/handler/system/tree"], IfaceTarget),
          check("granted tree get -> 200",
                ( client_execute_as(CC, Initiator, Session, TreeUri, "get", EP, IfaceTarget, RGet),
                  response_status(RGet, 200) )),
          check("tree get returns a system/handler/interface entity",
                ( client_execute_as(CC, Initiator, Session, TreeUri, "get", EP, IfaceTarget, RGet2),
                  response_result(RGet2, Res), entity_type(Res, "system/handler/interface") )),
          % capability request (200)
          atomics_to_string(["/", Remote, "/system/capability"], CapUri),
          req_grant_params(ReqParams),
          check("capability request -> 200",
                ( client_execute_as(CC, Initiator, Session, CapUri, "request", ReqParams, RCap),
                  response_status(RCap, 200) )),
          % 8-way request_id demux (N7/§6.11) — concurrent threads, each correlates.
          format("Concurrency (request_id demux):~n", []),
          check("8 interleaved requests each correlated -> 8/8",
                demux8(CC, Initiator, Session, TreeUri, IfaceTarget))
        ),
        ( client_close(CC), stop_listener(Sock) )).

req_grant_params(Params) :-
    Grant = map(["handlers"-map(["include"-["system/tree"]]),
                 "resources"-map(["include"-["system/type/*"]]),
                 "operations"-map(["include"-["get"]])]),
    make_entity("system/capability/request", map(["grants"-[Grant]]), Params).

demux8(CC, Initiator, Session, TreeUri, IfaceTarget) :-
    numlist(1, 8, Ns),
    empty_params(EP),
    findall(Q-Id,
            ( member(Id, Ns),
              message_queue_create(Q),
              thread_create(demux_worker(CC, Initiator, Session, TreeUri, IfaceTarget, EP, Q), _, [detached(true)]) ),
            QPairs),
    findall(OK, ( member(Q-_, QPairs), thread_get_message(Q, OK, [timeout(15)]) ), Results),
    include(==(true), Results, Good),
    length(Good, 8).

demux_worker(CC, Initiator, Session, TreeUri, IfaceTarget, EP, Q) :-
    ( catch(( client_execute_as(CC, Initiator, Session, TreeUri, "get", EP, IfaceTarget, R),
              response_status(R, 200),
              response_result(R, Res), entity_type(Res, "system/handler/interface") ), _, fail)
    -> thread_send_message(Q, true)
    ;  thread_send_message(Q, false) ).

% ── Scenario 2: Core Extensibility Boundary (open-grants + --validate) ────────────
scenario2 :-
    fixed_seed(0x33, RSeed), fixed_seed(0x44, ISeed),
    make_peer([seed=RSeed, open_grants=true, conformance=true], Responder),
    make_identity(ISeed, Initiator),
    peer_store(Responder, StoreId),
    % register a tree-emit consumer post-bootstrap — the §6.13(c) live hook.
    retractall(emit_count(_)), assertz(emit_count(0)),
    register_tree_consumer(StoreId, on_tree_event),
    start_listener(serve_goal(Responder), 0, Sock-Port),
    setup_call_cleanup(
        dial("127.0.0.1", Port, CC),
        ( client_handshake(CC, Initiator, Session),
          session_remote_peer(Session, Remote),
          format("Extensibility (open-grants + --validate):~n", []),
          emit_count(Before),
          % register live-hook (§6.13(a))
          atomics_to_string(["/", Remote, "/system/handler"], HUri),
          register_request_params(RegParams),
          resource_target(["system/handler/demo"], RegTarget),
          check("handler register -> 200 (live, not 501)",
                ( client_execute_as(CC, Initiator, Session, HUri, "register", RegParams, RegTarget, RReg),
                  response_status(RReg, 200) )),
          check("emit hook fired on register's tree writes (§6.13(c))",
                ( emit_count(After), After > Before )),
          % §7a echo conformance handler (resolve→dispatch)
          atomics_to_string(["/", Remote, "/system/validate/echo"], EUri),
          make_entity("primitive/any", map(["ping"-int(42)]), Payload),
          check("§7a echo -> 200",
                ( client_execute_as(CC, Initiator, Session, EUri, "echo", Payload, REcho),
                  response_status(REcho, 200) )),
          check("§7a echo returns params verbatim",
                ( client_execute_as(CC, Initiator, Session, EUri, "echo", Payload, REcho2),
                  response_result(REcho2, Res), entity_type(Res, "primitive/any"),
                  ent_uint(Res, "ping", 42) ))
        ),
        ( client_close(CC), stop_listener(Sock) )).

% ── Scenario 3: §3.3's effective-target ladder + the operation/resource ordering ──
%
% THE RESPONDER RUNS WITH OPEN GRANTS, AND THAT IS THE MEASUREMENT SETUP RATHER THAN A
% CONVENIENCE. Under the §6.9a discovery floor the caller's grant names operations `get`
% only, so an unknown-operation request is refused 403 at the DISPATCH authorization
% boundary and never reaches the tree handler at all -- which is exactly the ordering
% question this is trying to ask, answered by the wrong gate. Opening the grants removes
% that gate and nothing else; it is also how run-s4.sh launches the peer the census
% measures.
%
% AND ON THIS SUBSTRATE THE WIRE IS THE ONLY INSTRUMENT THAT CAN ANSWER. A refusal
% written as throw/1 does NOT fall through to the clause below it: it unwinds to
% dispatch/4's catch, where chain_error_outcome/2 turns it into 500 internal_error, and
% the clause that LOOKS like the refusal is dead code. Reading the source clears the peer
% in exactly that case, so every refusal added by the 0.8.2.25 work is driven here and
% its STATUS AND CODE are asserted -- a 500 would fail these, loudly, which is the point.
%
% The narrow-capability half of §6.3 -- check_path_permission/5 denying a path the
% caller's OWN exclude removed from the dispatch check -- is deliberately NOT here: it
% needs a minted capability narrower than the floor, which is tools/arc-probe's family G,
% and the relation itself is unit-tested in spec0825.pl.
scenario3 :-
    fixed_seed(0x55, RSeed), fixed_seed(0x66, ISeed),
    make_peer([seed=RSeed, open_grants=true], Responder),
    make_identity(ISeed, Initiator),
    start_listener(serve_goal(Responder), 0, Sock-Port),
    setup_call_cleanup(
        dial("127.0.0.1", Port, CC),
        ( client_handshake(CC, Initiator, Session),
          session_remote_peer(Session, Remote),
          format("Section 3.3 effective-target ladder:~n", []),
          atomics_to_string(["/", Remote, "/system/tree"], TreeUri),

          % RESOLVE THE OPERATION FIRST, THE DIFFERENTIAL. An unknown operation is an
          % OPERATION fault (501) and a resource fault is 400; a handler that validates
          % the resource FIRST answers the wrong one for every unknown operation --
          % measured across the cohort as the same call answering `ambiguous_resource`
          % WITHOUT a resource and 501 WITH one, i.e. the fault the caller is told about
          % depended on a field with nothing to do with it. BOTH arms are driven, and so
          % is a KNOWN operation, because "501 to everything" satisfies the first two
          % vacuously.
          check("RULE G: unknown op, NO resource -> 501 unsupported_operation",
                ask(CC, Initiator, Session, TreeUri, "bogusop", (-), 501, "unsupported_operation")),
          check("RULE G: unknown op, WITH a resource -> the same 501",
                ( tgt(["system/type/system/peer"], [], TR0),
                  ask(CC, Initiator, Session, TreeUri, "bogusop", TR0, 501, "unsupported_operation") )),
          check("RULE G control: a known op with a resource still routes -> 200",
                ( tgt(["system/type/system/peer"], [], TR1),
                  ask_status(CC, Initiator, Session, TreeUri, "get", TR1, 200) )),

          % §3.3 arithmetic on the EFFECTIVE list. SELF-EXCLUDED: `resource` PRESENT,
          % every target carved out by the caller's own exclude. EXTENSION-TREE §2.2a
          % (v4.11) declares `get` resource-OPTIONAL and BROAD-RESULT, so this is 400
          % path_required and NOT the absent case's root listing -- serving the listing
          % would answer a request for one excluded path with a listing of the whole tree.
          check("get, every target self-excluded -> 400 path_required",
                ( tgt(["system/type/system/peer"], ["system/type/*"], TR2),
                  ask(CC, Initiator, Session, TreeUri, "get", TR2, 400, "path_required") )),
          % ABSENT resource is the OTHER empty and answers the root listing (§2.2a's
          % absent-case answer). The two arms together are the non-lossy projection N11
          % requires: a peer that collapsed them could not answer both.
          check("get, NO resource -> 200 root listing (the absent case)",
                ask_status(CC, Initiator, Session, TreeUri, "get", (-), 200)),
          check("get, two effective targets -> 400 ambiguous_resource",
                ( tgt(["system/type/system/peer", "system/type/system/hash"], [], TR3),
                  ask(CC, Initiator, Session, TreeUri, "get", TR3, 400, "ambiguous_resource") )),
          % THE SELECTION MUST (F84). Two targets, the FIRST excluded: the survivor is
          % targets[1] and it resolves. A handler that counted the effective list and then
          % indexed targets[0] would read `no/such/thing` -- 404 -- with the arithmetic
          % entirely correct. The 200 is what says the selection came from the effective
          % set.
          check("get, targets[0] excluded -> the SURVIVOR is read (200), not targets[0] (404)",
                ( tgt(["no/such/thing", "system/type/system/peer"], ["no/such/*"], TR4),
                  ask_status(CC, Initiator, Session, TreeUri, "get", TR4, 200) )),
          % A §5.4 PATTERN is not a concrete path (0.8.2.20). A trailing "/" is a LISTING
          % request and stays one -- only a "*" makes a target a pattern.
          check("get, a pattern target -> 400 malformed_resource",
                ( tgt(["system/type/*"], [], TR5),
                  ask(CC, Initiator, Session, TreeUri, "get", TR5, 400, "malformed_resource") )),

          % `put` is resource-REQUIRED (§2.2a), so §3.3's "an empty effective list IS the
          % absent case" applies unscoped and BOTH empties answer path_required. This
          % branch answered `ambiguous_resource` until 0.8.2.20 named that as the exact
          % inversion it forbids: *supply a resource* is not *disambiguate your request*,
          % and the code selects the remedy.
          check("put, NO resource -> 400 path_required (not ambiguous_resource)",
                ask(CC, Initiator, Session, TreeUri, "put", (-), 400, "path_required")),
          check("put, every target self-excluded -> 400 path_required",
                ( tgt(["a/b"], ["a/*"], TR6),
                  ask(CC, Initiator, Session, TreeUri, "put", TR6, 400, "path_required") ))
        ),
        ( client_close(CC), stop_listener(Sock) )).

tgt(Targets, [], map(["targets"-Targets])) :- !.
tgt(Targets, Excl, map(["targets"-Targets, "exclude"-Excl])).

% Drive one request and assert BOTH the status and the disposition CODE. The code is the
% point: 401 is nine different sites in this peer and `401 authentication_failed` is one,
% and a 500 from the generic catch would pass a status-only assertion on any 4xx case it
% happened to match. Asserting the code is what makes a thrown-refusal regression loud.
ask(CC, Identity, Session, Uri, Op, Resource, Status, Code) :-
    empty_params(EP),
    client_execute_as(CC, Identity, Session, Uri, Op, EP, Resource, Resp),
    response_status(Resp, Status),
    response_result(Resp, Result),
    ent_text(Result, "code", Code).

ask_status(CC, Identity, Session, Uri, Op, Resource, Status) :-
    empty_params(EP),
    client_execute_as(CC, Identity, Session, Uri, Op, EP, Resource, Resp),
    response_status(Resp, Status).

on_tree_event(_Event) :-
    retract(emit_count(N)), N1 is N+1, assertz(emit_count(N1)).

register_request_params(Params) :-
    Manifest = map(["name"-"demo", "operations"-map([])]),
    make_entity("system/handler/register-request", map(["manifest"-Manifest]), Params).

atomics_to_string(List, S) :- atomic_list_concat(List, A), atom_string(A, S).
