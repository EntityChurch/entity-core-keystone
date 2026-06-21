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

on_tree_event(_Event) :-
    retract(emit_count(N)), N1 is N+1, assertz(emit_count(N1)).

register_request_params(Params) :-
    Manifest = map(["name"-"demo", "operations"-map([])]),
    make_entity("system/handler/register-request", map(["manifest"-Manifest]), Params).

atomics_to_string(List, S) :- atomic_list_concat(List, A), atom_string(A, S).
