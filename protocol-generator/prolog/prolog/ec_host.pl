% ec_host.pl — the standalone peer HOST entrypoint (S4 conformance target).
%
% Boots ONE Prolog peer, binds a TCP listener (ec_transport, library(socket) +
% native threads), prints a `LISTENING 127.0.0.1:PORT peer PEERID` readiness line
% on stdout, then parks the main thread so the accept loop keeps serving. The Go
% `validate-peer` oracle dials it over loopback (run-s4.sh, --network=none).
%
% Flags (mirroring the Ruby/OCaml hosts):
%   --port N            TCP port to bind (default 7777)
%   --name NAME         peer identity name (informational; default "conformance")
%   --debug-open-grants degenerate open-grants wildcard policy (grant-gated
%                       categories need it) — sets the peer's open_grants=true
%   --validate          enable the §7a conformance handlers (system/validate/*)
%                       — sets the peer's conformance=true
%
% Identity seed: fixed 0x11 × 32 (the cohort host default; matches the
% ~/.entity/peers/NAME/keypair the harness provisions so the oracle's multisig
% accept-path probe can co-sign AS this peer). peer_id is seed-derived, stable.

:- module(ec_host, [host_main/0]).

:- use_module(ec_codec).
:- use_module(ec_cbor).
:- use_module(ec_entity).
:- use_module(ec_identity).
:- use_module(ec_store).
:- use_module(ec_capability).
:- use_module(ec_wire).
:- use_module(ec_transport).
:- use_module(ec_peer).
:- use_module(ec_types).
:- use_module(library(lists)).

host_main :-
    catch(host_run, E, (print_message(error, E), halt(1))).

host_run :-
    current_prolog_flag(argv, Argv),
    parse_args(Argv, opts(Port, _Name, OpenGrants, Conformance)),
    fixed_seed(0x11, Seed),
    make_peer([seed=Seed, open_grants=OpenGrants, conformance=Conformance], Peer),
    peer_local_peer(Peer, PeerId),
    peer_store(Peer, StoreId),
    % register a no-op §6.13(c) tree-emit consumer so register/put live-hook
    % emits have a consumer present (the bus runs with zero consumers fine, but a
    % present consumer exercises the emit path the way the smoke does).
    register_tree_consumer(StoreId, host_on_tree_event),
    start_listener(serve_goal(Peer), Port, _Sock-BoundPort),
    format("LISTENING 127.0.0.1:~d peer ~w~n", [BoundPort, PeerId]),
    flush_output,
    % park forever — the accept loop + per-connection threads do the work; the
    % harness tears the whole container down (no graceful shutdown needed).
    message_queue_create(Park),
    thread_get_message(Park, _Never).

host_on_tree_event(_Event).

fixed_seed(Byte, Seed) :-
    length(Codes, 32), maplist(=(Byte), Codes), string_codes(Seed, Codes).

% ── argv parsing ────────────────────────────────────────────────────────────
parse_args(Argv, Opts) :-
    parse_args_(Argv, opts(7777, "conformance", false, false), Opts).

parse_args_([], Acc, Acc).
parse_args_(['--port', V | T], opts(_, N, O, C), Out) :- !,
    ( atom_number(V, P) -> true ; throw(error(host(bad_port, V), _)) ),
    parse_args_(T, opts(P, N, O, C), Out).
parse_args_(['--name', V | T], opts(P, _, O, C), Out) :- !,
    atom_string(V, N), parse_args_(T, opts(P, N, O, C), Out).
parse_args_(['--debug-open-grants' | T], opts(P, N, _, C), Out) :- !,
    parse_args_(T, opts(P, N, true, C), Out).
parse_args_(['--validate' | T], opts(P, N, O, _), Out) :- !,
    parse_args_(T, opts(P, N, O, true), Out).
parse_args_([_ | T], Acc, Out) :- parse_args_(T, Acc, Out).   % ignore unknown
