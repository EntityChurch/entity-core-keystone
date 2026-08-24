% ec_host.pl — the standalone peer HOST entrypoint (S4 conformance target).
%
% Boots ONE Prolog peer, binds a TCP listener (ec_transport, library(socket) +
% native threads), prints a `LISTENING 127.0.0.1:PORT peer PEERID` readiness line
% on stdout, then parks the main thread so the accept loop keeps serving. The Go
% `validate-peer` oracle dials it over loopback (run-s4.sh, --network=none).
%
% Flags (mirroring the Ruby/OCaml hosts):
%   --port N            TCP port to bind (default 7777)
%   --name NAME         load a persistent Ed25519 identity from the standard
%                       on-disk location ~/.entity/peers/NAME/keypair (base64 PEM
%                       seed — the Go entity-peer --name / peer-manager convention);
%                       a missing/unreadable file falls back to the fixed seed
%   --debug-open-grants degenerate open-grants wildcard policy (grant-gated
%                       categories need it) — sets the peer's open_grants=true
%   --validate          enable the §7a conformance handlers (system/validate/*)
%                       — sets the peer's conformance=true
%
% Identity seed: --name loads ~/.entity/peers/NAME/keypair; without it (or on a
% missing file) a fixed 0x11 × 32 seed is used (the cohort host default, which
% matches the keypair the harness provisions so the oracle's multisig accept-path
% probe can co-sign AS this peer). peer_id is seed-derived, stable.

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
:- use_module(library(readutil)).

host_main :-
    catch(host_run, E, (print_message(error, E), halt(1))).

host_run :-
    current_prolog_flag(argv, Argv),
    parse_args(Argv, opts(Port, Name, OpenGrants, Conformance)),
    % --name loads the persistent identity from ~/.entity/peers/NAME/keypair (the
    % Go entity-peer / peer-manager convention); absent/unreadable → fixed 0x11×32.
    ( load_seed_from_name(Name, Seed) -> true ; fixed_seed(0x11, Seed) ),
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

% ── §--name persistent identity: ~/.entity/peers/NAME/keypair ─────────────────
% The entity-core PEM keypair is base64(seed) between BEGIN/END ENTITY PRIVATE
% KEY lines (the Go entity-peer --name / peer-manager convention). Load it into a
% 32-code Seed string matching fixed_seed's shape. Fails (→ fixed-seed fallback)
% on a missing file or a non-32-byte body.
load_seed_from_name(Name, Seed) :-
    ( getenv('HOME', Home) -> true ; Home = "/root" ),
    format(string(Path), "~w/.entity/peers/~w/keypair", [Home, Name]),
    exists_file(Path),
    read_file_to_string(Path, Content, []),
    split_string(Content, "\n", "", Lines),
    exclude(is_pem_armor, Lines, BodyLines),
    atomic_list_concat(BodyLines, Joined),
    atom_codes(Joined, B64Codes),
    b64_decode(B64Codes, Bytes),
    length(Bytes, 32),
    string_codes(Seed, Bytes).

is_pem_armor(Line) :- sub_string(Line, 0, 5, _, "-----").

% Standard-alphabet base64 sextet value, or -1 for a non-alphabet char (which the
% decoder skips — so whitespace, newlines and '=' padding are ignored).
b64_char_val(C, V) :-
    ( C >= 0'A, C =< 0'Z -> V is C - 0'A
    ; C >= 0'a, C =< 0'z -> V is C - 0'a + 26
    ; C >= 0'0, C =< 0'9 -> V is C - 0'0 + 52
    ; C =:= 0'+          -> V = 62
    ; C =:= 0'/          -> V = 63
    ;                       V = -1
    ).

b64_decode(Chars, Bytes) :- b64_bits(Chars, 0, 0, Bytes).

b64_bits([], _, _, []).
b64_bits([C|Cs], Acc, Nbits, Bytes) :-
    b64_char_val(C, V),
    ( V < 0
    -> b64_bits(Cs, Acc, Nbits, Bytes)
    ;  Acc1 is Acc * 64 + V, Nbits1 is Nbits + 6,
       ( Nbits1 >= 8
       -> Nbits2 is Nbits1 - 8,
          Byte is (Acc1 >> Nbits2) /\ 0xFF,
          Acc2 is Acc1 /\ ((1 << Nbits2) - 1),
          Bytes = [Byte | Rest],
          b64_bits(Cs, Acc2, Nbits2, Rest)
       ;  b64_bits(Cs, Acc1, Nbits1, Bytes)
       )
    ).

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
