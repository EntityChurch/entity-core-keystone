% dispatch_probe.pl — in-process (no TCP) probe of the §6.5 dispatch chain, to
% isolate dispatch-logic bugs from transport. Builds the handshake envelopes by
% hand and calls dispatch/4 directly.
:- module(dispatch_probe, [probe/0, probe_main/0]).
:- use_module('../prolog/ec_codec').
:- use_module('../prolog/ec_cbor').
:- use_module('../prolog/ec_entity').
:- use_module('../prolog/ec_identity').
:- use_module('../prolog/ec_store').
:- use_module('../prolog/ec_capability').
:- use_module('../prolog/ec_wire').
:- use_module('../prolog/ec_peer').
:- use_module('../prolog/ec_client').
:- use_module(library(lists)).

probe_main :- ( probe -> halt(0) ; halt(1) ).

no_outbound(_, _) :- fail.

fixed_seed(B, S) :- length(C, 32), maplist(=(B), C), string_codes(S, C).

probe :-
    fixed_seed(0x11, RSeed), fixed_seed(0x22, ISeed),
    make_peer([seed=RSeed], Responder),
    make_identity(ISeed, Initiator),
    peer_local_peer(Responder, RPeerId),
    identity_peer_id(Initiator, IPeerId),
    identity_public_key(Initiator, IPub),
    format("responder=~w~ninitiator=~w~n", [RPeerId, IPeerId]),

    % ── hello ──
    make_entity("system/protocol/connect/hello",
                map(["peer_id"-IPeerId, "nonce"-bytes([1,2,3]),
                     "protocols"-["entity-core/1.0"], "timestamp"-int(0),
                     "hash_formats"-["ecfv1-sha256"], "key_types"-["ed25519"]]),
                Hello),
    format("hello built~n", []), flush_output,
    make_execute("r1", "system/protocol/connect", "hello", Hello, Exec1),
    format("exec built~n", []), flush_output,
    envelope(Exec1, [], Env1),
    format("env built~n", []), flush_output,
    ( dispatch(Responder, Env1, no_outbound, Resp1)
    -> ( Resp1 == (-) -> format("hello Resp is (-)~n"), fail ; true ),
       response_status(Resp1, S1), format("hello -> ~w~n", [S1]),
       ( S1 =:= 200 -> true ; format("HELLO FAILED~n"), fail )
    ;  format("hello dispatch threw/failed~n"), fail ),
    response_result(Resp1, RemoteHello),
    ent_bytes(RemoteHello, "nonce", RNonce), string_codes(RNonce, RNC),

    % ── authenticate ──
    string_codes(IPub, PubC),
    make_entity("system/protocol/connect/authenticate",
                map(["peer_id"-IPeerId, "public_key"-bytes(PubC),
                     "key_type"-"ed25519", "nonce"-bytes(RNC)]),
                Auth),
    sign_entity(Initiator, Auth, AuthSig),
    make_execute("r2", "system/protocol/connect", "authenticate", Auth, Exec2),
    identity_peer_entity(Initiator, IPeerEntity),
    findall(H-E, (member(E,[IPeerEntity,AuthSig]), entity_hash(E,H)), Inc2),
    envelope(Exec2, Inc2, Env2),
    ( dispatch(Responder, Env2, no_outbound, Resp2)
    -> response_status(Resp2, S2), format("authenticate -> ~w~n", [S2]),
       ( S2 =:= 200 -> true ; print_result(Resp2), fail )
    ;  format("authenticate dispatch threw/failed~n"), fail ),
    format("HANDSHAKE OK~n"),
    ( catch(envelope_to_bytes(Resp2, B2), EB, (format("ser threw ~w~n",[EB]),fail))
    -> string_length(B2, BL), format("serialize ok ~w bytes~n", [BL])
    ;  format("serialize FAILED~n") ).

print_result(Resp) :-
    ( response_result(Resp, R), ent_text(R, "code", C) -> format("  code=~w~n", [C]) ; true ).
