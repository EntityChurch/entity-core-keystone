:- use_module('../prolog/ec_codec').
:- use_module('../prolog/ec_entity').
:- use_module('../prolog/ec_identity').
:- use_module('../prolog/ec_wire').
:- use_module('../prolog/ec_peer').

fixed_seed(B,S):-length(C,32),maplist(=(B),C),string_codes(S,C).

% mock outbound seam: echo back a 200 response with the params as result.
mock_outbound(ReqEnv, RespEnv) :-
    envelope_root(ReqEnv, Exec),
    ( ent_text(Exec,"request_id",RID)->true;RID="x" ),
    ( ent_entity(Exec,"params",P)->true;P=map([]) ),
    make_response(RID, 200, P, Resp),
    envelope(Resp, [], RespEnv).

main :-
    fixed_seed(0x11,Seed),
    make_peer([seed=Seed, open_grants=true, conformance=true], Peer),
    make_entity("system/capability/token", map(["granter"-bytes([1,2,3])]), Cap),
    make_entity("system/peer", map(["public_key"-bytes([1,2,3])]), Granter),
    make_entity("system/signature", map(["target"-bytes([9])]), CapSig),
    catch(
      ( ec_peer:dispatch_outbound(Peer, mock_outbound, "system/validate/echo", "echo",
                                  map(["ping"-int(7)]), Cap, Granter, CapSig, RespEnv)
        -> writeln(dispatch_outbound_ok),
           envelope_root(RespEnv, RR), ( ent_uint(RR,"status",St)->true;St=none ),
           format("status=~w~n",[St])
        ;  writeln(dispatch_outbound_FAILED) ),
      E, ( write(threw(E)), nl )).
