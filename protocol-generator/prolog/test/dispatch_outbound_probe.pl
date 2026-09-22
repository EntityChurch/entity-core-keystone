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

% ⚠ WHAT THIS PROBE DOES AND DOES NOT MEASURE, because its name oversells it.
% It exercises the outbound FRAME BUILDER only — that an EXECUTE is assembled, signed and
% handed to the §6.11 seam. The credential below is a FABRICATION (`granter: <3 bytes>`,
% no signature over anything) and it is accepted here because dispatch_outbound/8 does not
% verify credentials: the §1.4 PD-2 gate runs one layer up, in outbound_gated/9, and is
% measured by test/spec0831.pl. Reading a green line here as "the reentry authority works"
% is the same error three peers in this arc shipped — a smoke test passing the WRONG
% credential and nobody noticing because it was never the thing under test.
%
% NOT INVOKED BY ANY HARNESS. run-s3.sh gates type_registry, spec0825, spec0831 and smoke;
% this is a hand-run diagnostic, which is why its arity was free to rot.
main :-
    fixed_seed(0x11,Seed),
    make_peer([seed=Seed, open_grants=true, conformance=true], Peer),
    make_entity("system/capability/token", map(["granter"-bytes([1,2,3])]), Cap),
    make_entity("system/peer", map(["public_key"-bytes([1,2,3])]), Granter),
    make_entity("system/signature", map(["target"-bytes([9])]), CapSig),
    Resource = map(["targets"-["system/handler/system/validate/echo"]]),
    catch(
      ( ec_peer:dispatch_outbound(Peer, mock_outbound, "system/validate/echo", "echo",
                                  map(["ping"-int(7)]),
                                  cred(Cap, [Granter], [CapSig]), Resource, RespEnv)
        -> writeln(dispatch_outbound_ok),
           envelope_root(RespEnv, RR), ( ent_uint(RR,"status",St)->true;St=none ),
           format("status=~w~n",[St])
        ;  writeln(dispatch_outbound_FAILED) ),
      E, ( write(threw(E)), nl )).
