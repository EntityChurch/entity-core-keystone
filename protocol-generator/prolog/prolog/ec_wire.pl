% ec_wire.pl — Wire framing (§1.6) + the message builders (§3.2 EXECUTE,
% §3.3 EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR envelope payload].
%
% THE "C WITH :-" PART (expected, per the handoff): read-exactly-N length framing
% over a binary stream is irreducibly imperative — there is no relational reading
% of a TCP byte stream. read_frame/2 + write_frame/2 are procedural by nature; the
% predicate arrows are punctuation, not logic. Noted as a finding (A-PL-014).

:- module(ec_wire,
          [ read_frame/2,            % +Stream, -PayloadBytes (byte-string)
            write_frame/2,           % +Stream, +PayloadBytes
            make_execute/5,          % +ReqId,+Uri,+Op,+ParamsEntity,-ExecEntity
            make_execute/6,          % +ReqId,+Uri,+Op,+ParamsEntity,+Opts,-ExecEntity
            make_response/4,         % +ReqId,+Status,+ResultEntity,-RespEntity
            error_result/3,          % +Code,+Message,-ErrorEntity
            empty_params/1,          % -PrimitiveAnyEntity
            resource_target/2        % +Targets(list of strings), -ResourceMap
          ]).

:- use_module(ec_entity).
:- use_module(library(lists)).

max_frame(16777216).   % §1.6 SHOULD bound — 16 MiB.

% ── framed binary I/O ───────────────────────────────────────────────────────

read_frame(Stream, Payload) :-
    read_exact(Stream, 4, Hdr),
    string_codes(Hdr, [B0,B1,B2,B3]),
    Len is (B0 << 24) \/ (B1 << 16) \/ (B2 << 8) \/ B3,
    max_frame(Max),
    ( Len < 0 ; Len > Max -> throw(error(ec_wire(frame_too_large(Len)), _)) ; true ),
    read_exact(Stream, Len, Payload).

% read EXACTLY N bytes (or throw on EOF). The stream is binary (octet codes).
read_exact(_, 0, "") :- !.
read_exact(Stream, N, Bytes) :-
    read_string(Stream, N, Got),
    string_length(Got, GotLen),
    ( GotLen =:= N -> Bytes = Got
    ; GotLen =:= 0 -> throw(error(ec_wire(transport_closed), _))
    ; Rem is N - GotLen, read_exact(Stream, Rem, Rest), string_concat(Got, Rest, Bytes) ).

write_frame(Stream, Payload) :-
    string_length(Payload, Len),
    B0 is (Len >> 24) /\ 0xff, B1 is (Len >> 16) /\ 0xff,
    B2 is (Len >> 8) /\ 0xff, B3 is Len /\ 0xff,
    string_codes(Hdr, [B0,B1,B2,B3]),
    write(Stream, Hdr),
    write(Stream, Payload),
    flush_output(Stream).

% ── EXECUTE builder (§3.2) ──────────────────────────────────────────────────
make_execute(ReqId, Uri, Op, Params, Exec) :- make_execute(ReqId, Uri, Op, Params, [], Exec).

make_execute(ReqId, Uri, Op, Params, Opts, Exec) :-
    entity_to_cbor(Params, ParamsV),
    Base = ["request_id"-ReqId, "uri"-Uri, "operation"-Op, "params"-ParamsV],
    opt_bytes(Opts, author, "author", A),
    opt_bytes(Opts, capability, "capability", C),
    opt_resource(Opts, R),
    append([Base, A, C, R], Pairs),
    make_entity("system/protocol/execute", map(Pairs), Exec).

opt_bytes(Opts, Key, Field, [Field-bytes(Codes)]) :-
    memberchk(Key=Val, Opts), Val \== (-), !, string_codes(Val, Codes).
opt_bytes(_,_,_,[]).

opt_resource(Opts, ["resource"-R]) :- memberchk(resource=R, Opts), R \== (-), !.
opt_resource(_, []).

% ── EXECUTE_RESPONSE builder (§3.3) ─────────────────────────────────────────
make_response(ReqId, Status, Result, Resp) :-
    entity_to_cbor(Result, ResultV),
    make_entity("system/protocol/execute/response",
                map(["request_id"-ReqId, "status"-int(Status), "result"-ResultV]),
                Resp).

% ── error result + empty params ──────────────────────────────────────────────
error_result(Code, "", E) :- !,
    make_entity("system/protocol/error", map(["code"-Code]), E).
error_result(Code, Message, E) :-
    make_entity("system/protocol/error", map(["code"-Code, "message"-Message]), E).

empty_params(E) :- make_entity("primitive/any", map([]), E).

resource_target(Targets, map(["targets"-Targets])).
