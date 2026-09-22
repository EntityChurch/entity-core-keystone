% ec_wire.pl — Wire framing (§1.6) + the message builders (§3.2 EXECUTE,
% §3.3 EXECUTE_RESPONSE). Frame := [4-byte BE length][CBOR envelope payload].
%
% THE "C WITH :-" PART (expected, per the handoff): read-exactly-N length framing
% over a binary stream is irreducibly imperative — there is no relational reading
% of a TCP byte stream. read_frame/2 + write_frame/2 are procedural by nature; the
% predicate arrows are punctuation, not logic. Noted as a finding (A-PL-014).

:- module(ec_wire,
          [ read_frame/2,            % +Stream, -PayloadBytes (byte-string)
            read_frame_result/2,     % +Stream, -frame(Payload) | closed | refuse(S,Code,Msg)
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
    read_frame_result(Stream, R),
    ( R = frame(Payload) -> true
    ; R = refuse(_, _, _) -> throw(error(ec_wire(frame_refused(R)), _))
    ; throw(error(ec_wire(transport_closed), _)) ).

% READ ONE FRAME AND CLASSIFY WHAT WENT WRONG (§4.11, 0.8.2.25).
%
%   frame(Payload)        a complete frame
%   closed                a clean EOF AT A FRAME BOUNDARY -- an ordinary hangup, owed
%                         NOTHING
%   refuse(S, Code, Msg)  a §4.11 pre-admission REFUSAL, owed a coded EXECUTE_RESPONSE
%
% THE DISCRIMINATOR BETWEEN A HANGUP AND A TRUNCATION IS WHERE THE STREAM ENDED, and
% this predicate is the only place that knows. A clean EOF before any byte of the length
% prefix is an ordinary close; a PARTIAL prefix, or a prefix declaring n bytes followed by
% fewer, is a frame that never completed -- §4.11's framing arm names that input outright.
% Getting it wrong in the other direction answers 400 to every peer that simply hangs up,
% which is why read_exact_partial/4 reports how many bytes DID arrive rather than throwing
% one term for both.
%
% §4.10(a)'s mood was raised SHOULD -> MUST at 0.8.2.25 (N14): the over-size condition is
% detected AT THE PREFIX with the connection intact and nothing spent, so the permissive
% mood had nothing to license. A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches
% the decoder and is refused there as bytes that never become an Envelope.
read_frame_result(Stream, Result) :-
    read_exact_partial(Stream, 4, Hdr, Got),
    (   Got =:= 0
    ->  Result = closed
    ;   Got < 4
    ->  Result = refuse(400, "invalid_request", "frame did not decode into an envelope")
    ;   string_codes(Hdr, [B0,B1,B2,B3]),
        Len is (B0 << 24) \/ (B1 << 16) \/ (B2 << 8) \/ B3,
        max_frame(Max),
        (   Len > Max
        ->  Result = refuse(413, "payload_too_large",
                            "inbound frame exceeds the configured maximum size")
        ;   read_exact_partial(Stream, Len, Payload, BodyGot),
            (   BodyGot =:= Len
            ->  Result = frame(Payload)
            ;   Result = refuse(400, "invalid_request",
                                "frame did not decode into an envelope") ) ) ).

% read UP TO N bytes, reporting how many arrived. Never throws on EOF -- the caller is
% the only place that can tell an ordinary close from a truncation.
read_exact_partial(_, 0, "", 0) :- !.
read_exact_partial(Stream, N, Bytes, Got) :-
    read_string(Stream, N, Chunk),
    string_length(Chunk, ChunkLen),
    (   ChunkLen =:= N
    ->  Bytes = Chunk, Got = N
    ;   ChunkLen =:= 0
    ->  Bytes = "", Got = 0
    ;   Rem is N - ChunkLen,
        read_exact_partial(Stream, Rem, Rest, RestGot),
        string_concat(Chunk, Rest, Bytes),
        Got is ChunkLen + RestGot ).


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
