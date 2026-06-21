% cbor_fixture.pl — minimal CBOR reader, HARNESS-ONLY (S2 conformance corpus nav).
%
% SCOPE: this is NOT the peer's codec. The peer's codec is the C-ABI (ec_codec.pl).
% This reader exists only to NAVIGATE the conformance fixture
% (conformance-vectors-v1.cbor), which is itself a CBOR array of vector-maps. To
% drive a vector through the C-ABI we must extract, per vector: the `id`/`kind`
% text, the `canonical` byte-string, and the `input` sub-value — both as a
% structured term (for content_hash/peer_id/signature field access) AND as its
% RAW encoded byte span (for the Class-A decode→re-encode driver, which feeds the
% input bytes to ec_encode_bare_value).
%
% It is deliberately a plain recursive parser over a code list (not the peer's
% paradigm work): a meta-layer harness tool. The fixture is canonical CBOR, so we
% need only the subset of major types the corpus uses (uint/nint/bstr/tstr/array/
% map/float16-32-64/simple), and we capture raw spans by difference-list length.

:- module(cbor_fixture,
          [ read_fixture/2,        % +Path, -Vectors (list of vec(Id,Kind,InputTerm,InputRawBytes,CanonBytes))
            cbor_parse_value/4     % helper: parse one value off a code list (with raw span)
          ]).

:- use_module(library(readutil)).
:- use_module('../prolog/ec_codec', [string_byte_codes/2]).

% read_fixture(+Path, -Vectors)
% Vectors = list of vec(IdAtom, KindAtom, InputTerm, InputRawBytes, CanonBytes).
% InputTerm is a structured term (see value grammar below); InputRawBytes is the
% input value's raw CBOR byte-string (a SWI string of codes 0..255); CanonBytes is
% the `canonical` field's byte-string contents.
read_fixture(Path, Vectors) :-
    read_file_to_codes(Path, Codes, [encoding(octet)]),
    once(cbor_parse_value(Codes, Rest, Top, _Raw)),
    ( Rest == [] -> true ; true ),   % trailing tolerance (none expected)
    Top = array(Items),
    maplist(vec_of_map, Items, Vectors).

vec_of_map(map(Pairs), vec(Id, Kind, Input, InputRaw, Canon)) :-
    map_get(Pairs, "id", text(IdS)),       atom_string(Id, IdS),
    map_get(Pairs, "kind", text(KindS)),   atom_string(Kind, KindS),
    % `input` is absent on decode_reject vectors (id/kind/canonical/description
    % only) — those drive off `canonical` alone, so input defaults to none.
    ( map_get_raw(Pairs, "input", Input0, InputRaw0)
    -> Input = Input0, InputRaw = InputRaw0
    ;  Input = none, InputRaw = ""
    ),
    map_get(Pairs, "canonical", bytes(Canon)).

% map_get(+Pairs, +KeyString, -ValueTerm): find the value for a text key.
map_get([text(K)-V-_Raw|_], K, V) :- !.
map_get([_|T], K, V) :- map_get(T, K, V).

% map_get_raw(+Pairs, +KeyString, -ValueTerm, -RawBytes).
map_get_raw([text(K)-V-Raw|_], K, V, Raw) :- !.
map_get_raw([_|T], K, V, Raw) :- map_get_raw(T, K, V, Raw).

% ─────────────────────────────────────────────────────────────────────────────
% Value grammar. cbor_parse_value(+Codes, -Rest, -Term, -RawBytes):
%   Term  — structured value (uint(N)|nint(N)|bytes(Str)|text(Str)|array(L)|
%           map(Pairs)|float(F)|bool(B)|null|undefined)
%   RawBytes — the SWI string (codes 0..255) of the exact bytes this value spans.
% Pairs for a map are KeyTerm-ValTerm-ValRaw triples (we keep each value's raw span
% so input sub-values can be re-fed to the C-ABI).
% ─────────────────────────────────────────────────────────────────────────────

cbor_parse_value(Codes, Rest, Term, RawBytes) :-
    cbor_value(Codes, Rest, Term),
    raw_span(Codes, Rest, RawBytes).

raw_span(Codes, Rest, RawBytes) :-
    length(Codes, LC), length(Rest, LR), N is LC - LR,
    length(Span, N), append(Span, Rest, Codes),
    string_byte_codes(RawBytes, Span).

cbor_value([B|T], Rest, Term) :-
    Major is B >> 5,
    Minor is B /\ 0x1f,
    cbor_by_major(Major, Minor, T, Rest, Term).

% major 0: unsigned int
cbor_by_major(0, Minor, T, Rest, uint(N)) :- arg_value(Minor, T, Rest, N).
% major 1: negative int  (-1 - n)
cbor_by_major(1, Minor, T, Rest, nint(V)) :- arg_value(Minor, T, Rest, N), V is -1 - N.
% major 2: byte string
cbor_by_major(2, Minor, T, Rest, bytes(Str)) :-
    arg_value(Minor, T, T1, Len),
    take(Len, T1, Codes, Rest),
    string_byte_codes(Str, Codes).
% major 3: text string
cbor_by_major(3, Minor, T, Rest, text(Str)) :-
    arg_value(Minor, T, T1, Len),
    take(Len, T1, Codes, Rest),
    string_codes(Str0, Codes), Str = Str0.
% major 4: array
cbor_by_major(4, Minor, T, Rest, array(Items)) :-
    arg_value(Minor, T, T1, N),
    parse_n_values(N, T1, Rest, Items).
% major 5: map
cbor_by_major(5, Minor, T, Rest, map(Pairs)) :-
    arg_value(Minor, T, T1, N),
    parse_n_pairs(N, T1, Rest, Pairs).
% major 7: floats / simple
cbor_by_major(7, 20, T, T, bool(false)).
cbor_by_major(7, 21, T, T, bool(true)).
cbor_by_major(7, 22, T, T, null).
cbor_by_major(7, 23, T, T, undefined).
cbor_by_major(7, 25, T, Rest, float(F)) :- take(2, T, Bs, Rest), half_to_float(Bs, F).
cbor_by_major(7, 26, T, Rest, float(F)) :- take(4, T, Bs, Rest), single_to_float(Bs, F).
cbor_by_major(7, 27, T, Rest, float(F)) :- take(8, T, Bs, Rest), double_to_float(Bs, F).

% arg_value(+Minor, +Codes, -Rest, -Value): decode the major-type argument.
arg_value(Minor, Codes, Codes, Minor) :- Minor =< 23, !.
arg_value(24, [B|T], T, B) :- !.
arg_value(25, [B1,B0|T], T, V) :- !, V is B1<<8 \/ B0.
arg_value(26, [B3,B2,B1,B0|T], T, V) :- !, V is B3<<24 \/ B2<<16 \/ B1<<8 \/ B0.
arg_value(27, [C7,C6,C5,C4,C3,C2,C1,C0|T], T, V) :- !,
    V is C7<<56 \/ C6<<48 \/ C5<<40 \/ C4<<32 \/ C3<<24 \/ C2<<16 \/ C1<<8 \/ C0.

take(0, L, [], L) :- !.
take(N, [H|T], [H|R], Rest) :- N > 0, N1 is N-1, take(N1, T, R, Rest).

parse_n_values(0, L, L, []) :- !.
parse_n_values(N, L, Rest, [V|Vs]) :- N > 0,
    cbor_value(L, L1, V), N1 is N-1, parse_n_values(N1, L1, Rest, Vs).

% Each map pair carries the VALUE's raw byte span (KeyTerm-ValTerm-ValRaw).
parse_n_pairs(0, L, L, []) :- !.
parse_n_pairs(N, L, Rest, [K-V-VRaw|Ps]) :- N > 0,
    cbor_value(L, L1, K),
    cbor_parse_value(L1, L2, V, VRaw),
    N1 is N-1, parse_n_pairs(N1, L2, Rest, Ps).

% ── IEEE-754 decode (fixture floats → SWI doubles) ──────────────────────────
% HARNESS-ONLY decode (we never re-encode floats; the C-ABI owns shortest-float).
half_to_float([B1,B0], F) :-
    Bits is B1<<8 \/ B0,
    Sign is (Bits >> 15) /\ 1,
    Exp  is (Bits >> 10) /\ 0x1f,
    Frac is Bits /\ 0x3ff,
    ( Exp =:= 0
    -> ( Frac =:= 0 -> M = 0.0 ; M is Frac / 1024.0 * (2.0 ** (-14)) ), F0 = M
    ;  Exp =:= 0x1f
    -> ( Frac =:= 0 -> F0 is inf ; F0 is nan )
    ;  F0 is (1.0 + Frac/1024.0) * (2.0 ** (Exp - 15))
    ),
    ( Sign =:= 1, float(F0), F0 =:= F0 -> F is -F0 ; F = F0 ).

single_to_float([B3,B2,B1,B0], F) :-
    Bits is B3<<24 \/ B2<<16 \/ B1<<8 \/ B0,
    ieee_bits_to_float(Bits, 8, 23, F).
double_to_float([C7,C6,C5,C4,C3,C2,C1,C0], F) :-
    Bits is C7<<56 \/ C6<<48 \/ C5<<40 \/ C4<<32 \/ C3<<24 \/ C2<<16 \/ C1<<8 \/ C0,
    ieee_bits_to_float(Bits, 11, 52, F).

ieee_bits_to_float(Bits, EBits, FBits, F) :-
    TotalBits is EBits + FBits + 1,
    Sign is (Bits >> (TotalBits - 1)) /\ 1,
    Exp  is (Bits >> FBits) /\ ((1 << EBits) - 1),
    Frac is Bits /\ ((1 << FBits) - 1),
    Bias is (1 << (EBits - 1)) - 1,
    MaxExp is (1 << EBits) - 1,
    ( Exp =:= 0
    -> F0 is Frac / (2.0 ** FBits) * (2.0 ** (1 - Bias))
    ;  Exp =:= MaxExp
    -> ( Frac =:= 0 -> F0 is inf ; F0 is nan )
    ;  F0 is (1.0 + Frac/(2.0 ** FBits)) * (2.0 ** (Exp - Bias))
    ),
    ( Sign =:= 1 -> F is -F0 ; F = F0 ).
