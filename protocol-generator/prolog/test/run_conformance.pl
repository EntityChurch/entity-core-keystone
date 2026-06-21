% run_conformance.pl — S2-FFI wire-conformance harness for the Prolog peer.
%
% Loads the normative ECF corpus (conformance-vectors-v1.cbor — 69 vectors:
% 64 encode_equal + 5 decode_reject) and drives EVERY vector through the C-ABI
% codec (ec_codec.pl over libentitycore_codec), checking byte-identity
% (encode_equal) or rejection (decode_reject). The fixture carries its own
% cross-blessed `canonical` bytes (Go × Rust × Python 3-way lock), so this is
% self-contained — no running Go oracle needed at S2 (the OCaml/C harness shape).
%
% Dispatch mirrors the C-ABI conformance_harness.c run_vector():
%   decode_reject       → ec_decode_entity_ok(Canon) MUST fail
%   content_hash        → ec_content_hash_prefixed(Type, ECF(data), format_code)
%   peer_id             → CBOR-text-encode(ec_peerid_format(kt,ht,digest))
%   signature           → ec_ed25519_sign(seed, ECF(entity))
%   Class A + nested/envelope/length/.. → ec_encode_bare_value(InputRaw)
%
% A-PL-005: every codec call is det (once/1 inside ec_codec). The harness adds NO
% backtracking of its own across the wire boundary.

:- module(run_conformance, [run_conformance_tests/0, main/0]).

:- use_module('../prolog/ec_codec').
:- use_module(cbor_fixture).
:- use_module(library(lists)).
:- use_module(library(apply)).

default_corpus('../../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor').

main :- run_conformance_tests.

run_conformance_tests :-
    ( current_prolog_flag(argv, [PathArg|_]), PathArg \== []
    -> Path = PathArg
    ;  default_corpus(Rel), absolute_corpus(Rel, Path)
    ),
    format("# entity-core-protocol-prolog — S2-FFI wire conformance~n"),
    ec_abi_version(ABI), ec_impl_info(Impl),
    format("# C-ABI ~w / ~w~n", [ABI, Impl]),
    format("# corpus: ~w~n~n", [Path]),
    read_fixture(Path, Vectors),
    length(Vectors, NVec),
    run_all(Vectors, 0-0, Pass-Fail, [], CatPairs),
    Total is Pass + Fail,
    format("~n── by category ──~n"),
    report_cats(CatPairs),
    format("~nTOTAL: ~w passed, ~w failed (of ~w; corpus carried ~w vectors)~n",
           [Pass, Fail, Total, NVec]),
    ( Fail =:= 0
    -> format("# RESULT: PASS (~w/~w)~n", [Pass, Total])
    ;  format("# RESULT: FAIL (~w/~w)~n", [Pass, Total])
    ),
    ( Fail =:= 0 -> halt(0) ; halt(1) ).

absolute_corpus(Rel, Abs) :-
    prolog_load_context(directory, Dir),
    atomic_list_concat([Dir, '/', Rel], Path0),
    absolute_file_name(Path0, Abs).

run_all([], Acc, Acc, Cats, Cats).
run_all([V|Vs], P0-F0, Pn-Fn, Cats0, Catsn) :-
    V = vec(Id, Kind, _, _, _),
    category_of(Id, Cat),
    ( run_vector(V) -> Res = pass ; Res = fail ),
    ( Res == pass
    -> P1 is P0+1, F1 = F0
    ;  P1 = P0, F1 is F0+1,
       format("FAIL ~w~t~20| [~w]~n", [Id, Kind])
    ),
    bump_cat(Cats0, Cat, Res, Cats1),
    run_all(Vs, P1-F1, Pn-Fn, Cats1, Catsn).

category_of(Id, Cat) :-
    atom_string(Id, S),
    ( sub_string(S, Before, _, _, ".")
    -> sub_string(S, 0, Before, _, CatS)
    ;  CatS = S
    ),
    atom_string(Cat, CatS).

bump_cat(Cats0, Cat, Res, Cats1) :-
    ( select(Cat-P-F, Cats0, Rest)
    -> ( Res == pass -> P1 is P+1, F1 = F ; P1 = P, F1 is F+1 ),
       Cats1 = [Cat-P1-F1|Rest]
    ;  ( Res == pass -> Cats1 = [Cat-1-0|Cats0] ; Cats1 = [Cat-0-1|Cats0] )
    ).

report_cats(Cats) :-
    sort(Cats, Sorted),
    forall(member(Cat-P-F, Sorted),
           ( T is P+F, format("  ~w~t~16|~w/~w~n", [Cat, P, T]) )).

% ── per-vector drivers ──────────────────────────────────────────────────────

run_vector(vec(_Id, decode_reject, _Input, _Raw, Canon)) :- !,
    % MUST reject: ec_decode_entity_ok succeeding is a FAILURE of the vector.
    \+ ec_decode_entity_ok(Canon).

run_vector(vec(Id, encode_equal, Input, InputRaw, Canon)) :-
    category_of(Id, Cat),
    encode_vector(Cat, Input, InputRaw, Produced),
    bytes_equal(Produced, Canon).

% content_hash: input = map{type, data, [format_code]}. Produce
% leb128(format_code) ‖ DIGEST(ECF({data,type})). Default format_code 0.
encode_vector(content_hash, Input, _Raw, Produced) :- !,
    map_field(Input, "type", text(TypeS)),
    map_field_raw(Input, "data", DataRaw),
    ( map_field(Input, "format_code", uint(FC)) -> true ; FC = 0 ),
    type_bytes(TypeS, TypeBytes),
    ec_content_hash_prefixed(TypeBytes, DataRaw, FC, Produced).

% peer_id: input = map{key_type, hash_type, digest}. Produce the CBOR text
% encoding of the base58 peer-id string (canonical is a tstr of the peer-id).
encode_vector(peer_id, Input, _Raw, Produced) :- !,
    map_field(Input, "key_type", uint(KT)),
    map_field(Input, "hash_type", uint(HT)),
    map_field(Input, "digest", bytes(Digest)),
    ec_peerid_format(KT, HT, Digest, B58),
    % CBOR-encode the peer-id text via the bare encoder (text major-3).
    cbor_text_encode(B58, Produced).

% signature: input = map{seed(32B), entity{type,data}}. Produce
% ed25519_sign(seed, ECF(entity)) — 64 raw signature bytes.
encode_vector(signature, Input, _Raw, Produced) :- !,
    map_field(Input, "seed", bytes(Seed)),
    map_field(Input, "entity", EntityTerm),
    map_field(EntityTerm, "type", text(TypeS)),
    map_field_raw(EntityTerm, "data", DataRaw),
    type_bytes(TypeS, TypeBytes),
    ec_encode_ecf(TypeBytes, DataRaw, Ecf),
    ec_ed25519_sign(Seed, Ecf, Produced).

% Class A + nested/envelope/length/map_keys/primitive/int/float: decode the input
% value and re-encode through the bare canonical encoder. The input's RAW byte
% span (as it sits in the fixture) is fed to ec_encode_bare_value, which decodes
% then re-emits canonically — the meaningful encoder exercise (minimization,
% map-key ordering) regardless of how the fixture stored the input.
encode_vector(_Cat, _Input, InputRaw, Produced) :-
    ec_encode_bare_value(InputRaw, Produced).

% ── small helpers ───────────────────────────────────────────────────────────

% type field is a text — its raw bytes are the UTF-8 (here ASCII) octets.
type_bytes(TypeS, Bytes) :- string_byte_codes_text(TypeS, Bytes).
string_byte_codes_text(S, Bytes) :- string_codes(S, Codes), string_byte_codes(Bytes, Codes).

% Encode a string as a CBOR text value (major 3) via the bare encoder: build the
% tstr bytes directly (head + utf8 body) and run through ec_encode_bare_value for
% canonical normalization. Simpler: hand-build the tstr head since it is canonical.
cbor_text_encode(Str, Bytes) :-
    string_codes(Str, Codes),
    length(Codes, Len),
    tstr_head(Len, Head),
    append(Head, Codes, AllCodes),
    string_byte_codes(Bytes, AllCodes).

tstr_head(Len, [H]) :- Len =< 23, !, H is 0x60 \/ Len.
tstr_head(Len, [0x78, Len]) :- Len =< 0xff, !.
tstr_head(Len, [0x79, B1, B0]) :- Len =< 0xffff, !, B1 is Len>>8, B0 is Len /\ 0xff.

% map_field(+MapTerm, +KeyString, -ValueTerm)
map_field(map(Pairs), Key, Value) :- map_field_(Pairs, Key, Value).
map_field_([text(K)-V-_Raw|_], K, V) :- !.
map_field_([_|T], K, V) :- map_field_(T, K, V).

% map_field_raw(+MapTerm, +KeyString, -RawBytes)
map_field_raw(map(Pairs), Key, Raw) :- map_field_raw_(Pairs, Key, Raw).
map_field_raw_([text(K)-_V-Raw|_], K, Raw) :- !.
map_field_raw_([_|T], K, Raw) :- map_field_raw_(T, K, Raw).

bytes_equal(A, B) :-
    string_byte_codes(A, CA), string_byte_codes(B, CB), CA == CB.
