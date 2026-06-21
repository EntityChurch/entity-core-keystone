% type_registry.pl — the §9.5 type-registry byte-diff (peer-side dual of the S2
% codec corpus). Renders all 53 core types (§9.5) from the in-code model
% (ec_types:core_type_model/2) via make_entity, and diffs each content_hash digest
% against the canonical type-registry-vectors-v1.diag (cross-impl Go-rendered).
% Proves render-from-model is byte-identical to the oracle's TypeDefinition
% entities — the S3 GATE companion to the loopback (53/53).
%
% Each .diag line carries:  "name": "X", ... "content_hash": "ecf-sha256:<64hex>"
% We extract name -> 64-hex digest and compare to OUR entity-hash digest (the
% 32-byte SHA-256 after the 1-byte 0x00 format prefix).

:- module(type_registry, [run_type_registry/1, run_type_registry_main/0]).

:- use_module(library(lists)).
:- use_module(library(readutil)).
:- use_module('../prolog/ec_codec').
:- use_module('../prolog/ec_cbor').
:- use_module('../prolog/ec_entity').
:- use_module('../prolog/ec_types').

% run_type_registry_main/0 — entry for swipl -g; expects the diag path as the
% first script arg (after --).
run_type_registry_main :-
    current_prolog_flag(argv, Argv),
    ( Argv = [DiagPath|_] -> true ; DiagPath = 'protocol-generator/shared/test-vectors/v0.8.0/type-registry-vectors-v1.diag' ),
    ( run_type_registry(DiagPath) -> halt(0) ; halt(1) ).

run_type_registry(DiagPath) :-
    read_diag_digests(DiagPath, Expected),
    core_type_names(Names),
    foldl(check_type(Expected), Names, 0-0, Pass-Fail),
    Total is Pass + Fail,
    format("type-registry: ~d/~d byte-identical~n", [Pass, Total]),
    Fail =:= 0.

check_type(Expected, Name, P0-F0, P-F) :-
    core_type_model(Name, Data),
    make_entity("system/type", Data, E),
    entity_hash(E, Hash33),                 % 0x00 ‖ 32-byte digest
    string_codes(Hash33, [_Fmt|DigestCodes]),
    string_codes(DigestStr, DigestCodes),
    bytes_hex(DigestStr, GotHexAtom),
    atom_string(GotHexAtom, GotHex),
    ( memberchk(Name-Exp, Expected)
    -> ( Exp == GotHex
       -> P is P0+1, F = F0
       ;  format("FAIL ~w~n  expected ~w~n  got      ~w~n", [Name, Exp, GotHex]),
          P = P0, F is F0+1 )
    ;  format("FAIL ~w — not found in vectors~n", [Name]), P = P0, F is F0+1 ).

% ── .diag parse: name -> 64-hex digest ────────────────────────────────────────
read_diag_digests(Path, Pairs) :-
    read_file_to_string(Path, Str, []),
    split_string(Str, "\n", "", Lines),
    foldl(scan_line, Lines, [], Pairs).

scan_line(Line, Acc, Acc1) :-
    ( field_after(Line, "name", Name),
      field_after(Line, "content_hash", CH)
    -> ( split_string(CH, ":", "", Parts), last(Parts, Digest)
       -> true
       ;  Digest = CH ),
       ( memberchk(Name-_, Acc) -> Acc1 = Acc ; Acc1 = [Name-Digest|Acc] )
    ;  Acc1 = Acc ).

% field_after(+Line, +Key, -Value): the string inside the quotes after  "Key": "
% Split on the needle, then take everything up to the next quote in the tail.
field_after(Line, Key, Value) :-
    atomic_list_concat(['"', Key, '": "'], NeedleA),
    atom_string(NeedleA, Needle),
    sub_string(Line, _, _, AfterLen, Needle), !,
    sub_string(Line, _, AfterLen, 0, Rest),       % tail after the needle
    sub_string(Rest, ValEnd, _, _, "\""), !,      % first quote closes the value
    sub_string(Rest, 0, ValEnd, _, Value).
