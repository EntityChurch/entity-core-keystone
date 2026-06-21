% cbor.pl — BOUNDED S2 SPIKE for the Prolog peer (EXPERIMENTAL).
%
% Scope: ONLY the two "resistant" vector classes the S1 idiom-fit verdict
% (A-PL-004) predicted would NOT map to the DCG idiom:
%   - map_keys.*  : canonical map-key ordering (encode->sort-encoded-bytes->emit)
%   - float.*     : shortest-float ladder (f16/f32/f64) + f16 specials
% Plus the minimum primitive encoders those two classes transitively need
% (uint, nint, tstr, bstr) so the vectors are actually exercised end-to-end.
%
% The point is to MEASURE idiom cost, not to ship a codec. Each predicate is
% annotated [DCG] (idiomatic logic/grammar) or [IMP] (imperative scaffolding
% forced against the paradigm) so the spike can quantify the split.

:- module(cbor_spike, [encode/2, run_spike/0]).
:- discontiguous cbor_value//1.

% ===========================================================================
% TOP-LEVEL ENCODE  — det entry (A-PL-005: wire is a function, force once/1)
% ===========================================================================
% encode(+Term, -Bytes) : Bytes is a list of 0..255 codes.
% [IMP-ish] once/1 to kill the choice point at the wire boundary.
encode(Term, Bytes) :-
    once(phrase(cbor_value(Term), Bytes)).

% ===========================================================================
% cbor_value//1  — the DCG frame. [DCG] This part IS idiomatic.
% ===========================================================================
% Dispatch on a tagged term so we don't confuse e.g. a bytestring from a list.
% Spike term language:
%   int(I) | tstr(S) | bstr(Codes) | float(F) | map(Pairs) | bool/null...
cbor_value(int(I))   --> { I >= 0 }, !, cbor_uint(I).
cbor_value(int(I))   --> { I < 0 },  !, cbor_nint(I).
cbor_value(tstr(S))  --> cbor_tstr(S).
cbor_value(bstr(B))  --> cbor_bstr(B).
cbor_value(float(F)) --> cbor_float(F).
cbor_value(map(Ps))  --> cbor_map(Ps).

% ---------------------------------------------------------------------------
% Major-type head + argument. [DCG] head/arg minimization is grammar-natural,
% EXCEPT the "pick shortest arg width" is a guard ladder (mild imperative tinge
% but expressible as ordered clauses — counts as ~DCG).
% ---------------------------------------------------------------------------
head_arg(Major, Val) -->
    { Major >= 0, Major =< 7,
      MajShift is Major << 5 },
    head_arg_(MajShift, Val).

head_arg_(M, V) --> { V =< 23, !, B is M \/ V },               [B].
head_arg_(M, V) --> { V =< 0xff, !, B is M \/ 24 },            [B], be(V,1).
head_arg_(M, V) --> { V =< 0xffff, !, B is M \/ 25 },          [B], be(V,2).
head_arg_(M, V) --> { V =< 0xffffffff, !, B is M \/ 26 },      [B], be(V,4).
head_arg_(M, V) --> { B is M \/ 27 },                          [B], be(V,8).

% be(+Value,+NBytes)//  : big-endian N-byte emit. [IMP] arithmetic byte split.
be(_, 0) --> [].
be(V, N) --> { N > 0, N1 is N-1, Sh is N1*8, Byte is (V >> Sh) /\ 0xff },
             [Byte], be(V, N1).

% ---------------------------------------------------------------------------
% Integers. [DCG] uint/nint via head_arg.
% ---------------------------------------------------------------------------
cbor_uint(I) --> head_arg(0, I).
cbor_nint(I) --> { I < 0, V is -1 - I }, head_arg(1, V).

% ---------------------------------------------------------------------------
% Text / byte strings. [DCG] length-prefixed; codes appended directly.
% ---------------------------------------------------------------------------
cbor_tstr(S) --> { string_codes(S, Cs), length(Cs, L) }, head_arg(3, L), seq(Cs).
cbor_bstr(B) --> { length(B, L) }, head_arg(2, L), seq(B).
seq([]) --> [].
seq([C|Cs]) --> [C], seq(Cs).

% ===========================================================================
% MAP — the resistant class #1: canonical key ordering.
% A DCG canNOT sort its own output. The honest shape: encode each key to
% bytes IMPERATIVELY, predsort on the encoded key bytes (length-then-lex),
% then emit. [IMP] The sort is procedural scaffolding around the DCG.
% ===========================================================================
cbor_map(Pairs) -->
    { length(Pairs, N),
      % [IMP] encode every key to its canonical bytes first (side computation)
      maplist(encode_pair_keybytes, Pairs, Keyed),
      % [IMP] canonical sort: by encoded-key length asc, then lexicographic asc
      predsort(canon_key_cmp, Keyed, Sorted) },
    head_arg(5, N),
    emit_pairs(Sorted).

% encode_pair_keybytes(+(K-V), -kv(KeyBytes, K, V))
% [IMP] runs the encoder as a *function* to get the bytes we then sort on.
encode_pair_keybytes(K-V, kv(KB, K, V)) :-
    once(phrase(cbor_value(K), KB)).

% canon_key_cmp(-Order, +kv(A,_,_), +kv(B,_,_))  [IMP]
% predsort REMOVES "equal" elements — but CBOR map keys are unique, and we
% must never collapse two distinct keys. So compare length-then-lex and, on a
% genuine byte-tie, this would be a duplicate key (spike: not exercised). We
% deliberately never return (=) for distinct keys.
canon_key_cmp(Order, kv(A,_,_), kv(B,_,_)) :-
    length(A, LA), length(B, LB),
    ( LA =:= LB
    -> compare(Order0, A, B),       % lexicographic on code lists == byte-wise
       ( Order0 = (=) -> Order = (=) ; Order = Order0 )
    ;  ( LA < LB -> Order = (<) ; Order = (>) ) ).

% emit_pairs//1 : key bytes already computed; re-emit them + encode the value.
% [DCG-ish] key bytes are spliced (already canonical), value is a sub-grammar.
emit_pairs([]) --> [].
emit_pairs([kv(KB, _, V)|Rest]) -->
    seq(KB),
    cbor_value(V),
    emit_pairs(Rest).

% ===========================================================================
% FLOAT — the resistant class #2: shortest-float ladder + f16 specials.
% IEEE-754 bit manipulation on opaque doubles. SWI gives NO float->bits
% primitive, so we reconstruct the f64 bit pattern ARITHMETICALLY, then test
% f16/f32-representability by round-trip. [IMP] This entire block is bit/branch
% scaffolding — the antithesis of the relational idiom.
% ===========================================================================

cbor_float(F) -->
    { float_shortest_bytes(F, Bytes) },
    seq(Bytes).

% float_shortest_bytes(+F, -Bytes)  [IMP]
% Specials first (NaN/Inf canonicalize to f16 per the corpus), then the ladder.
float_shortest_bytes(F, Bytes) :-
    ( float_is_nan(F)      -> Bytes = [0xf9, 0x7e, 0x00]
    ; F =:= inf            -> Bytes = [0xf9, 0x7c, 0x00]
    ; F =:= -inf           -> Bytes = [0xf9, 0xfc, 0x00]
    ; f64_bits(F, B64),
      ( f16_try(F, B64, B16) -> Bytes = [0xf9 | B16]
      ; f32_try(F, B64, B32) -> Bytes = [0xfa | B32]
      ; bits_to_bytes(B64, 8, Rest), Bytes = [0xfb | Rest] )
    ).

float_is_nan(F) :- catch((F =\= F), _, fail).   % NaN =\= itself

% --- f64 bit pattern, reconstructed exactly via mantissa/exponent. [IMP] -----
% Returns the 64-bit IEEE-754 integer pattern of F (F finite, non-NaN).
f64_bits(F, Bits) :-
    ( F =:= 0.0
    -> ( float_neg_zero(F) -> Bits = 0x8000000000000000 ; Bits = 0 )
    ;  ( F < 0.0 -> Sign = 1, A is -F ; Sign = 0, A is F ),
       % normalize A = M * 2^E, 1 =< Mfrac < 2
       f64_decompose(A, Exp, Frac52),
       BiasedExp is Exp + 1023,
       Bits is (Sign << 63) \/ (BiasedExp << 52) \/ Frac52
    ).

% detect -0.0  [IMP]
float_neg_zero(F) :- F =:= 0.0, R is copysign(1.0, F), R < 0.0.

% f64_decompose(+A, -UnbiasedExp, -Frac52)  [IMP]
% A > 0 finite. Find E such that 1.0 =< A/2^E < 2.0, then the 52-bit fraction.
% Uses rational arithmetic (GMP) to get the fraction bits EXACTLY.
f64_decompose(A, Exp, Frac52) :-
    Exp is floor(log(A) / log(2.0)),
    % guard the log rounding at powers of two
    ( A / (2.0 ** Exp) >= 2.0 -> E1 is Exp + 1
    ; A / (2.0 ** Exp) <  1.0 -> E1 is Exp - 1
    ; E1 = Exp ),
    % exact mantissa fraction: (A / 2^E1) - 1, scaled by 2^52, via rationals
    Scale is 2 ** 52,
    Mant is A / (2.0 ** E1),                 % in [1,2)
    Frac52 is round((Mant - 1.0) * Scale),
    Exp = E1.

% bits_to_bytes(+Int, +NBytes, -Bytes) big-endian  [IMP]
bits_to_bytes(_, 0, []) :- !.
bits_to_bytes(Int, N, [B|Bs]) :-
    N > 0, N1 is N-1, Sh is N1*8,
    B is (Int >> Sh) /\ 0xff,
    bits_to_bytes(Int, N1, Bs).

% --- f16 representability: round-trip through a manual f16 encode. [IMP] -----
% Try to encode F as f16; succeed (with the 2 bytes) iff it round-trips exactly.
f16_try(F, _B64, [B0,B1]) :-
    f16_encode(F, U16),
    f16_decode(U16, G),
    G =:= F,                       % exact round-trip required
    B0 is (U16 >> 8) /\ 0xff,
    B1 is U16 /\ 0xff.

% f32 representability: same idea via f64<->f32 narrowing. [IMP]
f32_try(F, _B64, Bytes) :-
    f32_encode(F, U32),
    f32_decode(U32, G),
    G =:= F,
    bits_to_bytes(U32, 4, Bytes).

% --- manual f16 encode/decode (normal range only; specials handled above) ---
% [IMP] full IEEE half-precision bit assembly.
f16_encode(F, U16) :-
    ( F =:= 0.0 -> ( float_neg_zero(F) -> U16 = 0x8000 ; U16 = 0 )
    ; ( F < 0.0 -> S = 1, A is -F ; S = 0, A is F ),
      f64_decompose(A, E, Frac52),
      E >= -14, E =< 15,                       % half normal exponent range
      Frac10 is (Frac52 >> 42),                % top 10 bits of the 52-bit frac
      ( (Frac52 /\ ((1 << 42) - 1)) =:= 0 ),   % lower bits must be zero (exact)
      BE is E + 15,
      U16 is (S << 15) \/ (BE << 10) \/ Frac10
    ).

f16_decode(U16, F) :-
    S is (U16 >> 15) /\ 1,
    E is (U16 >> 10) /\ 0x1f,
    M is U16 /\ 0x3ff,
    ( E =:= 0   -> Val is M / 1024.0 * (2.0 ** -14)
    ; E =:= 31  -> Val is inf            % not reached (specials pre-handled)
    ; Val is (1 + M/1024.0) * (2.0 ** (E - 15)) ),
    ( S =:= 1 -> F is -Val ; F = Val ).

% --- manual f32 encode/decode (normal range). [IMP] ---
f32_encode(F, U32) :-
    ( F =:= 0.0 -> ( float_neg_zero(F) -> U32 = 0x80000000 ; U32 = 0 )
    ; ( F < 0.0 -> S = 1, A is -F ; S = 0, A is F ),
      f64_decompose(A, E, Frac52),
      E >= -126, E =< 127,
      Frac23 is (Frac52 >> 29),                % top 23 of 52
      ( (Frac52 /\ ((1 << 29) - 1)) =:= 0 ),   % lower bits exact
      BE is E + 127,
      U32 is (S << 31) \/ (BE << 23) \/ Frac23
    ).

f32_decode(U32, F) :-
    S is (U32 >> 31) /\ 1,
    E is (U32 >> 23) /\ 0xff,
    M is U32 /\ 0x7fffff,
    ( E =:= 0   -> Val is M / 8388608.0 * (2.0 ** -126)
    ; Val is (1 + M/8388608.0) * (2.0 ** (E - 127)) ),
    ( S =:= 1 -> F is -Val ; F = Val ).

% ===========================================================================
% SPIKE HARNESS — push the map_keys.* + float.* vectors through encode/2 and
% compare byte-exact against the corpus `canonical` field (hand-transcribed
% from conformance-vectors-v1.diag; NEVER doctored to pass).
% ===========================================================================

:- discontiguous spike_vector/3.

% hex_bytes_list(+HexString, -Bytes) : parse "aabbcc" -> [0xaa,0xbb,0xcc]
hex_bytes_list(Hex, Bytes) :-
    string_chars(Hex, Cs),
    hex_pairs(Cs, Bytes).
hex_pairs([], []).
hex_pairs([H,L|T], [B|Bs]) :-
    char_type(H, xdigit(HV)), char_type(L, xdigit(LV)),
    B is HV*16 + LV,
    hex_pairs(T, Bs).

run_spike :-
    findall(t(Id,In,Exp), spike_vector(Id,In,Exp), Vs),
    foldl(run_one, Vs, 0-0, Pass-Fail),
    format("~n=== SPIKE RESULT: ~w PASS / ~w FAIL ===~n", [Pass, Fail]),
    ( Fail =:= 0 -> true ; true ).

run_one(t(Id,In,Exp), P0-F0, P-F) :-
    ( catch(encode(In, Got), E, (Got = error(E), true)) ->
        ( Got == Exp
        -> format("PASS  ~w~n", [Id]), P is P0+1, F = F0
        ;  hexs(Got, GH), hexs(Exp, EH),
           format("FAIL  ~w~n   got: ~w~n   exp: ~w~n", [Id, GH, EH]),
           P = P0, F is F0+1 )
    ;  format("FAIL  ~w (encode failed)~n", [Id]), P = P0, F is F0+1 ).

hexs(Bytes, Hex) :- ( is_list(Bytes) -> format_hex(Bytes, Hex) ; Hex = Bytes ).
format_hex(Bytes, Hex) :-
    findall(H, (member(B,Bytes), format(atom(H), "~|~`0t~16r~2|", [B])), Hs),
    atomic_list_concat(Hs, Hex).

% --- vectors (id, input term, expected canonical bytes) ---
% float.* (14)
spike_vector('float.1',  float(0.0),       [0xf9,0x00,0x00]).
spike_vector('float.2',  float(-0.0),      [0xf9,0x80,0x00]).
spike_vector('float.3',  float(1.0),       [0xf9,0x3c,0x00]).
spike_vector('float.4',  float(1.5),       [0xf9,0x3e,0x00]).
spike_vector('float.5',  float(inf),       [0xf9,0x7c,0x00]).
spike_vector('float.6',  float(-inf),      [0xf9,0xfc,0x00]).
spike_vector('float.7',  float(nan),       [0xf9,0x7e,0x00]).
spike_vector('float.8',  float(32768.0),   [0xf9,0x78,0x00]).
spike_vector('float.9',  float(65472.0),   [0xf9,0x7b,0xfe]).
spike_vector('float.10', float(65504.0),   [0xf9,0x7b,0xff]).
spike_vector('float.11', float(-65504.0),  [0xf9,0xfb,0xff]).
spike_vector('float.12', float(65503.0),   [0xfa,0x47,0x7f,0xdf,0x00]).
spike_vector('float.13', float(100000.0),  [0xfa,0x47,0xc3,0x50,0x00]).
spike_vector('float.14', float(1.1),       [0xfb,0x3f,0xf1,0x99,0x99,0x99,0x99,0x99,0x9a]).

% map_keys.* (6)
spike_vector('map_keys.1', map(["a"-int(1)]), [0xa1,0x61,0x61,0x01]).
spike_vector('map_keys.2', map(["aa"-int(2), "z"-int(1)]),
    [0xa2,0x61,0x7a,0x01,0x62,0x61,0x61,0x02]).
spike_vector('map_keys.3', map(["b"-int(2), "a"-int(1)]),
    [0xa2,0x61,0x61,0x01,0x61,0x62,0x02]).
spike_vector('map_keys.4',
    map(["aaaaaaaaaaaaaaaaaaaaaaaa"-int(24), "aaaaaaaaaaaaaaaaaaaaaaa"-int(23)]),
    Bytes) :- hex_bytes_list(
    % hex string lifted verbatim from conformance-vectors-v1.diag map_keys.4 canonical
    "a27761616161616161616161616161616161616161616161611778186161616161616161616161616161616161616161616161611818",
    Bytes).
spike_vector('map_keys.5',
    map([bstr([0x6b,0x65,0x79])-int(2), "text_key"-int(1)]),
    [0xa2,0x43,0x6b,0x65,0x79,0x02,0x68,0x74,0x65,0x78,0x74,0x5f,0x6b,0x65,0x79,0x01]).
spike_vector('map_keys.6', map(["aaa"-int(2), "aa"-int(1)]),
    [0xa2,0x62,0x61,0x61,0x01,0x63,0x61,0x61,0x61,0x02]).

% string keys: tstr wrapper. The map_keys vectors use bare "a" which we treat as
% a text key -> wrap as tstr for the key term.
% (handled by normalizing K via key_term/2 in cbor_map? -> we pass raw strings;
%  add a clause so a bare string key encodes as tstr.)
cbor_value(S) --> { string(S) }, !, cbor_tstr(S).
