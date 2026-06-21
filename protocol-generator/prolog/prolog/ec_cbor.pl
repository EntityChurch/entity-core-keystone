% ec_cbor.pl — canonical CBOR codec for the PEER DATA-VALUE layer (S3).
%
% WHY THIS EXISTS (the FFI seam, A-PL-013): the C-ABI ec_encode_ecf(Type, Data)
% treats `Data` as OPAQUE PRE-ENCODED bytes (ev_preencoded) — it canonicalizes
% only the outer {data,type} entity map, NOT the nested data value. So the peer
% MUST hand the data value to the C-ABI *already in canonical CBOR*. This module
% is that data-value codec: it turns the peer's value-term language into canonical
% ECF bytes (then ec_encode_ecf wraps + ec_content_hash digests them), and decodes
% a data byte-span back into value-terms so the relational core can read fields.
%
% The wire FRAMING + entity content_hash stay owned by the C-ABI (S2 floor); this
% module owns only the data-value canonicalization the ABI delegates to the caller.
% Protocol DATA carries no floats (strings/bytes/uints/bools/maps/arrays only), so
% the irreducibly-imperative shortest-float path (A-PL-004) is present for totality
% but is never on a protocol hot path.
%
% VALUE-TERM LANGUAGE (decoded form; mirrors the CL EC value model):
%   int(I)            <-> CBOR unsigned/negative integer        (major 0/1)
%   "text" (string)   <-> CBOR text string                      (major 3)
%   bytes(Codes)      <-> CBOR byte string (Codes: list 0..255) (major 2)
%   bool(true/false)  <-> CBOR true/false
%   null              <-> CBOR null
%   [V,...]           <-> CBOR array                            (major 4)
%   map([K-V,...])    <-> CBOR map (canonical key order)        (major 5)
%   float(F)          <-> CBOR float (shortest; rare on the peer path)
%
% DETERMINISM (A-PL-005): cbor_encode/2 and cbor_decode/2 are det (once/1) — the
% wire is a function, never a relation; no choice point leaks across the boundary.

:- module(ec_cbor,
          [ cbor_encode/2,          % +Value, -Codes        (list 0..255)
            cbor_encode_bytes/2,    % +Value, -ByteString   (SWI latin-1 string)
            cbor_decode/2,          % +Codes, -Value
            cbor_decode_bytes/2     % +ByteString, -Value
          ]).

:- use_module(library(lists)).

% ── public det entries ──────────────────────────────────────────────────────

cbor_encode(Value, Codes) :- once(phrase(cbor_value(Value), Codes)).

cbor_encode_bytes(Value, ByteString) :-
    cbor_encode(Value, Codes),
    string_codes(ByteString, Codes).

cbor_decode(Codes, Value) :-
    once(dec(Codes, 0, _, Value)).

cbor_decode_bytes(ByteString, Value) :-
    string_codes(ByteString, Codes),
    cbor_decode(Codes, Value).

% ═══════════════════════════════════════════════════════════════════════════
% ENCODE — DCG frame (the genuinely-grammar part) + imperative map canon-sort.
% ═══════════════════════════════════════════════════════════════════════════

cbor_value(int(I))   --> { integer(I), I >= 0 }, !, head_arg(0, I).
cbor_value(int(I))   --> { integer(I), I < 0 },  !, { V is -1 - I }, head_arg(1, V).
cbor_value(bool(true))  --> !, [0xf5].
cbor_value(bool(false)) --> !, [0xf4].
cbor_value(null)        --> !, [0xf6].
cbor_value(bytes(B)) --> { is_list(B) }, !, { length(B, L) }, head_arg(2, L), seq(B).
cbor_value(float(F)) --> !, { float_shortest_bytes(F, Bytes) }, seq(Bytes).
cbor_value(map(Ps))  --> { is_list(Ps) }, !, cbor_map(Ps).
cbor_value(L)        --> { is_list(L) }, !, { length(L, N) }, head_arg(4, N), seq_values(L).
cbor_value(S)        --> { string(S) }, !, cbor_tstr(S).
cbor_value(A)        --> { atom(A) }, !, { atom_string(A, S) }, cbor_tstr(S).

% Major-type head + minimal-width argument (ECF Rule 1 minimal encoding).
head_arg(Major, Val) -->
    { Major >= 0, Major =< 7, M is Major << 5 },
    head_arg_(M, Val).
head_arg_(M, V) --> { V =< 23, !, B is M \/ V },          [B].
head_arg_(M, V) --> { V =< 0xff, !, B is M \/ 24 },       [B], be(V,1).
head_arg_(M, V) --> { V =< 0xffff, !, B is M \/ 25 },     [B], be(V,2).
head_arg_(M, V) --> { V =< 0xffffffff, !, B is M \/ 26 }, [B], be(V,4).
head_arg_(M, V) --> { B is M \/ 27 },                     [B], be(V,8).

be(_, 0) --> [].
be(V, N) --> { N > 0, N1 is N-1, Sh is N1*8, Byte is (V >> Sh) /\ 0xff }, [Byte], be(V, N1).

cbor_tstr(S) --> { string_to_utf8_codes(S, Cs), length(Cs, L) }, head_arg(3, L), seq(Cs).

seq([]) --> [].
seq([C|Cs]) --> [C], seq(Cs).

seq_values([]) --> [].
seq_values([V|Vs]) --> cbor_value(V), seq_values(Vs).

% MAP — canonical key ordering (ECF Rule 2 / §3.5): sort by ENCODED-key length
% then byte-lexicographic. A DCG cannot sort its own output, so keys are encoded
% as a side computation, predsort'ed on the encoded bytes, then re-spliced. This
% imperative shell around a DCG is the A-PL-004 finding, reproduced minimally.
cbor_map(Pairs) -->
    { maplist(encode_pair_key, Pairs, Keyed),
      predsort(canon_key_cmp, Keyed, Sorted),
      length(Sorted, N) },
    head_arg(5, N),
    emit_pairs(Sorted).

encode_pair_key(K-V, kv(KB, V)) :- once(phrase(cbor_value(K), KB)).

% predsort drops elements it deems (=); CBOR map keys are unique, so a genuine
% byte-tie would be a duplicate key (a caller bug) — we never collapse distinct
% keys, returning the lexicographic order on a length tie.
canon_key_cmp(Order, kv(A,_), kv(B,_)) :-
    length(A, LA), length(B, LB),
    ( LA =:= LB -> compare(Order, A, B)
    ; LA < LB   -> Order = (<)
    ;              Order = (>) ).

emit_pairs([]) --> [].
emit_pairs([kv(KB, V)|Rest]) --> seq(KB), cbor_value(V), emit_pairs(Rest).

% ═══════════════════════════════════════════════════════════════════════════
% DECODE — recursive descent. Rejects major-6 tags (N2), indefinite lengths,
% and reserved arg widths. (The C-ABI is the authority for the wire entities we
% receive; this decoder reads the DATA-value spans the ABI hands back, plus the
% peer's own framed payloads. It is deliberately strict.)
% ═══════════════════════════════════════════════════════════════════════════

% dec(+Codes, +I, -Next, -Value) — decode one value at index I.
dec(O, I, Next, Value) :-
    nth0(I, O, IB),
    Major is IB >> 5, Info is IB /\ 0x1f,
    I1 is I + 1,
    dec_major(Major, Info, O, I1, Next, Value).

dec_major(0, Info, O, I, Next, int(V)) :- dec_arg(Info, O, I, Next, V).
dec_major(1, Info, O, I, Next, int(V)) :- dec_arg(Info, O, I, Ni, A), V is -1 - A, Next = Ni.
dec_major(2, Info, O, I, Next, bytes(Bs)) :-
    dec_arg(Info, O, I, Ni, Len), End is Ni + Len,
    take_range(O, Ni, End, Bs), Next = End.
dec_major(3, Info, O, I, Next, S) :-
    dec_arg(Info, O, I, Ni, Len), End is Ni + Len,
    take_range(O, Ni, End, Bs), utf8_codes_to_string(Bs, S), Next = End.
dec_major(4, Info, O, I, Next, L) :-
    dec_arg(Info, O, I, Ni, Len), dec_array(Len, O, Ni, Next, L).
dec_major(5, Info, O, I, Next, map(Ps)) :-
    dec_arg(Info, O, I, Ni, Len), dec_map(Len, O, Ni, Next, Ps).
dec_major(6, _, _, _, _, _) :- throw(error(ec_cbor(tag_rejected_major6), _)).   % N2
dec_major(7, Info, O, I, Next, V) :- dec_simple(Info, O, I, Next, V).

dec_arg(Info, _, I, I, Info)     :- Info < 24, !.
dec_arg(24, O, I, Ni, V)         :- !, nth0(I, O, V), Ni is I+1.
dec_arg(25, O, I, Ni, V)         :- !, be_read(O, I, 2, V), Ni is I+2.
dec_arg(26, O, I, Ni, V)         :- !, be_read(O, I, 4, V), Ni is I+4.
dec_arg(27, O, I, Ni, V)         :- !, be_read(O, I, 8, V), Ni is I+8.
dec_arg(Bad, _, _, _, _)         :- throw(error(ec_cbor(bad_argument(Bad)), _)).

be_read(_, _, 0, 0) :- !.
be_read(O, I, N, V) :- N > 0, nth0(I, O, B), I1 is I+1, N1 is N-1,
                       be_read(O, I1, N1, V0), V is (B << (N1*8)) \/ V0.

dec_array(0, _, I, I, []) :- !.
dec_array(N, O, I, Next, [V|Vs]) :-
    N > 0, dec(O, I, Ni, V), N1 is N-1, dec_array(N1, O, Ni, Next, Vs).

dec_map(0, _, I, I, []) :- !.
dec_map(N, O, I, Next, [K-V|Ps]) :-
    N > 0, dec(O, I, Ni, KV), map_key_term(KV, K),
    dec(O, Ni, Nj, V), N1 is N-1, dec_map(N1, O, Nj, Next, Ps).

% map keys decode as their value-term but we surface text/bytes keys directly.
map_key_term(S, S) :- string(S), !.
map_key_term(bytes(B), bytes(B)) :- !.
map_key_term(int(I), int(I)) :- !.
map_key_term(K, K).

dec_simple(20, _, I, I, bool(false)) :- !.
dec_simple(21, _, I, I, bool(true)) :- !.
dec_simple(22, _, I, I, null) :- !.
dec_simple(25, O, I, Ni, float(F)) :- !, nth0(I,O,B0), I1 is I+1, nth0(I1,O,B1), Ni is I+2, decode_f16(B0,B1,F).
dec_simple(26, O, I, Ni, float(F)) :- !, take_range(O,I,I+4,Bs), Ni is I+4, decode_f32(Bs,F).
dec_simple(27, O, I, Ni, float(F)) :- !, take_range(O,I,I+8,Bs), Ni is I+8, decode_f64(Bs,F).
dec_simple(Bad, _, _, _, _) :- throw(error(ec_cbor(bad_simple(Bad)), _)).

% take_range(+List, +Start, +EndExpr, -Sub) — codes [Start, End).
take_range(O, Start, EndExpr, Sub) :-
    End is EndExpr,
    Len is End - Start,
    length(Sub, Len),
    Skip is Start,
    length(Pre, Skip),
    append(Pre, Rest, O),
    append(Sub, _, Rest).

% ── UTF-8 (text strings) ──────────────────────────────────────────────────────
% Peer protocol text is ASCII-range (type names, ops, peer_ids/base58, hex), so
% a code is a byte; for full Unicode SWI's text<->octet conversion is used.
string_to_utf8_codes(S, Cs) :-
    ( string(S) -> Str = S ; atom_string(S, Str) ),
    string_codes(Str, CharCodes),
    ( max_member(Max, CharCodes), Max =< 127
    -> Cs = CharCodes                                  % ASCII fast path (1 code = 1 byte)
    ;  utf8_octets(Str, Cs) ).
string_to_utf8_codes(S, []) :- ( string(S) ; atom(S) ), string_length(S, 0).

utf8_octets(Str, Octets) :-
    setup_call_cleanup(
        new_memory_file(MF),
        ( open_memory_file(MF, write, W, [encoding(utf8)]),
          write(W, Str), close(W),
          open_memory_file(MF, read, R, [encoding(octet)]),
          read_string(R, _, S2), close(R),
          string_codes(S2, Octets) ),
        free_memory_file(MF)).

utf8_codes_to_string(Bs, S) :-
    ( max_member(Max, Bs), Max =< 127
    -> string_codes(S, Bs)
    ;  ( Bs == [] -> S = "" ; octets_utf8(Bs, S) ) ).
utf8_codes_to_string([], "").

octets_utf8(Bs, Str) :-
    setup_call_cleanup(
        new_memory_file(MF),
        ( open_memory_file(MF, write, W, [encoding(octet)]),
          forall(member(B, Bs), put_char(W, B)), close(W),
          open_memory_file(MF, read, R, [encoding(utf8)]),
          read_string(R, _, Str), close(R) ),
        free_memory_file(MF)).

% ═══════════════════════════════════════════════════════════════════════════
% FLOAT (shortest ladder) — imperative IEEE-754 (A-PL-004). Not on a protocol
% hot path; present for codec totality (lifted from the proven S2 spike).
% ═══════════════════════════════════════════════════════════════════════════

float_shortest_bytes(F, Bytes) :-
    ( float_is_nan(F)  -> Bytes = [0xf9,0x7e,0x00]
    ; F =:= inf        -> Bytes = [0xf9,0x7c,0x00]
    ; F =:= -inf       -> Bytes = [0xf9,0xfc,0x00]
    ; f64_bits(F, B64),
      ( f16_try(F, B16) -> Bytes = [0xf9|B16]
      ; f32_try(F, B32) -> Bytes = [0xfa|B32]
      ; bits_to_bytes(B64, 8, Rest), Bytes = [0xfb|Rest] ) ).

float_is_nan(F) :- catch((F =\= F), _, fail).
float_neg_zero(F) :- F =:= 0.0, R is copysign(1.0, F), R < 0.0.

f64_bits(F, Bits) :-
    ( F =:= 0.0 -> ( float_neg_zero(F) -> Bits = 0x8000000000000000 ; Bits = 0 )
    ; ( F < 0.0 -> Sign = 1, A is -F ; Sign = 0, A is F ),
      f64_decompose(A, Exp, Frac52), BiasedExp is Exp + 1023,
      Bits is (Sign << 63) \/ (BiasedExp << 52) \/ Frac52 ).

f64_decompose(A, Exp, Frac52) :-
    Exp0 is floor(log(A) / log(2.0)),
    ( A / (2.0 ** Exp0) >= 2.0 -> Exp is Exp0 + 1
    ; A / (2.0 ** Exp0) <  1.0 -> Exp is Exp0 - 1
    ; Exp = Exp0 ),
    Scale is 2 ** 52, Mant is A / (2.0 ** Exp),
    Frac52 is round((Mant - 1.0) * Scale).

bits_to_bytes(_, 0, []) :- !.
bits_to_bytes(Int, N, [B|Bs]) :- N>0, N1 is N-1, Sh is N1*8, B is (Int>>Sh)/\0xff, bits_to_bytes(Int,N1,Bs).

f16_try(F, [B0,B1]) :- f16_encode(F,U16), f16_decode(U16,G), G=:=F, B0 is (U16>>8)/\0xff, B1 is U16/\0xff.
f32_try(F, Bytes)   :- f32_encode(F,U32), f32_decode(U32,G), G=:=F, bits_to_bytes(U32,4,Bytes).

f16_encode(F, U16) :-
    ( F =:= 0.0 -> ( float_neg_zero(F) -> U16=0x8000 ; U16=0 )
    ; ( F<0.0 -> S=1, A is -F ; S=0, A is F ), f64_decompose(A,E,Frac52),
      E >= -14, E =< 15, Frac10 is (Frac52>>42), (Frac52 /\ ((1<<42)-1)) =:= 0,
      BE is E+15, U16 is (S<<15) \/ (BE<<10) \/ Frac10 ).
f16_decode(U16, F) :-
    S is (U16>>15)/\1, E is (U16>>10)/\0x1f, M is U16/\0x3ff,
    ( E=:=0 -> Val is M/1024.0*(2.0** -14)
    ; E=:=31 -> Val is inf
    ; Val is (1+M/1024.0)*(2.0**(E-15)) ),
    ( S=:=1 -> F is -Val ; F=Val ).
f32_encode(F, U32) :-
    ( F =:= 0.0 -> ( float_neg_zero(F) -> U32=0x80000000 ; U32=0 )
    ; ( F<0.0 -> S=1, A is -F ; S=0, A is F ), f64_decompose(A,E,Frac52),
      E >= -126, E =< 127, Frac23 is (Frac52>>29), (Frac52 /\ ((1<<29)-1)) =:= 0,
      BE is E+127, U32 is (S<<31) \/ (BE<<23) \/ Frac23 ).
f32_decode(U32, F) :-
    S is (U32>>31)/\1, E is (U32>>23)/\0xff, M is U32/\0x7fffff,
    ( E=:=0 -> Val is M/8388608.0*(2.0** -126)
    ; Val is (1+M/8388608.0)*(2.0**(E-127)) ),
    ( S=:=1 -> F is -Val ; F=Val ).

decode_f16(B0,B1,F) :-
    H is (B0<<8)\/B1, S is (H>>15)/\1, E is (H>>10)/\0x1f, M is H/\0x3ff,
    ( E=:=0, M=:=0 -> ( S=:=1 -> F = -0.0 ; F = 0.0 )
    ; E=:=31 -> ( M=:=0 -> ( S=:=1 -> F is -inf ; F is inf ) ; F is nan )
    ; f16_decode(H, F) ).
decode_f32(Bs,F) :-
    be_list(Bs, U), S is (U>>31)/\1, E is (U>>23)/\0xff, M is U/\0x7fffff,
    ( E=:=0, M=:=0 -> ( S=:=1 -> F = -0.0 ; F = 0.0 )
    ; E=:=255 -> ( M=:=0 -> ( S=:=1 -> F is -inf ; F is inf ) ; F is nan )
    ; f32_decode(U, F) ).
decode_f64(Bs,F) :-
    be_list(Bs, U), S is (U>>63)/\1, E is (U>>52)/\0x7ff, M is U/\0xfffffffffffff,
    ( E=:=0, M=:=0 -> ( S=:=1 -> F = -0.0 ; F = 0.0 )
    ; E=:=2047 -> ( M=:=0 -> ( S=:=1 -> F is -inf ; F is inf ) ; F is nan )
    ; f64_bits_decode(U, F) ).

be_list(Bs, U) :- foldl([B,A0,A1]>>(A1 is (A0<<8)\/B), Bs, 0, U).
f64_bits_decode(U, F) :-
    S is (U>>63)/\1, E is (U>>52)/\0x7ff, M is U/\0xfffffffffffff,
    Mant is 1.0 + M/(2.0**52), Val is Mant * (2.0**(E-1023)),
    ( S=:=1 -> F is -Val ; F = Val ).
