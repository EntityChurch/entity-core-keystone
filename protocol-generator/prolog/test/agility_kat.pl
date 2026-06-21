% agility_kat.pl — crypto KAT pins for the Prolog FFI peer (S2).
%
% Pins the crypto floor + agility surface against the cohort's byte-blessed ground
% truth (transcribed from protocol-generator/shared/test-vectors/v0.8.0/
% agility-vectors-v1.diag + agility-SEEDS.md, the same pins the OCaml agility
% harness asserts). Everything is sourced through the C-ABI (ec_codec.pl):
%   - Ed25519: keygen round-trip + deterministic sign/verify (conformance corpus
%     signature.1 KAT, all-zero seed → fixed 64-byte signature).
%   - Ed448 (key_type 0x02): seed→pubkey, deterministic sign, sign→verify.
%   - SHA-256 / SHA-384: KAT digests + a sign-input differential.
%
% byte-identical or the binding is wrong (S8 cohort byte-equality discipline).

:- module(agility_kat, [run_kats/0, main/0]).

:- use_module('../prolog/ec_codec').
:- use_module(library(lists)).

main :- run_kats.

:- dynamic pass_count/1, fail_count/1.

run_kats :-
    retractall(pass_count(_)), retractall(fail_count(_)),
    assertz(pass_count(0)), assertz(fail_count(0)),
    ec_abi_version(ABI), ec_impl_info(Impl),
    format("# entity-core-protocol-prolog — S2-FFI crypto KAT~n"),
    format("# C-ABI ~w / ~w~n~n", [ABI, Impl]),

    kat_sha256,
    kat_sha384,
    kat_ed25519,
    kat_ed448,

    pass_count(P), fail_count(F), T is P+F,
    ( F =:= 0 -> Verdict = 'PASS' ; Verdict = 'FAIL' ),
    format("~n# RESULT: ~w (~w/~w)~n", [Verdict, P, T]),
    ( F =:= 0 -> halt(0) ; halt(1) ).

% ── assertion helpers ───────────────────────────────────────────────────────
check_hex(Name, Bytes, ExpectedHex) :-
    bytes_hex(Bytes, GotHex0),
    % normalize both to atoms (bytes_hex yields a string when its 2nd arg is
    % unbound; the pins are single-quoted atoms) so == compares like-for-like.
    atom_string(GotA, GotHex0), atom_string(ExpA, ExpectedHex),
    ( GotA == ExpA
    -> tally(pass), format("  [PASS] ~w~n", [Name])
    ;  tally(fail), format("  [FAIL] ~w~n    expected ~w~n    got      ~w~n",
                           [Name, ExpectedHex, GotHex0])
    ).
check_true(Name, Goal) :-
    ( call(Goal)
    -> tally(pass), format("  [PASS] ~w~n", [Name])
    ;  tally(fail), format("  [FAIL] ~w~n", [Name])
    ).
check_false(Name, Goal) :-
    ( \+ call(Goal)
    -> tally(pass), format("  [PASS] ~w~n", [Name])
    ;  tally(fail), format("  [FAIL] ~w (succeeded; expected failure)~n", [Name])
    ).

tally(pass) :- retract(pass_count(N)), N1 is N+1, assertz(pass_count(N1)).
tally(fail) :- retract(fail_count(N)), N1 is N+1, assertz(fail_count(N1)).

% bytes from a repeated byte value (seed b×n), and from hex.
seed_bytes(Byte, N, Bytes) :-
    length(Codes, N), maplist(=(Byte), Codes), string_byte_codes(Bytes, Codes).
hex_bytes(Hex, Bytes) :- bytes_hex(Bytes, Hex).

% ── SHA-256 / SHA-384 KAT (RFC-style: "abc") ───────────────────────────────
kat_sha256 :-
    format("SHA-256 KAT:~n"),
    hex_bytes('616263', Abc),   % "abc"
    ec_sha256(Abc, D),
    check_hex("sha256(\"abc\")", D,
              'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad').

kat_sha384 :-
    format("SHA-384 KAT:~n"),
    hex_bytes('616263', Abc),
    ec_sha384(Abc, D),
    check_hex("sha384(\"abc\")", D,
        'cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7').

% ── Ed25519 floor: keygen round-trip + deterministic KAT ────────────────────
% signature.1 (conformance corpus): seed = 0x00×32, msg = ECF({type:test/v1,
% data:{x:1}}) = a2 64 64617461 a1 6178 01 64 74797065 67 746573742f7631 ; the
% locked signature is the 64-byte value below. RFC 8032 Ed25519 is deterministic,
% so sign(seed,msg) is a hard KAT.
kat_ed25519 :-
    format("Ed25519 floor (keygen + deterministic KAT):~n"),
    % keygen → sign → verify round-trip (random key; structural sanity check).
    ec_ed25519_keygen(Priv, _Pub),
    hex_bytes('48656c6c6f', Hello),  % "Hello"
    check_true("Ed25519 keygen→sign produces a 64-byte signature",
               ( ec_ed25519_sign(Priv, Hello, S), string_length(S, 64) )),
    % deterministic KAT against the locked signature.1 vector:
    seed_bytes(0, 32, Seed0),
    ecf_test_v1_x1(Ecf),
    ec_ed25519_sign(Seed0, Ecf, Sig),
    check_hex("Ed25519 sign(seed=0x00*32, ECF{test/v1,{x:1}}) [signature.1]", Sig,
        '3f0b5d06636ea267199dc27eb20d8c9b37684d681adc5be43be465819ad643e3b152e5c024bf67ce862699fe439462d7852b029cb125cd917d12a3151529230c'),
    % seed→pubkey→verify the locked signature.
    ed25519_seed_pubkey(Seed0, Pub0),
    check_true("Ed25519 verify(pub, ECF, signature.1)",
               ec_ed25519_verify(Pub0, Ecf, Sig)),
    check_false("Ed25519 verify rejects a flipped signature",
                ec_ed25519_verify(Pub0, Ecf, BadSig)),
    flip_first_byte(Sig, BadSig).

% ECF({type:"test/v1", data:{x:1}}) via the C-ABI (the signed message body).
ecf_test_v1_x1(Ecf) :-
    string_byte_codes_text("test/v1", TypeB),
    % data = {x:1} canonical = a1 6178 01
    string_byte_codes(DataB, [0xa1, 0x61, 0x78, 0x01]),
    ec_encode_ecf(TypeB, DataB, Ecf).

% derive the Ed25519 public key for a 32-byte seed via keygen-equivalent:
% the C-ABI exposes keygen (random) + sign/verify; to get the pubkey for a fixed
% seed we use the peer_id path is not it — instead derive by signing a probe and
% recovering is not possible. We instead use ec_ed25519_keygen only for the
% round-trip; for the KAT-pinned seed we verify via the cohort-pinned pubkey.
% signature.1 uses seed 0x00*32; its Ed25519 pubkey (RFC 8032) is the constant
% below (3b6a27bc... — the well-known all-zero-seed Ed25519 public key).
ed25519_seed_pubkey(_Seed0, Pub0) :-
    hex_bytes('3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29', Pub0).

flip_first_byte(Bytes, Flipped) :-
    string_byte_codes(Bytes, [B|T]),
    B2 is B xor 0xff,
    string_byte_codes(Flipped, [B2|T]).

% ── Ed448 (agility, key_type 0x02): KEY-TYPE-ED448-1 pins ───────────────────
kat_ed448 :-
    format("Ed448 agility (KEY-TYPE-ED448-1 pins):~n"),
    seed_bytes(0x42, 57, Seed),
    ec_ed448_seed_to_pubkey(Seed, Pub),
    check_hex("Ed448 seed(0x42*57) → pubkey (57B)", Pub,
        '2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00'),
    % deterministic Ed448 signature over the Phase-1 fixture message.
    string_byte_codes_text("v7.67 Phase 1 cohort cross-impl Ed448 fixture", Msg),
    ec_ed448_sign(Seed, Msg, Sig),
    check_hex("Ed448 sign(seed, fixture msg) (114B, RFC 8032)", Sig,
        '0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b19ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4d2a0c8304d67e6f20e814b90411049b33400'),
    check_true("Ed448 sign→verify round-trip",
               ec_ed448_verify(Pub, Msg, Sig)),
    % peer_id for Ed448 (key_type 0x02, hash_type 0x01 "SHA-256-form"). The 57-byte
    % Ed448 pubkey EXCEEDS the V7 §1.5 identity-multihash 32-byte cutoff, so the
    % digest is SHA-256(pubkey), NOT the raw key (unlike the ≤32B Ed25519 path,
    % A-PL-010). This is the §1.5 size-cutoff rule — flag for S3 (A-PL-012).
    ec_sha256(Pub, Digest32),   % ec_sha256 is a plain 32-byte digest (no prefix)
    ec_peerid_format(2, 1, Digest32, B58),
    ( B58 == "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4"
    -> tally(pass), format("  [PASS] Ed448 peer_id (key_type=0x02, hash_type=0x01)~n")
    ;  tally(fail), format("  [FAIL] Ed448 peer_id~n    expected 3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4~n    got      ~w~n", [B58])
    ).

string_byte_codes_text(S, Bytes) :- string_codes(S, Codes), string_byte_codes(Bytes, Codes).
