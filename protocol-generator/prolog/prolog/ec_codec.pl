% ec_codec.pl — deterministic Prolog codec surface over the entity-codec C-ABI.
%
% The FFI peer's byte-floor: canonical CBOR encode/decode, content_hash, peer_id,
% Ed25519/Ed448 sign+verify, SHA-256/384 — all sourced from libentitycore_codec
% (C-ABI v1.1) through the foreign shim c/ec_codec_pl.c. This module is the clean,
% DETERMINISTIC predicate API the rest of the peer (S3 relational core) builds on.
%
% A-PL-005 (determinism discipline): the wire is a FUNCTION, not a relation. Every
% public predicate here is wrapped in once/1 so NO choice point ever leaks across
% the codec boundary. The underlying foreign predicates are semidet (true on
% EC_OK, fail otherwise); once/1 makes that explicit and forecloses re-entry.
%
% BYTES are SWI strings of code-points 0..255 (REP_ISO_LATIN_1 in the shim) —
% NUL-safe, length-carried. Helpers below convert hex<->bytes for fixtures/KATs.

:- module(ec_codec,
          [ ec_encode_ecf/3,            % +Type, +DataBytes, -Bytes
            ec_encode_bare_value/2,     % +InBytes, -OutBytes
            ec_decode_entity_ok/1,      % +Bytes            (semidet: valid entity?)
            ec_content_hash/3,          % +Type, +DataBytes, -Hash33
            ec_content_hash_with_format/4, % +Type, +DataBytes, +FormatCode, -Hash
            ec_content_hash_prefixed/4, % +Type, +DataBytes, +FormatCode, -Hash (compose)
            ec_hash_format_code_encode/2,  % +Code, -Bytes
            ec_peerid_format/4,         % +KeyType, +HashType, +DigestBytes, -Base58
            ec_peerid_parse/4,          % +Base58, -KeyType, -HashType, -DigestBytes
            ec_ed25519_keygen/2,        % -PrivBytes, -PubBytes
            ec_ed25519_sign/3,          % +SeedBytes32, +MsgBytes, -SigBytes64
            ec_ed25519_verify/3,        % +PubBytes32, +MsgBytes, +SigBytes64 (semidet)
            ec_ed25519_seed_to_pubkey/2,% +SeedBytes32, -PubBytes32
            ec_sha256/2,                % +DataBytes, -Digest32
            ec_sha384/2,                % +DataBytes, -Digest48
            ec_ed448_seed_to_pubkey/2,  % +SeedBytes57, -PubBytes57
            ec_ed448_sign/3,            % +SeedBytes57, +MsgBytes, -SigBytes114
            ec_ed448_verify/3,          % +PubBytes57, +MsgBytes, +SigBytes114 (semidet)
            ec_abi_version/1,           % -Atom
            ec_impl_info/1,             % -Atom
            % byte/hex helpers (harness + S3 convenience)
            bytes_hex/2,                % ?Bytes, ?HexAtom
            string_byte_codes/2         % ?Bytes(string), ?Codes(list 0..255)
          ]).

% Load the foreign shim. The .so is expected next to this file (built by run-s2.sh
% as ec_codec_pl.so); SWI runs install_ec_codec_pl/0 on load. Path is resolved
% relative to this source file so it loads regardless of CWD.
:- use_module(library(error)).

:- dynamic ec_codec_source_dir/1.

% Capture THIS module's source directory at consult time (prolog_load_context is
% only valid during loading — the initialization goal below runs later, possibly
% with a different load context, so we freeze it now into a fact).
:- prolog_load_context(directory, D),
   assertz(ec_codec_source_dir(D)).

:- initialization(load_foreign_shim).

load_foreign_shim :-
    ( current_predicate(pl_abi_version/1)
    -> true
    ;  ec_codec_source_dir(Dir),
       atomic_list_concat([Dir, '/ec_codec_pl'], SoBase),
       catch(use_foreign_library(SoBase),
             E,
             ( print_message(error, E),
               throw(error(ec_codec_error(foreign_shim_load_failed, SoBase), _)) ))
    ).

% ── deterministic wrappers (A-PL-005: once/1 forecloses choice points) ──────

ec_encode_ecf(Type, Data, Bytes)            :- once(pl_encode_ecf(Type, Data, Bytes)).
ec_encode_bare_value(In, Out)               :- once(pl_encode_bare_value(In, Out)).
ec_decode_entity_ok(Bytes)                  :- once(pl_decode_entity(Bytes)).
ec_content_hash(Type, Data, Hash)           :- once(pl_content_hash(Type, Data, Hash)).
ec_content_hash_with_format(T, D, FC, H)    :- once(pl_content_hash_with_format(T, D, FC, H)).
ec_hash_format_code_encode(Code, Bytes)     :- once(pl_hash_format_code_encode(Code, Bytes)).
ec_peerid_format(KT, HT, Dig, B58)          :- once(pl_peerid_format(KT, HT, Dig, B58)).
ec_peerid_parse(B58, KT, HT, Dig)           :- once(pl_peerid_parse(B58, KT, HT, Dig)).
ec_ed25519_keygen(Priv, Pub)                :- once(pl_ed25519_keygen(Priv, Pub)).
ec_ed25519_sign(Seed, Msg, Sig)             :- once(pl_ed25519_sign(Seed, Msg, Sig)).
ec_ed25519_verify(Pub, Msg, Sig)            :- once(pl_ed25519_verify(Pub, Msg, Sig)).
ec_ed25519_seed_to_pubkey(Seed, Pub)        :- once(pl_ed25519_seed_to_pubkey(Seed, Pub)).
ec_sha256(Data, Dig)                        :- once(pl_sha256(Data, Dig)).
ec_sha384(Data, Dig)                        :- once(pl_sha384(Data, Dig)).
ec_ed448_seed_to_pubkey(Seed, Pub)          :- once(pl_ed448_seed_to_pubkey(Seed, Pub)).
ec_ed448_sign(Seed, Msg, Sig)               :- once(pl_ed448_sign(Seed, Msg, Sig)).
ec_ed448_verify(Pub, Msg, Sig)              :- once(pl_ed448_verify(Pub, Msg, Sig)).
ec_abi_version(V)                           :- once(pl_abi_version(V)).
ec_impl_info(V)                             :- once(pl_impl_info(V)).

% ec_content_hash_prefixed/4 — content_hash under an arbitrary (incl. forward-compat
% multi-byte) format code, COMPOSED from the public ABI. A-PL-011: the public
% ec_content_hash_with_format REJECTS unsupported codes (e.g. 0x80), but the
% conformance corpus (content_hash.4) still pins their wire bytes. The format_code
% contributes ONLY the LEB128 prefix, never the hashed body — so the prefixed hash
% is leb128(code) ‖ SHA-256-digest, reconstructable from ec_content_hash (which
% gives 0x00 ‖ digest) by swapping the 1-byte 0x00 prefix for the encoded code.
ec_content_hash_prefixed(Type, Data, 0, Hash) :- !,
    ec_content_hash(Type, Data, Hash).
ec_content_hash_prefixed(Type, Data, Code, Hash) :-
    once(( ec_content_hash(Type, Data, H33),       % 0x00 ‖ 32-byte SHA-256
           string_byte_codes(H33, [_0x00|Digest]), % drop the 0x00 prefix
           ec_hash_format_code_encode(Code, Prefix),
           string_byte_codes(Prefix, PrefixCodes),
           append(PrefixCodes, Digest, AllCodes),
           string_byte_codes(Hash, AllCodes) )).

% ── byte/hex helpers ────────────────────────────────────────────────────────

% string_byte_codes(?Bytes, ?Codes) — Bytes is a SWI string whose code-points are
% 0..255 (the shim's REP_ISO_LATIN_1 convention); Codes is the integer code list.
string_byte_codes(Bytes, Codes) :-
    ( var(Bytes)
    -> string_codes(S, Codes), Bytes = S
    ;  string_codes(Bytes, Codes)
    ).

% bytes_hex(?Bytes, ?HexAtom) — lowercase %02x hex <-> byte-string. Bidirectional.
bytes_hex(Bytes, Hex) :-
    ( nonvar(Bytes)
    -> string_codes(Bytes, Codes),
       maplist(byte_to_hex, Codes, Pairs),
       atomic_list_concat(Pairs, Hex0),
       ( atom(Hex) -> Hex = Hex0 ; atom_string(Hex0, Hex) )
    ;  ( atom(Hex) -> atom_codes(Hex, HC) ; string_codes(Hex, HC) ),
       hexcodes_bytes(HC, Codes),
       string_codes(Bytes, Codes)
    ).

byte_to_hex(B, Hex) :-
    format(atom(Hex), '~|~`0t~16r~2+', [B]).

hexcodes_bytes([], []).
hexcodes_bytes([H1,H2|T], [B|BT]) :-
    hexdigit(H1, V1), hexdigit(H2, V2),
    B is V1*16 + V2,
    hexcodes_bytes(T, BT).

hexdigit(C, V) :- C >= 0'0, C =< 0'9, !, V is C - 0'0.
hexdigit(C, V) :- C >= 0'a, C =< 0'f, !, V is C - 0'a + 10.
hexdigit(C, V) :- C >= 0'A, C =< 0'F, !, V is C - 0'A + 10.
