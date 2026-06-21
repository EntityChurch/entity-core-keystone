% ec_entity.pl — the materialized entity {type, data, content_hash} (§1.1, §3.4)
% and the §3.1 protocol envelope, layered on the S2 C-ABI codec + the S3 data-value
% CBOR codec.
%
% An entity's content_hash covers ONLY {type, data} (§1.1). We compute it through
% the C-ABI: cbor_encode the data value → canonical data bytes → ec_content_hash
% (which the C-ABI canonicalizes the OUTER {data,type} map over + SHA-256-prefixes).
% So the wire/hash bytes stay C-ABI-owned (S2 floor); the data-value canon is the
% one piece the ABI delegates to us (ec_cbor).
%
% REPRESENTATION
%   entity(Type, Data, Hash)
%     Type : a Prolog string (e.g. "system/protocol/execute")
%     Data : a value-term map([K-V,...]) (the ec_cbor data-value language)
%     Hash : a byte-string (SWI latin-1, 33 bytes: 0x00 ‖ SHA-256 digest)
%
% Field reads navigate the Data map term directly — unification IS the decode
% (A-PL-001 "decode = unification", realized): ent_field/3 unifies a K-V out of
% the map's pair list, no imperative getter.

:- module(ec_entity,
          [ make_entity/3,            % +Type, +DataValue, -Entity
            entity_type/2,            % +Entity, -Type
            entity_data/2,            % +Entity, -DataValue
            entity_hash/2,            % +Entity, -Hash33 (byte-string)
            entity_to_cbor/2,         % +Entity, -WireValue (map with content_hash)
            entity_of_cbor/2,         % +WireValue, -Entity (recompute+verify §1.8)
            entity_wire_bytes/2,      % +Entity, -ByteString (canonical wire entity)
            ent_field/3,              % +Entity, +Key, -Value   (semidet)
            ent_text/3,               % +Entity, +Key, -String
            ent_bytes/3,              % +Entity, +Key, -ByteString
            ent_uint/3,               % +Entity, +Key, -Int
            ent_entity/3,             % +Entity, +Key, -NestedEntity
            map_field/3,              % +Map, +Key, -Value
            envelope/3,               % +Root, +Included, -Envelope
            envelope_root/2,          % +Envelope, -RootEntity
            envelope_included/2,      % +Envelope, -Included (list of Hash-Entity)
            included_get/3,           % +Envelope, +Hash, -Entity (semidet)
            envelope_to_bytes/2,      % +Envelope, -ByteString (framed payload)
            envelope_of_bytes/2,      % +ByteString, -Envelope
            bytes_hash/2              % +ByteString, -HexAtom (lowercase)
          ]).

:- use_module(ec_codec).
:- use_module(ec_cbor).
:- use_module(library(lists)).

% ── entity construction ───────────────────────────────────────────────────────

make_entity(Type, Data, entity(Type, Data, Hash)) :-
    cbor_encode_bytes(Data, DataBytes),
    ec_content_hash(Type, DataBytes, Hash).      % 0x00 ‖ SHA-256({type,data})

entity_type(entity(T,_,_), T).
entity_data(entity(_,D,_), D).
entity_hash(entity(_,_,H), H).

entity_wire_bytes(entity(Type, Data, _), Bytes) :-
    cbor_encode_bytes(Data, DataBytes),
    ec_encode_ecf(Type, DataBytes, Bytes).       % canonical {data,type} entity

% wire form carries content_hash as a third field (§3.1).
entity_to_cbor(entity(Type, Data, Hash), map(Pairs)) :-
    string_codes(Hash, HCodes),
    Pairs = ["type"-Type, "data"-Data, "content_hash"-bytes(HCodes)].

% parse a wire entity map, RECOMPUTE the hash from {type,data}, verify §1.8.
entity_of_cbor(map(Pairs), entity(Type, Data, Hash)) :-
    memberchk("type"-Type, Pairs), string(Type),
    memberchk("data"-Data, Pairs),
    make_entity(Type, Data, entity(Type, Data, Hash)),
    ( memberchk("content_hash"-bytes(CarriedCodes), Pairs)
    -> string_codes(Carried, CarriedCodes),
       ( Carried == Hash -> true
       ; throw(error(ec_entity(content_hash_mismatch), _)) )   % §1.8 fidelity
    ;  true ).

% ── field reads (unification = decode) ─────────────────────────────────────────

map_field(map(Pairs), Key, Value) :- memberchk(Key-Value, Pairs).

ent_field(entity(_,Data,_), Key, Value) :- map_field(Data, Key, Value).

ent_text(E, Key, S) :- ent_field(E, Key, S), string(S).
ent_bytes(E, Key, ByteString) :- ent_field(E, Key, bytes(Codes)), string_codes(ByteString, Codes).
ent_uint(E, Key, I) :- ent_field(E, Key, int(I)), integer(I).
ent_entity(E, Key, Nested) :- ent_field(E, Key, map(P)), entity_of_cbor(map(P), Nested).

% ── envelope (§3.1) ─────────────────────────────────────────────────────────────
% included is a list of Hash-Entity (Hash = byte-string content_hash).

envelope(Root, Included, envelope(Root, Included)).
envelope_root(envelope(R,_), R).
envelope_included(envelope(_,I), I).

included_get(envelope(_, Included), Hash, Entity) :-
    member(H-Entity, Included), H == Hash, !.

envelope_to_bytes(envelope(Root, Included), Bytes) :-
    entity_to_cbor(Root, RootV),
    findall(HK-EV,
            ( member(_-E, Included),
              entity_hash(E, H), string_codes(H, HC), HK = bytes(HC),
              entity_to_cbor(E, EV) ),
            IncPairs),
    EnvV = map(["root"-RootV, "included"-map(IncPairs)]),
    cbor_encode_bytes(EnvV, Bytes).

envelope_of_bytes(Bytes, envelope(Root, Included)) :-
    cbor_decode_bytes(Bytes, map(Pairs)),
    memberchk("root"-RootV, Pairs),
    entity_of_cbor(RootV, Root),
    ( memberchk("included"-map(IncPairs), Pairs)
    -> findall(H-E,
               ( member(bytes(KC)-EV, IncPairs),
                 entity_of_cbor(EV, E),
                 entity_hash(E, H),
                 string_codes(KH, KC),
                 ( KH == H -> true ; throw(error(ec_entity(included_key_mismatch), _)) ) ),
               Included)
    ;  Included = [] ).

% ── hex helper ──────────────────────────────────────────────────────────────────
bytes_hash(ByteString, Hex) :- bytes_hex(ByteString, Hex).
