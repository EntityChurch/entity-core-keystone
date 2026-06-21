% ec_identity.pl — Identity (L1): a peer's Ed25519 keypair + derived entities
% (§1.5, §3.5, §7.3). All crypto is sourced over the C-ABI (S2 floor); this module
% composes it into the peer-identity surface.
%
%   public_key    = Ed25519 pub of seed                  (32 bytes, C-ABI)
%   peer_id       = §1.5 identity-multihash (A-PL-010)   (Base58, C-ABI)
%   peer entity   = system/peer {public_key, key_type}   (§3.5; NO peer_id in basis)
%   identity_hash = content_hash(peer entity)            (33 bytes)
%
% Signing is over the full 33-byte content_hash (format byte ‖ digest, §7.3).

:- module(ec_identity,
          [ make_identity/2,          % +Seed32(byte-string), -Identity
            identity_seed/2,          % +Identity, -Seed32
            identity_public_key/2,    % +Identity, -Pub32
            identity_peer_id/2,       % +Identity, -PeerIdString
            identity_peer_entity/2,   % +Identity, -PeerEntity
            identity_hash/2,          % +Identity, -Hash33
            peer_entity_of_pubkey/2,  % +Pub32, -PeerEntity
            peer_id_of_pubkey/2,      % +Pub32, -PeerIdString
            sign_entity/3,            % +Identity, +TargetEntity, -SignatureEntity
            verify_signature/2        % +SignatureEntity, +SignerPeerEntity (semidet)
          ]).

:- use_module(ec_codec).
:- use_module(ec_cbor).
:- use_module(ec_entity).
:- use_module(library(lists)).

% Identity is identity(Seed, Pub, PeerId, PeerEntity, Hash33).

make_identity(Seed, identity(Seed, Pub, PeerId, PeerEntity, Hash)) :-
    seed_to_pubkey(Seed, Pub),
    peer_id_of_pubkey(Pub, PeerId),
    peer_entity_of_pubkey(Pub, PeerEntity),
    entity_hash(PeerEntity, Hash).

% Ed25519 seed → public key. The C-ABI exposes ec_ed25519_seed_to_pubkey; reuse
% sign/verify round-trip is unnecessary — derive directly.
seed_to_pubkey(Seed, Pub) :- ec_ed25519_seed_to_pubkey(Seed, Pub).

identity_seed(identity(S,_,_,_,_), S).
identity_public_key(identity(_,P,_,_,_), P).
identity_peer_id(identity(_,_,I,_,_), I).
identity_peer_entity(identity(_,_,_,E,_), E).
identity_hash(identity(_,_,_,_,H), H).

% system/peer entity for a raw public key (v7.65: no peer_id field in the basis).
peer_entity_of_pubkey(Pub, E) :-
    string_codes(Pub, PubCodes),
    make_entity("system/peer",
                map(["public_key"-bytes(PubCodes), "key_type"-"ed25519"]),
                E).

% Ed25519 peer_id = §1.5 identity-multihash. key_type = 0x01 (Ed25519 in the
% §1.5 key registry — A-PL-010 CORRECTED at S4: the Go oracle @75c532e rejects
% key_type 0x00 as "unsupported key type"; the cohort uses {ed25519:1, ed448:2}).
% hash_type = 0x00 (identity-multihash: pubkey ≤32B ⇒ digest = the RAW pubkey).
% The C-ABI ec_peerid_format is digest-agnostic; the peer chooses the digest.
peer_id_of_pubkey(Pub, PeerId) :-
    string_codes(Pub, PubCodes),
    string_codes(Digest, PubCodes),
    ec_peerid_format(1, 0, Digest, PeerId).

% ── signing (§3.5) ──────────────────────────────────────────────────────────
% Sign TARGET's content_hash; produce a system/signature entity:
%   target = signed entity hash, signer = our identity hash.
sign_entity(Identity, Target, SigEntity) :-
    identity_seed(Identity, Seed),
    entity_hash(Target, TH),
    identity_hash(Identity, IH),
    ec_ed25519_sign(Seed, TH, SigBytes),
    string_codes(TH, THC), string_codes(IH, IHC), string_codes(SigBytes, SBC),
    make_entity("system/signature",
                map(["target"-bytes(THC), "signer"-bytes(IHC),
                     "algorithm"-"ed25519", "signature"-bytes(SBC)]),
                SigEntity).

% Verify a system/signature against the signer's system/peer entity.
% The §5.2 signer-hash binding check is the caller's responsibility.
verify_signature(SigEntity, SignerPeer) :-
    ent_bytes(SigEntity, "target", Target),
    ent_bytes(SigEntity, "signature", Sig),
    ent_bytes(SignerPeer, "public_key", Pub),
    catch(ec_ed25519_verify(Pub, Target, Sig), _, fail).
