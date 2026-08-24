%% entity-core-protocol-oz — identity.oz
%% L1 identity (§1.5, §3.5, §7.3/§7.4). Everything derives from a 32-byte
%% Ed25519 seed (crypto via the entity-codec-daemon):
%%   pub      = ed25519 pubkey                              (32 B)
%%   peer_id  = §1.5 canonical identity-multihash            (Base58 string)
%%   peerEnt  = system/peer {public_key, key_type}           (§3.5; NO peer_id)
%%   idHash   = content_hash(peerEnt)                        (33 B)
%% Signing is over the full 33-byte content_hash (§7.3).
functor
import
   Crypto at 'crypto.ozf'
   Varint at 'varint.ozf'
   Base58 at 'base58.ozf'
   Val at 'val.ozf'
   Ent at 'entity.ozf'
export
   OfSeed Seed Pub PeerId PeerEntity IdHash
   PeerIdOfPubkey PeerEntityOfPubkey Sign VerifySignature
define
   %% §1.5 size-cutoff canonical form: pubkey <= 32 B -> identity-multihash
   %% (key_type 0x01, hash_type 0x00, digest = raw pubkey)
   fun {PeerIdOfPubkey Pub}
      HashType Digest
   in
      if {Length Pub} =< 32 then HashType = 0 Digest = Pub
      else HashType = 1 Digest = {Crypto.sha256 Pub} end
      {Base58.encode {Append {Varint.encode 1}
                      {Append {Varint.encode HashType} Digest}}}
   end

   fun {PeerEntityOfPubkey Pub}
      {Ent.make "system/peer"
       map([{Val.mkPair "public_key" bytes(Pub)}
            {Val.mkPair "key_type" {Val.txt "ed25519"}}])}
   end

   fun {OfSeed SeedBytes}
      Pub = {Crypto.ed25519Pub SeedBytes}
      PE = {PeerEntityOfPubkey Pub}
   in
      id(seed:SeedBytes pub:Pub peerId:{PeerIdOfPubkey Pub}
         peerEnt:PE idHash:{Ent.hash PE})
   end

   fun {Seed I} I.seed end
   fun {Pub I} I.pub end
   fun {PeerId I} I.peerId end
   fun {PeerEntity I} I.peerEnt end
   fun {IdHash I} I.idHash end

   %% sign a target entity's content_hash -> a system/signature entity (§3.5)
   fun {Sign I Target}
      TH = {Ent.hash Target}
      Sig = {Crypto.ed25519Sign I.seed TH}
   in
      {Ent.make "system/signature"
       map([{Val.mkPair "target" bytes(TH)}
            {Val.mkPair "signer" bytes(I.idHash)}
            {Val.mkPair "algorithm" {Val.txt "ed25519"}}
            {Val.mkPair "signature" bytes(Sig)}])}
   end

   %% verify a system/signature entity against the signer's system/peer entity.
   %% (§5.2 signer-hash binding is the caller's responsibility.)
   fun {VerifySignature SigEnt SignerPeer}
      Target = {Ent.getBytes SigEnt "target"}
      Sig = {Ent.getBytes SigEnt "signature"}
      Pub = {Ent.getBytes SignerPeer "public_key"}
   in
      if Target == absent orelse Sig == absent orelse Pub == absent then false
      elseif {Length Sig} \= 64 orelse {Length Pub} \= 32 then false
      else {Crypto.ed25519Verify Pub Sig Target}
      end
   end
end
