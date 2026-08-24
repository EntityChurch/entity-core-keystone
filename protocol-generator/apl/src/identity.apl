⍝ entity-core-protocol-apl — src/identity.apl (L1 identity: §1.5, §3.5, §7.3).
⍝
⍝ Everything derives from a 32-byte Ed25519 seed:
⍝   pub         = Ed25519 pubkey of seed                 (32 bytes, C-ABI floor)
⍝   peerId      = §1.5 canonical-form identity-multihash (Base58, via C-ABI — no APL
⍝                 bignum, A-APL-010: hash_type 0x00 identity, digest = RAW 32-byte pubkey)
⍝   peerEntity  = system/peer {public_key, key_type}      (§3.5; NO peer_id in basis)
⍝   idHash      = content_hash(peerEntity)                (33 bytes)
⍝
⍝ An identity bundle is a 5-element nested array (seed pub peerId peerEntity idHash).
⍝ Ed25519 sign/verify + base58 cross the C-ABI (ffi.apl); no native APL crypto.

KEY_TYPE_ED25519←1 ⋄ HASH_TYPE_IDENTITY←0

IdSeed←{1⊃⍵} ⋄ IdPub←{2⊃⍵} ⋄ IdPeerId←{3⊃⍵} ⋄ IdPeerEntity←{4⊃⍵} ⋄ IdHash←{5⊃⍵}

⍝ the system/peer entity for a raw pubkey (no peer_id in the §3.5 basis).
∇Z←PeerEntityOfPubkey pub;m
 m←VMapEmpty
 m←m VmPut('public_key')(VBytes pub)
 m←m VmPut('key_type')(VText'ed25519')
 Z←'system/peer'EntMake m
∇

⍝ §1.5 identity-multihash peer_id from a raw Ed25519 pubkey (Base58 via the C-ABI).
∇Z←PeerIdOfPubkey pub
 Z←⎕UCS EcPeeridFmt KEY_TYPE_ED25519 HASH_TYPE_IDENTITY pub
∇

⍝ the §1.5 multihash key_type code carried by a base58 peer_id (¯1 if unparseable).
⍝ Lets §4.6 authenticate reject a peer_id encoding an unsupported key_type (AGILITY-1).
∇Z←PeerIdKeyType pid;r
 Z←¯1
 →(0=≢pid)/0
 r←EcPeeridParse ⎕UCS pid
 Z←r[1]
∇

⍝ build a full identity bundle from a 32-byte seed.
∇Z←IdOfSeed seed;pub;pe
 pub←EcSeedPub seed
 pe←PeerEntityOfPubkey pub
 Z←seed pub(PeerIdOfPubkey pub)pe(EntHash pe)
∇

⍝ sign a target entity's 33-byte content_hash -> a system/signature entity (§3.5).
∇Z←id IdSign target;th;sig;m
 th←EntHash target
 sig←EcSign(IdSeed id)th
 m←VMapEmpty
 m←m VmPut('target')(VBytes th)
 m←m VmPut('signer')(VBytes IdHash id)
 m←m VmPut('algorithm')(VText'ed25519')
 m←m VmPut('signature')(VBytes sig)
 Z←'system/signature'EntMake m
∇

⍝ verify a system/signature against the signer's system/peer entity (§5.2 signer-hash
⍝ binding is the caller's job). ⍺=signature entity ; ⍵=signer peer entity.
∇Z←sig IdVerifySignature signerPeer;target;s;pub
 Z←0
 target←sig EntBytes'target'
 s←sig EntBytes'signature'
 pub←signerPeer EntBytes'public_key'
 →((0=≢target)∨(64≠≢s)∨(32≠≢pub))/0
 Z←EC_OK=EcVerify pub target s
∇
