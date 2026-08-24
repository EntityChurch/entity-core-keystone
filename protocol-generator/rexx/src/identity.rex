/* entity-core-protocol-rexx — L1 identity (§1.5, §3.5, §7.3).
 *
 * Everything derived from a 32-byte Ed25519 seed:
 *   public_key  = Ed25519 pubkey of seed                 (32 bytes, eccrypto helper)
 *   peer_id     = §1.5 canonical-form identity-multihash  (Base58)
 *   peer_entity = system/peer {public_key, key_type}      (§3.5; NO peer_id in basis)
 *   id_hash     = content_hash(peer_entity)               (33 bytes)
 *
 * An identity is a HANDLE ("id<n>") into the EC. stem (the dict analogue). peer_id is
 * the §1.5 identity-multihash form (hash_type 0x00, digest = the raw <=32-byte pubkey),
 * which SUPERSEDES the stale §7.4 SHA-256 skeleton — baked in per the profile [spec]
 * note to avoid the handshake debug cycle. Signing is over the full 33-byte
 * content_hash (§7.3). Ed25519 sign/verify + SHA cross the C-ABI (eccrypto helper).
 */

/* Id_OfSeed: construct an identity handle from a 32-byte Ed25519 seed. */
Id_OfSeed: procedure expose EC.
  parse arg seed
  EC.!ID_CTR = EC.!ID_CTR + 1
  h = 'id' || EC.!ID_CTR
  pub = Crypto_Ed25519Pubkey(seed)
  pent = Id_PeerEntityOfPubkey(pub)
  EC.!ID_SEED.h = seed
  EC.!ID_PUB.h = pub
  EC.!ID_PID.h = Id_PeerIdOfPubkey(pub)
  EC.!ID_PENT.h = pent
  EC.!ID_HASH.h = Ent_Hash(pent)
  return h

Id_Seed: procedure expose EC.
  parse arg h
  return EC.!ID_SEED.h
Id_Pub: procedure expose EC.
  parse arg h
  return EC.!ID_PUB.h
Id_PeerId: procedure expose EC.
  parse arg h
  return EC.!ID_PID.h
Id_PeerEntity: procedure expose EC.
  parse arg h
  return EC.!ID_PENT.h
Id_IdHash: procedure expose EC.
  parse arg h
  return EC.!ID_HASH.h

/* §1.5 size-cutoff peer_id from a raw Ed25519 pubkey: <=32 B -> identity-multihash
 * (hash_type 0, digest = pubkey). Returns the Base58 string. KEY_TYPE_ED25519 = 1. */
Id_PeerIdOfPubkey: procedure expose EC.
  parse arg pub
  if length(pub) <= 32 then do
    hash_type = 0
    digest = pub
  end
  else do
    hash_type = 1
    digest = Crypto_Sha256(pub)
  end
  raw = Varint_Encode(1) || Varint_Encode(hash_type) || digest
  return Base58_Encode(raw)

/* the system/peer entity for a raw pubkey (no peer_id field in the basis). */
Id_PeerEntityOfPubkey: procedure expose EC.
  parse arg pub
  return Ent_Make('system/peer', Ecf_Map('public_key', Ecf_Bytes(pub), 'key_type', Ecf_Str('ed25519')))

/* sign a target entity's content_hash -> a system/signature entity (§3.5). */
Id_Sign: procedure expose EC.
  parse arg idh, target
  th = Ent_Hash(target)
  sig = Crypto_Ed25519Sign(Id_Seed(idh), th)
  m = Ecf_Map('target', Ecf_Bytes(th), 'signer', Ecf_Bytes(Id_IdHash(idh)))
  m = Ecf_MapPut(m, 'algorithm', Ecf_Str('ed25519'))
  m = Ecf_MapPut(m, 'signature', Ecf_Bytes(sig))
  return Ent_Make('system/signature', m)

/* verify a system/signature entity against the signer's system/peer entity. The §5.2
 * signer-hash binding is the caller's responsibility. Returns 1 | 0. */
Id_VerifySignature: procedure expose EC.
  parse arg signature, signer_peer
  target = Ent_Bytes(signature, 'target')
  sig = Ent_Bytes(signature, 'signature')
  pub = Ent_Bytes(signer_peer, 'public_key')
  if target == '' | sig == '' | pub == '' then return 0
  if length(sig) \== 64 then return 0
  if length(pub) \== 32 then return 0
  return Crypto_Ed25519Verify(pub, target, sig)
