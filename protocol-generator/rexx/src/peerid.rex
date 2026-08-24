/* entity-core-protocol-rexx — peer_id canonical form (§1.5 canonical-form table).
 *
 * peer_id wire form = Base58( varint(key_type) || varint(hash_type) || digest ), and
 * the peer_id VALUE on the wire is a CBOR text string wrapping that base58 string.
 * For Ed25519 the §1.5 table sets hash_type = 0x00 identity-multihash with digest =
 * the raw 32-byte public key; the conformance vectors also exercise SHA-256 peer-ids
 * (hash_type 0x01) and a synthetic multi-byte key_type (peer_id.3, the N1 varint test).
 */

/* Peerid_Format: key_type, hash_type, digest -> an internal TEXT TV (ready for
 * Cbor_Encode to wrap as CBOR mt3). */
Peerid_Format: procedure expose EC.
  parse arg key_type, hash_type, digest
  raw = Varint_Encode(key_type) || Varint_Encode(hash_type) || digest
  return Tv_MkText(Base58_Encode(raw))

/* Peerid_Parse: base58 peer_id string -> "key_type hash_type" (digest left in
 * EC.!PID_DIGEST). Throws on a bad char / truncated varint. */
Peerid_Parse: procedure expose EC.
  parse arg str
  raw = Base58_Decode(str)
  key_type = Varint_Decode(raw, 1)
  hash_type = Varint_Decode(raw, EC.!VPOS)
  EC.!PID_DIGEST = substr(raw, EC.!VPOS)
  return key_type hash_type
