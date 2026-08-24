/* entity-core-protocol-rexx — content-hash construction (ENTITY-CBOR-ENCODING §4.2):
 *
 *   content_hash = varint(format_code) || hash_alg(ECF({type, data}))
 *
 * Format code 0x00 = ecfv1-sha256 (the §9.1 floor); 0x01 = ecfv1-sha384 (agility).
 * The format_code is NOT part of the hashed basis — only {type, data} is hashed — and
 * its prefix is a multicodec LEB128 varint (N1). SHA crosses the C-ABI (the eccrypto
 * helper binary, A-RX-005); the ECF encoding is the pure-Rexx codec.
 */

/* Hash_Content: type string + arbitrary ECF `data` TV -> content_hash bytes.
 * `data` is any TV node (A-JAVA-010) — a map for protocol entities, a scalar
 * otherwise; NEVER assume a map here. */
Hash_Content: procedure expose EC.
  parse arg type, data, fmt
  if fmt == '' then fmt = 0
  basis = Ecf_Map('type', Ecf_Str(type), 'data', data)
  enc = Cbor_Encode(basis)
  if fmt == 1 then digest = Crypto_Sha384(enc)
  else digest = Crypto_Sha256(enc)
  return Varint_Encode(fmt) || digest
