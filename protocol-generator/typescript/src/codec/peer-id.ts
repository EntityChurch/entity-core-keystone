import { ByteWriter } from "./bytes.js";
import { base58Decode, base58Encode } from "./base58.js";
import { decodeLeb128, encodeLeb128 } from "./leb128.js";

/**
 * A parsed peer-id: `Base58(LEB128(keyType) ‖ LEB128(hashType) ‖ digest)`
 * (V7 §1.2 / §7.3). `keyType`/`hashType` are `bigint` so synthetic codes ≥ 0x80
 * (the multi-byte-varint forward-compat probe, `peer_id.3`) round-trip exactly.
 */
export interface PeerId {
  readonly keyType: bigint;
  readonly hashType: bigint;
  readonly digest: Uint8Array;
}

/** Format a peer-id string from its abstract components. */
export function formatPeerId(keyType: bigint, hashType: bigint, digest: Uint8Array): string {
  const writer = new ByteWriter();
  writer.pushBytes(encodeLeb128(keyType));
  writer.pushBytes(encodeLeb128(hashType));
  writer.pushBytes(digest);
  return base58Encode(writer.toBytes());
}

/** Parse a Base58 peer-id back into its components. */
export function parsePeerId(peerId: string): PeerId {
  const raw = base58Decode(peerId);
  const keyType = decodeLeb128(raw, 0);
  const hashType = decodeLeb128(raw, keyType.nextOffset);
  return {
    keyType: keyType.value,
    hashType: hashType.value,
    digest: raw.slice(hashType.nextOffset),
  };
}
