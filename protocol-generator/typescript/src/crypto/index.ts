import { nobleProvider } from "./noble-provider.js";
import type { CryptoProvider, HashFunction, SignatureScheme } from "./provider.js";

export type { CryptoProvider, HashFunction, SignatureScheme } from "./provider.js";
export { nobleProvider } from "./noble-provider.js";

/**
 * The default crypto provider. Browser-portable `@noble` (A-001). Swap by passing
 * a different {@link CryptoProvider} to the codec/peer surfaces that accept one.
 */
export const defaultProvider: CryptoProvider = nobleProvider;

/**
 * Key-type registry (V7 §1.2 agility). Maps the peer-id `key_type` varint to a
 * signature scheme. Floor: 0x01 = ed25519. Agility: 0x02 = ed448.
 */
export function keyTypeToScheme(keyType: bigint, provider: CryptoProvider = defaultProvider): SignatureScheme | undefined {
  switch (keyType) {
    case 0x01n:
      return provider.ed25519;
    case 0x02n:
      return provider.ed448;
    default:
      return undefined;
  }
}

/**
 * Content-hash-format registry (ENTITY-CBOR-ENCODING §4.3). Maps the format-code
 * varint to a hash function. Floor (Required): 0x00 = ecfv1-sha256. Reserved
 * agility: 0x01 = sha384, 0x02 = sha512.
 */
export function hashFormatToFunction(formatCode: bigint, provider: CryptoProvider = defaultProvider): HashFunction | undefined {
  switch (formatCode) {
    case 0x00n:
      return provider.sha256;
    case 0x01n:
      return provider.sha384;
    case 0x02n:
      return provider.sha512;
    default:
      return undefined;
  }
}
