import { type CryptoProvider, defaultProvider } from "../crypto/index.js";
import { EntityCodecError } from "../errors.js";

/**
 * The `key_type` registry (V7 §1.5) — the key half of the crypto-agility seam
 * (RESYNC v7.56→v7.70 §3). Dispatch by code or by name; a second key family is a
 * registry entry, not a rewrite. The conformance floor (§9.1) is Ed25519
 * (`0x01`); Ed448 (`0x02`) is validated, not required — so a default peer never
 * leaves the Ed25519 path.
 *
 * Where the C# reference uses an `IKeyAlgorithm` interface bundling name +
 * wire-code + the crypto primitives, here the primitives already live on the S2
 * {@link CryptoProvider}'s `SignatureScheme`s; a {@link KeyAlgorithm} pairs a
 * scheme with the protocol-level metadata (wire code, peer-id derivation). One
 * provider supplies both Ed25519 and Ed448 (`@noble/curves`), so the seam is a
 * single dependency here.
 */

/** Ed25519 — production / §9.1 floor. */
export const ED25519_CODE = 0x01n;

/** Ed448 — validated (v7.67), not required. */
export const ED448_CODE = 0x02n;

/** Test-only path-exercise stub (v7.66) — synthetic key, no signing. */
export const EXPERIMENTAL_TEST_CODE = 0xfen;

/** Reserved per §1.5 — never a valid key_type. */
export const RESERVED_KEY_CODE = 0xffn;

/** The size cutoff (bytes) that selects the canonical peer_id form (§1.5). */
const IDENTITY_MULTIHASH_CUTOFF = 32;

/**
 * A signature key family: the entity-data `name` (§3.5), the `peer_id` wire-code
 * varint (§1.5), the raw public-key length, and the sign/verify primitives. The
 * primitives delegate to the provider's {@link CryptoProvider} scheme.
 */
export interface KeyAlgorithm {
  /** Entity-data form, e.g. `"ed25519"` / `"ed448"`. */
  readonly name: string;
  /** peer_id wire-prefix varint, e.g. `0x01` / `0x02`. */
  readonly wireCode: bigint;
  /** Raw public-key length in bytes (32 Ed25519, 57 Ed448). */
  readonly publicKeyLength: number;
  /** True if this family can sign/verify (false for the 0xFE non-crypto stub). */
  readonly canSign: boolean;
  publicKeyFromSeed(seed: Uint8Array): Uint8Array;
  sign(seed: Uint8Array, message: Uint8Array): Uint8Array;
  verify(publicKey: Uint8Array, message: Uint8Array, signature: Uint8Array): boolean;
}

function fromScheme(name: string, wireCode: bigint, provider: CryptoProvider): KeyAlgorithm {
  const scheme = name === "ed25519" ? provider.ed25519 : provider.ed448;
  return {
    name,
    wireCode,
    publicKeyLength: scheme.publicKeyLength,
    canSign: true,
    publicKeyFromSeed: (seed) => scheme.publicKeyFromSeed(seed),
    sign: (seed, message) => scheme.sign(seed, message),
    verify: (publicKey, message, signature) => scheme.verify(publicKey, message, signature),
  };
}

/**
 * The v7.66 `0xFE` test-only stub: a synthetic 64-byte key with no real crypto.
 * It exercises the per-key_type non-crypto paths (peer-entity construction,
 * content_hash, the >32-byte SHA-256-form peer_id) without a signing primitive.
 */
const experimentalTest: KeyAlgorithm = {
  name: "experimental-test",
  wireCode: EXPERIMENTAL_TEST_CODE,
  publicKeyLength: 64,
  canSign: false,
  publicKeyFromSeed() {
    throw new EntityCodecError("experimental-test key_type is a non-crypto path-exercise stub");
  },
  sign() {
    throw new EntityCodecError("experimental-test key_type cannot sign");
  },
  verify() {
    throw new EntityCodecError("experimental-test key_type cannot verify");
  },
};

/** The default key family for a freshly generated identity — the §9.1 floor. */
export function defaultKeyAlgorithm(provider: CryptoProvider = defaultProvider): KeyAlgorithm {
  return fromScheme("ed25519", ED25519_CODE, provider);
}

/** Resolve a key family by its wire `code` (§1.5). */
export function keyAlgorithmByCode(code: bigint, provider: CryptoProvider = defaultProvider): KeyAlgorithm {
  switch (code) {
    case ED25519_CODE:
      return fromScheme("ed25519", ED25519_CODE, provider);
    case ED448_CODE:
      return fromScheme("ed448", ED448_CODE, provider);
    case EXPERIMENTAL_TEST_CODE:
      return experimentalTest;
    case RESERVED_KEY_CODE:
      throw new EntityCodecError("reserved key_type 255 (§1.5)");
    default:
      throw new EntityCodecError(`unsupported_key_type: 0x${code.toString(16)}`);
  }
}

/** Resolve a key family by its entity-data `name` (§3.5). */
export function keyAlgorithmByName(name: string, provider: CryptoProvider = defaultProvider): KeyAlgorithm {
  switch (name) {
    case "ed25519":
      return fromScheme("ed25519", ED25519_CODE, provider);
    case "ed448":
      return fromScheme("ed448", ED448_CODE, provider);
    case "experimental-test":
      return experimentalTest;
    default:
      throw new EntityCodecError(`unsupported_key_type: '${name}'`);
  }
}

/**
 * The key-type names this peer accepts, for the §4.5 `hello.key_types`
 * advertisement. Ed25519 (the §1.5 floor) leads; Ed448 is the validated agility
 * family. The experimental-test family is not advertised.
 */
export const SUPPORTED_KEY_TYPE_NAMES: readonly string[] = ["ed25519", "ed448"];

/** True if `code` names a key family this peer can interpret. */
export function isSupportedKeyType(code: bigint): boolean {
  return code === ED25519_CODE || code === ED448_CODE || code === EXPERIMENTAL_TEST_CODE;
}

/**
 * True if `code` is a key family this peer will accept on the handshake — i.e.
 * one it can sign/verify with (Ed25519, Ed448). The 0xFE experimental-test stub
 * is interpretable but has no signing primitive, so it is *not* a valid
 * handshake identity: a peer_id carrying it (or any unallocated/reserved code) is
 * rejected at the earliest handshake boundary with `unsupported_key_type`
 * (v7.66 §4.4 surface 6 / V7 §4.7 registry pin).
 */
export function isHandshakeSupportedKeyType(code: bigint): boolean {
  return code === ED25519_CODE || code === ED448_CODE;
}

/**
 * The canonical `(hashType, digest)` for a peer_id under the V7 §1.5 size-cutoff
 * rule: a public key that fits the identity-multihash bound (≤ 32 bytes) is
 * embedded raw under `hash_type=0x00`; anything larger is SHA-256-hashed under
 * `hash_type=0x01`. Uniform across key families — Ed25519 (32 B) →
 * identity-multihash; Ed448 (57 B) / the 0xFE stub → SHA-256-form.
 */
export function canonicalPeerIdParts(
  publicKey: Uint8Array,
  provider: CryptoProvider = defaultProvider,
): { hashType: bigint; digest: Uint8Array } {
  if (publicKey.length <= IDENTITY_MULTIHASH_CUTOFF) {
    return { hashType: 0x00n, digest: publicKey };
  }
  return { hashType: 0x01n, digest: provider.sha256.digest(publicKey) };
}
