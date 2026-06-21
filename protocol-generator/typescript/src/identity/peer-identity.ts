import { formatPeerId } from "../codec/peer-id.js";
import { type KeyAlgorithm, canonicalPeerIdParts, defaultKeyAlgorithm } from "../codec/key-types.js";
import { Entity } from "../model/index.js";
import { buildPeerEntity } from "./peer-entities.js";

/**
 * A local peer's cryptographic identity (V7 §1.5): a signature keypair of some
 * {@link keyType}, the derived Base58 peer id (§7.4 / §1.5 size-cutoff), the
 * materialized canonical `system/peer` entity (§3.5, §7.65), and that entity's
 * content hash — the *identity hash* used in the `author`, `granter`, `grantee`,
 * and `signer` reference fields throughout the protocol.
 *
 * The default key family is Ed25519 (the §9.1 floor); a non-default family (e.g.
 * Ed448) flows through the same paths via the {@link KeyAlgorithm} seam.
 */
export class PeerIdentity {
  readonly #seed: Uint8Array;

  private constructor(
    seed: Uint8Array,
    /** The key family backing this identity. */
    readonly keyType: KeyAlgorithm,
    /** Raw public key (32 bytes Ed25519, 57 bytes Ed448). */
    readonly publicKey: Uint8Array,
    /** Canonical Base58 peer id (§1.5). */
    readonly peerId: string,
    /** The materialized canonical `system/peer` entity for this identity. */
    readonly peerEntity: Entity,
  ) {
    this.#seed = seed;
  }

  /** The `key_type` name carried in `system/peer.data` (e.g. `"ed25519"`). */
  get keyTypeName(): string {
    return this.keyType.name;
  }

  /** Content hash of {@link peerEntity} — this identity's reference hash. */
  get identityHash(): Uint8Array {
    return this.peerEntity.contentHash;
  }

  /** Generate a fresh Ed25519 identity (the §9.1 floor) from a random seed. */
  static generate(): PeerIdentity {
    const seed = new Uint8Array(32);
    globalThis.crypto.getRandomValues(seed);
    return PeerIdentity.fromSeed(seed);
  }

  /** Construct an identity from a raw secret seed under a key family (default Ed25519). */
  static fromSeed(seed: Uint8Array, keyType: KeyAlgorithm = defaultKeyAlgorithm()): PeerIdentity {
    const publicKey = keyType.publicKeyFromSeed(seed);
    const peerId = PeerIdentity.derivePeerId(publicKey, keyType);
    const peerEntity = buildPeerEntity(keyType, publicKey);
    return new PeerIdentity(seed, keyType, publicKey, peerId, peerEntity);
  }

  /** Sign a message (full content-hash bytes) with this identity's private key (§7.3). */
  sign(message: Uint8Array): Uint8Array {
    return this.keyType.sign(this.#seed, message);
  }

  /**
   * Derive the canonical Base58 peer id from a raw public key under `keyType`
   * (§1.5 / §7.65): identity-multihash for keys that fit the ≤32-byte bound,
   * SHA-256-form otherwise.
   */
  static derivePeerId(publicKey: Uint8Array, keyType: KeyAlgorithm): string {
    const { hashType, digest } = canonicalPeerIdParts(publicKey);
    return formatPeerId(keyType.wireCode, hashType, digest);
  }
}
