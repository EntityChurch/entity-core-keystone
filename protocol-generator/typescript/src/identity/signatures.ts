import { keyAlgorithmByName } from "../codec/key-types.js";
import { EntityCodecError } from "../errors.js";
import { Entity, Ecf } from "../model/index.js";
import { peerPublicKey } from "./peer-entities.js";
import type { PeerIdentity } from "./peer-identity.js";

/**
 * Construct and verify `system/signature` entities (V7 §3.5, §7.3). Signatures
 * point *to* the content they sign (target-matching), are made over the full
 * `system/hash` bytes (format code + digest), and carry the `signer` field that
 * verification MUST check against the expected identity.
 */

const DEFAULT_ALGORITHM = "ed25519";

/**
 * Sign `target` with `signer`'s key and produce the detached `system/signature`
 * entity (§4.6 construction). The `algorithm` field records the signer's key
 * family so verification can dispatch the right verifier.
 */
export function signEntity(target: Entity, signer: PeerIdentity): Entity {
  const signatureBytes = signer.sign(target.contentHash);
  return buildSignature(target.contentHash, signer.identityHash, signatureBytes, signer.keyTypeName);
}

/** Materialize a `system/signature` entity from its parts. */
export function buildSignature(
  targetHash: Uint8Array,
  signerHash: Uint8Array,
  signatureBytes: Uint8Array,
  algorithm: string = DEFAULT_ALGORITHM,
): Entity {
  return Entity.create(
    "system/signature",
    Ecf.map(
      ["target", Ecf.bytes(targetHash)],
      ["signer", Ecf.bytes(signerHash)],
      ["algorithm", Ecf.text(algorithm)],
      ["signature", Ecf.bytes(signatureBytes)],
    ),
  );
}

export function signatureTarget(signature: Entity): Uint8Array {
  return Ecf.requireBytes(signature.data, "target");
}

export function signatureSigner(signature: Entity): Uint8Array {
  return Ecf.requireBytes(signature.data, "signer");
}

/**
 * Cryptographically verify a signature entity against the signer's peer entity.
 * Checks the algorithm and the signature over the signature's `target` bytes. The
 * caller is responsible for the `signer`-matches-expected-identity check (§3.5:
 * "Implementations MUST NOT skip this check").
 */
export function verifySignature(signature: Entity, signerPeer: Entity): boolean {
  if (signature.type !== "system/signature") {
    return false;
  }
  const algorithm = Ecf.optText(signature.data, "algorithm");
  if (algorithm === null) {
    return false;
  }

  let verifier;
  try {
    verifier = keyAlgorithmByName(algorithm);
  } catch (e) {
    if (e instanceof EntityCodecError) {
      return false; // unknown algorithm → not verifiable
    }
    throw e;
  }

  const target = signatureTarget(signature);
  const signatureBytes = Ecf.requireBytes(signature.data, "signature");
  const publicKey = peerPublicKey(signerPeer);
  return verifier.verify(publicKey, target, signatureBytes);
}
