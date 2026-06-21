import { type Envelope, Entity, TypeNames, hashEqual, hashHex } from "../model/index.js";
import { peerEntityId, signatureSigner, signatureTarget, verifySignature } from "../identity/index.js";
import { CapabilityToken } from "./capability-token.js";
import { checkDelegationCaveats, isAttenuated } from "./attenuation.js";

/**
 * Layer-1 capability-chain verdict (V7 §5.5, §5.10). Collects the full authority
 * chain to its root, then validates each level: signatures, structural linkage,
 * grantee resolution, temporal validity, attenuation, and delegation caveats.
 *
 * This is the deterministic Layer-1 entry point (§5.10 / N8): it consults only the
 * chain and the envelope's `included` map — no local policy, no extension state —
 * so the verdict is identical across conformant peers given the same inputs.
 * Layer-2 local policy gates live above this, in the dispatcher.
 */

const MAX_DEPTH = 64; // §5.5 collect_authority_chain default

/**
 * §4.10(b) structural-bound pre-check: true if the authority chain rooted at `cap`
 * exceeds {@link MAX_DEPTH} links. Walks parent pointers in `included` without
 * verifying signatures — depth is a purely structural property, gated BEFORE the
 * per-link authz walk so an over-deep chain is reported as 400 `chain_depth_exceeded`
 * (structural excess), distinct from a 403 `capability_denied` authz failure (arch
 * ruling, v7.75 §4.10(b)). An unreachable parent is NOT a depth problem — it returns
 * false here and is left for {@link verifyCapabilityChain} to deny (403).
 */
export function exceedsMaxDepth(cap: CapabilityToken, envelope: Envelope): boolean {
  let current: CapabilityToken | null = cap;
  let depth = 0;
  while (current !== null) {
    if (depth > MAX_DEPTH) {
      return true;
    }
    if (current.parent === null) {
      return false; // root reached within bound
    }
    const parent = envelope.find(current.parent);
    if (parent === undefined) {
      return false; // unreachable — not a depth problem
    }
    current = new CapabilityToken(parent);
    depth++;
  }
  return false;
}

/** Find the signature targeting `targetHash` in `included` (§5.2). */
export function findSignature(envelope: Envelope, targetHash: Uint8Array): Entity | null {
  for (const entity of envelope.included.values()) {
    if (entity.type === TypeNames.Signature && hashEqual(signatureTarget(entity), targetHash)) {
      return entity;
    }
  }
  return null;
}

/**
 * Verify a capability chain at dispatch time (§5.5). Returns true (ALLOW) only if
 * the chain roots at the local peer, every link's signature verifies, every
 * grantee resolves, all links are temporally valid, and each delegation is a valid
 * attenuation of its parent.
 */
export function verifyCapabilityChain(
  capability: CapabilityToken,
  envelope: Envelope,
  localPeerId: string,
  nowMs: bigint,
): boolean {
  const chain = collectAuthorityChain(capability, envelope);
  if (chain === null) {
    return false; // ChainUnreachable / ChainTooDeep — fail closed
  }

  // Root authority: a single-sig root must root at the local peer; a multi-sig
  // root (§3.6 M3, root-only) must pass k-of-n quorum validation.
  const root = chain[chain.length - 1]!;
  if (root.isMultiSig) {
    if (!verifyMultiSigRoot(root, envelope, localPeerId, nowMs)) {
      return false;
    }
  } else {
    const rootGranter = envelope.find(root.granter!);
    if (rootGranter === undefined || peerEntityId(rootGranter) !== localPeerId) {
      return false;
    }
  }

  for (const [i, current] of chain.entries()) {
    // A multi-sig token is root-only and is fully verified above.
    if (current.isMultiSig) {
      if (i !== chain.length - 1) {
        return false; // multi-sig must be the chain root (§3.6 M3)
      }
      continue;
    }

    // Signature.
    const sig = findSignature(envelope, current.contentHash);
    if (sig === null) {
      return false;
    }
    const granter = envelope.find(current.granter!);
    if (granter === undefined) {
      return false;
    }
    if (!hashEqual(signatureSigner(sig), current.granter!)) {
      return false;
    }
    if (!verifySignature(sig, granter)) {
      return false;
    }

    // Grantee resolution — per-link (§5.5 PR-3). Unresolvable → 401.
    if (envelope.find(current.grantee) === undefined) {
      return false;
    }

    // Temporal validity.
    if (current.notBefore !== null && nowMs < current.notBefore) {
      return false;
    }
    if (current.expiresAt !== null && current.expiresAt < nowMs) {
      return false;
    }

    // Delegation (not for root — root has no parent).
    if (i < chain.length - 1) {
      const parent = chain[i + 1]!;
      if (!hashEqual(parent.grantee, current.granter!)) {
        return false;
      }
      // §5.5a: resolve each link's granter peer_id as the per-link frame for its
      // resource patterns. Hard-fail (deny) on an unresolvable granter rather than
      // fall back to the local frame (Amendment-1 §4 scrutiny).
      const childPeerId = linkGranterPeerId(current, envelope, localPeerId);
      const parentPeerId = linkGranterPeerId(parent, envelope, localPeerId);
      if (childPeerId === null || parentPeerId === null) {
        return false;
      }
      if (!isAttenuated(current, parent, localPeerId, childPeerId, parentPeerId)) {
        return false;
      }
      if (!checkDelegationCaveats(parent, current, i)) {
        return false;
      }
    }
  }

  return true;
}

/**
 * §5.5a per-link granter frame: the peer_id a chain link's resource patterns
 * canonicalize against. Single-sig granter → derive from its identity public_key;
 * multi-sig granter (root-only M3) → the local peer. Returns null when the granter
 * identity is unresolvable or keyless → the caller denies the chain walk (hard-fail
 * per Amendment-1 §4, never a silent fallback to the local frame).
 */
function linkGranterPeerId(cap: CapabilityToken, envelope: Envelope, localPeerId: string): string | null {
  if (cap.granter === null) {
    return localPeerId; // multi-sig root (M3) → local frame
  }
  const granter = envelope.find(cap.granter);
  if (granter === undefined) {
    return null; // unresolvable granter → deny
  }
  try {
    return peerEntityId(granter);
  } catch {
    return null; // present identity, no usable key → deny
  }
}

/**
 * Validate a multi-signature root capability (V7 §3.6 M3 / §5.5 M4/M6). Returns
 * true (ALLOW) only if the structure is well-formed AND a quorum signs. Structural
 * validation precedes signature counting (§3.6 precedence 25). Every failure path
 * returns false → the dispatcher maps it to 403 `capability_denied`.
 */
function verifyMultiSigRoot(cap: CapabilityToken, envelope: Envelope, localPeerId: string, nowMs: bigint): boolean {
  const mg = cap.multiGranter!;

  // §3.6 M3 structure — root-only; a real quorum (n ≥ 2); a usable threshold
  // (2 ≤ threshold ≤ n); distinct signers.
  if (cap.parent !== null) {
    return false;
  }
  const n = mg.signers.length;
  if (n < 2) {
    return false;
  }
  if (mg.threshold < 2n || mg.threshold > BigInt(n)) {
    return false;
  }
  if (hasDuplicateSigners(mg.signers)) {
    return false;
  }

  // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
  const localInSigners = mg.signers.some((s) => {
    const p = envelope.find(s);
    return p !== undefined && peerEntityId(p) === localPeerId;
  });
  if (!localInSigners) {
    return false;
  }

  // Temporal validity + grantee resolution (as for any root).
  if (cap.notBefore !== null && nowMs < cap.notBefore) {
    return false;
  }
  if (cap.expiresAt !== null && cap.expiresAt < nowMs) {
    return false;
  }
  if (envelope.find(cap.grantee) === undefined) {
    return false;
  }

  // §5.5 M4 k-of-n: at least `threshold` distinct quorum members produced a valid
  // signature over the cap's content hash.
  const validSigners = new Set<string>();
  for (const signerHash of mg.signers) {
    const signerPeer = envelope.find(signerHash);
    if (signerPeer === undefined) {
      continue;
    }
    for (const sig of signaturesTargeting(envelope, cap.contentHash)) {
      if (hashEqual(signatureSigner(sig), signerHash) && verifySignature(sig, signerPeer)) {
        validSigners.add(hashHex(signerHash));
        break;
      }
    }
  }
  return BigInt(validSigners.size) >= mg.threshold;
}

function hasDuplicateSigners(signers: readonly Uint8Array[]): boolean {
  const seen = new Set<string>();
  for (const s of signers) {
    const hex = hashHex(s);
    if (seen.has(hex)) {
      return true;
    }
    seen.add(hex);
  }
  return false;
}

/** All signature entities in `included` that target `targetHash`. */
function signaturesTargeting(envelope: Envelope, targetHash: Uint8Array): Entity[] {
  const out: Entity[] = [];
  for (const entity of envelope.included.values()) {
    if (entity.type === TypeNames.Signature && hashEqual(signatureTarget(entity), targetHash)) {
      out.push(entity);
    }
  }
  return out;
}

/**
 * Walk the authority chain from `cap` to root, resolving parents from the envelope
 * (§5.5 shared walker). Returns null on an unreachable parent or a chain exceeding
 * {@link MAX_DEPTH}.
 */
function collectAuthorityChain(cap: CapabilityToken, envelope: Envelope): CapabilityToken[] | null {
  const chain: CapabilityToken[] = [];
  let current: CapabilityToken | null = cap;
  let depth = 0;

  while (current !== null) {
    if (depth > MAX_DEPTH) {
      return null; // ChainTooDeep
    }
    chain.push(current);
    if (current.parent === null) {
      return chain; // root reached
    }
    const parent = envelope.find(current.parent);
    if (parent === undefined) {
      return null; // ChainUnreachable
    }
    current = new CapabilityToken(parent);
    depth++;
  }
  return chain;
}
