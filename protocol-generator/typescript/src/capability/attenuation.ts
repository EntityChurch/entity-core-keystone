import { type EcfValue } from "../codec/ecf-value.js";
import { encode } from "../codec/canonical-cbor.js";
import { bytesEqual } from "../codec/bytes.js";
import { Ecf } from "../model/index.js";
import { CapabilityToken } from "./capability-token.js";
import { GrantEntry } from "./grant-entry.js";
import { Scope } from "./scope.js";
import * as Paths from "./paths.js";

/**
 * Attenuation rules (V7 §5.6): a child capability MUST be ≤ its parent. All four
 * scope dimensions narrow; constraint keys are retained with byte-equal values;
 * allowance keys are only ever removed, never added. CONFORMANCE-class — the
 * ALLOW/DENY outcome is what must match across impls.
 */

/**
 * True if every grant in `requested` is covered by some grant in `authority`
 * (V7 §6.2 / §5.6): a peer issuing a capability MUST NOT grant scope exceeding the
 * caller's presented authority. The per-grant subset rule is the same one
 * delegation uses ({@link isAttenuated}); this surfaces it for the `request` op. A
 * failure is the §6.2 `scope_exceeds_authority` rejection.
 */
export function grantsWithinAuthority(
  requested: readonly GrantEntry[],
  authority: readonly GrantEntry[],
  localPeerId: string,
): boolean {
  // §6.2 mint-time subset check — the capability-handler surface, not the dispatch
  // chain walk. No V1'-family vector gates it; kept on the local frame
  // (child = parent = local) to preserve current behavior.
  for (const req of requested) {
    if (!grantCoveredBy(req, authority, localPeerId, localPeerId, localPeerId)) {
      return false;
    }
  }
  return true;
}

/**
 * §5.5a (Amendment 1): `childPeerId` / `parentPeerId` are the per-link granter
 * frames for canonicalizing each side's RESOURCE patterns in the subset-check.
 * Handlers/operations/peers stay on `localPeerId`. When child = parent = local
 * (same-peer chain) this is byte-identical to the pre-Amendment behavior.
 */
export function isAttenuated(
  child: CapabilityToken,
  parent: CapabilityToken,
  localPeerId: string,
  childPeerId: string,
  parentPeerId: string,
): boolean {
  // 1. Every child grant must be covered by some parent grant.
  for (const childGrant of child.grants) {
    if (!grantCoveredBy(childGrant, parent.grants, localPeerId, childPeerId, parentPeerId)) {
      return false;
    }
  }

  // 2. Child expiration must not exceed parent's (null = infinite).
  if (parent.expiresAt !== null) {
    if (child.expiresAt === null) {
      return false; // child infinite, parent finite (§5.6 nil-vs-finite)
    }
    if (child.expiresAt > parent.expiresAt) {
      return false;
    }
  }

  return true;
}

function grantCoveredBy(
  childGrant: GrantEntry,
  parentGrants: readonly GrantEntry[],
  localPeerId: string,
  childPeerId: string,
  parentPeerId: string,
): boolean {
  for (const parentGrant of parentGrants) {
    if (grantSubset(childGrant, parentGrant, localPeerId, childPeerId, parentPeerId)) {
      return true;
    }
  }
  return false;
}

function grantSubset(
  child: GrantEntry,
  parent: GrantEntry,
  localPeerId: string,
  childPeerId: string,
  parentPeerId: string,
): boolean {
  // §5.5a: only the RESOURCE dimension uses the per-link granter frames; the other
  // dimensions stay on the local frame.
  if (!scopeSubset(child.handlers, parent.handlers, localPeerId, localPeerId)) return false;
  if (!scopeSubset(child.operations, parent.operations, localPeerId, localPeerId)) return false;
  if (!scopeSubset(child.resources, parent.resources, childPeerId, parentPeerId)) return false;
  if (!scopeSubset(child.effectivePeers(localPeerId), parent.effectivePeers(localPeerId), localPeerId, localPeerId)) return false;

  // Constraint attenuation: parent keys retained + byte-equal values.
  if (!constraintsRetained(parent.constraints, child.constraints)) return false;

  // Allowance attenuation: child keys ⊆ parent keys + byte-equal values.
  if (!allowancesContained(child.allowances, parent.allowances)) return false;

  return true;
}

function scopeSubset(child: Scope, parent: Scope, childPeerId: string, parentPeerId: string): boolean {
  // Every child include pattern (child granter frame) must be covered by some parent
  // include (parent granter frame).
  for (const childPattern of child.include) {
    const cc = Paths.canonicalize(childPattern, childPeerId);
    const covered = parent.include.some((pp) => Paths.matchesPattern(cc, Paths.canonicalize(pp, parentPeerId)));
    if (!covered) {
      return false;
    }
  }

  // Child must inherit all parent excludes (parent frame vs child frame).
  if (parent.exclude !== null) {
    for (const parentEx of parent.exclude) {
      const cp = Paths.canonicalize(parentEx, parentPeerId);
      const childHas =
        child.exclude !== null &&
        child.exclude.some((ce) => Paths.matchesPattern(cp, Paths.canonicalize(ce, childPeerId)));
      if (!childHas) {
        return false;
      }
    }
  }
  return true;
}

function constraintsRetained(parentConstraints: EcfValue | null, childConstraints: EcfValue | null): boolean {
  const parent = asMap(parentConstraints);
  const child = asMap(childConstraints);
  if (parent === null || child === null) {
    return false; // defensive: reject non-map values
  }
  for (const [key, parentValue] of parent) {
    const childValue = child.get(key);
    if (childValue === undefined) {
      return false; // key dropped — escalation
    }
    if (!valuesEqual(parentValue, childValue)) {
      return false; // value changed
    }
  }
  return true;
}

function allowancesContained(childAllowances: EcfValue | null, parentAllowances: EcfValue | null): boolean {
  const child = asMap(childAllowances);
  const parent = asMap(parentAllowances);
  if (child === null || parent === null) {
    return false;
  }
  for (const [key, childValue] of child) {
    const parentValue = parent.get(key);
    if (parentValue === undefined) {
      return false; // key added — escalation
    }
    if (!valuesEqual(childValue, parentValue)) {
      return false;
    }
  }
  return true;
}

/** A null map is the unconstrained empty map (§3.6 absent-field defaults). */
function asMap(value: EcfValue | null): Map<string, EcfValue> | null {
  if (value === null) {
    return new Map();
  }
  if (value.kind !== "map") {
    return null;
  }
  const dict = new Map<string, EcfValue>();
  for (const [key, v] of Ecf.entries(value)) {
    dict.set(key, v);
  }
  return dict;
}

/** Byte equality over the canonical CBOR encoding of two values (§5.6). */
function valuesEqual(a: EcfValue, b: EcfValue): boolean {
  return bytesEqual(encode(a), encode(b));
}

/** Per-link delegation caveat enforcement (§5.7). */
export function checkDelegationCaveats(parent: CapabilityToken, child: CapabilityToken, depth: number): boolean {
  const caveats = parent.caveats;
  if (caveats === null) {
    return true;
  }
  if (caveats.noDelegation === true) {
    return false;
  }
  if (caveats.maxDelegationDepth !== null && BigInt(depth) >= caveats.maxDelegationDepth) {
    return false;
  }
  if (caveats.maxDelegationTtl !== null) {
    if (child.expiresAt === null) {
      return false; // infinite lifetime exceeds any finite limit
    }
    const childTtl = child.expiresAt - child.createdAt;
    if (childTtl > caveats.maxDelegationTtl) {
      return false;
    }
  }
  return true;
}
