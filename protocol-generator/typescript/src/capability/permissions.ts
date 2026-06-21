import { type Envelope, type Execute, type ResourceTarget } from "../model/index.js";
import { peerEntityId } from "../identity/index.js";
import { CapabilityToken } from "./capability-token.js";
import { Scope } from "./scope.js";
import * as Paths from "./paths.js";

/**
 * Permission checks (V7 §5.2, §6.3): the dispatch-level {@link checkPermission}
 * (handler + operation + peer + resource), the tree handler's defense-in-depth
 * {@link checkPathPermission}, and the full resource-scope check. Both levels must
 * pass for any data access (§5.4 two-level authorization).
 */

/**
 * §PR-8 (v7.73): the canonicalization frame for a cap's grant RESOURCE patterns is
 * the GRANTER's peer_id, not the verifier's. Single-sig granter → derive the
 * peer_id from its identity public_key; multi-sig granter (no single key) or an
 * unresolvable granter → the local peer (M3 root-only fallback). A bare `*` on a
 * foreign-granted cap thus means `/{granter}/*`, which does NOT reach the local
 * peer's namespace — closing the V2(a) cross-peer under-enforcement.
 */
export function resolveGranterPeerId(
  capability: CapabilityToken,
  envelope: Envelope,
  localPeerId: string,
): string {
  if (capability.granter === null) return localPeerId; // multi-sig → local
  const granter = envelope.find(capability.granter);
  if (granter === undefined) return localPeerId; // unresolvable → local
  try {
    return peerEntityId(granter);
  } catch {
    return localPeerId; // not a single-key identity → local
  }
}

/**
 * Dispatch-time permission check (§5.2). All matched dimensions must come from a
 * single grant entry. When `resource` is absent, the resource dimension is
 * unchecked here (the handler may still check internally). `granterPeerId` is the
 * §PR-8 frame for grant resource patterns only; operation/handler/peer dimensions
 * stay on the local frame. Per proposal §3.2.3 the v7.73 gate is this dispatch
 * boundary only.
 */
export function checkPermission(
  execute: Execute,
  capability: CapabilityToken,
  handlerPattern: string,
  localPeerId: string,
  granterPeerId: string,
): boolean {
  const operation = execute.operation;
  const targetPeer = Paths.extractPeer(execute.uri, localPeerId);
  const resourceTarget = execute.resource;

  for (const grant of capability.grants) {
    if (!grant.operations.matches(operation, localPeerId)) continue;
    if (!grant.handlers.matches(handlerPattern, localPeerId)) continue;
    if (!grant.effectivePeers(localPeerId).matches(targetPeer, localPeerId)) continue;
    if (resourceTarget !== null && !checkResourceScope(resourceTarget, grant.resources, localPeerId, granterPeerId)) continue;
    return true;
  }
  return false;
}

/**
 * Defense-in-depth path check used by the tree handler after dispatch (§6.3). Sole
 * resource enforcement when `resource` is absent.
 */
export function checkPathPermission(
  operation: string,
  path: string,
  capability: CapabilityToken,
  handlerPattern: string,
  localPeerId: string,
): boolean {
  const canonicalPath = Paths.canonicalize(path, localPeerId);
  for (const grant of capability.grants) {
    if (!grant.handlers.matches(handlerPattern, localPeerId)) continue;
    if (!grant.operations.matches(operation, localPeerId)) continue;
    if (!grant.resources.matches(canonicalPath, localPeerId)) continue;
    return true;
  }
  return false;
}

/**
 * Full resource-scope check (§5.2): the effective target scope (targets minus
 * caller excludes) must lie within the effective grant scope (includes minus grant
 * excludes).
 */
export function checkResourceScope(
  resourceTarget: ResourceTarget,
  grantResources: Scope,
  localPeerId: string,
  granterPeerId: string,
): boolean {
  const callerExclude = resourceTarget.exclude ?? [];
  const grantInclude = grantResources.include;
  const grantExclude = grantResources.exclude ?? [];

  for (const target of resourceTarget.targets) {
    // Request target canonicalizes on the local/request frame (§5.4).
    const ct = Paths.canonicalize(target, localPeerId);
    if (!Paths.isPattern(ct)) {
      Paths.validateAbsolutePath(ct);
    }

    // Caller-supplied excludes stay on the local/request frame.
    if (isCoveredBy(ct, callerExclude, localPeerId)) {
      continue;
    }

    // §PR-8: the grant's own resource patterns canonicalize on the GRANTER frame.
    if (!isCoveredBy(ct, grantInclude, granterPeerId)) {
      return false;
    }

    if (Paths.isPattern(ct)) {
      // Every overlapping grant exclude (granter frame) must be covered by a caller
      // exclude (local frame).
      for (const ge of grantExclude) {
        const cge = Paths.canonicalize(ge, granterPeerId);
        if (!Paths.patternsOverlap(ct, cge)) {
          continue;
        }
        if (!isCoveredBy(cge, callerExclude, localPeerId)) {
          return false;
        }
      }
    } else {
      // Concrete target must not be in grant exclude (granter frame).
      for (const ge of grantExclude) {
        if (Paths.matchesPattern(ct, Paths.canonicalize(ge, granterPeerId))) {
          return false;
        }
      }
    }
  }
  return true;
}

function isCoveredBy(pathOrPattern: string, patternSet: readonly string[], localPeerId: string): boolean {
  for (const p of patternSet) {
    if (Paths.matchesPattern(pathOrPattern, Paths.canonicalize(p, localPeerId))) {
      return true;
    }
  }
  return false;
}
