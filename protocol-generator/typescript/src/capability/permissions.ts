import { type Envelope, type Execute, type ResourceTarget } from "../model/index.js";
import { Ecf } from "../model/index.js";
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
    if (!grant.operations.matches(operation, localPeerId, "id")) continue;
    if (!grant.handlers.matches(handlerPattern, localPeerId, "path")) continue;
    if (!grant.effectivePeers(localPeerId).matches(targetPeer, localPeerId, "id")) continue;
    if (resourceTarget !== null && !checkResourceScope(resourceTarget, grant.resources, localPeerId, granterPeerId)) continue;
    return true;
  }
  return false;
}

/**
 * The result of {@link effectiveTargets}: the surviving targets and whether the EXECUTE
 * carried a `resource` AT ALL.
 *
 * THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES `[MUST]` (0.8.2.25, N11): *"where an
 * implementation projects `resource.targets` onto the effective set ahead of the handler,
 * that projection MUST NOT be lossy about its own emptiness — narrow when narrowing leaves
 * something, and retain the raw pair when narrowing would empty it."* A function returning
 * only a list cannot satisfy that: collapsing `[qA] exclude [qA]` to `[]` deletes the
 * two-empties discriminator before any handler can read it, and the handler's refusal arm
 * becomes dead code that only a WIRE drive can detect.
 */
export interface EffectiveTargets {
  readonly survivors: readonly string[];
  readonly hasResource: boolean;
}

/**
 * Canonicalize for a MATCHER position, where there is no error channel to consume a throw.
 *
 * {@link Paths.canonicalize} refuses an empty path segment (`a//b`) by throwing, and that
 * refusal is correct where it is an ADMISSION check — §1.4 forbids the segment and
 * `validateCallerTarget` is the site that answers the caller. In a matcher it is the error
 * return 0.8.2.20 removed: a pattern nobody can canonicalize simply does not match, and
 * NEVER_MATCH is the value that says so in either operand.
 */
function canonForMatch(pattern: string, frame: string): string {
  try {
    return Paths.canonicalize(pattern, frame);
  } catch {
    return Paths.NEVER_MATCH;
  }
}

/**
 * §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude` removes
 * entries from `resource.targets` BEFORE anything else looks at the request.
 *
 * The survivors are returned in the caller's OWN SPELLING, not canonicalized — 0.8.2.21 is
 * explicit that `effective_targets` yields raw survivors, and the distinction is
 * load-bearing because the value flows on to the tree lookup, which canonicalizes for
 * itself.
 *
 * READ OFF THE RAW `resource` VALUE, not through {@link ResourceTarget}. That class is an
 * ADMISSION parser: it throws for an absent or empty `targets` (§3.2's "MUST contain at
 * least one entry"), which is the right answer at the dispatch boundary and the wrong shape
 * here, where the §3.3 ladder has to tell "no resource" from "a resource whose every target
 * was excluded" and answer each with its own disposition.
 *
 * A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list. Reporting
 * it absent would serve the WIDER absent-case answer to a request that named a resource,
 * which is N11's own defect one field over.
 *
 * The caller-exclude arm is fail-OPEN on an unmatchable pattern — §5.4 rules it separately
 * from the grant arm — and that is INHERITED here rather than restated: the pattern
 * canonicalizes to NEVER_MATCH, {@link Paths.matchesPattern} then answers false, and the
 * target simply survives.
 *
 * *"Every seam that narrows is exempted alike."* This peer has exactly ONE narrowing seam —
 * this function, called by the tree handler — and §6.5's dispatch chain does not project:
 * the dispatcher passes the EXECUTE through untouched and `checkPermission` reads `resource`
 * for itself. There is no second door to keep in step, and adding a projection at dispatch
 * would create one.
 */
export function effectiveTargets(execute: Execute, localPeerId: string): EffectiveTargets {
  const none: EffectiveTargets = { survivors: [], hasResource: false };
  const raw = Ecf.field(execute.entity.data, "resource");
  if (raw === null || raw.kind !== "map") {
    return none;
  }
  const targetsField = Ecf.field(raw, "targets");
  if (targetsField === null) {
    return none;
  }
  const targets =
    targetsField.kind === "array"
      ? targetsField.items.flatMap((t) => (t.kind === "text" ? [t.value] : []))
      : [];
  const excludeField = Ecf.field(raw, "exclude");
  const exclude =
    excludeField !== null && excludeField.kind === "array"
      ? excludeField.items.flatMap((e) => (e.kind === "text" ? [e.value] : []))
      : [];
  const survivors = targets.filter((t) => {
    const ct = canonForMatch(t, localPeerId);
    return !exclude.some((x) => Paths.matchesPattern(ct, canonForMatch(x, localPeerId)));
  });
  return { survivors, hasResource: true };
}

/**
 * §6.3's handler-level path check.
 *
 * IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the subject
 * is derived after dispatch, and the dispatch-level check can be made VACUOUS by
 * caller-controlled input: a caller who excludes the one target its capability does not
 * cover removes that target from {@link checkPermission}'s view entirely, and a handler
 * that then acts on it has authorized nothing.
 *
 * THREE DIMENSIONS, NOT FOUR. `peers` is not consulted — the path is local by construction
 * at this point (§1.4's inbound rule refuses a foreign namespace at §6.5 step 3, before any
 * handler runs), and §6.3's signature names only handlers, operations and resources.
 *
 * THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature rather
 * than a choice: §6.3's block reads
 * `matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)` — there is
 * no granter parameter to pass. §5.5a governs chain ATTENUATION, where the subject is a
 * pattern compared against a parent's pattern; this call site compares a CONCRETE local path
 * the handler is about to touch.
 *
 * An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no tree
 * paths) and DENIES every path here, which is what that note says it should.
 */
export function checkPathPermission(
  operation: string,
  path: string,
  capability: CapabilityToken,
  handlerPattern: string,
  localPeerId: string,
): boolean {
  // Canonicalization is total in a matcher position (0.8.2.20): a malformed path answers
  // NEVER_MATCH, which matches no grant (§5.4), so it falls through to DENY rather than
  // being matched against anything — or, worse, escaping as a throw the §6.5 frame would
  // answer with the ADMISSION disposition.
  const canonicalPath = canonForMatch(path, localPeerId);
  for (const grant of capability.grants) {
    if (!grant.handlers.matches(handlerPattern, localPeerId, "path")) continue;
    if (!grant.operations.matches(operation, localPeerId, "id")) continue;
    if (!grant.resources.matches(canonicalPath, localPeerId, "path")) continue;
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

  // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
  // target: the coverage tests below are correct in isolation and are simply never
  // reached on a sentinel, because matchesPattern answers false.
  if (Paths.excludeIsUnmatchable(grantExclude, granterPeerId)) {
    return false;
  }

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
