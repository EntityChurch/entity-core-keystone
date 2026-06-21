import { EntityProtocolError } from "../errors.js";

/**
 * URI normalization and path / pattern matching (V7 §1.4, §5.4). Canonicalization
 * is one-directional (peer-relative → absolute); pattern matching operates on
 * canonicalized absolute paths. This is CONFORMANCE-class logic (§7) — the exact
 * steps may vary but the ALLOW/DENY outcome must match across impls.
 */

/** Base58 (Bitcoin) alphabet — the legal character set for a peer id (§8.5). */
const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

const SCHEME = "entity://";

/** Strip the `entity://` scheme, producing an absolute path (§1.4). */
export function normalize(uri: string): string {
  return uri.startsWith(SCHEME) ? "/" + uri.slice(SCHEME.length) : uri;
}

/**
 * Resolve a peer-relative path to absolute form against the local peer (§5.4).
 * Rejects directory-relative and bare peer-wildcard forms.
 */
export function canonicalize(path: string, localPeerId: string): string {
  // §1.4: an empty path segment ("a//b") is malformed — every segment of a tree
  // path is a non-empty name. (Callers strip a single trailing '/' for listings
  // before canonicalizing, so an interior "//" is always an empty segment.)
  if (path.includes("//")) {
    throw new EntityProtocolError("empty path segment (§1.4)");
  }
  if (path.startsWith("./") || path.startsWith("../")) {
    throw new EntityProtocolError("reserved: directory-relative paths (§1.4)");
  }
  if (path.startsWith("*/")) {
    throw new EntityProtocolError("ambiguous: use /*/rest for peer wildcard patterns (§5.4)");
  }
  if (path.startsWith("/")) {
    return path;
  }
  return "/" + localPeerId + "/" + path;
}

/**
 * MUST hold for every canonicalized tree path: absolute, with a valid peer id as
 * its first segment (§5.4). NOT called on patterns (wildcard segments are not
 * valid peer ids).
 */
export function validateAbsolutePath(path: string): void {
  if (!path.startsWith("/")) {
    throw new EntityProtocolError("not absolute");
  }
  const segments = path.slice(1).split("/");
  if (segments.length === 0 || !isPeerId(segments[0]!)) {
    throw new EntityProtocolError("invalid peer_id segment");
  }
}

/**
 * Reject a caller-supplied tree target that violates §1.4 path validity (V7 v7.72
 * §9.5a CORE-TREE-PATH-FLEX-1): any C0 control byte (NUL included) or DEL in a
 * segment, or a leading-slash (absolute) form whose first segment is not a valid
 * peer_id. Peer-relative targets and legitimate cross-peer absolute paths pass
 * through. The `//` / `./` / `../` rejections live in {@link canonicalize}.
 */
export function validateCallerTarget(target: string): void {
  for (const ch of target) {
    const code = ch.charCodeAt(0);
    if (code < 0x20 || code === 0x7f) {
      throw new EntityProtocolError("control byte in path segment (§1.4)");
    }
  }
  if (target.startsWith("/")) {
    const rest = target.slice(1);
    const slash = rest.indexOf("/");
    const first = slash < 0 ? rest : rest.slice(0, slash);
    if (!isPeerId(first)) {
      throw new EntityProtocolError("leading / on caller-supplied path must name a peer_id (§1.4)");
    }
  }
}

/** Dispatch path resolution: normalize, canonicalize, validate (§1.4). */
export function dispatchPath(uri: string, localPeerId: string): string {
  const canonical = canonicalize(normalize(uri), localPeerId);
  validateAbsolutePath(canonical);
  return canonical;
}

export function isPeerId(segment: string): boolean {
  if (segment.length < 46) {
    return false;
  }
  for (const ch of segment) {
    if (!BASE58_ALPHABET.includes(ch)) {
      return false;
    }
  }
  return true;
}

export function isPattern(path: string): boolean {
  return path.includes("*");
}

/** Match a canonicalized path against a canonicalized pattern (§5.4). */
export function matchesPattern(path: string, pattern: string): boolean {
  if (pattern === "*") {
    return true;
  }

  // Peer wildcard: /*/rest — match any peer's subtree.
  if (pattern.startsWith("/*/")) {
    const remainder = pattern.slice(3);
    const secondSlash = path.length > 1 ? path.indexOf("/", 1) : -1;
    if (secondSlash < 0) {
      return false;
    }
    const pathRest = path.slice(secondSlash + 1);
    return matchesPattern(pathRest, remainder);
  }

  // Subtree: pattern/* — prefix match.
  if (pattern.endsWith("/*")) {
    const prefix = pattern.slice(0, -1); // keep trailing slash, drop '*'
    return path.startsWith(prefix);
  }

  return path === pattern;
}

/** Extract the prefix from a pattern for overlap comparison (§5.2). */
export function stripWildcard(pattern: string): string {
  if (pattern.endsWith("/*")) {
    return pattern.slice(0, -2);
  }
  if (pattern === "*") {
    return "";
  }
  return pattern;
}

/** True if any concrete path could match both patterns (§5.2). */
export function patternsOverlap(a: string, b: string): boolean {
  const prefixA = stripWildcard(a);
  const prefixB = stripWildcard(b);
  return prefixA.startsWith(prefixB) || prefixB.startsWith(prefixA);
}

/** Extract the peer id from a uri path; local peer for short-form paths (§5.2). */
export function extractPeer(uri: string, localPeerId: string): string {
  const normalized = normalize(uri);
  const trimmed = normalized.startsWith("/") ? normalized.slice(1) : normalized;
  const slash = trimmed.indexOf("/");
  const first = slash < 0 ? trimmed : trimmed.slice(0, slash);
  return isPeerId(first) ? first : localPeerId;
}
