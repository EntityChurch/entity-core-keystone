## URI normalization + tree-path / pattern matching (V8 §1.4, §5.4). Ported from
## the cohort reference (TypeScript `capability/paths.ts`) — CONFORMANCE-class
## logic: the exact steps may vary but the ALLOW/DENY outcome MUST match across
## impls. Canonicalization is one-directional (peer-relative → absolute); pattern
## matching operates on canonicalized absolute paths.
##
## The inbound EXECUTE `uri` arrives in the `entity://{peer_id}/{path}` scheme form
## (§1.4). `normalizeUri` strips the scheme to an absolute `/{peer_id}/{path}`; the
## dispatcher then canonicalizes + validates. A peer-relative caller target (no
## leading scheme/slash) resolves against the LOCAL peer.
##
## SPDX-License-Identifier: Apache-2.0

import ./errors

type PathError* = object of EcError   ## §1.4 malformed path → 400 at the boundary

const
  Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
  Scheme = "entity://"

proc normalizeUri*(uri: string): string =
  ## Strip the `entity://` scheme, producing an absolute path (§1.4).
  if uri.len >= Scheme.len and uri[0 ..< Scheme.len] == Scheme:
    "/" & uri[Scheme.len .. ^1]
  else:
    uri

proc isPeerId*(seg: string): bool =
  ## A Base58 peer_id is ≥46 chars and drawn from the Bitcoin alphabet (§8.5).
  if seg.len < 46: return false
  for ch in seg:
    if ch notin Base58Alphabet: return false
  true

proc contains2(s, sub: string): bool =
  ## `sub in s` without importing strutils (avoid a name clash surface).
  if sub.len == 0: return true
  var i = 0
  while i + sub.len <= s.len:
    if s[i ..< i + sub.len] == sub: return true
    inc i
  false

proc canonicalize*(path, localPeerId: string): string {.raises: [PathError].} =
  ## Resolve a peer-relative path to absolute form against the local peer (§5.4).
  ## Rejects empty segments, directory-relative, and bare peer-wildcard forms.
  if contains2(path, "//"):
    raise newException(PathError, "empty path segment (§1.4)")
  if path.len >= 2 and path[0 ..< 2] == "./":
    raise newException(PathError, "reserved: directory-relative path (§1.4)")
  if path.len >= 3 and path[0 ..< 3] == "../":
    raise newException(PathError, "reserved: directory-relative path (§1.4)")
  if path.len >= 2 and path[0 ..< 2] == "*/":
    raise newException(PathError, "ambiguous: use /*/rest for peer wildcard (§5.4)")
  if path.len > 0 and path[0] == '/':
    return path
  "/" & localPeerId & "/" & path

proc firstSegment(s: string): string =
  ## First `/`-delimited segment of `s` (with any leading `/` already stripped).
  var i = 0
  while i < s.len and s[i] != '/': inc i
  s[0 ..< i]

proc validateAbsolutePath*(path: string) {.raises: [PathError].} =
  ## Every canonicalized tree path MUST be absolute with a valid peer_id first
  ## segment (§5.4). NOT called on patterns (wildcard segments are not peer ids).
  if path.len == 0 or path[0] != '/':
    raise newException(PathError, "not absolute")
  let first = firstSegment(path[1 .. ^1])
  if not isPeerId(first):
    raise newException(PathError, "invalid peer_id segment")

proc validateCallerTarget*(target: string) {.raises: [PathError].} =
  ## Reject a caller-supplied tree target that violates §1.4 path validity
  ## (v7.72 §9.5a CORE-TREE-PATH-FLEX-1): any C0 control byte or DEL in a segment,
  ## or a leading-slash form whose first segment is not a valid peer_id.
  for ch in target:
    let code = int(ch)
    if code < 0x20 or code == 0x7f:
      raise newException(PathError, "control byte in path segment (§1.4)")
  if target.len > 0 and target[0] == '/':
    let first = firstSegment(target[1 .. ^1])
    if not isPeerId(first):
      raise newException(PathError, "leading / on caller target must name a peer_id (§1.4)")

proc dispatchPath*(uri, localPeerId: string): string {.raises: [PathError].} =
  ## Dispatch path resolution: normalize scheme, canonicalize, validate (§1.4).
  result = canonicalize(normalizeUri(uri), localPeerId)
  validateAbsolutePath(result)

proc extractPeer*(uri, localPeerId: string): string =
  ## The peer_id a uri targets; the local peer for short-form paths (§5.2).
  let normalized = normalizeUri(uri)
  let trimmed = if normalized.len > 0 and normalized[0] == '/': normalized[1 .. ^1] else: normalized
  let first = firstSegment(trimmed)
  if isPeerId(first): first else: localPeerId

proc isPattern*(path: string): bool = contains2(path, "*")

proc endsWith2(s, suf: string): bool =
  s.len >= suf.len and s[s.len - suf.len .. ^1] == suf

proc startsWith2(s, pre: string): bool =
  s.len >= pre.len and s[0 ..< pre.len] == pre

proc matchesPattern*(path, pattern: string): bool =
  ## Match a canonicalized path against a canonicalized pattern (§5.4).
  if pattern == "*": return true
  # Peer wildcard: /*/rest — match any peer's subtree.
  if startsWith2(pattern, "/*/"):
    let remainder = pattern[3 .. ^1]
    if path.len <= 1: return false
    var second = -1
    var i = 1
    while i < path.len:
      if path[i] == '/': second = i; break
      inc i
    if second < 0: return false
    return matchesPattern(path[second + 1 .. ^1], remainder)
  # Subtree: pattern/* — prefix match.
  if endsWith2(pattern, "/*"):
    let prefix = pattern[0 ..< pattern.len - 1]   # keep trailing '/', drop '*'
    return startsWith2(path, prefix)
  path == pattern

proc stripWildcard*(pattern: string): string =
  if endsWith2(pattern, "/*"): return pattern[0 ..< pattern.len - 2]
  if pattern == "*": return ""
  pattern

proc patternsOverlap*(a, b: string): bool =
  let pa = stripWildcard(a)
  let pb = stripWildcard(b)
  startsWith2(pa, pb) or startsWith2(pb, pa)
