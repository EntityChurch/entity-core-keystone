## Capability model + Layer-1 verdict (V8 §3.6, §5.2, §5.4, §5.5, §5.6). Ported
## from the cohort reference (TypeScript `capability/*`) — CONFORMANCE-class: the
## ALLOW/DENY outcome MUST match across impls, so the scope-matching, chain-walk,
## attenuation, and §3.6 K-of-N multisig logic follow the reference exactly.
##
## Parsing is TOTAL (never throws on a malformed inbound token) — a bad shape
## yields a zero/empty structure that fails validation, so an adversarial EXECUTE
## rejects, never hangs (the §3.6 "never swallow the response" lesson).
##
## SPDX-License-Identifier: Apache-2.0

import std/[options, sets]
import ./ecf
import ./model
import ./identity
import ./paths

const MaxDepth* = 64          ## §5.5 collect_authority_chain / §4.10(b) default

# ── scope (system/capability/{path,id}-scope) ──────────────────────────────────

type Scope* = object
  includes*: seq[string]
  excludes*: seq[string]
  hasExclude*: bool

proc scopeFromEcf(v: EcValue): Scope =
  ## {include: [..], exclude?: [..]}. Absent include → empty (matches nothing).
  if v == nil or v.kind != ekMap: return Scope()
  let inc = mapGet(v, "include")
  if inc != nil and inc.kind == ekArray:
    for it in inc.arr:
      if it != nil and it.kind == ekText: result.includes.add it.t
  let exc = mapGet(v, "exclude")
  if exc != nil and exc.kind == ekArray:
    result.hasExclude = true
    for it in exc.arr:
      if it != nil and it.kind == ekText: result.excludes.add it.t

type ScopeKind* = enum
  ## Which §5.2 matcher a grant dimension uses (0.8.1, F40). Named at every call site --
  ## there is no default -- so a new one cannot inherit the wrong matcher silently, which
  ## is exactly the F40 defect.
  skId    ## operations, peers   -- system/capability/id-scope
  skPath  ## handlers, resources -- system/capability/path-scope

proc matchesIdPattern*(value, pattern: string): bool =
  ## §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard forms
  ## -- bare `*` and a trailing slash-star segment-prefix. None of the §5.4 path
  ## transforms apply, so a pattern carrying path syntax is matched as a literal string:
  ## a non-match, never a fault.
  if pattern == "*": return true
  if pattern.len >= 2 and pattern[^2 .. ^1] == "/*":
    # prefix keeps the slash; open-coded rather than importing strutils (paths.nim
    # keeps its own startsWith2 private to avoid the name-clash surface).
    let prefix = pattern[0 ..< pattern.len - 1]
    return value.len >= prefix.len and value[0 ..< prefix.len] == prefix
  value == pattern

proc matches*(s: Scope; value, localPeerId: string; kind: ScopeKind): bool =
  ## True if `value` is included and not excluded (§5.2 matches_scope). `kind` selects
  ## the matcher by scope type: skPath canonicalizes both sides, skId compares literally.
  ## The two MUST NOT be interchanged.
  if kind == skId:
    var matchedId = false
    for pattern in s.includes:
      if matchesIdPattern(value, pattern): matchedId = true; break
    if not matchedId: return false
    if s.hasExclude:
      for pattern in s.excludes:
        if matchesIdPattern(value, pattern): return false
    return true
  # AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
  # in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an
  # exclude (carves out nothing -> the grant is SILENTLY WIDER than its author wrote):
  # same value, same matcher, opposite safety direction, so the reading is chosen where
  # the POSITION is known and matchesPattern stays uniform over its operands. The guard
  # sits outside the scope-type dispatch, transcribing §5.2's loop literally.
  if s.hasExclude:
    for pattern in s.excludes:
      let cpx = try: canonicalize(pattern, localPeerId) except PathError: continue
      if cpx == NeverMatch: return false
  let cv = try: canonicalize(value, localPeerId) except PathError: return false
  var matched = false
  for pattern in s.includes:
    let cp = try: canonicalize(pattern, localPeerId) except PathError: continue
    if matchesPattern(cv, cp): matched = true; break
  if not matched: return false
  if s.hasExclude:
    for pattern in s.excludes:
      let cp = try: canonicalize(pattern, localPeerId) except PathError: continue
      if matchesPattern(cv, cp): return false
  true

# ── grant entry (system/capability/grant-entry) ────────────────────────────────

type GrantEntry* = object
  handlers*, resources*, operations*: Scope
  peers*: Scope
  hasPeers*: bool
  constraints*, allowances*: EcValue   ## nil = absent (unconstrained empty map)

proc grantFromEcf(v: EcValue): GrantEntry =
  if v == nil or v.kind != ekMap: return GrantEntry()
  result.handlers = scopeFromEcf(mapGet(v, "handlers"))
  result.resources = scopeFromEcf(mapGet(v, "resources"))
  result.operations = scopeFromEcf(mapGet(v, "operations"))
  let p = mapGet(v, "peers")
  if p != nil and p.kind == ekMap:
    result.hasPeers = true
    result.peers = scopeFromEcf(p)
  result.constraints = mapGet(v, "constraints")
  result.allowances = mapGet(v, "allowances")

proc effectivePeers*(g: GrantEntry; localPeerId: string): Scope =
  ## Peer scope, defaulting to the local peer only when absent (§3.6).
  if g.hasPeers: g.peers else: Scope(includes: @[localPeerId])

proc grantsFromArray(a: seq[EcValue]): seq[GrantEntry] =
  for v in a: result.add grantFromEcf(v)

proc parseGrants*(v: EcValue): seq[GrantEntry] =
  ## Parse a `grants` array EcValue (capability:request / policy-entry).
  if v != nil and v.kind == ekArray: grantsFromArray(v.arr) else: @[]

# ── multi-granter (system/capability/multi-granter, §3.6 M3) ───────────────────

type MultiSigGranter* = object
  signers*: seq[seq[byte]]
  threshold*: uint64

proc multiGranterFromEcf(v: EcValue): MultiSigGranter =
  if v == nil or v.kind != ekMap: return MultiSigGranter()
  let sf = mapGet(v, "signers")
  if sf != nil and sf.kind == ekArray:
    for it in sf.arr:
      if it != nil and it.kind == ekBytes: result.signers.add it.b
  let tf = mapGet(v, "threshold")
  if tf != nil and tf.kind == ekUint: result.threshold = tf.u

# ── capability token (system/capability/token) ─────────────────────────────────

type CapabilityToken* = object
  entity*: Entity
  valid*: bool                 ## false = wrong type / missing required fields
  grants*: seq[GrantEntry]
  granter*: seq[byte]          ## single-sig granter hash (empty when multiSig)
  multiGranter*: MultiSigGranter
  isMultiSig*: bool
  grantee*: seq[byte]
  parent*: seq[byte]
  hasParent*: bool
  createdAt*: uint64
  expiresAt*: uint64
  hasExpiresAt*: bool
  notBefore*: uint64
  hasNotBefore*: bool
  # delegation caveats
  hasCaveats*: bool
  noDelegation*: bool
  maxDelegationDepth*: uint64
  hasMaxDelegationDepth*: bool
  maxDelegationTtl*: uint64
  hasMaxDelegationTtl*: bool

proc temporalFieldsRepresentable*(e: Entity): bool =
  ## §6.2 CAP-6a: true when every temporal field on a RECEIVED token is either absent
  ## (legal) or representable as a uint64.
  ##
  ## This is the reader-side half of CAP-6 and it is where a peer fails OPEN.
  ## `uintField` answers `none` BOTH when a field is ABSENT and when it is PRESENT but
  ## not `ekUint` -- a negative integer (`ekNint`) or a bignum -- so parseToken left
  ## `hasExpiresAt = false` for a token carrying `expires_at: -1`, the expiry check was
  ## silently skipped, and the token was honored with 200. §6.2 CAP-6a is explicit:
  ## such a token "is malformed. A verifier MUST refuse it and MUST NOT treat the
  ## unrepresentable field as absent." An absent expires_at stays legal and is NOT
  ## rejected here.
  ##
  ## Refusal must be the §5.2 capability_denied disposition (a status-bearing
  ## response), never a decode-layer silent drop or a transport close.
  for key in ["expires_at", "not_before", "created_at"]:
    let v = e.field(key)
    if v == nil: continue            # absent is legal
    if v.kind != ekUint: return false  # present but not a uint64 => malformed
  true

proc parseToken*(e: Entity): CapabilityToken =
  ## Total parse of a system/capability/token entity (§3.6). `valid = false` on
  ## the wrong type or a missing required field — never raises.
  result.entity = e
  if e.typ != "system/capability/token": return
  let grantsV = e.field("grants")
  if grantsV == nil or grantsV.kind != ekArray: return
  result.grants = grantsFromArray(grantsV.arr)
  let granterV = e.field("granter")
  if granterV == nil: return
  if granterV.kind == ekBytes:
    result.granter = granterV.b
  elif granterV.kind == ekMap:
    result.isMultiSig = true
    result.multiGranter = multiGranterFromEcf(granterV)
  else: return
  let g = e.bytesField("grantee")
  if g.isNone: return
  result.grantee = g.get
  let c = e.uintField("created_at")
  if c.isNone: return
  result.createdAt = c.get
  let p = e.bytesField("parent")
  if p.isSome: result.parent = p.get; result.hasParent = true
  let ex = e.uintField("expires_at")
  if ex.isSome: result.expiresAt = ex.get; result.hasExpiresAt = true
  let nb = e.uintField("not_before")
  if nb.isSome: result.notBefore = nb.get; result.hasNotBefore = true
  let cav = e.field("delegation_caveats")
  if cav != nil and cav.kind == ekMap:
    result.hasCaveats = true
    let nd = mapGet(cav, "no_delegation")
    if nd != nil and nd.kind == ekBool: result.noDelegation = nd.boolean
    let md = mapGet(cav, "max_delegation_depth")
    if md != nil and md.kind == ekUint:
      result.maxDelegationDepth = md.u; result.hasMaxDelegationDepth = true
    let mt = mapGet(cav, "max_delegation_ttl")
    if mt != nil and mt.kind == ekUint:
      result.maxDelegationTtl = mt.u; result.hasMaxDelegationTtl = true
  result.valid = true

# ── signature discovery ────────────────────────────────────────────────────────

proc findSignature*(env: Envelope; targetHash: seq[byte]): Option[Entity] =
  for inc in env.included:
    if inc.entity.typ == "system/signature":
      let t = inc.entity.bytesField("target")
      if t.isSome and t.get == targetHash: return some(inc.entity)
  none(Entity)

proc signaturesTargeting(env: Envelope; targetHash: seq[byte]): seq[Entity] =
  for inc in env.included:
    if inc.entity.typ == "system/signature":
      let t = inc.entity.bytesField("target")
      if t.isSome and t.get == targetHash: result.add inc.entity

proc signatureSigner(sig: Entity): seq[byte] = sig.bytesField("signer").get(@[])

# ── granter peer_id frame resolution (§5.5a / §PR-8) ───────────────────────────

proc peerEntityId(peer: Entity): Option[string] =
  ## The Base58 peer_id of a system/peer entity, or none for a non-Ed25519 /
  ## keyless identity (→ the caller denies or falls back per the call site).
  let kt = peer.textField("key_type").get("ed25519")
  let pk = peer.bytesField("public_key")
  if kt != "ed25519" or pk.isNone or pk.get.len != 32: return none(string)
  some(peerIdOfPubkey(pk.get))

proc resolveGranterPeerId*(cap: CapabilityToken; env: Envelope; localPeerId: string): string =
  ## §PR-8 dispatch frame: single-sig granter → its peer_id; multi-sig /
  ## unresolvable / keyless → the local peer (M3 root-only fallback).
  if cap.isMultiSig: return localPeerId
  let g = env.includedGet(cap.granter)
  if g.isNone: return localPeerId
  let pid = peerEntityId(g.get)
  if pid.isSome: pid.get else: localPeerId

proc linkGranterPeerId(cap: CapabilityToken; env: Envelope; localPeerId: string): Option[string] =
  ## §5.5a per-link frame: multi-sig root → local; single-sig → derive; an
  ## unresolvable / keyless granter → none (hard-deny, never a silent fallback).
  if cap.isMultiSig: return some(localPeerId)
  let g = env.includedGet(cap.granter)
  if g.isNone: return none(string)
  peerEntityId(g.get)

# ── attenuation (§5.6) ─────────────────────────────────────────────────────────

proc valuesEqual(a, b: EcValue): bool =
  ## Byte equality over canonical ECF (§5.6). nil = the empty map.
  let ea = try: encode(if a == nil: mapV(@[]) else: a) except CatchableError: return false
  let eb = try: encode(if b == nil: mapV(@[]) else: b) except CatchableError: return false
  ea == eb

proc asPairs(v: EcValue): seq[EcPair] =
  if v == nil: return @[]
  if v.kind != ekMap: return @[]   # caller treats a non-map as escalation
  v.pairs

proc mapKeyVal(v: EcValue; key: string): EcValue = mapGet(v, key)

proc constraintsRetained(parent, child: EcValue): bool =
  ## Parent constraint keys retained in child with byte-equal values (§5.6).
  if (parent != nil and parent.kind != ekMap) or (child != nil and child.kind != ekMap):
    return false
  for p in asPairs(parent):
    if p.key == nil or p.key.kind != ekText: continue
    let cv = mapKeyVal(child, p.key.t)
    if cv == nil: return false
    if not valuesEqual(p.val, cv): return false
  true

proc allowancesContained(child, parent: EcValue): bool =
  ## Child allowance keys ⊆ parent keys, byte-equal values (§5.6).
  if (child != nil and child.kind != ekMap) or (parent != nil and parent.kind != ekMap):
    return false
  for c in asPairs(child):
    if c.key == nil or c.key.kind != ekText: continue
    let pv = mapKeyVal(parent, c.key.t)
    if pv == nil: return false
    if not valuesEqual(c.val, pv): return false
  true

proc scopeSubset(child, parent: Scope; childPeerId, parentPeerId: string): bool =
  for childPat in child.includes:
    let cc = try: canonicalize(childPat, childPeerId) except PathError: return false
    var covered = false
    for pp in parent.includes:
      let cp = try: canonicalize(pp, parentPeerId) except PathError: continue
      if matchesPattern(cc, cp): covered = true; break
    if not covered: return false
  if parent.hasExclude:
    for parentEx in parent.excludes:
      let cp = try: canonicalize(parentEx, parentPeerId) except PathError: continue
      var childHas = false
      if child.hasExclude:
        for ce in child.excludes:
          let cce = try: canonicalize(ce, childPeerId) except PathError: continue
          if matchesPattern(cp, cce): childHas = true; break
      if not childHas: return false
  true

proc grantSubset(child, parent: GrantEntry; localPeerId, childPeerId, parentPeerId: string): bool =
  if not scopeSubset(child.handlers, parent.handlers, localPeerId, localPeerId): return false
  if not scopeSubset(child.operations, parent.operations, localPeerId, localPeerId): return false
  if not scopeSubset(child.resources, parent.resources, childPeerId, parentPeerId): return false
  if not scopeSubset(child.effectivePeers(localPeerId), parent.effectivePeers(localPeerId),
                     localPeerId, localPeerId): return false
  if not constraintsRetained(parent.constraints, child.constraints): return false
  if not allowancesContained(child.allowances, parent.allowances): return false
  true

proc grantCoveredBy(child: GrantEntry; parents: seq[GrantEntry];
                    localPeerId, childPeerId, parentPeerId: string): bool =
  for p in parents:
    if grantSubset(child, p, localPeerId, childPeerId, parentPeerId): return true
  false

proc grantsWithinAuthority*(requested, authority: seq[GrantEntry]; localPeerId: string): bool =
  ## §6.2 mint-time subset check (capability:request): every requested grant must
  ## be covered by the caller's presented authority. Failure → scope_exceeds_authority.
  for req in requested:
    if not grantCoveredBy(req, authority, localPeerId, localPeerId, localPeerId): return false
  true

proc isAttenuated(child, parent: CapabilityToken; localPeerId, childPeerId, parentPeerId: string): bool =
  for cg in child.grants:
    if not grantCoveredBy(cg, parent.grants, localPeerId, childPeerId, parentPeerId): return false
  if parent.hasExpiresAt:
    if not child.hasExpiresAt: return false          # child infinite, parent finite
    if child.expiresAt > parent.expiresAt: return false
  true

proc checkDelegationCaveats(parent, child: CapabilityToken; depth: int): bool =
  if not parent.hasCaveats: return true
  if parent.noDelegation: return false
  if parent.hasMaxDelegationDepth and uint64(depth) >= parent.maxDelegationDepth: return false
  if parent.hasMaxDelegationTtl:
    if not child.hasExpiresAt: return false
    let childTtl = child.expiresAt - child.createdAt
    if childTtl > parent.maxDelegationTtl: return false
  true

# ── chain walk (§5.5) + multisig root (§3.6 M3 / §5.5 M4/M6) ───────────────────

proc collectAuthorityChain(cap: CapabilityToken; env: Envelope): Option[seq[CapabilityToken]] =
  var chain: seq[CapabilityToken]
  var current = cap
  var depth = 0
  while true:
    if depth > MaxDepth: return none(seq[CapabilityToken])   # ChainTooDeep
    chain.add current
    if not current.hasParent: return some(chain)             # root reached
    let parent = env.includedGet(current.parent)
    if parent.isNone: return none(seq[CapabilityToken])      # ChainUnreachable
    let pt = parseToken(parent.get)
    if not pt.valid: return none(seq[CapabilityToken])
    current = pt
    inc depth

proc exceedsMaxDepth*(cap: CapabilityToken; env: Envelope): bool =
  ## §4.10(b): true if the chain exceeds MaxDepth links (structural, no sig work).
  ## An unreachable parent is NOT a depth problem (→ false; denied later as 403).
  var current = cap
  var depth = 0
  while true:
    if depth > MaxDepth: return true
    if not current.hasParent: return false
    let parent = env.includedGet(current.parent)
    if parent.isNone: return false
    current = parseToken(parent.get)
    inc depth

proc hasDuplicateSigners(signers: seq[seq[byte]]): bool =
  var seen = initHashSet[string]()
  for s in signers:
    let h = hexLower(s)
    if seen.containsOrIncl(h): return true
  false

proc verifyMultiSigRoot(cap: CapabilityToken; env: Envelope; localPeerId: string; nowMs: uint64): bool =
  ## §3.6 M3 structure THEN §5.5 M4/M6 k-of-n (structure precedes sig-counting).
  let mg = cap.multiGranter
  if cap.hasParent: return false                       # root-only
  let n = mg.signers.len
  if n < 2: return false                               # a real quorum
  if mg.threshold < 2'u64 or mg.threshold > uint64(n): return false
  if hasDuplicateSigners(mg.signers): return false
  # §5.5 M6: the local peer MUST be one of the quorum signers.
  var localIn = false
  for s in mg.signers:
    let p = env.includedGet(s)
    if p.isSome:
      let pid = peerEntityId(p.get)
      if pid.isSome and pid.get == localPeerId: localIn = true; break
  if not localIn: return false
  # CAP-6a FIRST: the range checks below cannot tell "absent" from "present but not a
  # uint64", so on their own they would skip and honor the token (fail-open).
  if not temporalFieldsRepresentable(cap.entity): return false
  if cap.hasNotBefore and nowMs < cap.notBefore: return false
  if cap.hasExpiresAt and cap.expiresAt < nowMs: return false
  if env.includedGet(cap.grantee).isNone: return false
  # §5.5 M4: ≥ threshold distinct quorum members produced a valid signature.
  var valid = initHashSet[string]()
  for signerHash in mg.signers:
    let signerPeer = env.includedGet(signerHash)
    if signerPeer.isNone: continue
    for sig in signaturesTargeting(env, cap.entity.hash):
      if signatureSigner(sig) == signerHash and verifySignatureEntity(sig, signerPeer.get):
        valid.incl hexLower(signerHash); break
  uint64(valid.len) >= mg.threshold

proc verifyCapabilityChain*(cap: CapabilityToken; env: Envelope; localPeerId: string; nowMs: uint64): bool =
  ## §5.5 dispatch-time chain verdict. True (ALLOW) only if the chain roots at the
  ## local peer (single-sig) or passes k-of-n (multi-sig root), every link's
  ## signature verifies, grantees resolve, temporal validity holds, and each
  ## delegation is a valid attenuation of its parent.
  let chainOpt = collectAuthorityChain(cap, env)
  if chainOpt.isNone: return false
  let chain = chainOpt.get
  let root = chain[^1]
  if root.isMultiSig:
    if not verifyMultiSigRoot(root, env, localPeerId, nowMs): return false
  else:
    let rootGranter = env.includedGet(root.granter)
    if rootGranter.isNone: return false
    let pid = peerEntityId(rootGranter.get)
    if pid.isNone or pid.get != localPeerId: return false
  for i in 0 ..< chain.len:
    let current = chain[i]
    if current.isMultiSig:
      if i != chain.len - 1: return false             # multi-sig must be the root
      continue
    let sig = findSignature(env, current.entity.hash)
    if sig.isNone: return false
    let granter = env.includedGet(current.granter)
    if granter.isNone: return false
    if signatureSigner(sig.get) != current.granter: return false
    if not verifySignatureEntity(sig.get, granter.get): return false
    if env.includedGet(current.grantee).isNone: return false   # §5.5 PR-3
    # CAP-6a FIRST -- see temporalFieldsRepresentable. Must precede the two range
    # checks below, because those are the ones the absent/unrepresentable ambiguity
    # defeats.
    if not temporalFieldsRepresentable(current.entity): return false
    if current.hasNotBefore and nowMs < current.notBefore: return false
    if current.hasExpiresAt and current.expiresAt < nowMs: return false
    if i < chain.len - 1:
      let parent = chain[i + 1]
      if parent.grantee != current.granter: return false
      let childPid = linkGranterPeerId(current, env, localPeerId)
      let parentPid = linkGranterPeerId(parent, env, localPeerId)
      if childPid.isNone or parentPid.isNone: return false
      if not isAttenuated(current, parent, localPeerId, childPid.get, parentPid.get): return false
      if not checkDelegationCaveats(parent, current, i): return false
  true

# ── permission check (§5.2 / §5.4) ─────────────────────────────────────────────

proc checkResourceScope(rt: ResourceTarget; grantResources: Scope;
                        localPeerId, granterPeerId: string): bool =
  let grantInclude = grantResources.includes
  # An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
  # target: the coverage tests below are correct in isolation and are simply never
  # reached on a sentinel, because matchesPattern answers false.
  if grantResources.hasExclude:
    for ge in grantResources.excludes:
      let cge0 = try: canonicalize(ge, granterPeerId) except PathError: continue
      if cge0 == NeverMatch: return false
  for target in rt.targets:
    let ct = try: canonicalize(target, localPeerId) except PathError: return false
    # Caller-supplied excludes stay on the local frame.
    var excluded = false
    for e in rt.exclude:
      let ce = try: canonicalize(e, localPeerId) except PathError: continue
      if matchesPattern(ct, ce): excluded = true; break
    if excluded: continue
    # §PR-8: the grant's own resource patterns canonicalize on the GRANTER frame.
    var covered = false
    for gi in grantInclude:
      let cgi = try: canonicalize(gi, granterPeerId) except PathError: continue
      if matchesPattern(ct, cgi): covered = true; break
    if not covered: return false
    if grantResources.hasExclude:
      if isPattern(ct):
        for ge in grantResources.excludes:
          let cge = try: canonicalize(ge, granterPeerId) except PathError: continue
          if not patternsOverlap(ct, cge): continue
          var callerCovers = false
          for e in rt.exclude:
            let ce = try: canonicalize(e, localPeerId) except PathError: continue
            if matchesPattern(cge, ce): callerCovers = true; break
          if not callerCovers: return false
      else:
        for ge in grantResources.excludes:
          let cge = try: canonicalize(ge, granterPeerId) except PathError: continue
          if matchesPattern(ct, cge): return false
  true

proc checkPermission*(exec: Entity; cap: CapabilityToken; handlerPattern, localPeerId, granterPeerId: string;
                      resource: Option[ResourceTarget]): bool =
  ## Dispatch-time permission check (§5.2): all matched dimensions from a SINGLE
  ## grant entry. Resource dimension only checked when `resource` is present.
  let operation = exec.textField("operation").get("")
  let targetPeer = extractPeer(exec.textField("uri").get(""), localPeerId)
  for grant in cap.grants:
    if not grant.operations.matches(operation, localPeerId, skId): continue
    if not grant.handlers.matches(handlerPattern, localPeerId, skPath): continue
    if not grant.effectivePeers(localPeerId).matches(targetPeer, localPeerId, skId): continue
    if resource.isSome and not checkResourceScope(resource.get, grant.resources, localPeerId, granterPeerId):
      continue
    return true
  false

proc checkPathPermission*(operation, path: string; cap: CapabilityToken;
                          handlerPattern, localPeerId: string): bool =
  ## Defense-in-depth path check for the tree handler (§6.3); sole resource
  ## enforcement when `resource` is absent.
  let cp = try: canonicalize(path, localPeerId) except PathError: return false
  for grant in cap.grants:
    if not grant.handlers.matches(handlerPattern, localPeerId, skPath): continue
    if not grant.operations.matches(operation, localPeerId, skId): continue
    if not grant.resources.matches(cp, localPeerId, skPath): continue
    return true
  false
