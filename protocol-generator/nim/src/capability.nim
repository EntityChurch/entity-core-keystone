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
  # the POSITION is known and matchesPattern stays uniform over its operands.
  #
  # PATH-SCOPE ONLY (0.8.2.24, N2/N3), AND THAT IS THIS CLAUSE'S POSITION RATHER THAN A
  # TEST IT PERFORMS. §5.2's exclude loop tests the sentinel INSIDE
  # `if dimension_type == "system/capability/path-scope"` and §5.4 scopes its own
  # invalid-capability rule the same way -- "it does NOT reach `operations` or `peers`
  # [MUST]". The skId arm above RETURNS, so everything from here down is already inside
  # the path-scope arm and no extra term is needed; the structure is the scoping.
  #
  # An unscoped guard would run an id pattern through the §5.4 transforms purely to
  # classify it and then DENY THE WHOLE DIMENSION on a property unrelated to whether the
  # exclude carves anything out: an `operations` exclude of `*/apply` -- an ordinary
  # namespaced operation name -- path-canonicalizes to the sentinel and would deny every
  # operation. Over-denial, invisible on any well-formed grant. §5.4 does not leave the
  # id dimensions unprotected either: under the id-scope grammar every non-`*` pattern is
  # a literal, and a literal is never structurally unmatchable.
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

proc scopeSubset(child, parent: Scope; childPeerId, parentPeerId: string;
                 kind: ScopeKind): bool =
  ## §5.5a/§5.6 subset: every child include covered by some parent include, and every
  ## parent exclude inherited by some child exclude.
  ##
  ## TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16; `entity-core-formalization` K-7).
  ## §3.6's id-scope grammar binds the scope TYPE, not one function -- "An
  ## implementation on the canonicalizing reading is non-conformant and MUST adopt the
  ## literal matcher" -- so the rule F40 landed on `matches` reaches here too, with
  ## delegation-chain WIDENING named as the reason: on the canonicalizing reading a bare
  ## id include reads as covered by a path-form parent pattern it does not literally
  ## match, and a child grant comes out WIDER than its parent. `lean`'s differential put
  ## it at 2 of 64 include pairs and 2 of 64 exclude pairs, fail-closed, with a 16-pair
  ## control alphabet reporting 0 -- which is why every hand-tried example missed it.
  ##
  ## `kind` has NO DEFAULT and is named at every call site, because a default is how the
  ## next dimension inherits the wrong matcher silently: the original F40 defect. The
  ## per-link granter frames are meaningless on the id arm (an id pattern is never
  ## canonicalized) and are simply unread there.
  if kind == skId:
    for childPat in child.includes:
      var covered = false
      for pp in parent.includes:
        if matchesIdPattern(childPat, pp): covered = true; break
      if not covered: return false
    if parent.hasExclude:
      for parentEx in parent.excludes:
        var childHas = false
        if child.hasExclude:
          for ce in child.excludes:
            if matchesIdPattern(parentEx, ce): childHas = true; break
        if not childHas: return false
    return true
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
  # §5.5a: only the RESOURCE dimension uses the per-link granter frames; the others stay
  # on the local frame. The scope KIND is a property of the DIMENSION and is named here,
  # never defaulted (F50 / 0.8.2.16).
  if not scopeSubset(child.handlers, parent.handlers, localPeerId, localPeerId, skPath): return false
  if not scopeSubset(child.operations, parent.operations, localPeerId, localPeerId, skId): return false
  if not scopeSubset(child.resources, parent.resources, childPeerId, parentPeerId, skPath): return false
  if not scopeSubset(child.effectivePeers(localPeerId), parent.effectivePeers(localPeerId),
                     localPeerId, localPeerId, skId): return false
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

proc verifyCapabilityChainRootedAt*(cap: CapabilityToken; env: Envelope;
                                    localPeerId, rootPeerId: string; nowMs: uint64): bool

proc verifyCapabilityChain*(cap: CapabilityToken; env: Envelope; localPeerId: string; nowMs: uint64): bool =
  ## §5.5 dispatch-time chain verdict. True (ALLOW) only if the chain roots at the
  ## local peer (single-sig) or passes k-of-n (multi-sig root), every link's
  ## signature verifies, grantees resolve, temporal validity holds, and each
  ## delegation is a valid attenuation of its parent.
  verifyCapabilityChainRootedAt(cap, env, localPeerId, localPeerId, nowMs)

proc verifyCapabilityChainRootedAt*(cap: CapabilityToken; env: Envelope;
                                    localPeerId, rootPeerId: string; nowMs: uint64): bool =
  ## `verifyCapabilityChain` with the expected ROOT granter named separately from the
  ## verifying peer.
  ##
  ## §1.4's PD-2 presented-authority arm needs this: the credential it evaluates is
  ## minted by the TARGET peer, so root-trust is relaxed away from the local peer — and
  ## every other clause (per-link signatures, grantee resolution, temporal validity,
  ## attenuation, caveats) is unchanged. Parameterized rather than forked because a
  ## second copy of a chain walk is a second copy that drifts.
  ##
  ## A MULTI-SIGNATURE ROOT IS ONLY EVER VALID LOCALLY (§1.4, 0.8.2.19). When `rootPeerId`
  ## differs from `localPeerId` the quorum arm is REFUSED outright rather than verified:
  ## *minted by the target* means the target SOLELY minted it, and a K-of-N root is a
  ## GROUP's authority — its co-signers authorized it too. Accepting it would let any one
  ## signer's target confer the whole group's grant, which is E3/F66's over-acceptance.
  ## §5.5's M6 also requires the LOCAL peer in the signer set, so the quorum arm has no
  ## meaning in a foreign frame even on its own terms.
  let chainOpt = collectAuthorityChain(cap, env)
  if chainOpt.isNone: return false
  let chain = chainOpt.get
  let root = chain[^1]
  if root.isMultiSig:
    if rootPeerId != localPeerId: return false
    if not verifyMultiSigRoot(root, env, localPeerId, nowMs): return false
  else:
    let rootGranter = env.includedGet(root.granter)
    if rootGranter.isNone: return false
    let pid = peerEntityId(rootGranter.get)
    if pid.isNone or pid.get != rootPeerId: return false
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

proc effectiveTargets*(exec: Entity; localPeerId: string):
    tuple[survivors: seq[string], hadResource: bool] =
  ## §5.2's effective target list (0.8.2.20): the caller's OWN `resource.exclude`
  ## removes entries from `resource.targets` BEFORE anything else looks at the request.
  ##
  ## Survivors come back in the caller's OWN SPELLING, not canonicalized -- 0.8.2.21 is
  ## explicit that `effective_targets` yields raw survivors, and the distinction is
  ## load-bearing here because the value flows on to `store.getAt`, which canonicalizes
  ## for itself.
  ##
  ## `hadResource` says whether a `resource` carrying a `targets` key was present at
  ## all. An ABSENT resource and a resource whose every target was excluded are
  ## DIFFERENT REQUESTS for a resource-OPTIONAL operation (0.8.2.24, N7), not merely
  ## different inputs to one disposition.
  ##
  ## THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11): "where
  ## an implementation projects resource.targets onto the effective set ahead of the
  ## handler, that projection MUST NOT be lossy about its own emptiness -- narrow when
  ## narrowing leaves something, and retain the raw pair when narrowing would empty it."
  ## A proc returning only a seq cannot satisfy that: collapsing `[qA] exclude [qA]` to
  ## `@[]` deletes the two-empties discriminator before any handler can read it, and the
  ## handler's refusal arm becomes dead code only a WIRE drive can detect.
  ##
  ## "Every seam that narrows is exempted alike." This peer has exactly ONE narrowing
  ## seam -- this proc, called by the tree handler -- and §6.5's dispatch chain does not
  ## project: `dispatchOutcome` passes `resource` through untouched and `checkPermission`
  ## reads it for itself. There is no second door to keep in step.
  ##
  ## A PRESENT-BUT-ILL-TYPED `targets` IS **PRESENT**, with an empty survivor list:
  ## reporting it absent would serve the WIDER absent-case answer to a request that named
  ## a resource, which is N11's own defect one field over.
  ##
  ## The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4 rules it
  ## separately from the grant arm) and that is INHERITED here rather than restated:
  ## `canonicalize` answers the sentinel, `matchesPattern` then answers false, and the
  ## target simply survives.
  let v = exec.field("resource")
  if v == nil or v.kind != ekMap: return (newSeq[string](), false)
  if mapGet(v, "targets") == nil: return (newSeq[string](), false)
  let rt = exec.resourceTarget()
  if rt.isNone: return (newSeq[string](), false)
  var survivors: seq[string]
  for target in rt.get.targets:
    let ct = try: canonicalize(target, localPeerId) except PathError: NeverMatch
    var dropped = false
    for x in rt.get.exclude:
      let cx = try: canonicalize(x, localPeerId) except PathError: continue
      if matchesPattern(ct, cx): dropped = true; break
    if not dropped: survivors.add target
  (survivors, true)

proc checkPathPermission*(operation, path: string; cap: CapabilityToken;
                          handlerPattern, localPeerId: string): bool =
  ## §6.3's handler-level path check: may the caller touch `path` AS A TREE PATH, under
  ## `handlerPattern`, with `cap`?
  ##
  ## IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
  ## subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
  ## by caller-controlled input: a caller who excludes the one target its capability does
  ## not cover removes that target from `checkPermission`'s view entirely, and a handler
  ## that then acts on it has authorized nothing.
  ##
  ## THREE DIMENSIONS, NOT FOUR. `peers` is not consulted -- the path is local by
  ## construction here (§1.4's inbound rule refuses a foreign namespace at §6.5 step 3,
  ## before any handler runs), and §6.3's signature names only handlers, operations and
  ## resources.
  ##
  ## THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
  ## rather than a choice: §6.3's block reads `matches_scope(canonical_path,
  ## grant.resources, "path-scope", local_peer_id)` -- there is no granter parameter to
  ## pass. §5.5a governs chain ATTENUATION, where the subject is a PATTERN compared
  ## against a parent's pattern; this call site compares a CONCRETE LOCAL PATH.
  ##
  ## An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no
  ## tree paths) and DENIES every path here. A malformed path canonicalizes to the §5.4
  ## sentinel, which matches no grant, so it falls through to DENY rather than being
  ## matched against anything.
  let cp = try: canonicalize(path, localPeerId) except PathError: return false
  for grant in cap.grants:
    if not grant.handlers.matches(handlerPattern, localPeerId, skPath): continue
    if not grant.operations.matches(operation, localPeerId, skId): continue
    if not grant.resources.matches(cp, localPeerId, skPath): continue
    return true
  false


# ── §1.4 PD-2: outbound sub-dispatch authorization ────────────────────────────

proc peerRelativeOf*(uri: string): string =
  ## Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
  ##
  ## §1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree`
  ## and `entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's
  ## handler pattern to be the target uri's peer-relative path, because a grant names
  ## HANDLERS and a handler pattern never carries a peer segment. Matching a grant
  ## against the absolute or schemed form matches nothing, silently, which reads at the
  ## wire as an authority refusal.
  ##
  ## The first segment is dropped ONLY when it is a peer_id. A peer-relative
  ## `system/protocol/connect` must not lose `system` — the standing defect on
  ## `smalltalk` and `forth`, where an unconditional strip made every self-minted grant
  ## unusable while the handshake stayed green.
  let p = normalizeUri(uri)
  if p.len == 0 or p[0] != '/': return p
  let body = p[1 .. ^1]
  let slash = body.find('/')
  let first = if slash >= 0: body[0 ..< slash] else: body
  if isPeerId(first):
    result = if slash >= 0: body[slash + 1 .. ^1] else: ""
  else:
    result = body

proc grantPathFor*(localPeerId, pattern: string): string =
  ## Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
  ## tolerant of the pattern arriving absolute or peer-relative.
  ##
  ## §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
  ## the grant path is built from the PEER-RELATIVE one. The two are one segment apart and
  ## concatenating the wrong one yields a doubled peer segment whose lookup misses — which
  ## fails closed as "no handler grant" and is indistinguishable, at the wire, from a
  ## genuine authority refusal.
  let prefix = "/" & localPeerId & "/"
  # Open-coded rather than importing strutils: this module deliberately keeps its own
  # prefix test private to avoid the name-clash surface (see the note at scopeFromEcf).
  let rel =
    if pattern.len >= prefix.len and pattern[0 ..< prefix.len] == prefix:
      pattern[prefix.len .. ^1]
    else:
      pattern
  "/" & localPeerId & "/system/capability/grants/" & rel

proc targetMintedPeersRelaxation*(cred: CapabilityToken; env: Envelope;
                                  localPeerId, targetPeerId: string; nowMs: uint64;
                                  revoked: bool): tuple[ok: bool, scope: Option[Scope]] =
  ## Verify a presented reentry credential against §1.4's clauses. `ok` is "did every
  ## clause hold"; `scope` is the `peers` scope Dimension 4 relaxes to, and `none` there
  ## means "the target itself" (an absent `peers` dimension is the ordinary reentry shape:
  ## "you may dispatch back to me").
  ##
  ## THE PAIR IS THE POINT. A `none` scope is a legitimate RESULT, so a lone
  ## `Option[Scope]` would collapse it into "relaxes nothing" — the absent-vs-present
  ## conflation §6.2's CAP-6a records for temporal accessors, one layer up and in the
  ## direction that REFUSES a valid reentry.
  ##
  ## Every clause is required: the chain ROOT granter resolves to the TARGET peer and is
  ## NOT a multi-signature root; the LEAF grantee is the local peer; the chain is valid
  ## and not revoked.
  result = (false, none(Scope))
  if targetPeerId == localPeerId: return
  if not verifyCapabilityChainRootedAt(cred, env, localPeerId, targetPeerId, nowMs): return
  if revoked: return
  let ge = env.includedGet(cred.grantee)
  if ge.isNone: return
  let pid = peerEntityId(ge.get)
  if pid.isNone or pid.get != localPeerId: return
  if cred.grants.len == 0: return
  let g0 = cred.grants[0]
  result = (true, if g0.hasPeers: some(g0.peers) else: none(Scope))

proc checkOutboundSubDispatch*(handlerGrant: CapabilityToken; localPeerId, targetPeerId,
                               handlerPattern, operation: string;
                               resource: ResourceTarget;
                               relaxOk: bool; relaxScope: Option[Scope]): bool =
  ## §1.4's PD-2 gate: `check_permission` run before a locally-originated sub-dispatch
  ## LEAVES the peer, with all four dimensions applied.
  ##
  ## ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT
  ## decides all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension 1's
  ## pattern the target uri's PEER-RELATIVE path; and a valid capability MINTED BY THE
  ## TARGET PEER naming this peer as `grantee` relaxes Dimension 4 (`peers`) AND ONLY
  ## DIMENSION 4.
  ##
  ## *"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT a
  ## grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
  ## sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
  ## BYPASS it is distinguished from is a peer that treats the credential as a standalone
  ## authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
  ## obvious vectors agree under either reading, so the only input that separates them is
  ## a VALID credential presented to a handler whose own grant does NOT cover the request.
  ##
  ## `relaxOk == false` is the ambient arm (and equally a credential that failed a clause):
  ## Dimension 4 is decided by the handler's grant alone.
  for grant in handlerGrant.grants:
    if not grant.handlers.matches(handlerPattern, localPeerId, skPath): continue
    if not grant.operations.matches(operation, localPeerId, skId): continue
    if not checkResourceScope(resource, grant.resources, localPeerId, localPeerId): continue
    # Dimension 4. §5.2's default for an absent `peers` scope is
    # {include: [local_peer_id]}, so a foreign target fails unless this grant names it or
    # a target-minted credential relaxes it.
    if grant.effectivePeers(localPeerId).matches(targetPeerId, localPeerId, skId): return true
    if relaxOk:
      if relaxScope.isSome:
        if relaxScope.get.matches(targetPeerId, localPeerId, skId): return true
      else:
        return true   # absent `peers` on the credential relaxes to the granter
  false
