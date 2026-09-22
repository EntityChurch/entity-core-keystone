## Peer machinery (V8 Layers 1–4): the §6.5 dispatch chain, the §4.1 connect
## responder (hello/authenticate + §4.5 negotiation), the full §5.2 verify_request
## (multi-link chain-walk + §3.6 K-of-N multisig), §5.2 check_permission, and the
## extension-free core handler bodies (tree / capability / handler / type) plus the
## §7a `--validate` conformance handlers (echo / dispatch-outbound reentry).
##
## §6.5 dispatch ORDER is load-bearing (F31 / auth-before-resolve): after the
## `system/protocol/connect` special case, the chain runs verify_request (§5.2)
## BEFORE resolving the handler. §5.2a verdict-to-status split (v7.73): auth-class
## → 401; authz-class → 403; a too-deep chain is STRUCTURAL → 400
## chain_depth_exceeded, checked BEFORE the per-link authz walk (§4.10(b)).
##
## The reentry seam (§6.11 / §6.13(b)) is an `OutboundSender` closure the transport
## supplies (peer.nim never imports transport — the one-way edge is preserved; the
## Future type comes from stdlib asyncdispatch).
##
## SPDX-License-Identifier: Apache-2.0

import std/[options, times, strutils, asyncdispatch]
import std/sysrand
import ./ecf
import ./model
import ./wire
import ./store
import ./identity
import ./crypto
import ./peer_id
import ./paths
import ./capability
import ./types

const
  MaxChainDepth = 64           ## §4.10(b) recommended default
  NonceLen = 32
  SupportedHashFormats = ["ecfv1-sha256"]
  SupportedKeyTypes = ["ed25519"]
  ProtocolVersion = "entity-core/1.0"

type
  Peer* = ref object
    identity*: Identity
    store*: Store
    localPeer*: string
    validate*: bool            ## §7a system/validate/* handlers enabled (--validate)
    openGrants*: bool          ## degenerate default→* seed policy (--debug-open-grants)

  Conn* = ref object
    established*: bool
    helloPeerId*: Option[string]
    issuedNonce*: seq[byte]
    outCounter*: int           ## per-connection reentry request_id counter

  Outcome* = tuple[status: uint64, result: Entity, included: seq[Included]]

  ## The §6.11 reentry sender the transport supplies to a handler (nil off-connection).
  OutboundSender* = proc(reqId: string; env: Envelope): Future[Envelope]

# ── small helpers ──────────────────────────────────────────────────────────────

proc nowMs(): uint64 = uint64(epochTime() * 1000.0)

proc randomNonce(): seq[byte] =
  result = newSeq[byte](NonceLen)
  discard urandom(result)

proc okOut(resultEntity: Entity): Outcome =
  (status: 200'u64, result: resultEntity, included: newSeq[Included]())

proc errOut(status: uint64; code: string; message = none(string)): Outcome =
  (status: status, result: errorResult(code, message), included: newSeq[Included]())

proc emptyAck(): Entity = makeEntity("primitive/any", mapV(@[]))

proc textArrayV(v: EcValue): seq[string] =
  if v != nil and v.kind == ekArray:
    for it in v.arr:
      if it != nil and it.kind == ekText: result.add it.t

proc isZeroHash(b: seq[byte]): bool =
  for x in b:
    if x != 0'u8: return false
  b.len > 0

proc abs(p: Peer; rel: string): string = "/" & p.localPeer & "/" & rel

# ── capability scope builders (§4.4 seed floor) ────────────────────────────────

proc pathScope(includes: openArray[string]): EcValue =
  var arr: seq[EcValue]
  for s in includes: arr.add textV(s)
  mapV(@[EcPair(key: textV("include"), val: arrV(arr))])

proc grantVal(handlers, resources, operations: openArray[string]): EcValue =
  mapV(@[
    EcPair(key: textV("handlers"), val: pathScope(handlers)),
    EcPair(key: textV("resources"), val: pathScope(resources)),
    EcPair(key: textV("operations"), val: pathScope(operations)),
  ])

proc discoveryFloorGrants(): seq[EcValue] =
  @[
    grantVal(["system/tree"], ["system/type/*", "system/handler/*"], ["get"]),
    grantVal(["system/capability"], [], ["request"]),
  ]

proc openGrantsGrants(): seq[EcValue] =
  @[grantVal(["*"], ["*", "/*/*"], ["*"])]

# ── token mint (§4.4 / §5.5 self-consistent root) ──────────────────────────────

## §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
## `createdAt`. Rule 3: a conversion that is not representable is treated as ABSENT
## exactly as a null term is -- it MUST NOT wrap and MUST NOT saturate to a
## representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
## bound no reader can distinguish from a deliberate one. Nim's uint64 `+` WRAPS, so
## the check is mandatory rather than decorative: without it an overflowing ttl mints
## an EARLIER expiry, which is what this peer was doing.
##
## `ttl == 0` is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
## yielding `createdAt` (expire immediately). The absent field is the only "no bound"
## spelling, and falling out of the arithmetic is what keeps the two from collapsing.
proc addTtl(createdAt, ttl: uint64): Option[uint64] =
  let sum = createdAt + ttl
  if sum < createdAt: none(uint64)   # uint64 wrap => not representable => drop
  else: some(sum)

## Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
##
## `expiresAt` none means no term was defined and the token genuinely has no expiry
## (the ONLY "no bound" spelling). A present value is emitted verbatim -- including one
## equal to `createdAt`, which §5.6 rule 2 requires for ttl_ms == 0.
##
## `createdAt` is supplied rather than sampled here so a computed expiry is guaranteed
## to be relative to the SAME instant that lands in the token; sampling the clock twice
## skews the two, which is what this peer was doing before.
proc mintTokenRaw(p: Peer; granteeHash: seq[byte]; grants: seq[EcValue];
                  expiresAt = none(uint64);
                  createdAt = nowMs()): tuple[token, signature: Entity] =
  var pairs = @[
    EcPair(key: textV("grants"), val: arrV(grants)),
    EcPair(key: textV("granter"), val: bytesV(p.identity.identityHash)),
    EcPair(key: textV("grantee"), val: bytesV(granteeHash)),
    EcPair(key: textV("created_at"), val: uintV(createdAt)),
  ]
  if expiresAt.isSome:
    pairs.add EcPair(key: textV("expires_at"), val: uintV(expiresAt.get))
  let token = makeEntity("system/capability/token", mapV(pairs))
  (token: token, signature: p.identity.signEntityHash(token))

# ── seed policy (§6.9a) ────────────────────────────────────────────────────────

proc materializeDefaultPolicy(p: Peer) =
  ## Write the `default` seed-policy entry at peer-init (§6.9a L0). --debug-open-grants
  ## routes through the real mechanism as a `default → *` policy-entry.
  let grants = if p.openGrants: openGrantsGrants() else: discoveryFloorGrants()
  let entry = makeEntity("system/capability/policy-entry", mapV(@[
    EcPair(key: textV("peer_pattern"), val: textV("default")),
    EcPair(key: textV("grants"), val: arrV(grants)),
  ]))
  p.store.bindAt(p.abs("system/capability/policy/default"), entry)

proc entryGrants(p: Peer; entry: Entity): seq[EcValue] =
  ## Grant EcValues from a matched seed-policy entry (§6.9a.0). A capability token
  ## is trusted only after its self-signature verifies; a policy-entry yields grants.
  if entry.typ == "system/capability/token":
    let sig = p.store.getAt(p.abs("system/signature/" & hexLower(entry.hash)))
    if sig.isNone or not verifySignatureEntity(sig.get, p.identity.peerEntity): return @[]
    let g = entry.field("grants")
    if g != nil and g.kind == ekArray: return g.arr
    return @[]
  if entry.typ == "system/capability/policy-entry":
    let g = entry.field("grants")
    if g != nil and g.kind == ekArray: return g.arr
  @[]

proc deriveSeedGrants(p: Peer; remotePeer: Entity; remotePeerId: string): seq[EcValue] =
  ## §6.9a authenticate-time derivation: dual-form lookup (hex → Base58 → default),
  ## UNION'd with the §4.4 discovery floor (v7.62 §8 — grant entries independent).
  let base = p.abs("system/capability/policy/")
  let hexKey = hexLower(remotePeer.hash)
  var entry = p.store.getAt(base & hexKey)
  if entry.isNone: entry = p.store.getAt(base & remotePeerId)
  if entry.isNone: entry = p.store.getAt(base & "default")
  let floor = discoveryFloorGrants()
  let policy = if entry.isNone: @[] else: p.entryGrants(entry.get)
  if policy.len == 0: floor else: floor & policy

# ── §4.1 connect responder (hello / authenticate + §4.5 negotiation) ───────────

proc peerIdKeyTypeOk(peerId: string): bool =
  ## Handshake-supported key family: Ed25519 (0x01) or Ed448 (0x02). An undecodable
  ## peer_id falls through (returns true — a later shape check surfaces it).
  try:
    let pid = peerIdParse(peerId)
    pid.keyType == 0x01'u64 or pid.keyType == 0x02'u64
  except CatchableError:
    true

proc connectHandler(p: Peer; conn: Conn; exec: Entity; env: Envelope): Outcome =
  let op = exec.textField("operation").get("")
  let paramsE = exec.entityField("params")
  if op == "hello":
    if conn.established: return errOut(409, "connection_already_established")
    if paramsE.isNone: return errOut(400, "connection_sequence_error")
    let pe = paramsE.get
    # §4.7: reject an unsupported peer_id key family up front (peer_canonicalization).
    let claimedPid = pe.textField("peer_id")
    if claimedPid.isSome and not peerIdKeyTypeOk(claimedPid.get):
      return errOut(400, "unsupported_key_type")
    # §4.5 negotiation: protocol / hash_format / key_type intersection.
    let protocols = textArrayV(pe.field("protocols"))
    if protocols.len > 0 and ProtocolVersion notin protocols:
      return errOut(400, "incompatible_protocol")
    let theirFormats = textArrayV(pe.field("hash_formats"))
    if theirFormats.len > 0:
      var overlap = false
      for f in SupportedHashFormats:
        if f in theirFormats: overlap = true; break
      if not overlap: return errOut(400, "incompatible_hash_format")
    let theirKeyTypes = textArrayV(pe.field("key_types"))
    if theirKeyTypes.len > 0 and SupportedKeyTypes[0] notin theirKeyTypes:
      return errOut(400, "unsupported_key_type")
    if claimedPid.isSome: conn.helloPeerId = claimedPid
    conn.issuedNonce = randomNonce()
    let hello = makeEntity("system/protocol/connect/hello", mapV(@[
      EcPair(key: textV("peer_id"), val: textV(p.localPeer)),
      EcPair(key: textV("nonce"), val: bytesV(conn.issuedNonce)),
      EcPair(key: textV("protocols"), val: arrV(@[textV(ProtocolVersion)])),
      EcPair(key: textV("hash_formats"), val: arrV(@[textV("ecfv1-sha256")])),
      EcPair(key: textV("key_types"), val: arrV(@[textV("ed25519")])),
      EcPair(key: textV("timestamp"), val: uintV(nowMs())),
    ]))
    return okOut(hello)
  elif op == "authenticate":
    if conn.established: return errOut(409, "connection_already_established")
    # FM-1 (§4.2, §4.7 row 6, 0.8.2.1): a pre-hello authenticate is a captured
    # authenticate replayed onto a fresh connection — 401 invalid_nonce, the same
    # status as the established-connection replay one line above, not a 400.
    if conn.issuedNonce.len == 0: return errOut(401, "invalid_nonce")
    if paramsE.isNone: return errOut(401, "authentication_failed")
    let a = paramsE.get
    let echoed = a.bytesField("nonce")
    if echoed.isNone or echoed.get != conn.issuedNonce: return errOut(401, "invalid_nonce")
    let claimed = a.textField("peer_id")
    # §4.7: an unsupported claimed key family → 400 BEFORE identity binding (AGILITY-UNKNOWN-1).
    if claimed.isSome and not peerIdKeyTypeOk(claimed.get):
      return errOut(400, "unsupported_key_type")
    let ktField = a.textField("key_type")
    if ktField.isSome and ktField.get notin ["ed25519", "ed448"]:
      return errOut(400, "unsupported_key_type")
    let pub = a.bytesField("public_key")
    if pub.isNone or pub.get.len != 32: return errOut(400, "unsupported_key_type")
    let sig = findSignature(env, a.hash)
    if sig.isNone: return errOut(401, "authentication_failed")
    let sigB = sig.get.bytesField("signature")
    if sigB.isNone or sigB.get.len != 64: return errOut(401, "authentication_failed")
    if not ed25519Verify(pub.get, sigB.get, a.hash): return errOut(401, "authentication_failed")
    let derived = peerIdOfPubkey(pub.get)
    if claimed.isNone or claimed.get != derived: return errOut(401, "identity_mismatch")
    if conn.helloPeerId.isSome and conn.helloPeerId.get != claimed.get:
      return errOut(401, "identity_mismatch")
    let remotePeer = peerEntityOfPubkey(pub.get)
    let grants = deriveSeedGrants(p, remotePeer, claimed.get)
    let minted = mintTokenRaw(p, remotePeer.hash, grants)
    conn.established = true
    let grant = makeEntity("system/capability/grant", mapV(@[
      EcPair(key: textV("token"), val: bytesV(minted.token.hash)),
    ]))
    return (status: 200'u64, result: grant, included: @[
      (key: minted.token.hash, entity: minted.token),
      (key: p.identity.identityHash, entity: p.identity.peerEntity),
      (key: remotePeer.hash, entity: remotePeer),
      (key: minted.signature.hash, entity: minted.signature),
    ])
  return errOut(501, "unsupported_operation", some(op))

# ── §6.5 signature ingestion ────────────────────────────────────────────────────

proc ingestSignatures(p: Peer; env: Envelope) =
  for inc in env.included:
    if inc.entity.typ == "system/signature":
      p.store.put(inc.entity)
      let signer = inc.entity.bytesField("signer")
      let target = inc.entity.bytesField("target")
      if signer.isNone or target.isNone: continue
      var signerPeer = p.store.getHash(signer.get)
      if signerPeer.isNone:
        signerPeer = env.includedGet(signer.get)
        if signerPeer.isNone: continue
        p.store.put(signerPeer.get)
      let pk = signerPeer.get.bytesField("public_key")
      if pk.isNone or pk.get.len != 32: continue
      let pid = peerIdOfPubkey(pk.get)
      let path = "/" & pid & "/system/signature/" & hexLower(target.get)
      if p.store.getAt(path).isNone:
        p.store.bindAt(path, inc.entity)

# ── §5.2 verify_request (auth-before-resolve; §5.2a status split) ──────────────

type VerifyResult = object
  status: uint64
  code: string
  cap: CapabilityToken
  ok: bool

proc deny(status: uint64; code: string): VerifyResult =
  VerifyResult(status: status, code: code, ok: false)

proc isChainRevoked(p: Peer; leaf: CapabilityToken; env: Envelope): bool =
  var current = leaf
  var depth = 0
  while depth <= MaxChainDepth:
    let path = p.abs("system/capability/revocations/" & hexLower(current.entity.hash))
    if p.store.getAt(path).isSome: return true
    if not current.hasParent: break
    let parent = env.includedGet(current.parent)
    if parent.isNone: break
    current = parseToken(parent.get)
    inc depth
  false

proc verifyRequest(p: Peer; exec: Entity; env: Envelope): VerifyResult =
  let authorHash = exec.bytesField("author").get(@[])
  let capHash = exec.bytesField("capability").get(@[])
  # Integrity: signature over the EXECUTE, signer == author, author resolvable.
  let sig = findSignature(env, exec.hash)
  if sig.isNone: return deny(401, "invalid_signature")
  if sig.get.bytesField("signer").get(@[]) != authorHash: return deny(401, "invalid_signature")
  let author = env.includedGet(authorHash)
  if author.isNone: return deny(401, "unresolvable_author")
  if not verifySignatureEntity(sig.get, author.get): return deny(401, "invalid_signature")
  # Capability integrity.
  let capEntity = env.includedGet(capHash)
  if capEntity.isNone: return deny(403, "capability_denied")
  let cap = parseToken(capEntity.get)
  if not cap.valid: return deny(403, "capability_denied")
  # §5.2 401 carve-out: the leaf grantee MUST resolve to a system/peer entity.
  let grantee = env.includedGet(cap.grantee)
  if grantee.isNone or grantee.get.typ != "system/peer":
    return deny(401, "unresolvable_grantee")
  if cap.grantee != authorHash: return deny(403, "capability_denied")
  # §4.10(b) structural depth pre-check BEFORE the per-link authz walk.
  if exceedsMaxDepth(cap, env): return deny(400, "chain_depth_exceeded")
  if not verifyCapabilityChain(cap, env, p.localPeer, nowMs()): return deny(403, "capability_denied")
  if p.isChainRevoked(cap, env): return deny(403, "capability_revoked")
  VerifyResult(status: 200, code: "", cap: cap, ok: true)

# ── §6.6 handler resolution (longest-prefix; returns the RELATIVE pattern) ─────

proc resolveHandler(p: Peer; path: string): Option[string] =
  var segs = path.split('/')
  while segs.len > 1:
    let prefix = segs.join("/")
    let e = p.store.getAt(prefix)
    if e.isSome and e.get.typ == "system/handler":
      # strip "/{localPeer}/" → the relative pattern
      let leading = "/" & p.localPeer & "/"
      if prefix.len > leading.len and prefix.startsWith(leading):
        return some(prefix[leading.len .. ^1])
      return some(prefix)
    segs.setLen(segs.len - 1)
  none(string)

# ── core handler bodies (§6.3 tree, §6.2 capability, §6.13 handler) ────────────

proc treeGet(p: Peer; params: Entity; cap: CapabilityToken; rt: ResourceTarget; pattern: string): Outcome =
  let target = rt.targets[0]
  try: validateCallerTarget(target)
  except PathError: return errOut(400, "invalid_path")
  if target.len == 0 or target[^1] == '/':
    var raw = target
    while raw.len > 0 and raw[^1] == '/': raw.setLen(raw.len - 1)
    let prefix = (try: canonicalize(raw, p.localPeer) except PathError: return errOut(400, "invalid_path"))
    var entries: seq[EcPair]
    var count = 0'u64
    for child in p.store.listChildren(prefix):
      let entryPath = prefix & "/" & child.name
      if not checkPathPermission("get", entryPath, cap, pattern, p.localPeer): continue
      var hv = if child.hasHash: bytesV(child.hash) else: nullV()
      # §6.3 / v7.72 §9.5a CORE-TREE-DELETE-1: a child bound to a
      # system/deletion-marker reads as absent (omit a marked leaf); a marker that
      # still prefixes deeper live paths survives as a pure branch (hash=null).
      if child.hasHash:
        let bound = p.store.getAt(entryPath)
        if bound.isSome and bound.get.typ == "system/deletion-marker":
          if not child.hasChildren: continue
          hv = nullV()
      entries.add EcPair(key: textV(child.name), val: mapV(@[
        EcPair(key: textV("hash"), val: hv),
        EcPair(key: textV("has_children"), val: boolV(child.hasChildren)),
      ]))
      inc count
    let listing = makeEntity("system/tree/listing", mapV(@[
      EcPair(key: textV("path"), val: textV(prefix)),
      EcPair(key: textV("entries"), val: mapV(entries)),
      EcPair(key: textV("count"), val: uintV(count)),
      EcPair(key: textV("offset"), val: uintV(0)),
    ]))
    return okOut(listing)
  let path = (try: canonicalize(target, p.localPeer) except PathError: return errOut(400, "invalid_path"))
  if not checkPathPermission("get", path, cap, pattern, p.localPeer):
    return errOut(403, "capability_denied")
  let mode = params.textField("mode").get("entity")
  let ent = p.store.getAt(path)
  if ent.isNone: return errOut(404, "not_found")
  if mode == "hash":
    return okOut(makeEntity("primitive/any", bytesV(ent.get.hash)))
  okOut(ent.get)

proc treePut(p: Peer; params: Entity; cap: CapabilityToken; rt: ResourceTarget; pattern: string): Outcome =
  let target = rt.targets[0]
  try: validateCallerTarget(target)
  except PathError: return errOut(400, "invalid_path")
  let path = (try: canonicalize(target, p.localPeer) except PathError: return errOut(400, "invalid_path"))
  if not checkPathPermission("put", path, cap, pattern, p.localPeer):
    return errOut(403, "capability_denied")
  let entityV = params.field("entity")
  let expected = params.bytesField("expected_hash")
  if entityV == nil or entityV.kind == ekNull:
    # Removal (§6.3), CAS-checked when a non-zero expected_hash is present.
    if expected.isSome and not isZeroHash(expected.get):
      let cur = p.store.getAt(path)
      if cur.isNone or cur.get.hash != expected.get:
        return errOut(409, "hash_mismatch")
    p.store.removeAt(path)
    return okOut(emptyAck())
  var ent: Entity
  try: ent = entityOfValue(entityV)
  except CatchableError: return errOut(400, "invalid_entity")
  # §3.9 / v7.72 §9.5a CAS: a ZERO expected_hash is CREATE-ONLY (path must be
  # currently unbound → 409 if it exists); a non-zero expected_hash must match the
  # current binding (§CORE-TREE-PUT-CAS-1).
  if expected.isSome:
    let cur = p.store.getAt(path)
    if isZeroHash(expected.get):
      if cur.isSome: return errOut(409, "hash_mismatch")
    else:
      if cur.isNone or cur.get.hash != expected.get: return errOut(409, "hash_mismatch")
  p.store.bindAt(path, ent)
  okOut(emptyAck())

proc capabilityRequest(p: Peer; exec, params: Entity; cap: CapabilityToken; env: Envelope): Outcome =
  let authorHash = exec.bytesField("author").get(@[])
  let granteePeer = env.includedGet(authorHash)
  if granteePeer.isNone: return errOut(400, "unresolvable_grantee")
  let requestedV = params.field("grants")
  let requested = parseGrants(requestedV)
  if not grantsWithinAuthority(requested, cap.grants, p.localPeer):
    return errOut(403, "scope_exceeds_authority")
  # §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6).
  #
  # This peer already had a ceiling, and it was WRONG IN THREE WAYS -- which is why a
  # partial implementation is worse than an absent one: it produced a plausible value
  # and read as done. (a) It carried only the request's ttl_ms term and never the
  # caller capability's absolute expiry, so an over-long ttl minted a token that
  # OUTLIVED the capability authorizing it (measured: expires_at 2102711331804 against
  # a caller cap of 1787354931804 -- 10 years past its own authority). (b) It sampled
  # nowMs() here and AGAIN inside mintTokenRaw for created_at, so the emitted
  # created_at and the expiry computed from it were two different instants. (c)
  # `nowMs() + ttl.get` WRAPS on uint64, so an overflowing ttl minted an EARLIER
  # expiry rather than dropping the term -- §5.6 rule 3 forbids exactly that.
  #
  # Note what this is NOT: an authorization decision. An over-long ttl_ms from a
  # bounded caller MINTS a clamped token and returns 200 -- "rejecting it is
  # non-conformant" (§5.6).
  let createdAt = nowMs()
  var ceiling = none(uint64)
  proc fold(term: Option[uint64]) =
    if term.isSome and (ceiling.isNone or term.get < ceiling.get):
      ceiling = term
  if cap.hasExpiresAt: fold(some(cap.expiresAt))          # absolute
  let ttl = params.uintField("ttl_ms")
  if ttl.isSome: fold(addTtl(createdAt, ttl.get))        # duration
  let grantsArr = if requestedV != nil and requestedV.kind == ekArray: requestedV.arr else: @[]
  let minted = mintTokenRaw(p, granteePeer.get.hash, grantsArr, ceiling, createdAt)
  let grant = makeEntity("system/capability/grant", mapV(@[
    EcPair(key: textV("token"), val: bytesV(minted.token.hash)),
  ]))
  (status: 200'u64, result: grant, included: @[
    (key: minted.token.hash, entity: minted.token),
    (key: p.identity.identityHash, entity: p.identity.peerEntity),
    (key: granteePeer.get.hash, entity: granteePeer.get),
    (key: minted.signature.hash, entity: minted.signature),
  ])

proc validPolicyPattern(pattern: string): bool =
  if pattern == "default": return true
  if '*' in pattern: return false
  if pattern.len == 66 or pattern.len == 98:
    for c in pattern:
      if not ((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F')):
        return false
    return true
  try:
    let pid = peerIdParse(pattern)
    (pid.keyType == 0x01'u64 or pid.keyType == 0x02'u64) and pid.digest.len > 0
  except CatchableError:
    false

proc capabilityConfigure(p: Peer; params: Entity): Outcome =
  if params.typ != "system/capability/policy-entry":
    return errOut(400, "invalid_params")
  let peerPattern = params.textField("peer_pattern")
  if peerPattern.isNone or not validPolicyPattern(peerPattern.get):
    return errOut(400, "invalid_params")
  # CAP-2 (§6.2): `grants: []` is the WITHDRAWAL form and MUST be accepted -- it
  # writes a present policy entry carrying an empty grants array, which is how an
  # operator revokes a seed policy without deleting the entry. Rejecting it with
  # 400 conflates "no grants" with "malformed", and the two are distinct states:
  # the absent field is malformed, the empty array is a deliberate withdrawal.
  if params.field("grants") == nil or params.field("grants").kind != ekArray:
    return errOut(400, "invalid_params")
  p.store.bindAt(p.abs("system/capability/policy/" & peerPattern.get), params)
  okOut(emptyAck())

proc capabilityRevoke(p: Peer; params: Entity): Outcome =
  let token = params.bytesField("token")
  if token.isNone or isZeroHash(token.get):
    return errOut(400, "invalid_params")
  let reason = params.textField("reason")
  var pairs = @[
    EcPair(key: textV("token"), val: bytesV(token.get)),
    EcPair(key: textV("revoked_at"), val: uintV(nowMs())),
  ]
  if reason.isSome: pairs.add EcPair(key: textV("reason"), val: textV(reason.get))
  let marker = makeEntity("system/capability/revocation", mapV(pairs))
  p.store.bindAt(p.abs("system/capability/revocations/" & hexLower(token.get)), marker)
  okOut(emptyAck())

proc patternFromResource(rt: ResourceTarget): Option[string] =
  if rt.targets.len != 1: return none(string)
  const prefix = "system/handler/"
  let target = rt.targets[0]
  if not target.startsWith(prefix) or target.len == prefix.len: return none(string)
  some(target[prefix.len .. ^1])

proc installTypes(p: Peer; req: Entity) =
  let types = req.field("types")
  if types == nil or types.kind != ekMap: return
  for pair in types.pairs:
    if pair.key != nil and pair.key.kind == ekText and pair.val != nil:
      let te = makeEntity("system/type", pair.val)
      p.store.bindAt(p.abs("system/type/" & pair.key.t), te)

proc isReservedSystemPattern(pattern: string): bool =
  ## §6.2: user-installed handlers MUST NOT register at system/* paths.
  pattern == "system" or pattern.startsWith("system/")

proc handlerRegister(p: Peer; params: Entity; rt: ResourceTarget): Outcome =
  let patOpt = patternFromResource(rt)
  if patOpt.isNone: return errOut(400, "ambiguous_resource")
  let pattern = patOpt.get
  if isReservedSystemPattern(pattern):
    return errOut(403, "forbidden_pattern",
      some("§6.2: user-installed handlers MUST NOT register at system/* paths: " & pattern))
  if params.typ != "system/handler/register-request":
    return errOut(400, "invalid_params")
  let manifest = params.field("manifest")
  let name = (if manifest != nil: mapGet(manifest, "name") else: nil)
  let nameStr = if name != nil and name.kind == ekText: name.t else: pattern
  let operations = (if manifest != nil: mapGet(manifest, "operations") else: nil)
  let opsVal = if operations != nil: operations else: mapV(@[])
  let expressionPath = (if manifest != nil: mapGet(manifest, "expression_path") else: nil)
  let maxScope = (if manifest != nil: mapGet(manifest, "max_scope") else: nil)
  let internalScope = (if manifest != nil: mapGet(manifest, "internal_scope") else: nil)
  let interfaceRelPath = "system/handler/" & pattern
  var hPairs = @[EcPair(key: textV("interface"), val: textV(interfaceRelPath))]
  if maxScope != nil: hPairs.add EcPair(key: textV("max_scope"), val: maxScope)
  if internalScope != nil: hPairs.add EcPair(key: textV("internal_scope"), val: internalScope)
  if expressionPath != nil: hPairs.add EcPair(key: textV("expression_path"), val: expressionPath)
  let handlerEntity = makeEntity("system/handler", mapV(hPairs))
  # (3) self-issued signed handler grant
  let grantScopeV = block:
    let rs = params.field("requested_scope")
    if rs != nil and rs.kind == ekArray: rs.arr
    elif internalScope != nil and internalScope.kind == ekArray: internalScope.arr
    else: @[]
  let minted = mintTokenRaw(p, p.identity.identityHash, grantScopeV)
  let ifaceEntity = makeEntity("system/handler/interface", mapV(@[
    EcPair(key: textV("pattern"), val: textV(pattern)),
    EcPair(key: textV("name"), val: textV(nameStr)),
    EcPair(key: textV("operations"), val: opsVal),
  ]))
  p.store.bindAt(p.abs(pattern), handlerEntity)                                    # 1
  installTypes(p, params)                                                          # 2
  p.store.bindAt(p.abs("system/capability/grants/" & pattern), minted.token)       # 3
  p.store.bindAt(p.abs("system/signature/" & hexLower(minted.token.hash)), minted.signature)  # 4
  p.store.bindAt(p.abs(interfaceRelPath), ifaceEntity)                             # 5
  let result = makeEntity("system/handler/register-result", mapV(@[
    EcPair(key: textV("pattern"), val: textV(pattern)),
    EcPair(key: textV("grant"), val: minted.token.data),
  ]))
  okOut(result)

proc handlerUnregister(p: Peer; rt: ResourceTarget): Outcome =
  let patOpt = patternFromResource(rt)
  if patOpt.isNone: return errOut(400, "ambiguous_resource")
  let pattern = patOpt.get
  let grant = p.store.getAt(p.abs("system/capability/grants/" & pattern))
  if grant.isSome:
    p.store.removeAt(p.abs("system/signature/" & hexLower(grant.get.hash)))
    p.store.removeAt(p.abs("system/capability/grants/" & pattern))
  p.store.removeAt(p.abs(pattern))
  p.store.removeAt(p.abs("system/handler/" & pattern))
  okOut(emptyAck())

# ── §7a conformance handlers (echo / dispatch-outbound reentry) ────────────────

proc validateEcho(params: Entity): Outcome =
  ## §7a echo: return the params entity verbatim (the literal value round-trips).
  okOut(params)

proc validateDispatchOutbound(p: Peer; params: Entity; sender: OutboundSender;
                              conn: Conn): Future[Outcome] {.async.} =
  ## §7a dispatch-outbound: originate exactly one outbound EXECUTE back to the caller
  ## over the §6.11 reentry seam, invoking `operation` on `target` with `value`.
  if sender == nil:
    return errOut(503, "no_outbound_seam")
  let target = params.textField("target")
  let operation = params.textField("operation")
  let value = params.field("value")
  let capV = params.field("reentry_capability")
  let granterV = params.field("reentry_granter")
  let capSigV = params.field("reentry_cap_signature")
  if target.isNone or operation.isNone or value == nil or
     capV == nil or granterV == nil or capSigV == nil:
    return errOut(400, "invalid_params")
  var capE, granterE, capSigE: Entity
  try:
    capE = entityOfValue(capV)
    granterE = entityOfValue(granterV)
    capSigE = entityOfValue(capSigV)
  except CatchableError:
    return errOut(400, "invalid_params")
  # §7a.1: the `value` field IS the outbound params entity data — pass through.
  let inner = makeEntity("primitive/any", value)
  let resource = mapV(@[EcPair(key: textV("targets"),
    val: arrV(@[textV("system/handler/" & target.get)]))])
  inc conn.outCounter
  let rid = "ro-" & $conn.outCounter
  let outExec = makeExecute(rid, target.get, operation.get, inner,
    author = some(p.identity.identityHash), capability = some(capE.hash),
    resource = resource)
  let execSig = p.identity.signEntityHash(outExec)
  let outEnv = Envelope(root: outExec, included: @[
    (key: capE.hash, entity: capE),
    (key: granterE.hash, entity: granterE),
    (key: p.identity.identityHash, entity: p.identity.peerEntity),
    (key: capSigE.hash, entity: capSigE),
    (key: execSig.hash, entity: execSig),
  ])
  var resp: Envelope
  try:
    resp = await sender(rid, outEnv)
  except CatchableError:
    return errOut(504, "reentry_failed")
  let downStatus = resp.root.uintField("status").get(0)
  let downResult = resp.root.field("result")
  let result = makeEntity("primitive/any", mapV(@[
    EcPair(key: textV("status"), val: uintV(downStatus)),
    EcPair(key: textV("result"), val: (if downResult != nil: downResult else: nullV())),
  ]))
  return okOut(result)

# ── §6.5 dispatch chain ────────────────────────────────────────────────────────

proc dispatchOutcome(p: Peer; conn: Conn; env: Envelope; sender: OutboundSender): Future[Outcome] {.async.} =
  let exec = env.root
  let uri = exec.textField("uri").get("")
  var path: string
  try:
    path = dispatchPath(uri, p.localPeer)
  except PathError:
    return errOut(400, "invalid_request")
  if extractPeer(uri, p.localPeer) != p.localPeer:
    return errOut(400, "invalid_request", some("not local peer"))
  let connectPath = p.abs("system/protocol/connect")
  if path == connectPath and not conn.established:
    return connectHandler(p, conn, exec, env)

  if exec.bytesField("author").isNone: return errOut(401, "missing_author")
  if exec.bytesField("capability").isNone: return errOut(403, "missing_authorization")

  ingestSignatures(p, env)
  let verify = verifyRequest(p, exec, env)
  if not verify.ok: return errOut(verify.status, verify.code)

  let patOpt = resolveHandler(p, path)
  if patOpt.isNone: return errOut(404, "handler_not_found", some(path))
  let pattern = patOpt.get
  let cap = verify.cap
  let granterPeerId = resolveGranterPeerId(cap, env, p.localPeer)
  let resource = exec.resourceTarget()
  if not checkPermission(exec, cap, pattern, p.localPeer, granterPeerId, resource):
    return errOut(403, "capability_denied")

  let params = exec.entityField("params").get(makeEntity("primitive/any", mapV(@[])))
  let op = exec.textField("operation").get("")

  case pattern
  of "system/tree":
    if op == "get" or op == "put":
      if resource.isNone or resource.get.targets.len != 1:
        return errOut(400, "ambiguous_resource")
      if op == "get": return treeGet(p, params, cap, resource.get, pattern)
      else: return treePut(p, params, cap, resource.get, pattern)
    return errOut(501, "unsupported_operation", some(op))
  of "system/capability":
    case op
    of "request": return capabilityRequest(p, exec, params, cap, env)
    of "configure": return capabilityConfigure(p, params)
    of "revoke": return capabilityRevoke(p, params)
    of "delegate": return errOut(501, "unsupported_operation", some("delegate"))
    else: return errOut(501, "unsupported_operation", some(op))
  of "system/handler":
    if resource.isNone: return errOut(400, "ambiguous_resource")
    case op
    of "register": return handlerRegister(p, params, resource.get)
    of "unregister": return handlerUnregister(p, resource.get)
    else: return errOut(501, "unsupported_operation", some(op))
  of "system/validate/echo":
    if op == "echo": return validateEcho(params)
    return errOut(501, "unsupported_operation", some(op))
  of "system/validate/dispatch-outbound":
    if op == "dispatch":
      return await validateDispatchOutbound(p, params, sender, conn)
    return errOut(501, "unsupported_operation", some(op))
  else:
    return errOut(501, "no_handler_body", some(pattern))

proc dispatch*(p: Peer; conn: Conn; env: Envelope; sender: OutboundSender = nil): Future[Option[Envelope]] {.async.} =
  ## Materialize a response Envelope for an inbound EXECUTE. A non-EXECUTE root is
  ## ignored (§3.3). Any unexpected exception → 500, connection stays alive.
  let exec = env.root
  if exec.typ != ExecuteType: return none(Envelope)
  let requestId = exec.textField("request_id").get("")
  var outcome: Outcome
  try:
    outcome = await dispatchOutcome(p, conn, env, sender)
  except CatchableError:
    outcome = errOut(500, "internal_error")
  let root = makeResponse(requestId, outcome.status, outcome.result)
  return some(Envelope(root: root, included: outcome.included))

# ── §6.9 bootstrap ─────────────────────────────────────────────────────────────

const BootstrapHandlers = [
  "system/tree", "system/handler", "system/type",
  "system/capability", "system/protocol/connect",
]

proc handlerOps(pattern: string): seq[string] =
  ## The operation names each core handler advertises in its §6 interface manifest.
  case pattern
  of "system/protocol/connect": @["hello", "authenticate"]
  of "system/tree": @["get", "put"]
  of "system/capability": @["request", "revoke", "delegate", "configure"]
  of "system/handler": @["register", "unregister"]
  of "system/type": @["get", "register"]
  of "system/validate/echo": @["echo"]
  of "system/validate/dispatch-outbound": @["dispatch"]
  else: @[]

proc bindHandler(p: Peer; pattern: string) =
  ## Bind a MUST core handler (§6.2): the dispatch manifest at the pattern path +
  ## the interface index at system/handler/{pattern} (so tree:get resolves it).
  let handlerE = makeEntity("system/handler", mapV(@[
    EcPair(key: textV("interface"), val: textV("system/handler/" & pattern)),
  ]))
  p.store.bindAt(p.abs(pattern), handlerE)
  var opsPairs: seq[EcPair]
  for op in handlerOps(pattern):
    opsPairs.add EcPair(key: textV(op), val: mapV(@[]))   # empty operation-spec
  let ifaceE = makeEntity("system/handler/interface", mapV(@[
    EcPair(key: textV("pattern"), val: textV(pattern)),
    EcPair(key: textV("name"), val: textV(pattern)),
    EcPair(key: textV("operations"), val: mapV(opsPairs)),
  ]))
  p.store.bindAt(p.abs("system/handler/" & pattern), ifaceE)

proc bootstrap(p: Peer) =
  for pattern in BootstrapHandlers:
    p.bindHandler(pattern)
  if p.validate:
    p.bindHandler("system/validate/echo")
    p.bindHandler("system/validate/dispatch-outbound")
  seedCoreTypes(p.store, p.localPeer)
  p.materializeDefaultPolicy()

proc newPeer*(seed: openArray[byte]; validate = false; openGrants = false): Peer =
  let id = identityOfSeed(seed)
  result = Peer(
    identity: id, store: newStore(), localPeer: id.peerId,
    validate: validate, openGrants: openGrants,
  )
  result.bootstrap()
