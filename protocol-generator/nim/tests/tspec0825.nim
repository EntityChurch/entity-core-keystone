## Spec 0.8.2.20 -> 0.8.2.25: the §3.3 effective-targets ladder, §6.3's
## `check_path_permission` and the listing filter, §5.4's sentinel scoped to path-scope,
## §5.2a's decode-boundary code, and §4.11's pre-admission frame obligation.
##
## THE PINNED CHECK SET (778) HAS NO VECTOR ON ANY OF THESE SURFACES, which is why the
## coverage is authored here rather than inherited. Each section states which rule it
## drives and what the peer answered BEFORE the change, because a test whose failure mode
## is not written down is a test nobody can read a regression out of.
##
## EVERY WIRE CASE CARRIES A POSITIVE CONTROL and EVERY READ CARRIES A DEADLINE. §4.11's
## non-conformant behaviour is "no response at all", so a socket read with no deadline
## HANGS on a regression instead of failing -- and a hung suite is strictly worse than a
## red one: it reports nothing and blocks everything behind it.
##
## Run (in-container, sealed offline):
##   nim c -r --mm:orc --overflowChecks:on -d:release --hints:off \
##     -o:/tmp/tspec0825 tests/tspec0825.nim
##
## SPDX-License-Identifier: Apache-2.0

import std/[asyncdispatch, asyncnet, nativesockets, options, strutils]
import std/posix except Port
import ../src/ecf
import ../src/model
import ../src/wire
import ../src/paths
import ../src/errors
import ../src/identity
import ../src/capability
import ../src/peer
import ../src/transport

var passCount = 0
var failCount = 0

proc check(name: string; ok: bool) =
  if ok: inc passCount else: inc failCount
  echo "  [", (if ok: "PASS" else: "FAIL"), "] ", name

proc section(name: string) = echo "-- ", name

proc mkSeed(b: byte): seq[byte] =
  result = newSeq[byte](32)
  for i in 0 ..< 32: result[i] = b

proc scope(includes: openArray[string]; excludes: openArray[string] = []): Scope =
  result.includes = @includes
  if excludes.len > 0:
    result.hasExclude = true
    result.excludes = @excludes

# ──────────────────────────────────────────────────────────────────────────────
# RULE B — §5.4's sentinel is scoped to PATH-SCOPE (0.8.2.24, N2/N3)
# ──────────────────────────────────────────────────────────────────────────────

proc ruleB(localPeer: string) =
  section "RULE B: the sentinel reaches path-scope only (0.8.2.24 N2/N3)"

  # THE WITNESS IS THE RULE'S OWN EXAMPLE. `*/apply` is an ordinary namespaced operation
  # name and a literal that matches nothing under the id-scope grammar; PATH-canonicalized
  # it answers the §5.4 sentinel. An unscoped guard classifies the id pattern with the
  # path transforms and then denies THE WHOLE DIMENSION on a property unrelated to whether
  # the exclude carves anything out -- over-denial, invisible on any well-formed grant.
  check "canonicalize(*/apply) IS the sentinel, so the witness is a real one":
    canonicalize("*/apply", localPeer) == NeverMatch
  let ops = scope(["get", "put"], ["*/apply"])
  check "an operations exclude that path-canonicalizes to the sentinel does NOT deny":
    ops.matches("get", localPeer, skId)
  check "and the SAME exclude still excludes what it literally names":
    not scope(["*"], ["get"]).matches("get", localPeer, skId)

  # The path arm keeps the guard, which is the half 0.8.2.21 landed and .24 did not touch.
  check "a RESOURCES exclude that canonicalizes to the sentinel DENIES the dimension":
    not scope(["system/type/*"], ["../nope"]).matches(
      "/" & localPeer & "/system/type/x", localPeer, skPath)
  check "and an ordinary resources grant with no sentinel still matches":
    scope(["system/type/*"]).matches("/" & localPeer & "/system/type/x", localPeer, skPath)

# ──────────────────────────────────────────────────────────────────────────────
# RULE E — `scope_subset` is typed by scope kind (F50, ruled 0.8.2.16; K-7)
# ──────────────────────────────────────────────────────────────────────────────

proc ruleE(localPeer: string) =
  section "RULE E: scope_subset dispatches on scope KIND (F50 / 0.8.2.16)"

  # `entity-core-formalization`'s differential on `lean`: 2 of 64 include pairs and 2 of
  # 64 exclude pairs disagree between the two readings, FAIL-CLOSED, with a 16-pair
  # control alphabet reporting 0 -- which is why every hand-tried example missed it. Both
  # witnesses are driven here, each with the control that says the pair is otherwise
  # ordinary.
  #
  # The mechanism: on the CANONICALIZING reading a bare id include reads as covered by a
  # path-form parent pattern it does not LITERALLY match, so a child grant comes out WIDER
  # than its parent -- delegation-chain widening, which is the reason arch gave for ruling
  # F50 yes.
  let parentStar = scope(["*"])

  # THE DISCRIMINATING PAIR: child operations include `*/apply` against a parent include
  # of `*`. Under the ID grammar a bare `*` covers everything, so the child is covered.
  # Under the canonicalizing reading `*/apply` PATH-canonicalizes to the §5.4 sentinel,
  # which matches nothing in either operand -- so the child comes out UNCOVERED and a
  # legitimate delegation is refused. FAIL-CLOSED, which is why it hid: nothing breaks
  # loudly, a chain just stops working.
  #
  # Measured rather than assumed: forcing the path arm here reddens THIS case and leaves
  # `compute/*` vs `compute/apply` below green, because that pair agrees under both
  # readings (the path form prefix-matches too). A plant is only a control for the cases
  # it actually moves.
  check "id: parent `*` covers a child include of `*/apply` (path reading REFUSES it)":
    grantsWithinAuthority(
      @[parseGrants(arrV(@[mapV(@[
        EcPair(key: textV("handlers"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[textV("*")]))])),
        EcPair(key: textV("resources"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[]))])),
        EcPair(key: textV("operations"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[textV("*/apply")]))])),
      ])]))[0]],
      @[parseGrants(arrV(@[mapV(@[
        EcPair(key: textV("handlers"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[textV("*")]))])),
        EcPair(key: textV("resources"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[]))])),
        EcPair(key: textV("operations"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[textV("*")]))])),
      ])]))[0]],
      localPeer)

  # Witness 2, and this is the one the typing decides: an operations include of
  # `compute/apply` against a parent include of `*/apply`. Under the ID grammar `*/apply`
  # is a LITERAL (its only wildcard forms are a bare `*` and a trailing `/*`), so it does
  # NOT cover `compute/apply` and the child must be refused. Under the canonicalizing
  # reading `*/apply` path-canonicalizes to the sentinel, which covers nothing either --
  # so the two readings agree here and the discriminator is the NEXT pair.
  #
  # The discriminating pair is a parent of `compute/*` against a child of `compute/apply`:
  # id-scope's trailing `/*` form covers it, and the sentinel reading would not.
  proc grantOf(opsInclude: string): GrantEntry =
    parseGrants(arrV(@[mapV(@[
      EcPair(key: textV("handlers"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[textV("*")]))])),
      EcPair(key: textV("resources"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[]))])),
      EcPair(key: textV("operations"), val: mapV(@[EcPair(key: textV("include"), val: arrV(@[textV(opsInclude)]))])),
    ])]))[0]

  check "id: parent `compute/*` COVERS child `compute/apply` (literal prefix form)":
    grantsWithinAuthority(@[grantOf("compute/apply")], @[grantOf("compute/*")], localPeer)
  check "id: parent `compute/apply` does NOT cover child `storage/apply`":
    not grantsWithinAuthority(@[grantOf("storage/apply")], @[grantOf("compute/apply")], localPeer)
  check "id: parent `*/apply` does NOT cover child `compute/apply` (it is a LITERAL)":
    not grantsWithinAuthority(@[grantOf("compute/apply")], @[grantOf("*/apply")], localPeer)
  discard parentStar

# ──────────────────────────────────────────────────────────────────────────────
# RULE F — the sentinel guard sits on every path reaching the decision
# ──────────────────────────────────────────────────────────────────────────────

proc ruleF() =
  section "RULE F: the NEVER_MATCH guard is the matcher's first statement"

  # ALREADY SATISFIED BY CONSTRUCTION HERE, AND THIS IS THE EVIDENCE RATHER THAN THE FIX.
  # 0.8.2.22: "a sentinel arm is a control-flow obligation, not a line ... the guard MUST
  # sit on every path that reaches the decision it protects." On `lean` the guard lived in
  # a WRAPPER beside the running matcher, so `scopeSubset` called the raw form and bypassed
  # it in the PERMISSIVE direction. This peer has no wrapper: the guard is the first
  # statement of `matchesPattern` itself (paths.nim), the single running matcher, so every
  # one of its 9 call sites -- 1 recursive in paths.nim, 8 in capability.nim across
  # `matches`, `scopeSubset`, and `checkResourceScope` -- inherits it and the bypass shape
  # cannot occur.
  check "the sentinel never matches in the PATH operand":
    not matchesPattern(NeverMatch, "*")
  check "the sentinel never matches in the PATTERN operand":
    not matchesPattern("/p/system/tree", NeverMatch)
  check "not even against itself":
    not matchesPattern(NeverMatch, NeverMatch)
  check "and a bare * still matches an ordinary path (the guard is not a blanket deny)":
    matchesPattern("/p/system/tree", "*")

# ──────────────────────────────────────────────────────────────────────────────
# RULE A — effective targets (§3.3 / 0.8.2.20, .21, .24 N7/N11, .25 N10)
# ──────────────────────────────────────────────────────────────────────────────

proc execWithResource(targets, excludes: openArray[string]; withTargetsKey = true): Entity =
  var pairs: seq[EcPair]
  if withTargetsKey:
    var t: seq[EcValue]
    for s in targets: t.add textV(s)
    pairs.add EcPair(key: textV("targets"), val: arrV(t))
  if excludes.len > 0:
    var e: seq[EcValue]
    for s in excludes: e.add textV(s)
    pairs.add EcPair(key: textV("exclude"), val: arrV(e))
  makeExecute("r1", "system/tree", "get", emptyParams(), resource = mapV(pairs))

proc ruleA(localPeer: string) =
  section "RULE A: effective_targets is the non-lossy projection (N11)"

  block:
    # THE TWO EMPTIES ARE DIFFERENT REQUESTS (0.8.2.24 N7, 0.8.2.25 N10/N11), and a proc
    # returning only a seq cannot say so: collapsing `[qA] exclude [qA]` to `@[]` deletes
    # the discriminator before any handler can read it, and the handler's refusal arm
    # becomes dead code only a WIRE drive can detect.
    let noResource = makeExecute("r1", "system/tree", "get", emptyParams())
    let (s0, had0) = effectiveTargets(noResource, localPeer)
    check "absent resource -> hadResource=false": (not had0) and s0.len == 0
    let (s1, had1) = effectiveTargets(execWithResource(["system/type/a"], ["system/type/a"]), localPeer)
    check "self-excluded resource -> hadResource=TRUE with an empty survivor list":
      had1 and s1.len == 0
    let (s2, had2) = effectiveTargets(execWithResource([], [], withTargetsKey = false), localPeer)
    check "a resource map with no `targets` key reads as ABSENT": (not had2) and s2.len == 0

  block:
    let (s, had) = effectiveTargets(
      execWithResource(["system/type/a", "system/type/b"], ["system/type/a"]), localPeer)
    # F71's arm: the effective set is size 1 and the COUNT rule says PROCEED. A raw
    # `targets.len != 1` arity check refuses this, and a raw `targets[0]` selector
    # proceeds on the EXCLUDED entry -- two different wrong answers to one request.
    check "two targets, one excluded -> ONE survivor, and it is the SURVIVOR":
      had and s.len == 1 and s[0] == "system/type/b"

  block:
    # SURVIVORS COME BACK IN THE CALLER'S OWN SPELLING (0.8.2.21), not canonicalized: the
    # value flows on to the store lookup, which canonicalizes for itself.
    let (s, _) = effectiveTargets(execWithResource(["system/type/a"], []), localPeer)
    check "survivors are the caller's raw spelling, not canonicalized":
      s.len == 1 and s[0] == "system/type/a" and not s[0].startsWith("/")

  block:
    # THE CALLER-EXCLUDE ARM IS FAIL-OPEN on an unmatchable pattern -- §5.4 rules it
    # separately from the grant arm -- and that is INHERITED from the primitives rather
    # than restated: canonicalize answers the sentinel, matchesPattern answers false, and
    # the target simply survives. Opposite direction from RULE B's grant-exclude case
    # above, on purpose.
    let (s, had) = effectiveTargets(execWithResource(["system/type/a"], ["../nope"]), localPeer)
    check "an unmatchable CALLER exclude carves out nothing (fail-OPEN)":
      had and s.len == 1

# ──────────────────────────────────────────────────────────────────────────────
# §6.3 check_path_permission (0.8.2.20/.23)
# ──────────────────────────────────────────────────────────────────────────────

proc tokenWithGrants(grants: seq[EcValue]): CapabilityToken =
  parseToken(makeEntity("system/capability/token", mapV(@[
    EcPair(key: textV("grants"), val: arrV(grants)),
    EcPair(key: textV("granter"), val: bytesV(newSeq[byte](33))),
    EcPair(key: textV("grantee"), val: bytesV(newSeq[byte](33))),
    EcPair(key: textV("created_at"), val: uintV(1000'u64)),
  ])))

proc grantV(handlers, resources, operations: openArray[string];
            resourceExcl: openArray[string] = []): EcValue =
  proc sc(inc: openArray[string]; exc: openArray[string]): EcValue =
    var i: seq[EcValue]
    for s in inc: i.add textV(s)
    var pairs = @[EcPair(key: textV("include"), val: arrV(i))]
    if exc.len > 0:
      var e: seq[EcValue]
      for s in exc: e.add textV(s)
      pairs.add EcPair(key: textV("exclude"), val: arrV(e))
    mapV(pairs)
  mapV(@[
    EcPair(key: textV("handlers"), val: sc(handlers, [])),
    EcPair(key: textV("resources"), val: sc(resources, resourceExcl)),
    EcPair(key: textV("operations"), val: sc(operations, [])),
  ])

proc pathCheck(localPeer: string) =
  section "§6.3 check_path_permission: three dimensions, local frame"

  let cap = tokenWithGrants(@[grantV(["system/tree"], ["system/type/*"], ["get"])])
  let inScope = "/" & localPeer & "/system/type/a"
  let outScope = "/" & localPeer & "/system/handler/a"

  # THE ACCEPT CASE IS WHAT VALIDATES THE FIXTURE. A predicate test built only from deny
  # cases is indistinguishable from one asserting False == False: a broken fixture denies
  # everything and every deny control passes.
  check "ACCEPT: a covered path under the granted handler and operation":
    checkPathPermission("get", inScope, cap, "system/tree", localPeer)
  check "DENY on the RESOURCES dimension":
    not checkPathPermission("get", outScope, cap, "system/tree", localPeer)
  check "DENY on the OPERATIONS dimension":
    not checkPathPermission("put", inScope, cap, "system/tree", localPeer)
  check "DENY on the HANDLERS dimension":
    not checkPathPermission("get", inScope, cap, "system/capability", localPeer)

  # An empty `resources.include` is a LEGAL grant shape (§5.2: handlers that touch no tree
  # paths) and DENIES every path here -- `covered` over an empty include list is false.
  let noPaths = tokenWithGrants(@[grantV(["system/tree"], [], ["get"])])
  check "an empty resources.include denies every path":
    not checkPathPermission("get", inScope, noPaths, "system/tree", localPeer)

  # A malformed path canonicalizes to the sentinel, which matches no grant, so it falls
  # through to DENY rather than being matched against anything.
  let wide = tokenWithGrants(@[grantV(["*"], ["*", "/*/*"], ["*"])])
  check "ACCEPT under a wide grant (the control for the malformed case below)":
    checkPathPermission("get", inScope, wide, "system/tree", localPeer)
  check "a path that canonicalizes to the sentinel is DENIED even under a wide grant":
    not checkPathPermission("get", "../nope", wide, "system/tree", localPeer)

  # THREE DIMENSIONS, NOT FOUR: `peers` is not consulted, because the path is local by
  # construction here (§1.4 refuses a foreign namespace at §6.5 step 3, before any handler
  # runs) and §6.3's signature names only handlers, operations and resources. A grant
  # whose `peers` names nobody must still authorize a LOCAL path.
  var withPeers = grantV(["system/tree"], ["system/type/*"], ["get"])
  withPeers.pairs.add EcPair(key: textV("peers"),
    val: mapV(@[EcPair(key: textV("include"), val: arrV(@[textV("some-other-peer")]))]))
  check "the `peers` dimension is NOT consulted by check_path_permission":
    checkPathPermission("get", inScope, tokenWithGrants(@[withPeers]), "system/tree", localPeer)

# ──────────────────────────────────────────────────────────────────────────────
# RULES C + D — the decode boundary and §4.11's frame obligation
# ──────────────────────────────────────────────────────────────────────────────

proc ruleCUnit() =
  section "RULE C/D: the code belongs to the CAUSE (§5.2a, §4.11)"

  # A MAPPING is exactly the thing that regresses silently when a new failure joins an
  # existing branch, so it is asserted row by row and the row COUNT is asserted too.
  type Row = tuple[e: ref Exception, status: uint64, code: string]
  let rows: seq[Row] = @[
    # §5.2a / §1.8 resolution integrity. 0.8.2.24 (N4/N5) pins this and rules
    # non_canonical_ecf NON-CONFORMANT here.
    ((ref Exception)(newException(IncludedKeyMismatch, "x")), 400'u64, "hash_mismatch"),
    ((ref Exception)(newException(ContentHashMismatch, "x")), 400'u64, "hash_mismatch"),
    # ENTITY-CBOR-ENCODING §6.3 -- the tag-policy arm KEEPS its own code.
    ((ref Exception)(newException(TagRejected, "x")), 400'u64, "non_canonical_ecf"),
    # §4.11's framing arm: bytes that never become an Envelope. The one that makes the
    # ordering load-bearing is NonCanonicalEcf -- "non-canonical CBOR" by name, and NOT
    # the tag-policy arm.
    ((ref Exception)(newException(NonCanonicalEcf, "x")), 400'u64, "invalid_request"),
    ((ref Exception)(newException(TruncatedInput, "x")), 400'u64, "invalid_request"),
    ((ref Exception)(newException(DuplicateKey, "x")), 400'u64, "invalid_request"),
    ((ref Exception)(newException(BadEntity, "x")), 400'u64, "invalid_request"),
  ]
  check "examined-N, not merely `no failures`": rows.len == 7
  for r in rows:
    let got = preAdmissionRefusal(r.e)
    check "cause -> " & r.code & " (" & $r.status & ")":
      got.status == r.status and got.code == r.code
    check "the wire-visible message for " & r.code & " is ASCII":
      (block:
        var ok = true
        for ch in got.message:
          if ord(ch) > 127: ok = false
        ok and got.message.len > 0)

# ── wire drive ────────────────────────────────────────────────────────────────

const ReadDeadlineMs = 5000
  ## THE DEADLINE IS THE ASSERTION, not a convenience. §4.11's non-conformant behaviour
  ## is NO RESPONSE, so a read with no deadline HANGS on a regression instead of failing
  ## it -- and a hung suite reports nothing and blocks everything behind it.

proc serveConnection(p: Peer; sock: AsyncSocket) {.async.} =
  let io = newIo(sock)
  await readLoop(p, Conn(), io)
  sock.close()

proc acceptLoop(p: Peer; server: AsyncSocket) {.async.} =
  while true:
    let client = await server.accept()
    asyncCheck serveConnection(p, client)

proc framed(payload: seq[byte]): string =
  let n = uint32(payload.len)
  result = newString(4 + payload.len)
  result[0] = char((n shr 24) and 0xff)
  result[1] = char((n shr 16) and 0xff)
  result[2] = char((n shr 8) and 0xff)
  result[3] = char(n and 0xff)
  for i in 0 ..< payload.len: result[4 + i] = char(payload[i])

proc recvN(sock: AsyncSocket; n: int): Future[string] {.async.} =
  var buf = ""
  while buf.len < n:
    let chunk = await sock.recv(n - buf.len)
    if chunk.len == 0: break
    buf.add chunk
  return buf

proc readResponse(sock: AsyncSocket): Future[Option[Envelope]] {.async.} =
  ## One framed response under the deadline. `none` means the peer answered NOTHING,
  ## which is §4.11's silent drop and is the failure this whole section exists to catch.
  let hdrF = recvN(sock, 4)
  if not await withTimeout(hdrF, ReadDeadlineMs): return none(Envelope)
  let hdr = await hdrF
  if hdr.len < 4: return none(Envelope)
  let n = int((uint32(byte hdr[0]) shl 24) or (uint32(byte hdr[1]) shl 16) or
              (uint32(byte hdr[2]) shl 8) or uint32(byte hdr[3]))
  let bodyF = recvN(sock, n)
  if not await withTimeout(bodyF, ReadDeadlineMs): return none(Envelope)
  let body = await bodyF
  if body.len < n: return none(Envelope)
  var payload = newSeq[byte](n)
  for i in 0 ..< n: payload[i] = byte(body[i])
  try: return some(envelopeOfFrame(payload))
  except CatchableError: return none(Envelope)

proc statusCode(env: Envelope): tuple[status: uint64, code, rid: string] =
  let res = env.root.entityField("result")
  let code = if res.isSome: res.get.textField("code").get("") else: ""
  (env.root.uintField("status").get(0'u64), code, env.root.textField("request_id").get(""))

proc controlFrame(): string =
  ## A well-formed EXECUTE the peer MUST answer -- the positive control. `system/type:get`
  ## with no capability is refused at §5.2 with 401, which is a REAL answer and is all the
  ## control needs to establish: the connection is alive and the peer is serving.
  framed(encodeEnvelope(Envelope(
    root: makeExecute("ctl-1", "system/tree", "get", emptyParams()), included: @[])))

proc wireCases(port: Port) {.async.} =
  section "RULE D: every pre-admission refusal puts a CODED frame on the wire (§4.11)"

  # The positive control on its own FIRST. If this ever fails, nothing below is a reading
  # about the peer -- it is a reading about this file.
  block:
    let s = await dial(port)
    await s.send(controlFrame())
    let r = await readResponse(s)
    check "POSITIVE CONTROL: a well-formed EXECUTE is answered":
      r.isSome and statusCode(r.get).rid == "ctl-1"
    s.close()

  # A COMPLETE frame the decoder refused: the framing is intact, so the peer answers and
  # KEEPS SERVING. Each refusal is followed by the control ON THE SAME CONNECTION -- the
  # differential that says the answer was a refusal of the FRAME and not the connection
  # collapsing.
  block:
    let s = await dial(port)
    # (a) a MIS-KEYED included entry -> resolution integrity. Its encoding is canonical
    #     and it carries no tag; what is false is the claim the KEY makes. This peer
    #     answered `non_canonical_ecf` here until 0.8.2.24 -- arc-probe B1/B2.
    let good = makeEntity("primitive/any", mapV(@[EcPair(key: textV("x"), val: uintV(1))]))
    let root = makeExecute("t1", "system/tree", "get", emptyParams())
    var badKey = newSeq[byte](33)
    for i in 0 ..< 33: badKey[i] = 0x11'u8
    let misKeyed = encode(mapV(@[
      EcPair(key: textV("root"), val: root.toValue()),
      EcPair(key: textV("included"), val: mapV(@[EcPair(key: bytesV(badKey), val: good.toValue())])),
    ]))
    await s.send(framed(misKeyed))
    let r1 = await readResponse(s)
    check "mis-keyed included -> 400 hash_mismatch, CORRELATED":
      r1.isSome and statusCode(r1.get) == (400'u64, "hash_mismatch", "t1")
    # (b) a root that is neither EXECUTE nor EXECUTE_RESPONSE -> 400 invalid_request
    #     (§3.3/§6.5 "Other type?", N12/N17). NOT a bare close, and NOT the silent drop
    #     this peer used to answer it with.
    let otherRoot = makeEntity("primitive/any", mapV(@[
      EcPair(key: textV("request_id"), val: textV("x-1"))]))
    await s.send(framed(encodeEnvelope(Envelope(root: otherRoot, included: @[]))))
    let r2 = await readResponse(s)
    check "a non-EXECUTE root -> 400 invalid_request, not silence and not a close":
      r2.isSome and statusCode(r2.get) == (400'u64, "invalid_request", "x-1")
    # (c) the connection is STILL SERVING after both refusals.
    await s.send(controlFrame())
    let r3 = await readResponse(s)
    check "the connection is still serving after two refusals":
      r3.isSome and statusCode(r3.get).rid == "ctl-1"
    s.close()

  # Where no request_id can be recovered, §4.11 prescribes "a best-effort coded frame
  # carrying no correlation" -- an EMPTY request_id IS that form. Guessing one would
  # correlate the refusal to somebody else's in-flight request. This peer emitted NOTHING
  # here, which is §4.11's silent drop.
  block:
    let s = await dial(port)
    await s.send(framed(encode(mapV(@[EcPair(key: textV("nope"), val: uintV(1))]))))
    let r1 = await readResponse(s)
    check "an un-attributable frame -> 400 invalid_request with an EMPTY request_id":
      r1.isSome and statusCode(r1.get) == (400'u64, "invalid_request", "")
    await s.send(framed(@[0xff'u8, 0xff, 0xff, 0xff]))
    let r2 = await readResponse(s)
    check "garbage bytes -> 400 invalid_request, best-effort uncorrelated":
      r2.isSome and statusCode(r2.get).status == 400'u64
    await s.send(controlFrame())
    let r3 = await readResponse(s)
    check "still serving after two un-attributable refusals":
      r3.isSome and statusCode(r3.get).rid == "ctl-1"
    s.close()

  # §4.10(a) N14: SHOULD -> MUST. The over-size condition is detected at the length prefix
  # with the connection intact and nothing spent, so the permissive mood had nothing to
  # license.
  block:
    let s = await dial(port)
    var hdr = newString(4)
    let n = uint32(MaxFrame + 1)
    hdr[0] = char((n shr 24) and 0xff); hdr[1] = char((n shr 16) and 0xff)
    hdr[2] = char((n shr 8) and 0xff);  hdr[3] = char(n and 0xff)
    await s.send(hdr)   # prefix only; no body ever sent
    let r = await readResponse(s)
    check "an oversize length prefix -> 413 payload_too_large, uncorrelated":
      r.isSome and statusCode(r.get) == (413'u64, "payload_too_large", "")
    s.close()

  # §4.11's framing arm names this input outright: "a length prefix that never completes".
  # The write side is shut down so the peer sees EOF MID-FRAME rather than an idle
  # connection. This used to arrive as a clean close and take a bare `break` -- "closing
  # with no coded frame", indistinguishable from a network fault.
  block:
    let s = await dial(port)
    var hdr = newString(4)
    hdr[0] = '\0'; hdr[1] = '\0'; hdr[2] = '\x10'; hdr[3] = '\0'   # declares 4096
    await s.send(hdr & "\xa1")                                     # sends 1
    discard shutdown(s.getFd(), 1)                                 # SHUT_WR -> EOF mid-frame
    let r = await readResponse(s)
    check "a truncated frame -> 400 invalid_request BEFORE the close":
      r.isSome and statusCode(r.get) == (400'u64, "invalid_request", "")
    s.close()

  # A clean EOF AT A FRAME BOUNDARY is an ordinary hangup and is owed NOTHING. Getting the
  # truncated arm wrong in this direction would answer 400 to every peer that simply hangs
  # up, so the negative is asserted rather than assumed: the listener must survive it.
  block:
    let s = await dial(port)
    s.close()
    let s2 = await dial(port)
    await s2.send(controlFrame())
    let r = await readResponse(s2)
    check "a bare connect-and-close costs the listener nothing":
      r.isSome and statusCode(r.get).rid == "ctl-1"
    s2.close()

# ──────────────────────────────────────────────────────────────────────────────
# RULE A + G over the wire: the §3.3 ladder and operation-before-resource
# ──────────────────────────────────────────────────────────────────────────────

proc resourceVal(targets: openArray[string]; excludes: openArray[string] = []): EcValue =
  var t: seq[EcValue]
  for s in targets: t.add textV(s)
  var pairs = @[EcPair(key: textV("targets"), val: arrV(t))]
  if excludes.len > 0:
    var e: seq[EcValue]
    for s in excludes: e.add textV(s)
    pairs.add EcPair(key: textV("exclude"), val: arrV(e))
  mapV(pairs)

proc ladderCases(localPort, remotePort: Port; local: Peer) {.async.} =
  section "RULES A + G on the wire: the ladder, and the operation resolves FIRST"

  let sock = await dial(remotePort)
  let io = newIo(sock)
  let conn = Conn()
  asyncCheck readLoop(local, conn, io)
  let s = await initiate(local, io, conn)

  proc ask(op: string; res: EcValue): tuple[status: uint64, code, rid: string] =
    statusCode(waitFor s.execute("system/tree", op, emptyParams(), resource = res))

  # The §6.9a discovery floor grants tree:get over system/type/* and system/handler/*.
  # Both targets below are INSIDE it, so authorization is not the variable in A1/A2/A3 --
  # the only question is whether the handler resolves through effective_targets.
  const qA = "system/type/primitive/any"
  const qB = "system/type/primitive/string"

  block:
    let got = ask("get", resourceVal([qA]))
    check "POSITIVE CONTROL: a single in-grant target answers 200": got.status == 200'u64

  block:
    # §3.3, 0.8.2.24 N7 + EXTENSION-TREE §2.2a: `get` is resource-OPTIONAL and
    # BROAD-RESULT, so the SELF-EXCLUDED case is refused rather than served the (wider)
    # absent-case listing. This peer answered 200 with the excluded entity.
    let got = ask("get", resourceVal([qA], [qA]))
    check "targets:[qA] exclude:[qA] -> 400 path_required":
      got.status == 400'u64 and got.code == "path_required"

  block:
    let got = ask("get", resourceVal([qA, qB]))
    check "two surviving targets -> 400 ambiguous_resource":
      got.status == 400'u64 and got.code == "ambiguous_resource"

  block:
    # F71's arm, and the 0.8.2.20 MUST: the effective set is {qB}, size 1, so the COUNT
    # rule says PROCEED -- on qB. A raw arity check refuses this (which is what this peer
    # did) and a raw targets[0] selector proceeds on the EXCLUDED qA.
    let env = waitFor s.execute("system/tree", "get", emptyParams(),
                                resource = resourceVal([qA, qB], [qA]))
    let got = statusCode(env)
    let res = env.root.entityField("result")
    let name = if res.isSome: res.get.textField("name").get("") else: ""
    check "targets:[qA,qB] exclude:[qA] -> 200 ON qB, never on the excluded qA":
      got.status == 200'u64 and name == "primitive/string"

  block:
    # 0.8.2.20: a resource-requiring operation takes a CONCRETE path. A pattern used to be
    # resolved as a literal path and answered 404, which tells the caller the wrong thing.
    let got = ask("get", resourceVal(["system/type/*"]))
    check "a PATTERN subject -> 400 malformed_resource":
      got.status == 400'u64 and got.code == "malformed_resource"

  block:
    # §6.3's check_path_permission, which is NOT a secondary check: the caller excludes
    # the one target its capability does not cover, which removes it from
    # check_permission's view entirely -- so the dispatch-level check is VACATED and this
    # is the sole enforcement. Serving it would be "a path no authorization covered".
    # NOTE THE ORDER: the SURVIVOR is the out-of-grant path and the EXCLUDED entry is the
    # in-grant one. Written the other way round the survivor is covered and the case
    # measures nothing -- which is what the first cut of this test did.
    #
    # WHICH RUNG REFUSES THIS ON *THIS* PEER IS NOT WHAT THE CASE ASSERTS, AND SAYING SO
    # MATTERS. Measured by planting: removing the check_path_permission call from treeGet
    # leaves this case GREEN, because nim's dispatch-level checkResourceScope SKIPS a
    # caller-excluded target and then requires every SURVIVOR to be covered -- so on this
    # peer the dispatch check is not vacated by a caller exclude and the two rungs agree
    # on every input the wire can supply. The handler-level check is therefore a genuine
    # §6.3 backstop here rather than the sole enforcement, and its own behaviour is
    # asserted directly in `pathCheck` above (where a plant on the function DOES redden
    # four cases) and on the listing path below (where it IS load-bearing).
    #
    # That is F84's empty cell from the inside: a backstop is only DEMONSTRATED by an
    # input that fails the primary and is caught by it, and this peer supplies none.
    let got = ask("get", resourceVal([qA, "system/capability/policy/default"], [qA]))
    check "an out-of-grant survivor is REFUSED (403), never served":
      got.status == 403'u64 and got.code == "capability_denied"

  # §6.3's listing filter (0.8.2.21/.22): each ENTRY is checked with check_path_permission
  # and `count` follows the FILTERED total. The §6.9a floor covers `system/type/*` and
  # `system/handler/*`; the root's only child is the node `system` ITSELF, which neither
  # pattern covers -- so a conforming filter emits NOTHING here.
  #
  # ASSERTING THE CONTENT, NOT count-vs-entries CONSISTENCY. The first cut of this case
  # asserted `count == len(entries)`, which is TRUE WITH THE FILTER REMOVED -- the count is
  # incremented inside the loop, so both move together and the assertion survives the
  # defect it exists to catch. Found by planting; the plant ran green.
  block:
    # THE ABSENT-RESOURCE FORM, deliberately: a trailing-slash target IS a resource, and
    # the §6.9a floor's resources scope does not cover the peer root -- so naming one is
    # refused at §5.2 before the handler ever runs, and the filter would go unmeasured.
    let env = waitFor s.execute("system/tree", "get", emptyParams())
    let got = statusCode(env)
    let res = env.root.entityField("result")
    var names: seq[string]
    var declared = 0'u64
    if res.isSome:
      declared = res.get.uintField("count").get(0'u64)
      let entries = res.get.field("entries")
      if entries != nil and entries.kind == ekMap:
        for pr in entries.pairs:
          if pr.key != nil and pr.key.kind == ekText: names.add pr.key.t
    check "a root listing is answered at all (the control for the filter)":
      got.status == 200'u64
    check "an entry the caller's own capability does not cover is OMITTED":
      "system" notin names
    check "and `count` follows the FILTERED total, not the source tree's":
      declared == uint64(names.len)
    discard localPort

proc ruleGCases(remotePort: Port; local: Peer) {.async.} =
  section "RULE G: the operation resolves BEFORE the resource ladder"

  # DRIVEN AGAINST AN OPEN-GRANTS RESPONDER ON PURPOSE, and the reason is the measurement
  # rather than convenience: under the §6.9a discovery floor the caller's `operations`
  # scope is `["get"]`, so ANY unknown operation is refused 403 at §5.2 two gates before
  # the handler is reached and the ordering inside the handler is unobservable. Widening
  # the caller's grant decides only whether the request is ADMITTED; it cannot make a
  # wrongly-ordered handler answer correctly. (Everything that is about AUTHORIZATION is
  # driven against the floor peer, in ladderCases.)
  let sock = await dial(remotePort)
  let io = newIo(sock)
  let conn = Conn()
  asyncCheck readLoop(local, conn, io)
  let s = await initiate(local, io, conn)

  # THE DIFFERENTIAL IS THE POINT, not either arm alone. A peer that validates the
  # resource first answers a RESOURCE fault for the no-resource arm and 501 for the
  # other -- two different answers to ONE operation fault, and that disagreement is the
  # tell. This peer answered `400 ambiguous_resource` without a resource, because a raw
  # arity check sat above the operation switch.
  let without = statusCode(waitFor s.execute("system/tree", "bogusop", emptyParams()))
  let withRes = statusCode(waitFor s.execute("system/tree", "bogusop", emptyParams(),
                                             resource = resourceVal(["system/type/primitive/any"])))
  check "unknown op WITHOUT a resource -> 501 unsupported_operation":
    without.status == 501'u64 and without.code == "unsupported_operation"
  check "unknown op WITH a resource -> the SAME 501 (the differential AGREES)":
    withRes.status == 501'u64 and withRes.code == "unsupported_operation"
  check "the two arms agree, which is what says the operation resolved first":
    without.status == withRes.status and without.code == withRes.code

  # The same inversion lived on system/handler, where the resource test preceded the op
  # case outright. Both of its operations require a resource, so the check moved inside
  # them rather than away.
  let hWithout = statusCode(waitFor s.execute("system/handler", "bogusop", emptyParams()))
  check "system/handler: unknown op WITHOUT a resource -> 501, not a resource fault":
    hWithout.status == 501'u64 and hWithout.code == "unsupported_operation"
  let hRegister = statusCode(waitFor s.execute("system/handler", "register", emptyParams()))
  check "system/handler: a KNOWN op with no resource -> 400 path_required":
    hRegister.status == 400'u64 and hRegister.code == "path_required"

  # THE LISTING CONTROL, and it belongs here because it needs a wide grant. `ladderCases`
  # asserts that the §6.9a floor sees an EMPTY root listing -- which is the right answer
  # and is indistinguishable from a peer that cannot list at all. This is the other half:
  # the SAME listing under a grant that covers everything must NAME the entry the floor
  # peer omits. Without it, "the filter works" rests on an empty result.
  let listEnv = waitFor s.execute("system/tree", "get", emptyParams())
  let listRes = listEnv.root.entityField("result")
  var openNames: seq[string]
  var openCount = 0'u64
  if listRes.isSome:
    openCount = listRes.get.uintField("count").get(0'u64)
    let entries = listRes.get.field("entries")
    if entries != nil and entries.kind == ekMap:
      for pr in entries.pairs:
        if pr.key != nil and pr.key.kind == ekText: openNames.add pr.key.t
  check "CONTROL: under a wide grant the SAME root listing DOES name `system`":
    "system" in openNames and openCount == uint64(openNames.len) and openNames.len > 0

  # A known operation still reaches the ladder: the ordering change must not have made
  # the resource optional. This is the control for the four cases above.
  let getNoRes = statusCode(waitFor s.execute("system/tree", "put", emptyParams()))
  check "CONTROL: a known resource-REQUIRED op with no resource -> 400 path_required":
    getNoRes.status == 400'u64 and getNoRes.code == "path_required"
  sock.close()

proc main() =
  let localPeer = identityOfSeed(mkSeed(0x7b'u8)).peerId
  echo "spec 0.8.2.20 -> 0.8.2.25 unit + wire gate"
  ruleB(localPeer)
  ruleE(localPeer)
  ruleF()
  ruleA(localPeer)
  pathCheck(localPeer)
  ruleCUnit()

  let responder = newPeer(mkSeed(0x7b'u8))
  let server = listen(Port(0))
  let port = getLocalAddr(server.getFd(), AF_INET)[1]
  asyncCheck acceptLoop(responder, server)
  waitFor wireCases(port)

  let client = newPeer(mkSeed(0x2a'u8))
  waitFor ladderCases(Port(0), port, client)

  # A SECOND responder, open-grants, for the RULE G ordering differential only.
  let openResponder = newPeer(mkSeed(0x5c'u8), openGrants = true)
  let openServer = listen(Port(0))
  let openPort = getLocalAddr(openServer.getFd(), AF_INET)[1]
  asyncCheck acceptLoop(openResponder, openServer)
  waitFor ruleGCases(openPort, newPeer(mkSeed(0x3d'u8)))

  echo ""
  echo "spec0825: ", passCount, " passed, ", failCount, " failed (", passCount + failCount, " executed)"
  # EXAMINED-N: a gate whose success message contains no number cannot distinguish "all
  # green" from "nothing ran". The floor is asserted, not merely the failure count.
  if passCount + failCount < 68:
    echo "spec0825: FAILED - fewer cases executed than the floor of 68"
    quit(1)
  if failCount > 0: quit(1)
  quit(0)

main()
