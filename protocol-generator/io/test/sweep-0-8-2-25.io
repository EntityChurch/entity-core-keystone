// entity-core-protocol-io — 0.8.2.25 sweep unit gate (offline, no network).
//
// Pins the six pieces the 0.8.2.20 -> .25 arc landed on this peer, at the UNIT level.
// The wire-level half -- "a pre-admission refusal reaches the socket" -- cannot be asked
// here and is driven by output/scratch/preadm411.c against the peer's own run-s4.sh
// launch; what this file pins is the MAPPING ("the code belongs to the cause") plus the
// §3.3 ladder, §6.3's path check, the §5.4 sentinel's scoping and §5.5a's scope typing.
//
// EVERY PREDICATE CASE CARRIES AN ACCEPT ASSERTION. A deny-only test of an authorization
// predicate is indistinguishable from one asserting False == False, and the accept case
// is what validates the FIXTURE: a grant fixture built the wrong way parses empty, the
// predicate then denies everything, and every deny case passes for free.
//
// Run: io test/sweep-0-8-2-25.io

EntityCodec
srcDir := Path with(File thisSourceFile parentDirectory parentDirectory path, "src")
loadSrc := method(n, Lobby doFile(Path with(srcDir, n)))
loadSrc("Ec.io"); loadSrc("Entity.io"); loadSrc("Envelope.io"); loadSrc("Identity.io")
loadSrc("Wire.io"); loadSrc("Store.io"); loadSrc("Capability.io"); loadSrc("CoreTypes.io")
loadSrc("Handlers.io"); loadSrc("Peer.io")

fails := 0
ran := 0
check := method(name, ok,
    ran = ran + 1
    if(ok, ("  ok   " .. name) println, fails = fails + 1; ("  FAIL " .. name) println))

LP := "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"   // a syntactically valid peer_id

// ── fixtures ────────────────────────────────────────────────────────────────
// An EXECUTE carrying an explicit `resource` map. `targets`/`excl` are Lists; passing
// nil for `targets` omits the whole `resource` field, which is the input §3.3 makes
// DIFFERENT from a present resource whose targets all drop out.
mkExec := method(targets, excl,
    res := nil
    if(targets != nil,
        res = EcMap with("targets", targets)
        if(excl != nil, res atPut("exclude", excl))
    )
    Wire makeExecute("r1", "system/tree", "get", Wire emptyParams, nil, nil, res)
)

sc := method(incl, excl, EcMap with("include", incl, "exclude", excl))
// A capability token carrying ONE grant. Each dimension is (include, exclude).
mkToken := method(hi, hx, oi, ox, ri, rx,
    Entity with("system/capability/token", EcMap with("grants",
        list(EcMap with("handlers", sc(hi, hx), "operations", sc(oi, ox), "resources", sc(ri, rx)))))
)
scopeOf := method(incl, excl, Map clone atPut("incl", incl) atPut("excl", excl))

// ══════════════════════════════════════════════════════════════════════════════
// §3.3 / §5.2 effectiveTargets (0.8.2.20/.21, N11)
// ══════════════════════════════════════════════════════════════════════════════
"-- effectiveTargets (3.3/5.2) --" println

// THE NON-LOSSY PROJECTION [MUST] (0.8.2.25 N11): collapsing `[qA] exclude [qA]` to an
// empty List would delete the two-empties discriminator before any handler can read it,
// and the handler's refusal arm becomes dead code that only a WIRE drive can detect.
eAbsent := Capability effectiveTargets(LP, mkExec(nil, nil))
eSelf   := Capability effectiveTargets(LP, mkExec(list("app/a"), list("app/a")))
check("absent resource -> had == false", eAbsent at("had") == false)
check("present resource -> had == true (even when every target drops)", eSelf at("had") == true)
check("self-excluded request -> empty survivor list", eSelf at("list") size == 0)
check("the two empties are DISTINGUISHABLE", eAbsent at("had") != eSelf at("had"))

// Survivors in the caller's OWN SPELLING (0.8.2.21), not canonicalized -- the value
// flows on to the store lookup, which canonicalizes for itself.
eTwo := Capability effectiveTargets(LP, mkExec(list("app/a", "app/b"), list("app/b")))
check("survivor keeps the caller's raw spelling", eTwo at("list") at(0) == "app/a")
check("the non-excluded target survives, the excluded one does not", eTwo at("list") size == 1)
check("a wildcard caller exclude carves out its whole subtree",
    Capability effectiveTargets(LP, mkExec(list("app/a", "app/b"), list("app/*"))) at("list") size == 0)

// THE CALLER-EXCLUDE ARM IS FAIL-OPEN on an unmatchable pattern -- §5.4 rules it
// separately from the GRANT arm, which is fail-CLOSED (see the sentinel block below).
// The asymmetry is 0.8.2.21's whole point and it is INHERITED here rather than restated:
// canonicalize answers the sentinel, matchesPattern then answers false, and the target
// simply survives.
check("unmatchable caller exclude carves out NOTHING (fail-open)",
    Capability effectiveTargets(LP, mkExec(list("app/a"), list("../nope"))) at("list") == list("app/a"))

// ══════════════════════════════════════════════════════════════════════════════
// §6.3 checkPathPermission (0.8.2.20/.22/.23)
// ══════════════════════════════════════════════════════════════════════════════
"-- checkPathPermission (6.3) --" println
tok := mkToken(list("system/tree"), list(), list("get"), list(), list("app/*"), list())
pOk   := "/" .. LP .. "/app/a"
pDeny := "/" .. LP .. "/other/a"

// THE ACCEPT CASE IS THE FIXTURE VALIDATOR. Without it every deny below passes against
// a grant that parsed empty.
check("ACCEPT: all three dimensions match",
    Capability checkPathPermission(LP, "get", pOk, tok, "system/tree"))
// One deny per DIMENSION: a single deny cannot distinguish "the predicate checks the
// dimension I care about" from "the predicate denies".
check("DENY on the resources dimension",
    Capability checkPathPermission(LP, "get", pDeny, tok, "system/tree") not)
check("DENY on the operations dimension (id-scope)",
    Capability checkPathPermission(LP, "put", pOk, tok, "system/tree") not)
check("DENY on the handlers dimension",
    Capability checkPathPermission(LP, "get", pOk, tok, "system/other") not)

// An empty resources.include is a LEGAL grant shape (§5.2: handlers that touch no tree
// paths) and DENIES every path here.
check("empty resources.include denies every path",
    Capability checkPathPermission(LP, "get", pOk,
        mkToken(list("system/tree"), list(), list("get"), list(), list(), list()), "system/tree") not)
// A malformed path canonicalizes to NEVER_MATCH, which matches no grant, so it falls
// through to DENY rather than being matched against anything.
check("malformed path falls through to DENY, not to a raise",
    Capability checkPathPermission(LP, "get", "../escape",
        mkToken(list("system/tree"), list(), list("get"), list(), list("*"), list()), "system/tree") not)
// THREE DIMENSIONS, NOT FOUR: `peers` is not consulted (the path is local by
// construction here; §6.3's signature names only handlers, operations and resources).
// A grant whose `peers` dimension names a DIFFERENT peer still authorizes the path.
tokP := Entity with("system/capability/token", EcMap with("grants",
    list(EcMap with("handlers", sc(list("system/tree"), list()),
                    "operations", sc(list("get"), list()),
                    "resources", sc(list("app/*"), list()),
                    "peers", sc(list("someotherpeer"), list())))))
check("the `peers` dimension is NOT consulted (three dimensions, not four)",
    Capability checkPathPermission(LP, "get", pOk, tokP, "system/tree"))

// ══════════════════════════════════════════════════════════════════════════════
// §5.4 sentinel scoped to PATH-SCOPE (0.8.2.24, N2/N3) — RULE B
// ══════════════════════════════════════════════════════════════════════════════
"-- 5.4 sentinel is path-scope only (0.8.2.24) --" println
// The symptom of the UN-scoped form: an `operations` exclude that PATH-canonicalizes to
// the sentinel -- an ordinary namespaced operation name -- denied the WHOLE dimension.
// Over-denial, invisible on any well-formed grant.
check("id-scope: a star-slash operations exclude does NOT deny the dimension",
    Capability matchesScope(LP, "get", scopeOf(list("*"), list("*/apply")), "id"))
check("id-scope ACCEPT control: no exclude at all",
    Capability matchesScope(LP, "get", scopeOf(list("*"), list()), "id"))
check("id-scope still EXCLUDES a literal that matches",
    Capability matchesScope(LP, "get", scopeOf(list("*"), list("get")), "id") not)
// path-scope keeps the fail-CLOSED reading: an unmatchable GRANT exclude excludes
// everything (0.8.2.21).
check("path-scope: an unmatchable exclude still denies the dimension",
    Capability matchesScope(LP, "app/a", scopeOf(list("*"), list("../nope")), "path") not)
check("path-scope ACCEPT control: a matchable exclude that misses",
    Capability matchesScope(LP, "app/a", scopeOf(list("*"), list("other/*")), "path"))

// ══════════════════════════════════════════════════════════════════════════════
// §5.5a scopeSubset typed by scope kind (F50, 0.8.2.16) — RULE E
// ══════════════════════════════════════════════════════════════════════════════
"-- 5.5a scopeSubset is typed (F50 / 0.8.2.16) --" println
// grantSubset over two single-grant shapes, local frames on both sides.
sub := method(ch, cr, co, ph, pr, po,
    g := method(h, r, o,
        Map clone atPut("handlers", scopeOf(h, list())) \
                  atPut("resources", scopeOf(r, list())) \
                  atPut("operations", scopeOf(o, list())) \
                  atPut("peers", nil))
    Capability grantSubset(LP, LP, LP, g(ch, cr, co), g(ph, pr, po))
)
// entity-core-formalization's K-7 differential: 2 of 64 include pairs and 2 of 64
// exclude pairs disagree between the literal and the canonicalizing readings,
// fail-closed, with a 16-pair control alphabet reporting 0 -- which is why every
// hand-tried example missed it. Both witnesses are on the ID arm, where §3.6 binds the
// literal matcher.
check("id-scope subset: child /tree/get is inside parent *",
    sub(list("*"), list("*"), list("/tree/get"), list("*"), list("*"), list("*")))
// The divergence: under the CANONICALIZING reading a child operations include of the
// star-slash-apply form canonicalizes to the NEVER_MATCH sentinel, matchesPattern then
// answers false in EITHER operand, and the subset check REFUSES a child that is plainly
// inside `*`. Under the literal matcher the parent's bare `*` covers it, which is what
// §3.6 requires.
check("id-scope subset: star-slash-apply is inside parent * (the K-7 witness)",
    sub(list("*"), list("*"), list("*/apply"), list("*"), list("*"), list("*")))
// DENY control on the same arm, so the two above are not "subset always answers yes".
check("id-scope subset DENY: a child operation outside the parent include",
    sub(list("*"), list("*"), list("put"), list("*"), list("*"), list("get")) not)

// THE TYPING HAS TWO HALVES AND THE WITNESSES ABOVE ONLY MEASURE ONE. Found by planting
// on the sibling `tcl` peer: forcing the MATCHER to the path flavour while leaving the
// FRAME on id left every case above green, because for the star-slash-apply form against
// a bare star the two matchers AGREE (both take the bare-star arm) and the whole
// divergence comes from CANONICALIZATION manufacturing the sentinel. So a pair is needed
// whose canonical forms are identical and whose MATCHERS disagree: the peer-wildcard
// form is a §5.4 PATTERN under the path matcher and an ordinary literal under the id
// matcher, and canonicalize is the identity on both operands (each already starts with
// "/"). §3.6: "An implementation on the canonicalizing reading is non-conformant and
// MUST adopt the literal matcher."
check("id-scope subset MATCHER arm: /a/get is NOT literally inside the peer-wildcard form",
    sub(list("*"), list("*"), list("/a/get"), list("*"), list("*"), list("/*/get")) not)
check("path-scope subset MATCHER arm: /a/get IS inside the peer-wildcard PATTERN",
    sub(list("/a/get"), list("*"), list("*"), list("/*/get"), list("*"), list("*")))

// The PATH arm keeps the canonicalizing reading -- handlers and resources are path-scope.
check("path-scope subset: child app/a is inside parent app/*",
    sub(list("*"), list("app/a"), list("*"), list("*"), list("app/*"), list("*")))
check("path-scope subset DENY: child outside the parent resource include",
    sub(list("*"), list("other/a"), list("*"), list("*"), list("app/*"), list("*")) not)

// ══════════════════════════════════════════════════════════════════════════════
// §4.11 / §5.2a — the code belongs to the CAUSE — RULES C/D
// ══════════════════════════════════════════════════════════════════════════════
"-- 4.11 pre-admission: the code belongs to the cause --" println
r := method(k, Wire preAdmissionRefusal(k))
sc2 := method(k, list(r(k) at(0), r(k) at(1)))

check("over-limit prefix -> 413 payload_too_large", sc2("payload_too_large") == list(413, "payload_too_large"))
// The tag arm KEEPS non_canonical_ecf: ENTITY-CBOR-ENCODING defines that code for CBOR
// tag-policy violations specifically and still MUSTs it at decode time. Disjoint by
// CAUSE rather than in conflict.
check("a CBOR tag in a data field KEEPS 400 non_canonical_ecf", sc2("tag_rejected") == list(400, "non_canonical_ecf"))
// Everything else that never becomes an Envelope is the framing arm, on which
// non_canonical_ecf is explicitly NOT conformant.
check("non-minimal head -> 400 invalid_request (framing arm)", sc2("non_canonical_ecf") == list(400, "invalid_request"))
check("truncated input -> 400 invalid_request", sc2("truncated_input") == list(400, "invalid_request"))
check("decoded but not an Envelope -> 400 invalid_request", sc2("not_an_envelope") == list(400, "invalid_request"))
check("a non-EXECUTE root -> 400 invalid_request", sc2("non_execute_root") == list(400, "invalid_request"))
// THE DIFFERENTIAL: the tag arm and the framing arm must answer DIFFERENT codes, or the
// peer is not classifying, it is just refusing.
check("the tag arm and the framing arm are DISTINGUISHED", sc2("tag_rejected") != sc2("non_canonical_ecf"))
//
// THE RESOLUTION-INTEGRITY ROW IS NOT ASSERTED AS BEHAVIOUR HERE, and that is recorded
// rather than papered over. §5.2a pins `400 hash_mismatch` for a peer that REFUSES AT
// THE DECODE BOUNDARY -- §1.8 mechanism (a). This peer implements mechanism (b):
// `Envelope fromWire` DISCARDS a mis-keyed `included` entry and every authority lookup
// addresses by validated content_hash, so a forged entry is never DETECTED, the lookup
// simply MISSES, and §5.2a's own table answers that miss with 401/403. Measured on the
// wire: arc-probe B1/B2 grade both arms `yes` under mechanism (b). Asserting
// `hash_mismatch` as this peer's answer would be asserting a code its mechanism cannot
// produce. What IS asserted is that the classifier maps the KIND correctly if ever
// reached, which is a claim about the table and not about the peer's behaviour:
check("the classifier maps a resolution-integrity kind to hash_mismatch (table, not behaviour)",
    sc2("included_key_mismatch") == list(400, "hash_mismatch"))

// THE CLASSIFIER IS DRIVEN FROM REAL BYTES, not only from kind strings -- otherwise it
// is a test of a lookup table and says nothing about whether the codec reports the kind
// the table expects.
tagFrame := EntityCodec hexDecode("a1646461746183c00001")     // {"data": [tag(0) 0, 1]}
check("refusalKind on a tagged frame reports the TAG cause", Wire refusalKind(tagFrame) == "tag_rejected")
check("refusalKind on a non-minimal head reports non_canonical_ecf",
    Wire refusalKind(EntityCodec hexDecode("1817")) == "non_canonical_ecf")
check("refusalKind on a truncated frame reports truncated_input",
    Wire refusalKind(EntityCodec hexDecode("a164646174")) == "truncated_input")
check("refusalKind on garbage reports a framing cause, not nil",
    Wire refusalKind(EntityCodec hexDecode("ffffff")) != nil)
// A VALID frame must NOT be classified as a refusal -- the control that says
// decodeErrorKind is not simply always answering something.
check("refusalKind CONTROL: a well-formed CBOR map is not a codec refusal",
    EntityCodec decodeErrorKind(EntityCodec hexDecode("a0")) == nil)
// END-TO-END: the tag cause must reach the pinned code through the real codec.
check("a tagged frame classifies END-TO-END to 400 non_canonical_ecf",
    sc2(Wire refusalKind(tagFrame)) == list(400, "non_canonical_ecf"))
check("a non-minimal head classifies END-TO-END to 400 invalid_request",
    sc2(Wire refusalKind(EntityCodec hexDecode("1817"))) == list(400, "invalid_request"))

// Every wire-visible message stays ASCII. THIS PEER IS ONE OF THE TWO WHOSE CRASH
// ESTABLISHED THAT RULE: its own UTF-8 validator rejected byte-correct UTF-8 in an
// error message, killed the single-threaded process, and cascaded 104 FAILs.
asciiOnly := method(s,
    ok := true
    s foreach(i, c, if(c < 32 or(c > 126), ok = false; break))
    ok)
list("payload_too_large", "included_key_mismatch", "tag_rejected", "not_an_envelope") foreach(k,
    check("refusal message is ASCII-only (" .. k .. ")", asciiOnly(r(k) at(2))))

// ══════════════════════════════════════════════════════════════════════════════
// §3.3 ladder + §6.3 in the tree handler
// ══════════════════════════════════════════════════════════════════════════════
"-- 3.3 ladder + 6.3 in the tree handler --" println
peerA := Peer create(EntityCodec hexDecode("37" repeated(32)), false, false)
LP2 := peerA localPeer
th := peerA getHandler("system/tree")

tout := method(op, targets, excl, cap,
    th dispatch(op, Map clone atPut("exec", mkExec(targets, excl)) atPut("conn", nil) \
        atPut("included", list()) atPut("callerCap", cap) atPut("env", nil) \
        atPut("handlerPattern", "/" .. LP2 .. "/system/tree"))
)
tstatus := method(op, targets, excl, cap, tout(op, targets, excl, cap) status)
tcode := method(op, targets, excl, cap, tout(op, targets, excl, cap) result text("code"))
tmsg := method(op, targets, excl, cap, tout(op, targets, excl, cap) result text("message"))

// RULE G -- OPERATION RESOLUTION PRECEDES RESOURCE VALIDATION. The defect this pins is
// an op ladder whose *any-operation, no-resource* arm matches BEFORE the
// unknown-operation arm, so `system/tree:bogusop` with no resource answers a RESOURCE
// error for an OPERATION fault. The differential is the point: the SAME unknown
// operation must answer 501 with a resource AND without one, or the resource ladder is
// reachable for an unknown op.
check("RULE G: unknown op WITHOUT a resource -> 501", tstatus("bogusop", nil, nil, nil) == 501)
check("RULE G: unknown op WITH a resource -> 501 (the differential)",
    tstatus("bogusop", list("app/a"), nil, nil) == 501)
check("RULE G: and it is the OPERATION code, not a resource code",
    tcode("bogusop", nil, nil, nil) == "unsupported_operation")
// The companion control, so "501 to everything" cannot satisfy the above vacuously: a
// KNOWN op must still route into the ladder.
check("RULE G control: a KNOWN op still routes (not 501)", tstatus("get", nil, nil, nil) != 501)

// The §3.3 ladder on `get` -- resource-OPTIONAL, BROAD-RESULT (EXTENSION-TREE §2.2a).
check("get, absent resource -> the root listing at 200", tstatus("get", nil, nil, nil) == 200)
check("get, PRESENT resource whose every target is self-excluded -> 400 path_required",
    tcode("get", list("app/a"), list("app/a"), nil) == "path_required")
check("get, two surviving targets -> 400 ambiguous_resource",
    tcode("get", list("app/a", "app/b"), nil, nil) == "ambiguous_resource")
// THE SELECTION MUST COME FROM THE EFFECTIVE SET, NOT targets[0] (0.8.2.20). With app/a
// excluded the survivor is app/b, so the handler must look for app/b -- a peer indexing
// targets[0] reports on app/a instead.
//
// THE PARENTHESES ARE LOAD-BEARING AND THIS CASE WAS VACUOUS WITHOUT THEM. In Io `==`
// BINDS TIGHTER THAN `..`, so `tmsg(...) == "/" .. LP2 .. "/app/b"` parses as
// `(tmsg(...) == "/") .. LP2 .. "/app/b"` -- a SEQUENCE ("falsey..."), and any non-nil
// non-false object is TRUE in Io, so the check could not fail. Caught by PLANTING (the
// targets[0] plant reddened three other cases and left THIS one green, which is the
// signature of an inert control); confirmed with a two-line probe:
// `2 == 1 .. "y"` evaluates to the Sequence "falsey". AGENTS.md records the same
// precedence trap on this peer for `b & 0x80 == 0` in a varint loop -- same operator,
// different neighbour. Parenthesize any comparison whose other operand is built with an
// operator on this substrate.
check("get selects from the EFFECTIVE set, never targets[0]",
    tmsg("get", list("app/a", "app/b"), list("app/a"), nil) == ("/" .. LP2 .. "/app/b"))
check("get, a PATTERN target -> 400 malformed_resource",
    tcode("get", list("app/*"), nil, nil) == "malformed_resource")
check("get, a trailing slash is a LISTING request, not a pattern",
    tstatus("get", list("system/"), nil, nil) == 200)
// §1.4's universal tree root survives the restructuring. It has no peer segment, so the
// §1.4 absolute-path test refuses it, which is why its arm sits ABOVE pathFlexOk.
check("get, the bare universal root / still lists", tstatus("get", list("/"), nil, nil) == 200)

// The §3.3 ladder on `put` -- resource-REQUIRED, so BOTH empties answer path_required.
// 0.8.2.20 names answering `ambiguous_resource` for an absent resource as the exact
// inversion it forbids: *supply a resource* is not *disambiguate your request*.
check("put, absent resource -> 400 path_required (NOT ambiguous_resource)",
    tcode("put", nil, nil, nil) == "path_required")
check("put, self-excluded resource -> 400 path_required",
    tcode("put", list("app/a"), list("app/a"), nil) == "path_required")
check("put, two surviving targets -> 400 ambiguous_resource",
    tcode("put", list("app/a", "app/b"), nil, nil) == "ambiguous_resource")
check("put, a PATTERN target -> 400 malformed_resource",
    tcode("put", list("app/*"), nil, nil) == "malformed_resource")

// §6.3's path check AT THE HANDLER. The caller's own exclude vacates the dispatch-level
// check, so this is the only thing standing between the caller and the path.
capOk := mkToken(list("*"), list(), list("*"), list(), list("app/*"), list())
check("6.3 ACCEPT: a covered path is not refused by the path check",
    tstatus("get", list("app/a"), nil, capOk) != 403)
check("6.3 DENY: an UNCOVERED path -> 403 capability_denied",
    tcode("get", list("other/a"), nil, capOk) == "capability_denied")
check("6.3 DENY on put as well as get",
    tcode("put", list("other/a"), nil, capOk) == "capability_denied")
// An unauthenticated / internal context has no caller to narrow and is NOT filtered.
check("no caller capability -> the path check does not fire",
    tstatus("get", list("other/a"), nil, nil) == 404)

// ══════════════════════════════════════════════════════════════════════════════
// §6.3 listing filter (0.8.2.21/.22)
// ══════════════════════════════════════════════════════════════════════════════
"-- 6.3 listing filter (0.8.2.21/.22) --" println
list("qA", "qB", "qC") foreach(seg,
    peerA store bind("/" .. LP2 .. "/lst/" .. seg, Entity with("primitive/string", seg)))

listingOf := method(cap,
    o := tout("get", list("lst/"), nil, cap)
    d := o result data
    names := List clone
    d at("entries") foreachEntry(k, v, names append(k asString))
    list(names sort, d at("count")))

// THE UNFILTERED CONTROL, and it is what makes the filtered case falsifiable: if the
// directory get does not work at all, "qB absent" is the trivial truth and measures
// nothing.
check("listing control: all three entries visible with no caller capability",
    listingOf(nil) == list(list("qA", "qB", "qC"), 3))
capX := mkToken(list("*"), list(), list("*"), list(), list("lst/*"), list("lst/qB"))
// `count` FOLLOWING THE SOURCE TOTAL IS THE DISCLOSURE BY ITSELF -- it tells the caller
// how many bindings exist under a prefix its capability does not cover.
check("listing filter: the excluded entry is omitted AND count follows the filtered total",
    listingOf(capX) == list(list("qA", "qC"), 2))
// An include-narrowing filter, not only an exclude: the same rule has to hold when the
// grant simply does not reach the sibling.
check("listing filter: narrowing the INCLUDE omits the uncovered entries too",
    listingOf(mkToken(list("*"), list(), list("*"), list(), list("lst/qA"), list())) == list(list("qA"), 1))
//
// NOT DRIVEN, and recorded rather than asserted with a case that would pass either way:
// §6.3's "the DIRECTORY itself is deliberately not checked". Through this handler a
// grant covering only `lst/qA` still yields a listing OF `lst/` (the case directly above
// proves the filter runs, not that the prefix is unchecked), and a grant covering `lst/`
// cannot distinguish a prefix-checking filter from a correct one. Separating the two
// needs a caller whose grant covers children but NOT the node above them AND a dispatch
// chain that lets the request reach the handler -- and §5.2 refuses that request one
// layer earlier. The case above (`lst/qA` only) is the closest observable approximation:
// it reaches the handler because this test drives the handler directly, and a
// prefix-checking filter would answer an EMPTY listing there rather than qA. That is
// evidence, not a proof.

"" println
("=== sweep 0.8.2.25: " .. (ran - fails) .. " pass / " .. fails .. " fail (" .. ran .. " cases) ===") println
// ASSERT THE COUNT, not merely that the failure list is empty: a gate that examined zero
// things prints the same word as one that examined every case.
if(ran < 60, ("FAIL: only " .. ran .. " cases executed; the suite lost cases") println; System exit(1))
if(fails > 0, System exit(1))
// THE POSITIVE VERDICT LINE IS THE GATE, NOT THE EXIT CODE, and that is measured rather
// than stylistic: `io` EXITS 0 ON AN UNCAUGHT EXCEPTION. Verified in this peer's own
// image -- a one-line script referencing a missing slot prints the exception and exits
// 0 -- so a raise anywhere above this point would leave `make` perfectly happy having
// run none of the cases below it. The Makefile greps for THIS line, which only a run
// that reached the end can print. Asserting the absence of "FAIL" would not do: absence
// is a property of the pattern, presence is a property of the run.
"SWEEP-0.8.2.25 OK" println
System exit(0)
