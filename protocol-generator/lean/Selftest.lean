/-
  Pure verdict-core selftest (S3). Validates that the SEGMENT-model §5.4 matcher
  and the §5.6 attenuation logic are faithful to the spec/cohort semantics BEFORE
  the running shell or the Track-B proofs depend on them. Not a conformance gate
  (that is validate-peer); a fast faithfulness check on the highest-risk novel
  representation (matchesSeg) + the attenuation frames.
-/
import EntityCore.Capability
import EntityCore.Wire
import EntityCore.Peer

open EntityCore (Value)
open EntityCore.Capability
open EntityCore.Model

def mkGrant (resIncl : List String) (resExcl : List String) : Value :=
  .map [(.text "resources",
         .map [(.text "include", .array (resIncl.map (.text ·))),
               (.text "exclude", .array (resExcl.map (.text ·)))])]

/-- A token entity carrying one grant. -/
def tokenWith (grantVals : List Value) : Entity :=
  make "system/capability" (.map [(.text "grants", .array grantVals)])

def cases : List (String × Bool × Bool) := [
  -- (name, got, expect)
  -- ── §5.4 matchesSeg over canonical segments ──
  ("trailing /* matches deeper path",
    matchesSeg (canonSegs "alice" "/alice/system/peer") (canonSegs "alice" "/alice/system/*"), true),
  ("trailing /* needs >=1 more segment",
    matchesSeg (canonSegs "alice" "/alice/system") (canonSegs "alice" "/alice/system/*"), false),
  ("leading /*/ matches one peer segment",
    matchesSeg (canonSegs "alice" "/bob/foo") (canonSegs "alice" "/*/foo"), true),
  ("leading /*/ rejects wrong tail",
    matchesSeg (canonSegs "alice" "/bob/foo") (canonSegs "alice" "/*/bar"), false),
  ("exact literal match",
    matchesSeg (canonSegs "alice" "/alice/x/y") (canonSegs "alice" "/alice/x/y"), true),
  ("literal mismatch",
    matchesSeg (canonSegs "alice" "/alice/x/y") (canonSegs "alice" "/alice/x/z"), false),
  ("bare * canonicalizes to frame namespace (covers under frame)",
    matchesSeg (canonSegs "alice" "/alice/anything/deep") (canonSegs "alice" "*"), true),
  ("bare * under frame does NOT cover a foreign peer",
    matchesSeg (canonSegs "alice" "/bob/x") (canonSegs "alice" "*"), false),
  -- ── §5.6 scopeSubset same-frame ──
  ("subset: child ⊆ parent (same frame)",
    scopeSubset .path "alice" "alice" ⟨["/alice/a/b"], []⟩ ⟨["/alice/a/*"], []⟩, true),
  ("not subset: child broadens parent",
    scopeSubset .path "alice" "alice" ⟨["/alice/a/*"], []⟩ ⟨["/alice/a/b"], []⟩, false),
  -- ── §PR-8 / §5.5a granter-frame discipline (the V2(a) class) ──
  -- A foreign-granted bare "*" must canonicalize to the GRANTER's namespace, so it
  -- does NOT subset a parent bare "*" framed on a DIFFERENT granter. Same pattern
  -- text, different frames ⇒ not a subset (this is the v7.73 fix in pure form).
  ("granter-frame: bare * across different frames is NOT a subset",
    scopeSubset .path "bob" "alice" ⟨["*"], []⟩ ⟨["*"], []⟩, false),
  ("granter-frame: bare * within the SAME frame IS a subset",
    scopeSubset .path "alice" "alice" ⟨["*"], []⟩ ⟨["*"], []⟩, true),
  -- ── §5.6 isAttenuated through full grant entities ──
  ("attenuated: narrower child resource grant",
    isAttenuated "alice" "alice" "alice"
      (tokenWith [mkGrant ["/alice/docs/a"] []]) (tokenWith [mkGrant ["/alice/docs/*"] []]), true),
  ("not attenuated: child broader than parent",
    isAttenuated "alice" "alice" "alice"
      (tokenWith [mkGrant ["/alice/docs/*"] []]) (tokenWith [mkGrant ["/alice/docs/a"] []]), false)
]

-- ── §3.6 M3 multi-signature K-of-N — ACCEPT path (the oracle's blind spot) ──
-- The validate-peer `multisig` category is 100% rejection tests (malformed quorum
-- → 403), which a fail-closed peer passes WITHOUT genuine k-of-n. This exercises
-- the direction the oracle cannot: a real 2-of-3 root MUST be ALLOWed, and each
-- M3/M4/M6 invariant flip MUST deny. Pure layer — no crypto, the resolved signer
-- booleans (isLocal/signed) stand in for the shell's resolution.

/-- A root-only multi-sig link: no parent edge, grantee resolvable, no temporal
bounds, single-sig validity irrelevant (quorum lives in `rootAuthority`). -/
def msRootLink : ResolvedLink :=
  { entity := make "system/capability/token" (.map [(.text "grants", .array [])]),
    granterPeer := some "alice", sigValid := false, granteeResolvable := true,
    isMultiSig := true }

/-- A normal single-sig root link (sig valid, grantee resolvable, no temporal). -/
def ssRootLink : ResolvedLink :=
  { entity := make "system/capability/token" (.map [(.text "grants", .array [])]),
    granterPeer := some "alice", sigValid := true, granteeResolvable := true,
    isMultiSig := false }

def msChain (auth : RootAuthority) (link : ResolvedLink := msRootLink) : ResolvedChain :=
  { links := [link], rootAuthority := auth }

def sA : ResolvedSigner := { key := "a", isLocal := true,  signed := true  }
def sB : ResolvedSigner := { key := "b", isLocal := false, signed := true  }
def sC : ResolvedSigner := { key := "c", isLocal := false, signed := false }

def msCases : List (String × Bool × Bool) := [
  -- valid 2-of-3 (local in quorum, 2 signed) → Allow
  ("multisig 2-of-3 valid quorum → Allow",
    verifyChain (msChain (.multi [sA, sB, sC] 2 true)) "alice" 0 == .allow, true),
  -- below threshold (only 1 signed) → Deny (M4)
  ("multisig 1-of-3 below threshold → Deny",
    verifyChain (msChain (.multi [sA, sC, {key:="d",isLocal:=false,signed:=false}] 2 true)) "alice" 0 == .allow, false),
  -- local peer not among signers → Deny (M6)
  ("multisig local-not-in-signers → Deny",
    verifyChain (msChain (.multi [sB, {key:="d",isLocal:=false,signed:=true}] 2 true)) "alice" 0 == .allow, false),
  -- threshold = 1 (M3 structure) → Deny even with valid sigs (precedence)
  ("multisig threshold=1 (M3) → Deny",
    verifyChain (msChain (.multi [sA, sB, sC] 1 true)) "alice" 0 == .allow, false),
  -- duplicate signer keys (M3 structure) → Deny
  ("multisig duplicate-keys (M3) → Deny",
    verifyChain (msChain (.multi [sA, {key:="a",isLocal:=false,signed:=true}] 2 true)) "alice" 0 == .allow, false),
  -- non-null parent (M3 root-only) → Deny
  ("multisig non-root parentNull=false (M3) → Deny",
    verifyChain (msChain (.multi [sA, sB] 2 false)) "alice" 0 == .allow, false),
  -- n = 1 (M3 real quorum n≥2) → Deny
  ("multisig n=1 (M3) → Deny",
    verifyChain (msChain (.multi [sA] 2 true)) "alice" 0 == .allow, false),
  -- a multi-sig link OFF the root denies (root-only): leaf is multi-sig, parent single
  ("multisig link off-root → Deny",
    verifyChain { links := [msRootLink, ssRootLink], rootAuthority := .single true } "alice" 0 == .allow, false),
  -- pure gate: multiSigRootOk true on the valid 2-of-3
  ("multiSigRootOk 2-of-3 = true", multiSigRootOk [sA, sB, sC] 2 true, true),
  ("multiSigRootOk threshold>n = false", multiSigRootOk [sA, sB] 3 true, false),
  -- single-sig strict superset: a normal single-sig root still verifies
  ("single-sig root (.single true) → Allow",
    verifyChain { links := [ssRootLink], rootAuthority := .single true } "alice" 0 == .allow, true),
  ("single-sig foreign root (.single false) → Deny",
    verifyChain { links := [ssRootLink], rootAuthority := .single false } "alice" 0 == .allow, false)
]

-- ── §5 scope algebra + §4.11 pre-admission (0.8.2.24 / 0.8.2.25) ─────────────
-- The rules landed for spec 0.8.2.25, in the direction the conformance oracle
-- cannot reach: the §6.3 path check and the §3.3 effective-targets ladder moved
-- this peer from violating three landed MUSTs to conformant WITHOUT MOVING A SINGLE
-- SEVERITY in the pinned check set, so these cases are the only thing standing
-- between the code and a silent regression.
--
-- Each predicate group carries at least one ACCEPT case and one DENY case PER
-- DIMENSION. The accept case is what validates the FIXTURE — a predicate built over
-- a mis-shaped grant denies everything, and a deny-only group is then
-- indistinguishable from one asserting `false == false`.

/-- A stand-in local peer_id. Only its SHAPE matters; nothing derives a key. -/
def lp : String := "2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg"

def scopeV (incl excl : List String) : Value :=
  .map [(.text "include", .array (incl.map (.text ·))),
        (.text "exclude", .array (excl.map (.text ·)))]

/-- A one-grant token over the three dimensions §6.3 consults. -/
def tok (h r o : Value) : Entity :=
  make "system/capability/token"
    (.map [(.text "grants", .array [.map [(.text "handlers", h), (.text "resources", r),
                                          (.text "operations", o)]])])

/-- The grant the §6.3 cases narrow from: `system/tree` may `get` under
`system/type/*`, and nothing else. -/
def narrowTok : Entity :=
  tok (scopeV ["system/tree"] []) (scopeV ["system/type/*"] []) (scopeV ["get"] [])

/-- An EXECUTE carrying a `resource` map verbatim. -/
def execRes (r : Value) : Entity :=
  make "system/protocol/execute"
    (.map [(.text "operation", .text "get"), (.text "uri", .text "system/tree"),
           (.text "resource", r)])

def targetsV (ts : List String) : Value :=
  .map [(.text "targets", .array (ts.map (.text ·)))]

def targetsExclV (ts xs : List String) : Value :=
  .map [(.text "targets", .array (ts.map (.text ·))),
        (.text "exclude", .array (xs.map (.text ·)))]

/-- A well-formed envelope `Value` whose single `included` entry is filed under
`key`. The entry's own content_hash is the control; anything else is the §5.2a
forgery. -/
def envWithKey (key : Value) : Value :=
  let root := make "primitive/any" (.map [])
  let e := make "primitive/any" (.map [(.text "x", .uint 1)])
  .map [(.text "root", toCbor root), (.text "included", .map [(key, toCbor e)])]

def includedEntityHash : ByteArray := (make "primitive/any" (.map [(.text "x", .uint 1)])).hash

/-- The (status, code) a decode refusal reaches the wire as. -/
def decodeAnswer (v : Value) : Nat × String :=
  match envelopeOfCborE v with
  | .ok _ => (200, "decoded")
  | .error .hashMismatch => EntityCore.Wire.preAdmissionRefusal .hashMismatch
  | .error .malformed => EntityCore.Wire.preAdmissionRefusal .malformed

def scopeCases : List (String × Bool × Bool) := [
  -- ── §5.2 effective targets (0.8.2.20/.21, N11) ──
  ("effectiveTargets ACCEPT: a survivor comes back in the caller's OWN spelling",
    effectiveTargets lp (execRes (targetsV ["system/type/qA"])) == (["system/type/qA"], true), true),
  ("effectiveTargets DENY: the caller's own exclude removes a target first",
    effectiveTargets lp (execRes (targetsExclV ["system/type/qA", "system/type/qB"] ["system/type/qB"]))
      == (["system/type/qA"], true), true),
  -- N11's non-lossy projection [MUST]: collapsing `[qA] exclude [qA]` to `[]` would
  -- delete the two-empties discriminator before any handler could read it.
  ("effectiveTargets TWO EMPTIES: absent resource is ([], false)",
    effectiveTargets lp (make "system/protocol/execute" (.map [(.text "operation", .text "get")]))
      == (([] : List String), false), true),
  ("effectiveTargets TWO EMPTIES: self-excluded resource is ([], true)",
    effectiveTargets lp (execRes (targetsExclV ["system/type/qA"] ["system/type/qA"]))
      == (([] : List String), true), true),
  -- Reading a non-array `targets` as ABSENT answers it with the absent case, which
  -- for `get` is the whole root listing — WIDER than the request, the answer §3.3
  -- forbids.
  ("effectiveTargets: a non-array `targets` is PRESENT-and-empty, never absent",
    effectiveTargets lp (execRes (.map [(.text "targets", .text "not-an-array")]))
      == (([] : List String), true), true),
  -- §5.4 rules the CALLER arm separately from the grant arm: the sentinel carves out
  -- nothing here, so the target SURVIVES. Fail-OPEN, and the asymmetry is the point.
  ("effectiveTargets: the caller-exclude arm is fail-OPEN on an unmatchable pattern",
    effectiveTargets lp (execRes (targetsExclV ["system/type/qA"] ["../nope"]))
      == (["system/type/qA"], true), true),

  -- ── §6.3 check_path_permission ──
  -- THE FIXTURE-VALIDATING CASE. Without it the denies below would all pass against
  -- a token whose grants parsed EMPTY, which denies everything.
  ("checkPathPermission ACCEPT: a path inside every dimension is authorized",
    checkPathPermission lp "get" ("system/type/qA") narrowTok "system/tree", true),
  ("checkPathPermission DENY (resources): a path outside the resource scope",
    checkPathPermission lp "get" ("system/other/qA") narrowTok "system/tree", false),
  ("checkPathPermission DENY (operations): an operation the grant does not name",
    checkPathPermission lp "put" ("system/type/qA") narrowTok "system/tree", false),
  ("checkPathPermission DENY (handlers): a handler the grant does not name",
    checkPathPermission lp "get" ("system/type/qA") narrowTok "system/other", false),
  -- §5.2's note: an empty `resources.include` is a legal grant shape (a handler that
  -- touches no tree paths) and denies every path — `any` over `[]` is false.
  ("checkPathPermission DENY: an empty resources.include denies every path",
    checkPathPermission lp "get" ("system/type/qA")
      (tok (scopeV ["*"] []) (scopeV [] []) (scopeV ["*"] [])) "system/tree", false),
  ("checkPathPermission DENY: a malformed path is the sentinel and matches no grant",
    checkPathPermission lp "get" "../escape"
      (tok (scopeV ["*"] []) (scopeV ["*"] []) (scopeV ["*"] [])) "system/tree", false),
  ("checkPathPermission DENY: a grant exclude covering the subject denies it",
    checkPathPermission lp "get" ("system/type/qB")
      (tok (scopeV ["system/tree"] []) (scopeV ["system/type/*"] ["system/type/qB"])
           (scopeV ["get"] [])) "system/tree", false),

  -- ── RULE B: the §5.4 sentinel reaches PATH-SCOPE only (0.8.2.24, N2/N3) ──
  ("sentinel PATH-SCOPE: an unmatchable resources exclude denies the dimension",
    checkPathPermission lp "get" ("system/type/qA")
      (tok (scopeV ["system/tree"] []) (scopeV ["system/type/*"] ["../nope"])
           (scopeV ["get"] [])) "system/tree", false),
  -- THE 0.8.2.24 REGRESSION THIS GUARDS. `*/apply` is an ordinary namespaced
  -- operation name and a literal matching nothing under the id-scope grammar. Asked
  -- outside the type dispatch it was run through the §5.4 path transforms purely to
  -- classify it, canonicalized to the sentinel, and DENIED EVERY OPERATION —
  -- over-denial, invisible on any well-formed grant. §5.4: "It does NOT reach
  -- `operations` or `peers` [MUST]".
  ("sentinel ID-SCOPE: an operations exclude of `*/apply` does NOT deny",
    checkPathPermission lp "get" ("system/type/qA")
      (tok (scopeV ["system/tree"] []) (scopeV ["system/type/*"] [])
           (scopeV ["get"] ["*/apply"])) "system/tree", true),
  -- The companion: scoping the sentinel OFF the id dimension must not make id
  -- excludes inert. Without this, "does not deny" and "is never read" are the same
  -- observation.
  ("sentinel ID-SCOPE: the exclude still EXCLUDES what it literally names",
    checkPathPermission lp "get" ("system/type/qA")
      (tok (scopeV ["system/tree"] []) (scopeV ["system/type/*"] [])
           (scopeV ["*"] ["get"])) "system/tree", false),

  -- ── RULE E: scopeSubset is TYPED by scope kind (F50, 0.8.2.16) ──
  -- entity-core-formalization's differential on this very peer: 2 of 64 include
  -- pairs and 2 of 64 exclude pairs diverged, FAIL-CLOSED, with a 16-pair control
  -- alphabet reporting ZERO — which is why every hand-tried example missed it.
  ("scopeSubset ID: child include `/tree/get` IS covered by parent `*`",
    scopeSubset .id lp lp ⟨["/tree/get"], []⟩ ⟨["*"], []⟩, true),
  ("scopeSubset ID: child include `*/apply` IS covered by parent `*`",
    scopeSubset .id lp lp ⟨["*/apply"], []⟩ ⟨["*"], []⟩, true),
  -- The two accepts above would also pass against a `scopeSubset` that answered
  -- true unconditionally. This is the case that says it is still a subset check.
  ("scopeSubset ID still ATTENUATES: an operation outside a narrow parent is refused",
    scopeSubset .id lp lp ⟨["put"], []⟩ ⟨["get"], []⟩, false),
  ("scopeSubset PATH is unchanged: the same pair under the path matcher is NOT covered",
    scopeSubset .path lp lp ⟨["/tree/get"], []⟩ ⟨["*"], []⟩, false),

  -- ── RULE F: the sentinel guard sits on the ATTENUATION path too (K-6) ──
  -- `scopeSubset` called the RAW `matchesSeg` in both arms while `covered` called
  -- the guarded wrapper, so §5.4's "never matches in EITHER operand" was bypassed
  -- here, in the PERMISSIVE direction. The witness is the sentinel against ITSELF:
  -- raw `matchesSeg` answers true by the literal-equality arm, which made an
  -- unmatchable parent exclude look inherited by an unmatchable child exclude.
  ("RULE F: an unmatchable include is NOT a subset of itself (matchesSegNM, not matchesSeg)",
    scopeSubset .path "alice" "alice" ⟨["../nope"], []⟩ ⟨["../nope"], []⟩, false),
  ("RULE F: an unmatchable parent exclude is NOT inherited by an unmatchable child exclude",
    scopeSubset .path "alice" "alice" ⟨[], ["../nope"]⟩ ⟨[], ["../nope"]⟩, false),
  -- The control: an ordinary pattern IS a subset of itself, so the two rows above
  -- measure the sentinel rather than a broken subset check.
  ("RULE F control: an ordinary pattern IS still a subset of itself",
    scopeSubset .path "alice" "alice" ⟨["/alice/a/b"], ["/alice/a/c"]⟩ ⟨["/alice/a/b"], ["/alice/a/c"]⟩, true),

  -- ── RULE C / §4.11: the code belongs to the CAUSE (§5.2a, 0.8.2.24 N4/N5) ──
  -- "A peer that refuses at the decode boundary MUST answer 400 hash_mismatch
  -- [MUST] ... 400 non_canonical_ecf is NOT conformant here." The entry's encoding
  -- is CANONICAL; what is false is the claim the key makes.
  ("decode: a mis-keyed `included` entry answers 400 hash_mismatch",
    decodeAnswer (envWithKey (.bytes "not-this-entitys-content-hash".toUTF8)) == (400, "hash_mismatch"), true),
  -- THE FIXTURE CONTROL: without it the row above would pass against an envelope
  -- builder producing garbage, which fails to decode for unrelated reasons.
  ("decode control: a correctly-keyed `included` entry still decodes",
    decodeAnswer (envWithKey (.bytes includedEntityHash)) == (200, "decoded"), true),
  -- §4.11's table: "the frame obligation belongs to the class; the CODE belongs to
  -- the cause [MUST]".
  ("§4.11 table: oversize is 413 payload_too_large",
    EntityCore.Wire.preAdmissionRefusal .frameTooLarge == (413, "payload_too_large"), true),
  ("§4.11 table: a truncated frame is 400 invalid_request",
    EntityCore.Wire.preAdmissionRefusal .frameTruncated == (400, "invalid_request"), true),
  -- ENTITY-CBOR-ENCODING §5.4 defines this code for tag-policy violations
  -- SPECIFICALLY, and §6.3 disjoins the two cases by CAUSE — so the tag arm keeps it.
  ("§4.11 table: a CBOR tag in a data field keeps non_canonical_ecf",
    EntityCore.Wire.preAdmissionRefusal .tagRejected == (400, "non_canonical_ecf"), true),
  ("§4.11 table: resolution integrity is 400 hash_mismatch",
    EntityCore.Wire.preAdmissionRefusal .hashMismatch == (400, "hash_mismatch"), true)
]

-- ── §3.3 ladder + §4.11 non-EXECUTE root, driven against a REAL peer ─────────
-- These are IO because the ladder's ORDER is only observable through the handler:
-- every arm below answers 200 or a DIFFERENT 400 if the handler reads
-- `resource.targets` directly, or resolves the resource before the operation.
--
-- They run with `callerCap := none` — the bootstrap/internal context, where §6.3's
-- path check is correctly inert — so they measure the LADDER and not the path
-- check. The path check's wire behaviour is measured by `tools/arc-probe`, which
-- mints the narrow capability a seed policy cannot produce.

/-- (status, code) of an Outcome, so an assertion can name the code. Several arms
below differ ONLY in the code, and a status-only assertion cannot tell
`path_required` from `ambiguous_resource` — the exact inversion 0.8.2.20 forbids. -/
def outcomeAnswer (o : EntityCore.Peer.Outcome) : Nat × String :=
  (o.status, (textField o.result "code").getD "")

def treeExec (op : String) (resource : Option Value) : Entity :=
  make "system/protocol/execute"
    (.map ([(.text "operation", .text op), (.text "uri", .text "system/tree")]
           ++ (match resource with | some r => [(.text "resource", r)] | none => [])))

def ioCases (peer : EntityCore.Peer.Peer) : IO (List (String × Bool × Bool)) := do
  let ctx (op : String) (r : Option Value) : EntityCore.Peer.DispatchCtx :=
    { exec := treeExec op r, callerCap := none, pattern := "system/tree" }
  -- RESOLVE THE OPERATION FIRST. A peer that validates the resource first answers a
  -- RESOURCE fault for every unknown operation; the arm with a resource present
  -- always answered 501, which is what hides it.
  let bogusNoRes ← EntityCore.Peer.treeHandler peer (ctx "bogusop" none)
  let bogusRes ← EntityCore.Peer.treeHandler peer (ctx "bogusop" (some (targetsV ["system/type/primitive/any"])))
  -- The SELF-EXCLUDED get: resource PRESENT, every target carved out by the caller's
  -- own exclude. EXTENSION-TREE §2.2a makes `get` resource-OPTIONAL and BROAD-RESULT,
  -- so this is 400 path_required and NOT the absent case — serving the root listing
  -- here "answers a request for one excluded path with a listing of the tree".
  let selfExcl ← EntityCore.Peer.treeHandler peer
    (ctx "get" (some (targetsExclV ["system/type/primitive/any"] ["system/type/primitive/any"])))
  -- The ABSENT case stays the root listing, so the row above is a real
  -- discrimination rather than a blanket refusal.
  let absent ← EntityCore.Peer.treeHandler peer (ctx "get" none)
  let ambig ← EntityCore.Peer.treeHandler peer
    (ctx "get" (some (targetsV ["system/type/primitive/any", "system/type/primitive/text"])))
  let pattern ← EntityCore.Peer.treeHandler peer (ctx "get" (some (targetsV ["system/type/*"])))
  -- `put` is resource-REQUIRED (§2.2a), so BOTH empties collapse to path_required.
  -- This answered `ambiguous_resource` for a MISSING target, which 0.8.2.20 names as
  -- the exact inversion it forbids: the remedies differ — *supply a resource* is not
  -- *disambiguate your request* — and the code is what selects between them.
  let putNoRes ← EntityCore.Peer.treeHandler peer (ctx "put" none)
  let putSelfExcl ← EntityCore.Peer.treeHandler peer
    (ctx "put" (some (targetsExclV ["system/type/qA"] ["system/type/qA"])))
  -- §4.11 / N12-N17: a non-EXECUTE root gets a CODED FRAME. §6.5's "Other type?" arm
  -- as rewritten at 0.8.2.25: "400 invalid_request, coded frame; MAY then close. NOT
  -- a bare close." This peer did something weaker still — it returned `none`, the
  -- transport wrote NOTHING and kept the connection open, which is §4.11's SILENT
  -- DROP, "the weaker of the two precisely because nothing surfaces it".
  let conn ← EntityCore.Peer.Conn.new
  let otherRoot := make "system/protocol/some-other-thing" (.map [(.text "request_id", .text "r-1")])
  let nonExec ← EntityCore.Peer.dispatch peer conn { root := otherRoot, included := [] }
  let nonExecAnswer : Nat × String := match nonExec with
    | none => (0, "SILENTLY DROPPED")
    | some env =>
      (((uintField env.root "status").getD 0).toNat,
       ((field env.root "result").bind ofCbor |>.bind (fun r => textField r "code")).getD "")
  let nonExecCorrelated : String := match nonExec with
    | none => ""
    | some env => (textField env.root "request_id").getD ""
  pure [
    ("tree: unknown op with NO resource is an OPERATION fault (501), not a resource one",
      outcomeAnswer bogusNoRes == (501, "unsupported_operation"), true),
    ("tree: unknown op WITH a resource is 501 (unchanged)",
      outcomeAnswer bogusRes == (501, "unsupported_operation"), true),
    ("tree get: self-excluded resource is 400 path_required, not the absent case",
      outcomeAnswer selfExcl == (400, "path_required"), true),
    ("tree get: absent resource is still the root listing (the two empties are distinct)",
      absent.status == 200 && absent.result.typ == "system/tree/listing", true),
    ("tree get: two effective targets is 400 ambiguous_resource",
      outcomeAnswer ambig == (400, "ambiguous_resource"), true),
    ("tree get: a §5.4 PATTERN target is 400 malformed_resource",
      outcomeAnswer pattern == (400, "malformed_resource"), true),
    ("tree put: absent resource is 400 path_required (NOT ambiguous_resource)",
      outcomeAnswer putNoRes == (400, "path_required"), true),
    ("tree put: self-excluded resource is 400 path_required (both empties collapse)",
      outcomeAnswer putSelfExcl == (400, "path_required"), true),
    ("§4.11: a non-EXECUTE root gets a coded 400 invalid_request, never silence",
      nonExecAnswer == (400, "invalid_request"), true),
    ("§4.11: that refusal is correlated by request_id where one is recoverable",
      nonExecCorrelated == "r-1", true)
  ]

def main : IO Unit := do
  let peer ← EntityCore.Peer.create (openGrants := false) (conformance := false)
  let io ← ioCases peer
  let mut fails := 0
  for (name, got, expect) in cases ++ msCases ++ scopeCases ++ io do
    if got != expect then
      fails := fails + 1
      IO.eprintln s!"FAIL: {name}  (got {got}, expected {expect})"
  let total := (cases ++ msCases ++ scopeCases ++ io).length
  IO.println s!"verdict-core selftest: {total - fails} pass · {fails} fail (of {total})"
  if fails != 0 then IO.Process.exit 1
