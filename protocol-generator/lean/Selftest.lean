/-
  Pure verdict-core selftest (S3). Validates that the SEGMENT-model §5.4 matcher
  and the §5.6 attenuation logic are faithful to the spec/cohort semantics BEFORE
  the running shell or the Track-B proofs depend on them. Not a conformance gate
  (that is validate-peer); a fast faithfulness check on the highest-risk novel
  representation (matchesSeg) + the attenuation frames.
-/
import EntityCore.Capability

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
    scopeSubset "alice" "alice" ⟨["/alice/a/b"], []⟩ ⟨["/alice/a/*"], []⟩, true),
  ("not subset: child broadens parent",
    scopeSubset "alice" "alice" ⟨["/alice/a/*"], []⟩ ⟨["/alice/a/b"], []⟩, false),
  -- ── §PR-8 / §5.5a granter-frame discipline (the V2(a) class) ──
  -- A foreign-granted bare "*" must canonicalize to the GRANTER's namespace, so it
  -- does NOT subset a parent bare "*" framed on a DIFFERENT granter. Same pattern
  -- text, different frames ⇒ not a subset (this is the v7.73 fix in pure form).
  ("granter-frame: bare * across different frames is NOT a subset",
    scopeSubset "bob" "alice" ⟨["*"], []⟩ ⟨["*"], []⟩, false),
  ("granter-frame: bare * within the SAME frame IS a subset",
    scopeSubset "alice" "alice" ⟨["*"], []⟩ ⟨["*"], []⟩, true),
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

def main : IO Unit := do
  let mut fails := 0
  for (name, got, expect) in cases ++ msCases do
    if got != expect then
      fails := fails + 1
      IO.eprintln s!"FAIL: {name}  (got {got}, expected {expect})"
  let total := (cases ++ msCases).length
  IO.println s!"verdict-core selftest: {total - fails} pass · {fails} fail (of {total})"
  if fails != 0 then IO.Process.exit 1
