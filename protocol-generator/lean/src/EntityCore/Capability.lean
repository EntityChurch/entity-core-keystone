/-
  Capability system (L3) — the §5 verification core, written as a PURE TOTAL
  function so it is both the running verdict AND the Track-B proof surface (T4/T5).

  ── The provability cut (the whole point of the Lean peer) ───────────────────
  §5.10 says the Layer-1 cap-chain verdict "MUST be a function of the chain and
  these Layer-1 inputs only." We realize that literally: `verifyChain` is a pure
  total `def` of `(ResolvedChain, localPeer, now)` → determinism is then a free
  corollary (T4). Two deliberate factorings, each surfacing a 1b finding:

    • TIME is a single explicit parameter `now`, sampled once by the shell — not
      `now()` re-sampled per link (OCaml `capability.ml:361`). Forcing this is
      A-LEAN-1: §5.5 samples time per-link (V7:2630) while §5.10 demands a
      cross-peer-deterministic verdict listing TTL as a Layer-1 input.

    • REVOCATION is EXCLUDED from the pure core (the core-peer
      `supports_revocation = false` path, V7:2080). `is_revoked` reads the local
      mutable entity tree (V7:1969) — not cross-peer state — so it cannot live in
      a function "of the chain and Layer-1 inputs only." That is A-LEAN-2; the
      running `verifyRequest` (shell) composes this proven core with the unproven
      revocation + Layer-2 post-gate.

    • CRYPTO (Ed25519 verify) is opaque FFI, so per-link signature validity is a
      RESOLVED `Bool` input (`ResolvedLink.sigValid`), exactly as `Float.toBits`
      is the float boundary. Likewise the per-link GRANTER peer_id frame (§5.5a,
      a store lookup of the granter identity) is resolved by the shell into
      `ResolvedLink.granterPeer`. The pure core reasons about structural linkage,
      attenuation, temporal validity, and depth — never about the primitive.

  ── Pattern model (a representation choice made for provability) ──────────────
  §5.4 patterns/paths are modeled as SEGMENT LISTS (`List String`), not raw
  strings: the shell splits on '/', and `matchesSeg` is structurally recursive on
  the two lists → total (no string-length termination dance) and tractable for the
  T5a subset-transitivity proof, while staying faithful to the §5.4 grammar
  (bare `*`, leading `/*/` peer-wildcard = one segment, trailing `/*` = ≥1
  segment, else exact). This is the running matcher too (no prove-vs-run gap).
-/
import EntityCore.Model
import EntityCore.Base58

namespace EntityCore.Capability

open EntityCore (Value)
open EntityCore.Model

/-- The §5.10 Layer-1 verdict. The dispatcher maps `deny`→403, and the
`unresolvableGrantee` §5.5 carve-out→401. -/
inductive ChainVerdict where
  | allow
  | deny
  | unresolvableGrantee
  deriving Repr, DecidableEq, Inhabited

/-- A bare allow/deny (the §5.2 dispatch-authz gate). -/
inductive Verdict where
  | allow
  | deny
  deriving Repr, DecidableEq, Inhabited

structure Scope where
  incl : List String
  excl : List String
  deriving Inhabited

structure Grant where
  handlers : Scope
  resources : Scope
  operations : Scope
  peers : Option Scope
  deriving Inhabited

-- ── parse helpers (pure over `Value`) ────────────────────────────────────────

def textList (v : Value) : List String :=
  match v with
  | .array xs => xs.filterMap (fun x => match x with | .text s => some s | _ => none)
  | _ => []

def parseScope (v : Value) : Scope :=
  { incl := match mapGet v "include" with | some a => textList a | none => []
    excl := match mapGet v "exclude" with | some a => textList a | none => [] }

def parseGrant (v : Value) : Grant :=
  let sc (key : String) : Scope :=
    match mapGet v key with | some s => parseScope s | none => { incl := [], excl := [] }
  { handlers := sc "handlers", resources := sc "resources", operations := sc "operations",
    peers := match mapGet v "peers" with | some s => some (parseScope s) | none => none }

def grantsOfToken (token : Entity) : List Grant :=
  match field token "grants" with
  | some (.array l) => l.map parseGrant
  | _ => []

-- ── §5.4 pattern matching (segment model) ────────────────────────────────────

/-- Bitcoin Base58 alphabet membership (peer-id segment test, §5.2). -/
def base58Char (c : Char) : Bool := EntityCore.Base58.alphabet.contains c

/-- Split a path into segments. Drops the LEADING empty (from an absolute path's
leading `/`) but KEEPS a trailing empty segment — a trailing `/` is the §3.9
listing marker, and it is exactly what lets a trailing-`*` pattern match a bare
directory path (`/{peer}/` matches `/*/*`) while a non-slashed path does not.
Interior `//` cannot occur in a valid target (pathFlexOk rejects it). -/
def splitSegs (s : String) : List String :=
  match s.splitOn "/" with
  | "" :: rest => rest
  | parts => parts

/-- §1.4 URI normalization: strip the `entity://` scheme to an absolute path. -/
def normalizeUri (uri : String) : String :=
  if uri.startsWith "entity://" then "/" ++ (uri.drop "entity://".length).toString else uri

/-- Canonicalize a path/pattern to absolute SEGMENTS under a frame peer (§5.4):
absolute (`/…`) passes through; a relative path is rooted at `/{frame}/…`. Built
by splitting the absolute STRING (not consing), so a relative `""` or `foo/`
yields the correct trailing-empty segment — exactly the cohort `canonicalize`
(`"" → "/{frame}/"`, `"*" → "/{frame}/*"`). -/
def canonSegs (frame : String) (path : String) : List String :=
  if path.startsWith "/" then splitSegs path else splitSegs ("/" ++ frame ++ "/" ++ path)

/-- Pattern match over canonical segments (§5.4). Total, structurally recursive on
both lists — the running matcher AND the T5a proof surface.
  • trailing `*`  (pattern `["*"]`)   matches ≥1 remaining segment (the `/{p}/*` form)
  • leading `*`   (`"*" :: pt`, pt≠[]) matches exactly one segment (the `/*/…` form)
  • literal       matches by equality. -/
def matchesSeg : List String → List String → Bool
  | path,    ["*"]      => !path.isEmpty
  | [],      []         => true
  | _ :: _,  []         => false
  | [],      _ :: _     => false
  | _ :: ps, "*" :: pt  => matchesSeg ps pt
  | s :: ps, p :: pt    => s == p && matchesSeg ps pt

/-- `value` (canonicalized in `valueFrame`) is covered by some pattern in `pats`
(each canonicalized in `patFrame`). -/
def covered (valueFrame patFrame : String) (value : String) (pats : List String) : Bool :=
  let cv := canonSegs valueFrame value
  pats.any (fun p => matchesSeg cv (canonSegs patFrame p))

/-- §5.4 scope membership on the LOCAL frame (handlers/operations/peers
dimensions): value in include, not in exclude. -/
def matchesScope (localPeer : String) (value : String) (s : Scope) : Bool :=
  covered localPeer localPeer value s.incl && !covered localPeer localPeer value s.excl

-- ── §5.6 attenuation (the T5a surface) ───────────────────────────────────────

/-- §5.6 scope subset under per-side §5.5a granter frames: every child include is
covered by some parent include (child frame vs parent frame), and the child
inherits every parent exclude (parent frame vs child frame). When the two frames
are equal (same-peer chain) this is the pre-Amendment behavior byte-for-byte. -/
def scopeSubset (childFrame parentFrame : String) (child parent : Scope) : Bool :=
  child.incl.all (fun cp =>
    let cc := canonSegs childFrame cp
    parent.incl.any (fun pp => matchesSeg cc (canonSegs parentFrame pp)))
  && parent.excl.all (fun pe =>
       let cpe := canonSegs parentFrame pe
       child.excl.any (fun ce => matchesSeg cpe (canonSegs childFrame ce)))

/-- §5.6 grant subset. Handlers/operations/peers compare on the LOCAL frame;
RESOURCES use the §5.5a per-link granter frames (`childFrame`/`parentFrame`). -/
def grantSubset (localPeer childFrame parentFrame : String) (child parent : Grant) : Bool :=
  scopeSubset localPeer localPeer child.handlers parent.handlers
  && scopeSubset localPeer localPeer child.operations parent.operations
  && scopeSubset childFrame parentFrame child.resources parent.resources
  && (let cp := child.peers.getD { incl := [localPeer], excl := [] }
      let pp := parent.peers.getD { incl := [localPeer], excl := [] }
      scopeSubset localPeer localPeer cp pp)

/-- §5.6 attenuation: every child grant is covered by some parent grant, and the
child's expiry does not exceed the parent's (a finite parent forbids an infinite
child). -/
def isAttenuated (localPeer childFrame parentFrame : String) (child parent : Entity) : Bool :=
  let cg := grantsOfToken child
  let pg := grantsOfToken parent
  cg.all (fun c => pg.any (fun p => grantSubset localPeer childFrame parentFrame c p))
  && (match uintField parent "expires_at", uintField child "expires_at" with
      | some _,  none    => false
      | some pe, some ce => ce ≤ pe
      | none,    _       => true)

/-- §5.7 delegation caveats: a parent's caveats constrain its direct child. -/
def checkDelegationCaveats (parent child : Entity) (depth : Nat) : Bool :=
  match field parent "delegation_caveats" with
  | none => true
  | some caveats =>
      let noDeleg := match mapGet caveats "no_delegation" with | some (.bool b) => b | _ => false
      if noDeleg then false
      else
        let depthOk := match mapGet caveats "max_delegation_depth" with
          | some (.uint m) => (UInt64.ofNat depth) < m
          | _ => true
        let ttlOk := match mapGet caveats "max_delegation_ttl" with
          | some (.uint maxttl) =>
              (match uintField child "expires_at", uintField child "created_at" with
               | some ex, some cr => (ex - cr) ≤ maxttl
               | some _,  none    => true
               | none,    _       => false)
          | _ => true
        depthOk && ttlOk

-- ── §5.5 chain verification (the T4 surface) ─────────────────────────────────

/-- A chain link with the shell-resolved boundary facts the pure verdict needs.
`granterPeer` = the §5.5a granter frame (store lookup; `none` ⇒ hard-fail deny).
`sigValid` = the Ed25519 verify result (opaque FFI). `granteeResolvable` = the
§5.5 grantee store lookup. `isMultiSig` = the §3.6 multi-granter root marker (the
single-sig per-link signature check is skipped; the quorum is `rootAuthorityOk`,
and a multi-sig link is allowed ONLY at the root). -/
structure ResolvedLink where
  entity : Entity
  granterPeer : Option String
  sigValid : Bool
  granteeResolvable : Bool
  isMultiSig : Bool := false
  deriving Inhabited

/-- A shell-resolved multi-sig signer (§3.6). `key` = hex of the signer identity
hash (M3 distinctness); `isLocal` = peerId == localPeer (M6); `signed` = a valid
signature from this signer over the cap content hash exists (M4). -/
structure ResolvedSigner where
  key : String
  isLocal : Bool
  signed : Bool
  deriving Inhabited

/-- Resolved root authority: single-sig (granter derives local peer) or §3.6 M3
multi-sig (root-only). -/
inductive RootAuthority where
  | single (isLocal : Bool)
  | multi (signers : List ResolvedSigner) (threshold : Nat) (parentNull : Bool)
  deriving Inhabited

/-- A resolved authority chain, leaf → root, plus the resolved root authority
(single-sig: root granter derives `localPeer`; §3.6 multi-sig: k-of-n quorum). -/
structure ResolvedChain where
  links : List ResolvedLink
  rootAuthority : RootAuthority
  deriving Inhabited

/-- M3 distinct signers: no repeated signer key. -/
def noDupKeys : List ResolvedSigner → Bool
  | [] => true
  | s :: rest => !(rest.any (fun t => t.key == s.key)) && noDupKeys rest

/-- §3.6 M3 / §5.5 M4·M6 multi-sig root gate (PURE). M3 structure (root-only,
n≥2, 2≤threshold≤n, distinct signers) precedes the M4 quorum count; M6 = the
local peer is a signer. The M4 count is over DISTINCT signers (the list is
distinct by M3), so a duplicate signature can't inflate the quorum. -/
def multiSigRootOk (signers : List ResolvedSigner) (threshold : Nat) (parentNull : Bool) : Bool :=
  parentNull
  && (2 ≤ signers.length)
  && (2 ≤ threshold) && (threshold ≤ signers.length)
  && noDupKeys signers
  && signers.any (fun s => s.isLocal)
  && (threshold ≤ (signers.filter (fun s => s.signed)).length)

def rootAuthorityOk : RootAuthority → Bool
  | .single isLocal => isLocal
  | .multi signers threshold parentNull => multiSigRootOk signers threshold parentNull

/-- Per-link temporal validity (§5.5) against the single explicit `now`. -/
def temporalOk (e : Entity) (now : UInt64) : Bool :=
  (match uintField e "not_before" with | some nb => !(now < nb) | none => true)
  && (match uintField e "expires_at" with | some ex => !(ex < now) | none => true)

/-- Structural linkage + attenuation + §5.7 caveats for one (child, parent) edge
under the per-link granter frames. A `none` granter frame on either side hard-fails
(§5.5a §4 scrutiny: never silently fall back to the local frame). -/
def edgeOk (localPeer : String) (depth : Nat) (child parent : ResolvedLink) : Bool :=
  match child.granterPeer, parent.granterPeer with
  | some cf, some pf =>
      (match bytesField parent.entity "grantee", bytesField child.entity "granter" with
       | some pg, some cg => baEq pg cg
       | _, _ => false)
      && isAttenuated localPeer cf pf child.entity parent.entity
      && checkDelegationCaveats parent.entity child.entity depth
  | _, _ => false

/-- The §5.5 single-sig chain walk, leaf → root, as a PURE TOTAL function of
`(links, localPeer, now)`. Mirrors the cohort `verify_capability_chain`:
short-circuits to `deny` on the first failing link; a reached link whose grantee
is unresolvable yields `unresolvableGrantee` (the 401 carve-out), taking
precedence over a same-link signature failure (faithful to the cohort's
raise-after-sig ordering). -/
def walk (localPeer : String) (now : UInt64) : Nat → List ResolvedLink → ChainVerdict
  | _,     []              => .allow
  | depth, link :: rest =>
      if !link.granteeResolvable then .unresolvableGrantee
      else
        let here := temporalOk link.entity now
          && (match rest with
              | []          => if link.isMultiSig then true else link.sigValid   -- root: quorum handled by rootAuthorityOk
              | parent :: _ => !link.isMultiSig && link.sigValid && edgeOk localPeer depth link parent)
        if here then walk localPeer now (depth + 1) rest else .deny

/-- §5.5 verdict: the root authority must hold (single-sig: root granter derives
the local peer; §3.6 multi-sig: k-of-n quorum), then the per-link walk. PURE,
TOTAL, `now` explicit, revocation excluded — the §5.10 Layer-1-minus-revocation
entry point (T4). -/
def verifyChain (rc : ResolvedChain) (localPeer : String) (now : UInt64) : ChainVerdict :=
  if !rootAuthorityOk rc.rootAuthority then .deny
  else walk localPeer now 0 rc.links

/-- §4.10(b) structural pre-check: does the chain exceed the max depth (64)?
Purely structural (counts links), gated BEFORE the authz walk so an over-deep
chain reports `400 chain_depth_exceeded`, distinct from a `403` authz denial
(arch v7.75 ruling). An unreachable parent is NOT a depth problem — the shell
truncates the resolved chain there, and the walk denies it (403). -/
def chainExceedsDepth (rc : ResolvedChain) : Bool := rc.links.length > 65

-- ── §5.2 dispatch-authz gate (the v7.73 §3.2.3 boundary) ─────────────────────

def firstSegment (uri : String) : String :=
  let u := if uri.startsWith "/" then (uri.drop 1).toString else uri
  match splitSegs u with | seg :: _ => seg | [] => u

def isPeerId (seg : String) : Bool :=
  seg.length ≥ 46 && seg.all base58Char

def extractPeer (localPeer uri : String) : String :=
  let first := firstSegment (normalizeUri uri)
  if isPeerId first then first else localPeer

/-- §5.4 concrete-target resource subset under the §PR-8 frame split: the request
TARGET + caller EXCLUDE stay on the local frame; the GRANT's resource patterns
canonicalize on the GRANTER frame. -/
def checkResourceScope (localPeer granterPeer : String) (resource : Value) (s : Scope) : Bool :=
  let targets := match mapGet resource "targets" with | some a => textList a | none => []
  let callerExcl := match mapGet resource "exclude" with | some a => textList a | none => []
  let coveredLocal (pats : List String) (ct : List String) : Bool :=
    pats.any (fun p => matchesSeg ct (canonSegs localPeer p))
  let coveredGrant (pats : List String) (ct : List String) : Bool :=
    pats.any (fun p => matchesSeg ct (canonSegs granterPeer p))
  !targets.isEmpty &&
  targets.all (fun tgt =>
    let ct := canonSegs localPeer tgt
    if coveredLocal callerExcl ct then true
    else if !coveredGrant s.incl ct then false
    else !coveredGrant s.excl ct)

/-- §5.2 dispatch authorization gate. `granterPeer` is the §PR-8 frame for the
cap's resource patterns; every other dimension stays local. -/
def checkPermission (localPeer granterPeer : String) (exec token : Entity)
    (handlerPattern : String) : Verdict :=
  let operation := (textField exec "operation").getD ""
  let uri := (textField exec "uri").getD ""
  let targetPeer := extractPeer localPeer uri
  let resource := field exec "resource"
  let grantOk (g : Grant) : Bool :=
    matchesScope localPeer operation g.operations
    && matchesScope localPeer handlerPattern g.handlers
    && (let peers := g.peers.getD { incl := [localPeer], excl := [] }
        matchesScope localPeer targetPeer peers)
    && (match resource with
        | none => true
        | some r => checkResourceScope localPeer granterPeer r g.resources)
  if (grantsOfToken token).any grantOk then .allow else .deny

end EntityCore.Capability
