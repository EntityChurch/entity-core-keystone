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

/-- The unmatchable value (0.8.2.20), in this peer's SEGMENT representation:
`splitSegs "/never-match"`. Unreachable as a canonical path by CONSTRUCTION — its
only segment cannot be a peer_id, since `isPeerId` requires >= 46 Base58 characters
and `-` is outside the Base58 alphabet. -/
def neverMatch : List String := ["never-match"]

/-- Canonicalize a path/pattern to absolute SEGMENTS under a frame peer (§5.4):
absolute (`/…`) passes through; a relative path is rooted at `/{frame}/…`. Built
by splitting the absolute STRING (not consing), so a relative `""` or `foo/`
yields the correct trailing-empty segment — exactly the cohort `canonicalize`
(`"" → "/{frame}/"`, `"*" → "/{frame}/*"`).

TOTAL (0.8.2.20): the return domain is "canonical segments OR `neverMatch`". The
two reserved arms were ABSENT here — `../x` came back as `[frame, "..", "x"]`, which
matched no literal, so a grant exclude carrying it carved out nothing and the grant
was silently wider than its author wrote (measured on the wire 2026-09-14). A
non-match is the desired outcome in an INCLUDE and the opposite of it in an EXCLUDE. -/
def canonSegs (frame : String) (path : String) : List String :=
  if path.startsWith "./" || path.startsWith "../" then neverMatch
  else if path.startsWith "*/" then neverMatch
  else if path.startsWith "/" then splitSegs path
  else splitSegs ("/" ++ frame ++ "/" ++ path)

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

/-- `matchesSeg` with the §5.4 sentinel rule in front: `neverMatch` never matches, in
EITHER operand (0.8.2.20).

This is a WRAPPER rather than a new first arm of `matchesSeg`, deliberately.
`matchesSeg` is not only the running matcher, it is the T5a PROOF SURFACE — the
transitivity theorem and its five arm-characterization lemmas in
`EntityCoreProofs.CapabilityProofs` are `rfl`-level facts about its exact clause
order. Adding a clause would re-derive every one of them to prove a property that is
not about pattern matching at all. The rule is a MATCHER rule and not a property of
the value, which is why it cannot simply be left to the construction: the first arm
of `matchesSeg` answers `true` for ANY non-empty path against the bare `["*"]`
pattern, sentinel included. -/
def matchesSegNM (path pat : List String) : Bool :=
  if path == neverMatch || pat == neverMatch then false else matchesSeg path pat

/-- AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
in an include (covers nothing -> the grant grants nothing) and fail-OPEN in an exclude
(carves out nothing), so the reading is chosen where the POSITION is known and the
matcher stays uniform over its operands.

EVERY CALL SITE MUST GUARD IT ON PATH-SCOPE (0.8.2.24, N2/N3). This used to be asked
of every dimension — the comment here said so, "transcribing §5.2's loop literally",
and that was true of the loop as it then read. §5.2's exclude test now sits INSIDE
`if dimension_type == "system/capability/path-scope"`, and §5.4 says the same from the
other side: "a capability carrying an unmatchable PATH-SCOPE pattern is INVALID ... It
does NOT reach `operations` or `peers` [MUST]".

`neverMatch` is a §5.4 PATH-canonicalization sentinel with no meaning on an id-scope
dimension, whose patterns are literal identifiers that §5.2's own id-scope arm forbids
putting through the §5.4 transforms. Asked outside the type dispatch it ran an id
pattern through those transforms purely to classify it and then DENIED THE WHOLE
DIMENSION on a property unrelated to whether the exclude carves anything out: an
`operations` exclude of `*/apply` — an ordinary namespaced operation name, a literal
matching nothing under the id-scope grammar — canonicalized to the sentinel and denied
every operation. Over-denial, and invisible on any well-formed grant. -/
def excludeUnmatchable (frame : String) (excl : List String) : Bool :=
  excl.any (fun p => canonSegs frame p == neverMatch)

/-- `value` (canonicalized in `valueFrame`) is covered by some pattern in `pats`
(each canonicalized in `patFrame`). -/
def covered (valueFrame patFrame : String) (value : String) (pats : List String) : Bool :=
  let cv := canonSegs valueFrame value
  pats.any (fun p => matchesSegNM cv (canonSegs patFrame p))

/-- Which §5.2 matcher a grant dimension uses (0.8.1, F40). Named at every call site —
there is no default — so a new one cannot inherit the wrong matcher silently, which is
exactly the F40 defect. -/
inductive ScopeKind where
  /-- `operations`, `peers` — `system/capability/id-scope`. -/
  | id
  /-- `handlers`, `resources` — `system/capability/path-scope`. -/
  | path
  deriving DecidableEq, Repr

/-- §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard forms
— bare `*` and a trailing slash-star segment-prefix. None of the §5.4 path transforms
apply, so a pattern carrying path syntax is matched as a literal string: a non-match,
never a fault. -/
-- `dropEnd`, not `dropRight`: the latter is deprecated in Lean 4.29.1 and the
-- replacement returns a `String.Slice` rather than a `String`. That reads like a
-- breaking change and is not one here — `String.startsWith` is generic over
-- `String.Slice.Pattern.ForwardPattern`, so the slice is accepted directly with no
-- `.toString` copy. Verified by differential evaluation over 21 inputs (segment-prefix
-- hits and misses, bare `*`, `/*`, empty value, and 2- and 3-byte multi-byte prefixes):
-- ZERO divergence from the `dropRight` form. Disclosed to us by
-- entity-core-formalization, whose ledger pins this file by digest.
def matchesIdPattern (value pattern : String) : Bool :=
  if pattern == "*" then true
  else if pattern.length ≥ 2 && pattern.endsWith "/*" then
    value.startsWith (pattern.dropEnd 1)
  else value == pattern

def coveredId (value : String) (pats : List String) : Bool :=
  pats.any (fun p => matchesIdPattern value p)

/-- §5.2 scope membership, typed by scope kind (0.8.1, F40): `path` canonicalizes both
sides on the LOCAL frame; `id` compares literally. Value in include, not in exclude. -/
def matchesScope (localPeer : String) (value : String) (s : Scope) (kind : ScopeKind) : Bool :=
  match kind with
  -- The two id-scope dimensions reach the literal matcher UNGUARDED, and that is
  -- correct rather than an omission (0.8.2.24, N2/N3 — see `excludeUnmatchable`):
  -- under the id-scope grammar every non-`*` pattern is a literal, and a literal is
  -- never structurally unmatchable, so there is nothing here for the sentinel to
  -- detect. §5.4 says so outright and leaves the id-scope form of the
  -- carves-out-nothing hazard deliberately open rather than minting a second
  -- sentinel for it.
  | .id => coveredId value s.incl && !coveredId value s.excl
  | .path =>
    if excludeUnmatchable localPeer s.excl then false   -- 0.8.2.21 — deny
    else covered localPeer localPeer value s.incl && !covered localPeer localPeer value s.excl

-- ── §5.6 attenuation (the T5a surface) ───────────────────────────────────────

/-- §5.6 scope subset under per-side §5.5a granter frames: every child include is
covered by some parent include (child frame vs parent frame), and the child
inherits every parent exclude (parent frame vs child frame). When the two frames
are equal (same-peer chain) this is the pre-Amendment behavior byte-for-byte.

TYPED BY SCOPE KIND (F50, ruled YES at 0.8.2.16). §3.6's grammar binds the scope
TYPE, not one function — "an implementation on the canonicalizing reading is
non-conformant and MUST adopt the literal matcher" — so F40's id-scope pin reaches
here exactly as it reaches `matchesScope`, with delegation-chain WIDENING named as
the reason. This function used to canonicalize both operands on every dimension, so
an `operations` or `peers` pattern went through the §5.4 path transforms purely to
be compared: `entity-core-formalization` measured 2 of 64 include pairs and 2 of 64
exclude pairs diverging (`/tree/get` vs `*`, `*/apply` vs `*`), FAIL-CLOSED, with a
16-pair control alphabet reporting zero — which is why every hand-tried example
missed it. The kind has NO DEFAULT and is named at every call site, because a
default is how the next dimension inherits the wrong matcher silently, which is the
original F40 defect.

AND IT CALLS `matchesSegNM`, NOT `matchesSeg` (K-6, 0.8.2.22). `covered` already
took the guarded wrapper and this function did not, so §5.4's "never matches in
either operand" was bypassed on the ATTENUATION path — in the PERMISSIVE direction.
"A sentinel arm is a control-flow obligation, not a line ... the guard MUST sit on
every path that reaches the decision it protects." The wrapper exists precisely so
the running matcher can be guarded without touching `matchesSeg`, which is the T5a
proof surface: six `rfl`-level lemmas in `EntityCoreProofs.CapabilityProofs` are
facts about its exact clause order, and a new first arm would re-derive all of them
to prove a property that is not about pattern matching. -/
def scopeSubset (kind : ScopeKind) (childFrame parentFrame : String)
    (child parent : Scope) : Bool :=
  match kind with
  | .id =>
    child.incl.all (fun cp => parent.incl.any (fun pp => matchesIdPattern cp pp))
    && parent.excl.all (fun pe => child.excl.any (fun ce => matchesIdPattern pe ce))
  | .path =>
    child.incl.all (fun cp =>
      let cc := canonSegs childFrame cp
      parent.incl.any (fun pp => matchesSegNM cc (canonSegs parentFrame pp)))
    && parent.excl.all (fun pe =>
         let cpe := canonSegs parentFrame pe
         child.excl.any (fun ce => matchesSegNM cpe (canonSegs childFrame ce)))

/-- §5.6 grant subset. Handlers/operations/peers compare on the LOCAL frame;
RESOURCES use the §5.5a per-link granter frames (`childFrame`/`parentFrame`). The
scope KIND is named per dimension alongside the frame: `handlers`/`resources` are
path-scope, `operations`/`peers` id-scope (§3.6, F40/F50). -/
def grantSubset (localPeer childFrame parentFrame : String) (child parent : Grant) : Bool :=
  scopeSubset .path localPeer localPeer child.handlers parent.handlers
  && scopeSubset .id localPeer localPeer child.operations parent.operations
  && scopeSubset .path childFrame parentFrame child.resources parent.resources
  && (let cp := child.peers.getD { incl := [localPeer], excl := [] }
      let pp := parent.peers.getD { incl := [localPeer], excl := [] }
      scopeSubset .id localPeer localPeer cp pp)

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

/-- §6.2 CAP-6a: every temporal field on a RECEIVED token must be either ABSENT
(legal) or representable as `primitive/uint`.

This is the reader-side half of CAP-6 and where a peer fails OPEN: `uintField`
answers `none` for BOTH an absent field and a present non-uint one, so a token
carrying `expires_at: -1` slips past the range checks below and is honoured.
§6.2 CAP-6a: such a token "is malformed. A verifier MUST refuse it and MUST NOT
treat the unrepresentable field as absent." -/
def temporalFieldsRepresentable (e : Entity) : Bool :=
  ["expires_at", "not_before", "created_at"].all (fun k =>
    match field e k with
    | none => true            -- absent is legal
    | some (.uint _) => true  -- representable
    | some _ => false)        -- present but undecodable as uint64

/-- §5.6 rule 3: convert a DURATION term to an absolute timestamp, or `none` when
it contributes no ceiling. An overflowing conversion is treated as ABSENT exactly
as a null term is -- never wrapped, never saturated (saturating manufactures
`expires_at = 2^64-1`, a finite bound indistinguishable from a deliberate one).

`ttl = 0` is deliberately NOT special-cased: §5.6 rule 2 makes it a DEFINED value
yielding `created_at` (expire immediately), and letting it fall out of the
arithmetic is what keeps it from collapsing into the absent/"no bound" spelling. -/
def addTtl (createdAt ttl : UInt64) : Option UInt64 :=
  let sum := createdAt + ttl
  if sum < createdAt then none else some sum

/-- §5.6 MIN_DEFINED: the minimum over the DEFINED terms only; `none` when no term
is defined (the token genuinely has no expiry). Absolute terms enter directly;
durations must be converted with `addTtl` first. -/
def minDefined (terms : List (Option UInt64)) : Option UInt64 :=
  terms.foldl (fun acc t =>
    match acc, t with
    | none, x => x
    | x, none => x
    | some a, some b => some (if b < a then b else a)) none

/-- Per-link temporal validity (§5.5) against the single explicit `now`.

CAP-6a runs FIRST and must: the two range checks use `uintField`, which cannot
tell "absent" from "present but not a uint" -- exactly the ambiguity that made an
unrepresentable field fail open. -/
def temporalOk (e : Entity) (now : UInt64) : Bool :=
  temporalFieldsRepresentable e
  && (match uintField e "not_before" with | some nb => !(now < nb) | none => true)
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

/-- Is the resolved root a §3.6 multi-signature quorum? -/
def rootIsMultiSig : RootAuthority → Bool
  | .multi _ _ _ => true
  | .single _    => false

/-- `verifyChain` with the ROOT frame named separately from the verifying peer.

§1.4's PD-2 presented-authority arm needs this: the credential it evaluates is
minted by the TARGET peer, so root-trust is relaxed away from the local peer. The
shell already expresses that by resolving `RootAuthority.single isLocal` against
the ROOT peer rather than the local one, so the single-sig case needs nothing here.

What DOES need saying is the quorum case. A MULTI-SIGNATURE ROOT IS ONLY EVER VALID
LOCALLY (§1.4, 0.8.2.19): *minted by the target* means the target SOLELY minted it,
and a K-of-N root is a GROUP's authority — its co-signers authorized it too.
Verifying the quorum in a foreign frame and accepting it would let any one signer's
target confer the whole group's grant, which is E3/F66's over-acceptance. §5.5's M6
also requires the LOCAL peer in the signer set, so the quorum arm has no meaning in
a foreign frame even on its own terms.

A WRAPPER, NOT A NEW CLAUSE IN `verifyChain`. That function and `multiSigRootOk`
are T5a proof surfaces: the transitivity theorem and the arm-characterization lemmas
below depend on their exact shape, so adding an arm would re-derive all of them to
prove a property that is not about chain walking at all. The guard is expressible
outside, and outside is where it goes. -/
def verifyChainRootedAt (rc : ResolvedChain) (localPeer : String) (now : UInt64)
    (frameIsLocal : Bool) : ChainVerdict :=
  if !frameIsLocal && rootIsMultiSig rc.rootAuthority then .deny
  else verifyChain rc localPeer now

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
    pats.any (fun p => matchesSegNM ct (canonSegs localPeer p))
  let coveredGrant (pats : List String) (ct : List String) : Bool :=
    pats.any (fun p => matchesSegNM ct (canonSegs granterPeer p))
  -- An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
  -- target: the coverage test below is correct in isolation and is simply never
  -- reached on a sentinel, because matchesSegNM answers false.
  !excludeUnmatchable granterPeer s.excl &&
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
    matchesScope localPeer operation g.operations .id
    && matchesScope localPeer handlerPattern g.handlers .path
    && (let peers := g.peers.getD { incl := [localPeer], excl := [] }
        matchesScope localPeer targetPeer peers .id)
    && (match resource with
        | none => true
        | some r => checkResourceScope localPeer granterPeer r g.resources)
  if (grantsOfToken token).any grantOk then .allow else .deny

-- ── §5.2 effective targets and §6.3 check_path_permission ────────────────────

/-- §5.2's effective target list (0.8.2.20): the caller's own `resource.exclude`
removes entries from the request BEFORE anything else looks at it.

Survivors come back in the caller's OWN SPELLING, not canonicalized — 0.8.2.21 is
explicit that `effective_targets` yields raw survivors, and the distinction is
load-bearing because the value flows on to the store lookup, which canonicalizes
for itself.

The `Bool` says whether a `resource` was present AT ALL. An ABSENT resource and a
resource whose every target was excluded are different inputs to §3.3 — the first
is "no resource", the second is an empty effective list — and for a
resource-OPTIONAL operation 0.8.2.24 (N7) makes them DIFFERENT REQUESTS with
different answers, not merely different inputs to one.

THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES [MUST] (0.8.2.25, N11): "where
an implementation projects resource.targets onto the effective set ahead of the
handler, that projection MUST NOT be lossy about its own emptiness — narrow when
narrowing leaves something, and retain the raw pair when narrowing would empty it."
A function returning only a list cannot satisfy that: collapsing `[qA] exclude
[qA]` to `[]` deletes the two-empties discriminator before any handler can read it,
and the handler's refusal arm becomes dead code that only a WIRE drive can detect.

A `targets` key PRESENT but not an array reads as PRESENT-and-empty, never as
absent: reading it as absent answers it with the ABSENT case, which for `get` is the
whole root listing — wider than the request, which is the answer §3.3 forbids. -/
def effectiveTargets (localPeer : String) (exec : Entity) : List String × Bool :=
  match field exec "resource" with
  | some r@(.map _) =>
    match mapGet r "targets" with
    | none => ([], false)
    | some targetsV =>
      let targets := textList targetsV
      let callerExcl := match mapGet r "exclude" with | some a => textList a | none => []
      -- The caller-exclude arm is fail-OPEN on an unmatchable pattern (§5.4's table
      -- rules it separately from the grant arm): `canonSegs` answers the sentinel and
      -- `matchesSegNM` then answers false, so the target simply SURVIVES. That
      -- asymmetry is 0.8.2.21's whole point and it is INHERITED from the primitives
      -- here rather than restated.
      let dropped (t : String) : Bool :=
        let ct := canonSegs localPeer t
        callerExcl.any (fun x => matchesSegNM ct (canonSegs localPeer x))
      (targets.filter (fun t => !dropped t), true)
  | _ => ([], false)

/-- §6.3's handler-level path check.

IT IS NOT A SECONDARY CHECK (§5.2, 0.8.2.20). It is the enforcement wherever the
subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
by caller-controlled input: a caller who excludes the one target its capability does
not cover removes that target from `checkPermission`'s view entirely, and a handler
that then acts on it has authorized nothing.

THREE DIMENSIONS, NOT FOUR. `peers` is not consulted here — the path is local by
construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
step 3, before any handler runs), and §6.3's signature names only `handlers`,
`operations` and `resources`.

THE FRAME IS `local_peer_id`, NOT THE GRANTER, AND THAT IS THE SPEC'S OWN SIGNATURE
RATHER THAN A CHOICE. §6.3's block reads `matches_scope(canonical_path,
grant.resources, "path-scope", local_peer_id)` — there is no granter parameter to
pass. §5.5a governs chain ATTENUATION, where the subject is a pattern compared
against a parent's pattern; this call site compares a CONCRETE local path the
handler is about to touch.

There is no caller-exclude set here: the subject is a single concrete path and the
caller's exclusions were already applied in DERIVING it, so every grant exclude
covering the subject denies — which `matchesScope` already implements, including
0.8.2.21's sentinel rule, so this is three calls to it and nothing else.

An empty `resources.include` is a legal grant shape (§5.2: handlers that touch no
tree paths) and DENIES every path, which is what that note says it should: `any`
over an empty include list is false. A malformed path canonicalizes to the sentinel,
which matches no grant (§5.4), so it falls through to DENY rather than being matched
against anything. -/
def checkPathPermission (localPeer operation path : String) (token : Entity)
    (handlerPattern : String) : Bool :=
  (grantsOfToken token).any (fun g =>
    matchesScope localPeer handlerPattern g.handlers .path
    && matchesScope localPeer operation g.operations .id
    && matchesScope localPeer path g.resources .path)

-- ── §1.4 PD-2: outbound sub-dispatch authorization ───────────────────────────

/-- Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.

§1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree`
and `entity://{peer}/system/tree` — and §1.4's PD-2 block requires Dimension 1's
handler pattern to be the target uri's peer-relative path, because a grant names
HANDLERS and a handler pattern never carries a peer segment. Matching a grant
against the absolute or schemed form matches nothing, silently, which reads at the
wire as an authority refusal.

The first segment is dropped ONLY when it is a peer_id. A peer-relative
`system/protocol/connect` must not lose `system` — the standing defect on
`smalltalk` and `forth`, where an unconditional strip made every self-minted grant
unusable while the handshake stayed green. -/
def peerRelativeOf (uri : String) : String :=
  let p := normalizeUri uri
  if !p.startsWith "/" then p
  else
    match splitSegs (p.drop 1).toString with
    | seg :: rest => if isPeerId seg then String.intercalate "/" rest
                     else String.intercalate "/" (seg :: rest)
    | []          => p

/-- Store key of a handler's OWN grant (§6.8: `system/capability/grants/{pattern}`),
tolerant of the pattern arriving absolute or peer-relative.

§6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
the grant path is built from the PEER-RELATIVE one. The two are one segment apart
and concatenating the wrong one yields a doubled peer segment whose lookup misses —
which fails closed as "no handler grant" and is indistinguishable, at the wire, from
a genuine authority refusal. -/
def grantPathFor (localPeer pattern : String) : String :=
  let pfx := "/" ++ localPeer ++ "/"
  let rel := if pattern.startsWith pfx then (pattern.drop pfx.length).toString else pattern
  "/" ++ localPeer ++ "/system/capability/grants/" ++ rel

/-- §1.4's PD-2 gate: `check_permission` run before a locally-originated
sub-dispatch LEAVES the peer, with all four dimensions applied.

ONE GATE AND ONE EXEMPTION, in §1.4's own words:

* the EXECUTING HANDLER'S GRANT decides all four dimensions (§6.8), evaluated in
  the LOCAL frame, with Dimension 1's pattern the target uri's PEER-RELATIVE path;
* a valid capability MINTED BY THE TARGET PEER naming this peer as `grantee`
  relaxes Dimension 4 (`peers`) AND ONLY DIMENSION 4, to the peers that capability
  covers, evaluated in the TARGET's frame.

*"The target answers WHERE; the handler's grant answers WHAT."* A credential is NOT
a grant: with no handler grant there is nothing to supply Dimensions 1-3, so the
sub-dispatch is refused however good the credential is. That is the COMPOSE, and the
BYPASS it is distinguished from is a peer that treats the credential as a standalone
authorizer and steers past its own grant — §6.8's confused-deputy substitution. Both
obvious vectors agree under either reading (sources agree → allow, no source →
refuse), so the only input that separates them is a VALID credential presented to a
handler whose own grant does NOT cover the request, which MUST refuse.

`relaxTo` is the peers scope the credential earned, already decided by the shell
(which owns resolution and the clock); `none` is both the ambient arm and a
credential that failed any clause. A credential failing verification relaxes NOTHING
and the handler grant gates unrelaxed — it does not turn the verdict into an error.

PURE and TOTAL: every resolution the decision needs has been done by the caller, so
this is a function of the grant, the request and one already-computed relaxation. -/
def checkOutboundSubDispatch (localPeer targetPeer handlerPattern operation : String)
    (handlerGrant : Entity) (resource : Value) (relaxTo : Option Scope) : Bool :=
  let grantOk (g : Grant) : Bool :=
    matchesScope localPeer handlerPattern g.handlers .path
    && matchesScope localPeer operation g.operations .id
    && checkResourceScope localPeer localPeer resource g.resources
    -- Dimension 4. §5.2's default for an absent `peers` scope is
    -- {include: [local_peer_id]}, so a foreign target fails unless this grant names
    -- it or a target-minted credential relaxes it.
    && ((let peers := g.peers.getD { incl := [localPeer], excl := [] }
         matchesScope localPeer targetPeer peers .id)
        || (match relaxTo with
            | some s => matchesScope localPeer targetPeer s .id
            | none   => false))
  (grantsOfToken handlerGrant).any grantOk
end EntityCore.Capability
