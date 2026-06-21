/-
  Track B — T5a / T4 / T5b: the §5.5/§5.6 capability-chain verdict.

  The headline proof of the Lean peer. The §5.6 attenuation check is applied
  PER ADJACENT LINK by the chain walk; the global security property — a leaf's
  effective authority is a subset of the root's (delegation never broadens) —
  holds ONLY if the per-link subset relation COMPOSES, i.e. is transitive. The
  whole thing reduces to one fact about the §5.4 segment matcher:

      `matchesSeg` is TRANSITIVE.

  We prove it (no counterexample — A-LEAN-4 resolved in the spec's favour), then
  lift it through `scopeSubset` → `grantSubset` → `isAttenuated` and confirm the
  load-bearing role of the §5.5a per-link granter frame (A-LEAN-3): composition
  works *because* the shared middle link canonicalizes on the same granter frame
  on both of its edges. The verdict-factoring (T4) and termination/depth (T5b)
  results are at the bottom — low proof effort, high documentation value.

  Honesty gate (`#print axioms`) at the very bottom — no `sorryAx`.
-/
import EntityCore.Capability

namespace EntityCore.Capability.Proofs

open EntityCore.Capability

-- ── matchesSeg reduction lemmas (the arm characterizations) ───────────────────

/-- Leading `*` with a NON-empty tail consumes exactly one segment (arm 5; arm 1
`["*"]` does not fire because the tail is non-empty). Definitional. -/
theorem ms_lead (a : String) (as : List String) (h : String) (cs : List String) :
    matchesSeg (a :: as) ("*" :: h :: cs) = matchesSeg as (h :: cs) := rfl

/-- Trailing `*` (`["*"]`) matches any non-empty path (arm 1). Definitional. -/
theorem ms_trail (a : String) (as : List String) :
    matchesSeg (a :: as) ["*"] = true := rfl

/-- A non-`*` pattern head matches literally (arm 6): neither the trailing-`*`
arm 1 nor the leading-`*` arm 5 can fire. -/
theorem ms_lit {a b : String} {as bs : List String} (hb : b ≠ "*") :
    matchesSeg (a :: as) (b :: bs) = (a == b && matchesSeg as bs) := by
  simp [matchesSeg, hb]

/-- The empty path never matches a non-empty pattern (arm 1 gives
`![].isEmpty = false` on `["*"]`; arm 4 gives `false` on any other). Proved in
isolation so its `simp_all` runs in a clean context (no `Classical`). -/
theorem matchesSeg_nil_cons (b : String) (bs : List String) :
    matchesSeg [] (b :: bs) = false := by unfold matchesSeg; split <;> simp_all

/-- The empty path matches only the empty pattern: `matchesSeg [] y = true → y = []`. -/
theorem matchesSeg_nil_left : ∀ y, matchesSeg [] y = true → y = [] := by
  intro y h
  cases y with
  | nil => rfl
  | cons b bs => rw [matchesSeg_nil_cons] at h; exact absurd h Bool.false_ne_true

-- ── T5a crux: matchesSeg is transitive ───────────────────────────────────────

/-- **The headline.** `matchesSeg` is a transitive relation on segment lists:
if path `x` matches pattern `y`, and `y` (read as a path) matches pattern `z`,
then `x` matches `z`. Proof by induction on `x`; in the recursive arms all three
lists shrink together. The trailing-`*` vs leading-`*` asymmetry never desyncs the
lengths because a `"*"` segment is ALWAYS a wildcard, never a literal — so the
branches where it could break carry a false hypothesis and close. -/
theorem matchesSeg_trans : ∀ (x y z : List String),
    matchesSeg x y = true → matchesSeg y z = true → matchesSeg x z = true := by
  intro x
  induction x with
  | nil =>
    intro y z hxy hyz
    have hy := matchesSeg_nil_left y hxy; subst hy
    have hz := matchesSeg_nil_left z hyz; subst hz
    rfl
  | cons xh xt ih =>
    intro y z hxy hyz
    cases y with
    | nil =>
      rw [show matchesSeg (xh :: xt) ([] : List String) = false from rfl] at hxy
      exact absurd hxy Bool.false_ne_true
    | cons yh yt =>
      cases z with
      | nil =>
        rw [show matchesSeg (yh :: yt) ([] : List String) = false from rfl] at hyz
        exact absurd hyz Bool.false_ne_true
      | cons zh zt =>
        by_cases hzstar : zh = "*"
        · subst hzstar
          cases zt with
          | nil =>
            -- z = ["*"] : the trailing-star arm. x is non-empty, so it matches.
            exact ms_trail xh xt
          | cons zt0 ztr =>
            -- z = "*" :: (zt0 :: ztr) : leading star, consumes one segment a side.
            rw [ms_lead] at hyz
            rw [ms_lead]
            -- reduce hxy to `matchesSeg xt yt` (the y-head splits literal/wildcard)
            by_cases hystar : yh = "*"
            · subst hystar
              cases yt with
              | nil =>
                -- y = ["*"] : then hyz = matchesSeg [] (zt0::ztr) is false.
                rw [matchesSeg_nil_cons] at hyz
                exact absurd hyz Bool.false_ne_true
              | cons yt0 ytr =>
                rw [ms_lead] at hxy
                exact ih (yt0 :: ytr) (zt0 :: ztr) hxy hyz
            · rw [ms_lit hystar, Bool.and_eq_true] at hxy
              exact ih yt (zt0 :: ztr) hxy.2 hyz
        · -- zh ≠ "*" : literal head.
          rw [ms_lit hzstar, Bool.and_eq_true] at hyz
          obtain ⟨hyzh, hytzt⟩ := hyz
          have hyhzh : yh = zh := eq_of_beq hyzh
          have hyhstar : yh ≠ "*" := by rw [hyhzh]; exact hzstar
          rw [ms_lit hyhstar, Bool.and_eq_true] at hxy
          obtain ⟨hxhyh, hxtyt⟩ := hxy
          rw [ms_lit hzstar, Bool.and_eq_true]
          exact ⟨beq_iff_eq.mpr ((eq_of_beq hxhyh).trans hyhzh), ih yt zt hxtyt hytzt⟩

#print axioms matchesSeg_trans

-- ── Lifting: the generic all/any composition combinator ───────────────────────

/-- The plumbing lemma that lifts a transitive per-element relation through the
`List.all`/`List.any` "every X is covered by some Y" shape. The three relations
are distinct (`R_AB`, `R_BC`, `R_AC`) so the SAME middle list `ys` is read with
`R_AB`'s right slot and `R_BC`'s left slot — this is where the §5.5a shared
granter frame becomes load-bearing (A-LEAN-3): the middle link canonicalizes on
one frame, used on both of its edges. -/
theorem all_any_compose {α} {R_AB R_BC R_AC : α → α → Bool} {xs ys zs : List α}
    (htr : ∀ x y z, R_AB x y = true → R_BC y z = true → R_AC x z = true)
    (h1 : (xs.all (fun x => ys.any (fun y => R_AB x y))) = true)
    (h2 : (ys.all (fun y => zs.any (fun z => R_BC y z))) = true) :
    (xs.all (fun x => zs.any (fun z => R_AC x z))) = true := by
  rw [List.all_eq_true]
  intro x hx
  rw [List.all_eq_true] at h1
  have hx1 := h1 x hx
  rw [List.any_eq_true] at hx1
  obtain ⟨y, hy, hxy⟩ := hx1
  rw [List.all_eq_true] at h2
  have hy2 := h2 y hy
  rw [List.any_eq_true] at hy2
  obtain ⟨z, hz, hyz⟩ := hy2
  rw [List.any_eq_true]
  exact ⟨z, hz, htr x y z hxy hyz⟩

-- ── T5a lift: scopeSubset is transitive (under the shared middle frame) ───────

/-- §5.6 scope subset composes along a delegation chain: if scope `A` (granted in
frame `fA`) is a subset of `B` (frame `fB`), and `B` is a subset of `C` (frame
`fC`), then `A` is a subset of `C`. The INCLUDE direction composes covariantly
(A→B→C), the EXCLUDE direction contravariantly (C→B→A) — both via the SAME
`matchesSeg_trans` through `all_any_compose`, the middle frame `fB` shared. -/
theorem scopeSubset_trans (fA fB fC : String) (A B C : Scope)
    (h1 : scopeSubset fA fB A B = true) (h2 : scopeSubset fB fC B C = true) :
    scopeSubset fA fC A C = true := by
  unfold scopeSubset at h1 h2 ⊢
  rw [Bool.and_eq_true] at h1 h2 ⊢
  refine ⟨?_, ?_⟩
  · exact all_any_compose
      (R_AB := fun x y => matchesSeg (canonSegs fA x) (canonSegs fB y))
      (R_BC := fun y z => matchesSeg (canonSegs fB y) (canonSegs fC z))
      (R_AC := fun x z => matchesSeg (canonSegs fA x) (canonSegs fC z))
      (fun x y z hxy hyz => matchesSeg_trans _ _ _ hxy hyz)
      h1.1 h2.1
  · exact all_any_compose
      (R_AB := fun x y => matchesSeg (canonSegs fC x) (canonSegs fB y))
      (R_BC := fun y z => matchesSeg (canonSegs fB y) (canonSegs fA z))
      (R_AC := fun x z => matchesSeg (canonSegs fC x) (canonSegs fA z))
      (fun x y z hxy hyz => matchesSeg_trans _ _ _ hxy hyz)
      h2.2 h1.2

#print axioms scopeSubset_trans

/-- §5.6 grant subset composes: each of the four dimensions (handlers/operations
on the local frame, resources on the per-link granter frames, peers on the local
frame) composes via `scopeSubset_trans`, the middle frame `fB` shared. -/
theorem grantSubset_trans (lp fA fB fC : String) (A B C : Grant)
    (h1 : grantSubset lp fA fB A B = true) (h2 : grantSubset lp fB fC B C = true) :
    grantSubset lp fA fC A C = true := by
  unfold grantSubset at h1 h2 ⊢
  simp only [Bool.and_eq_true] at h1 h2 ⊢
  obtain ⟨⟨⟨h1h, h1o⟩, h1r⟩, h1p⟩ := h1
  obtain ⟨⟨⟨h2h, h2o⟩, h2r⟩, h2p⟩ := h2
  exact ⟨⟨⟨scopeSubset_trans lp lp lp _ _ _ h1h h2h,
           scopeSubset_trans lp lp lp _ _ _ h1o h2o⟩,
          scopeSubset_trans fA fB fC _ _ _ h1r h2r⟩,
         scopeSubset_trans lp lp lp _ _ _ h1p h2p⟩

/-- **T5a, the entity-level security theorem.** §5.6 attenuation composes along a
delegation chain: if entity `A` is an attenuation of granter `B` (in frames
fA/fB), and `B` of granter `C` (fB/fC), then `A` is an attenuation of `C`
(fA/fC). Grant coverage composes via `grantSubset_trans` through
`all_any_compose`; the expiry bound composes by transitivity of `≤` in the
finite-or-∞ lattice (a finite parent forbids an infinite child). Hence a leaf
capability's effective authority is a subset of the root's — delegation never
broadens. -/
theorem isAttenuated_trans (lp fA fB fC : String) (A B C : EntityCore.Model.Entity)
    (h1 : isAttenuated lp fA fB A B = true) (h2 : isAttenuated lp fB fC B C = true) :
    isAttenuated lp fA fC A C = true := by
  unfold isAttenuated at h1 h2 ⊢
  simp only [Bool.and_eq_true] at h1 h2 ⊢
  obtain ⟨h1g, h1e⟩ := h1
  obtain ⟨h2g, h2e⟩ := h2
  refine ⟨?_, ?_⟩
  · exact all_any_compose
      (R_AB := fun c p => grantSubset lp fA fB c p)
      (R_BC := fun c p => grantSubset lp fB fC c p)
      (R_AC := fun c p => grantSubset lp fA fC c p)
      (fun x y z hxy hyz => grantSubset_trans lp fA fB fC x y z hxy hyz)
      h1g h2g
  · -- expiry: A.exp ≤ B.exp ≤ C.exp in the {finite < ∞} lattice ⇒ A.exp ≤ C.exp.
    -- `none` = ∞ = top; a finite parent (some) forbids an infinite child (none).
    split at h1e <;> split at h2e <;> split <;> simp_all <;>
      exact UInt64.le_trans (by assumption) (by assumption)

#print axioms grantSubset_trans
#print axioms isAttenuated_trans

-- ── T4: verdict factoring & time-stability ───────────────────────────────────

/-- **T4, the load-bearing factoring (A-LEAN-1).** The walk's ONLY coupling to
`now` is through the per-link `temporalOk`. If two times agree on every link's
temporal predicate, the walk returns the same verdict — `now` is otherwise inert.
This is the precise content of "the §5.10 Layer-1 verdict is a function of the
chain and Layer-1 inputs only": `now` enters at exactly one place, per link,
sampled once by the shell. -/
theorem walk_time_stable (lp : String) (n₁ n₂ : UInt64) :
    ∀ (links : List ResolvedLink) (d : Nat),
    (∀ link ∈ links, temporalOk link.entity n₁ = temporalOk link.entity n₂) →
    walk lp n₁ d links = walk lp n₂ d links := by
  intro links
  induction links with
  | nil => intro d _; rfl
  | cons link rest ih =>
    intro d h
    have hlink := h link (List.mem_cons_self ..)
    have hrest := fun l hl => h l (List.mem_cons_of_mem link hl)
    simp only [walk]
    rw [hlink, ih (d + 1) hrest]

/-- The whole §5.5 verdict is time-stable across any two times that agree on every
link's temporal predicate (the root-granter check carries no `now`). -/
theorem verifyChain_time_stable (rc : ResolvedChain) (lp : String) (n₁ n₂ : UInt64)
    (h : ∀ link ∈ rc.links, temporalOk link.entity n₁ = temporalOk link.entity n₂) :
    verifyChain rc lp n₁ = verifyChain rc lp n₂ := by
  unfold verifyChain
  rw [walk_time_stable lp n₁ n₂ rc.links 0 h]

/-- Corollary: a chain with NO temporal bounds (`not_before`/`expires_at` absent
on every link) yields a verdict fully independent of `now`. Time only ever
matters at an actual TTL boundary — confirming A-LEAN-1's reading that the
verdict's apparent time-dependence is entirely localized to declared expiries. -/
theorem verifyChain_time_independent (rc : ResolvedChain) (lp : String) (n₁ n₂ : UInt64)
    (h : ∀ link ∈ rc.links,
      EntityCore.Model.uintField link.entity "not_before" = none ∧
      EntityCore.Model.uintField link.entity "expires_at" = none) :
    verifyChain rc lp n₁ = verifyChain rc lp n₂ :=
  verifyChain_time_stable rc lp n₁ n₂ (fun link hl => by
    obtain ⟨hnb, hex⟩ := h link hl
    simp [temporalOk, hnb, hex])

-- ── T5b: termination & the depth pre-check ───────────────────────────────────
-- `walk`/`verifyChain` are accepted as TOTAL `def`s (structural recursion on the
-- link list) — Lean machine-verifies their termination by accepting them; there
-- is no `partial`, hence no termination obligation left to state. The §4.10(b)
-- depth interception is a pure structural length predicate:

/-- The root-foreign short-circuit: a chain whose root granter is not the local
peer is denied outright (the §5.5 single-sig precondition), independent of `now`. -/
theorem verifyChain_foreign_root (rc : ResolvedChain) (lp : String) (n : UInt64)
    (h : rc.rootAuthority = .single false) : verifyChain rc lp n = .deny := by
  unfold verifyChain rootAuthorityOk; rw [h]; rfl

/-- §4.10(b): the depth interception is exactly a structural length test —
purely a function of the chain shape, with no signature/authz work, so it can be
gated BEFORE the walk to report `400 chain_depth_exceeded` distinctly from a
`403` denial (the v7.75 ruling). -/
theorem chainExceedsDepth_iff (rc : ResolvedChain) :
    chainExceedsDepth rc = true ↔ rc.links.length > 65 := by
  unfold chainExceedsDepth; exact decide_eq_true_iff

-- ── §3.6 multi-sig quorum soundness (the M3/M4/M6 record) ─────────────────────

/-- **A satisfied §3.6 root authority means a real quorum signed and the local peer
is in it.** `multiSigRootOk` cannot return `true` unless at least `threshold`
distinct signers signed (M4) AND the local peer is one of the signers (M6). The
verdict cannot grant a multi-sig root authority below threshold or excluding the
local peer. -/
theorem multiSigRootOk_quorum (signers : List ResolvedSigner) (k : Nat) (pn : Bool)
    (h : multiSigRootOk signers k pn = true) :
    k ≤ (signers.filter (·.signed)).length ∧ signers.any (·.isLocal) = true := by
  unfold multiSigRootOk at h
  simp only [Bool.and_eq_true, decide_eq_true_eq] at h
  -- `&&` nests left here: h = ((((((pn ∧ n≥2) ∧ k≥2) ∧ k≤n) ∧ dup) ∧ local) ∧ quorum)
  exact ⟨h.2, h.1.2⟩

#print axioms walk_time_stable
#print axioms verifyChain_time_stable
#print axioms verifyChain_time_independent
#print axioms verifyChain_foreign_root
#print axioms chainExceedsDepth_iff
#print axioms multiSigRootOk_quorum

-- ── The verdict ENFORCES the per-edge check (the bridge to the security heart) ─
-- isAttenuated_trans says the §5.6 check COMPOSES *if applied per edge*. These
-- close the loop: an `allow` verdict PROVABLY means every adjacent edge passed
-- `edgeOk` (which contains `isAttenuated`). Step + bridge ⇒ leaf ⊆ root is then a
-- mechanical fold over the chain (reflexivity base below).

/-- One-step extraction: if the walk allows a chain with at least one delegation
edge, that edge passed `edgeOk` (grantee/granter linkage + `isAttenuated` +
caveats) AND the rest of the chain also allows. The verdict cannot say `allow`
while skipping a link's attenuation check. -/
theorem walk_allow_cons (lp : String) (now : UInt64) (d : Nat)
    (child parent : ResolvedLink) (rest : List ResolvedLink)
    (h : walk lp now d (child :: parent :: rest) = .allow) :
    edgeOk lp d child parent = true ∧ walk lp now (d + 1) (parent :: rest) = .allow := by
  -- A non-root edge's `here` is `temporalOk && (!isMultiSig && sigValid && edgeOk)`
  -- (the §3.6 multi-sig form is root-only, so it is excluded off-root). `edgeOk` is
  -- the last conjunct; extract it after splitting the gate.
  simp only [walk] at h
  split at h
  · exact absurd h (by simp)
  · split at h
    · rename_i hhere
      simp only [Bool.and_eq_true] at hhere
      -- left-nested: temporalOk ∧ ((!isMultiSig ∧ sigValid) ∧ edgeOk)
      obtain ⟨_htemporal, ⟨_hnotms, _hsig⟩, hedge⟩ := hhere
      exact ⟨hedge, h⟩
    · exact absurd h (by simp)

/-- The leaf's immediate delegation is genuinely attenuated: an allowed chain whose
leaf is granted by a resolvable granter has `isAttenuated` holding between leaf and
its parent under their §5.5a granter frames. (Combine with `walk_allow_cons` +
`isAttenuated_trans` to fold to leaf ⊆ root.) -/
theorem walk_allow_leaf_attenuated (lp : String) (now : UInt64) (d : Nat)
    (child parent : ResolvedLink) (rest : List ResolvedLink) (cf pf : String)
    (hcf : child.granterPeer = some cf) (hpf : parent.granterPeer = some pf)
    (h : walk lp now d (child :: parent :: rest) = .allow) :
    isAttenuated lp cf pf child.entity parent.entity = true := by
  have he := (walk_allow_cons lp now d child parent rest h).1
  unfold edgeOk at he
  rw [hcf, hpf] at he
  simp only [Bool.and_eq_true] at he
  exact he.1.2

-- ── §5.4 reflexivity (the fold base case: a 1-link chain is trivially leaf ⊆ root) ─

/-- The segment matcher is reflexive: any path matches itself as a pattern. -/
theorem matchesSeg_refl : ∀ x, matchesSeg x x = true := by
  intro x
  induction x with
  | nil => rfl
  | cons xh xt ih =>
    by_cases h : xh = "*"
    · subst h
      cases xt with
      | nil => rfl
      | cons _ _ => rw [ms_lead]; exact ih
    · rw [ms_lit h, Bool.and_eq_true]; exact ⟨beq_iff_eq.mpr rfl, ih⟩

-- ── §5.2 dispatch-gate soundness (the OTHER half of authority) ─────────────────
-- verifyChain proves the cap CHAIN is valid; checkPermission proves the REQUEST is
-- within the granted scope. These certify the security-critical defaults.

/-- **Deny-by-default.** A token carrying no grants can never authorize a request —
`checkPermission` returns `.deny`. (No grant ⇒ no `.any` witness ⇒ the else branch.) -/
theorem checkPermission_no_grants_deny (lp gp : String) (exec token : EntityCore.Model.Entity)
    (hp : String) (h : grantsOfToken token = []) :
    checkPermission lp gp exec token hp = .deny := by
  unfold checkPermission; rw [h]; rfl

/-- **Excludes cannot be bypassed.** If a value falls in a scope's exclude set, the
scope does not match it — the exclude overrides any include (§5.4 deny-override). -/
theorem matchesScope_excl_override (lp value : String) (s : Scope)
    (h : covered lp lp value s.excl = true) : matchesScope lp value s = false := by
  simp [matchesScope, h]

-- ── Reflexivity chain (the fold base case) ───────────────────────────────────

theorem scopeSubset_refl (f : String) (s : Scope) : scopeSubset f f s s = true := by
  unfold scopeSubset
  rw [Bool.and_eq_true]
  refine ⟨?_, ?_⟩ <;>
    · rw [List.all_eq_true]; intro x hx; rw [List.any_eq_true]
      exact ⟨x, hx, matchesSeg_refl _⟩

theorem grantSubset_refl (lp f : String) (g : Grant) : grantSubset lp f f g g = true := by
  unfold grantSubset
  simp only [Bool.and_eq_true]
  exact ⟨⟨⟨scopeSubset_refl _ _, scopeSubset_refl _ _⟩, scopeSubset_refl _ _⟩,
         scopeSubset_refl _ _⟩

theorem isAttenuated_refl (lp f : String) (e : EntityCore.Model.Entity) :
    isAttenuated lp f f e e = true := by
  unfold isAttenuated
  rw [Bool.and_eq_true]
  refine ⟨?_, ?_⟩
  · rw [List.all_eq_true]; intro x hx; rw [List.any_eq_true]
    exact ⟨x, hx, grantSubset_refl lp f x⟩
  · split <;> first | rfl | simp_all | exact decide_eq_true (UInt64.le_refl _)

-- ── Edge-frame extraction ────────────────────────────────────────────────────

/-- An `edgeOk` edge exposes BOTH granter frames (hard-fail on `none`, §5.5a §4)
and the `isAttenuated` step between the two link entities under those frames. -/
theorem edgeOk_atten (lp : String) (d : Nat) (child parent : ResolvedLink)
    (h : edgeOk lp d child parent = true) :
    ∃ cf pf, child.granterPeer = some cf ∧ parent.granterPeer = some pf ∧
      isAttenuated lp cf pf child.entity parent.entity = true := by
  unfold edgeOk at h
  split at h
  · rename_i cf pf hcf hpf
    simp only [Bool.and_eq_true] at h
    exact ⟨cf, pf, hcf, hpf, h.1.2⟩
  · exact absurd h (by simp)

-- ── THE CAPSTONE: an allowed chain has leaf authority ⊆ root authority ────────

/-- **End-to-end verdict soundness.** If the §5.5 walk allows a chain (leaf at the
head, root at the tail), then the leaf entity is provably an `isAttenuated`
attenuation of the root entity, under their respective §5.5a granter frames. The
verdict cannot return `allow` for a chain whose leaf broadens the root's
authority — `walk_allow_cons` extracts each edge's `isAttenuated`, and
`isAttenuated_trans` folds them. Combined with `verifyChain`'s root-granter-local
check, this is the closed statement of "a requester only ever wields authority the
local peer actually delegated." -/
theorem allowed_chain_leaf_atten_root (lp : String) (now : UInt64) :
    ∀ (rest : List ResolvedLink) (leaf : ResolvedLink) (d : Nat) (lf : String),
    walk lp now d (leaf :: rest) = .allow → leaf.granterPeer = some lf →
    ∃ root rf, (leaf :: rest).getLast? = some root ∧ root.granterPeer = some rf ∧
      isAttenuated lp lf rf leaf.entity root.entity = true := by
  intro rest
  induction rest with
  | nil =>
    intro leaf _ lf _ hlf
    exact ⟨leaf, lf, rfl, hlf, isAttenuated_refl lp lf leaf.entity⟩
  | cons snd tl ih =>
    intro leaf d lf hwalk hlf
    obtain ⟨hedge, hwalk'⟩ := walk_allow_cons lp now d leaf snd tl hwalk
    obtain ⟨cf, pf, hcf, hpf, hatten⟩ := edgeOk_atten lp d leaf snd hedge
    -- cf = lf (leaf's frame is determined)
    rw [hlf] at hcf; injection hcf with hcfeq; subst hcfeq
    -- recurse on the tail chain (snd :: tl), whose leaf is snd with frame pf
    obtain ⟨root, rf, hlast, hrf, hsnd⟩ := ih snd (d + 1) pf hwalk' hpf
    refine ⟨root, rf, ?_, hrf, isAttenuated_trans lp lf pf rf leaf.entity snd.entity root.entity hatten hsnd⟩
    -- getLast? (leaf :: snd :: tl) = getLast? (snd :: tl)
    rw [List.getLast?_cons_cons] at *; exact hlast

#print axioms walk_allow_cons
#print axioms walk_allow_leaf_attenuated
#print axioms matchesSeg_refl
#print axioms checkPermission_no_grants_deny
#print axioms matchesScope_excl_override
#print axioms isAttenuated_refl
#print axioms edgeOk_atten
#print axioms allowed_chain_leaf_atten_root

-- ── Completeness: the verdict applies the FULL per-link check (not just edgeOk) ─
-- walk's gate is `here = sigValid && temporalOk && edgeOk`; the capstone extracted
-- only `edgeOk`. These name the other conjuncts so "allow ⇒ every link is signed /
-- temporally valid / grantee-resolvable / caveat-respecting" is on the record —
-- cryptographic authorship is the whole point of the verdict.

/-- One-step full extraction: an `allow` on `link :: rest` means `link` was grantee-
resolvable, temporally valid, the tail still allows, and the link is authenticated —
either a §3.6 multi-sig root (quorum verified separately by `rootAuthorityOk`) OR a
single-sig link with a valid signature. (The §3.6 widening of "every link is signed":
the root may carry its authority as a k-of-n quorum instead of one signature.) -/
theorem walk_allow_head (lp : String) (now : UInt64) (d : Nat)
    (link : ResolvedLink) (rest : List ResolvedLink)
    (h : walk lp now d (link :: rest) = .allow) :
    link.granteeResolvable = true ∧ (link.isMultiSig = true ∨ link.sigValid = true) ∧
      temporalOk link.entity now = true ∧ walk lp now (d + 1) rest = .allow := by
  -- case on `rest` so the inner `match` (and hence the `let here`) reduces to a
  -- concrete `&&`, exactly as in `walk_allow_cons`.
  cases rest with
  | nil =>
    -- root link: `here = temporalOk && (if isMultiSig then true else sigValid)`.
    -- Eliminate the inner isMultiSig `if` FIRST (so `split` later lands on the gate,
    -- not on it); `walk lp now (d+1) [] = allow` is then definitional (`rfl`).
    simp only [walk] at h
    by_cases hm : link.isMultiSig = true
    · -- multi-sig root: inner `if` is `true`, so authentication is `Or.inl hm`
      rw [if_pos hm, Bool.and_true] at h
      split at h
      · exact absurd h (by decide)
      · rename_i hgr; split at h
        · rename_i ht
          exact ⟨by simpa using hgr, Or.inl hm, ht, rfl⟩
        · exact absurd h (by decide)
    · -- single-sig root: inner `if` is `sigValid`; here = temporalOk && sigValid
      rw [if_neg hm] at h
      split at h
      · exact absurd h (by decide)
      · rename_i hgr; split at h
        · rename_i hhere
          simp only [Bool.and_eq_true] at hhere
          exact ⟨by simpa using hgr, Or.inr hhere.2, hhere.1, rfl⟩
        · exact absurd h (by decide)
  | cons parent tl =>
    -- non-root link: `here = temporalOk && (!isMultiSig && sigValid && edgeOk)`.
    simp only [walk] at h
    split at h
    · exact absurd h (by decide)
    · rename_i hgr; split at h
      · rename_i hhere
        simp only [Bool.and_eq_true] at hhere
        -- left-nested: temporalOk ∧ ((!isMultiSig ∧ sigValid) ∧ edgeOk)
        obtain ⟨htemporal, ⟨_hnotms, hsig⟩, _hedge⟩ := hhere
        exact ⟨by simpa using hgr, Or.inr hsig, htemporal, h⟩
      · exact absurd h (by decide)

/-- **Every link in an allowed chain is authenticated, temporally valid, and grantee-
resolvable.** The verdict cannot `allow` a chain containing an unauthenticated,
expired, or dangling-grantee link. Authentication is `isMultiSig ∨ sigValid`: a §3.6
multi-sig root proves its authority by a k-of-n quorum (verified by `rootAuthorityOk`)
rather than a single signature. (Companion to `allowed_chain_leaf_atten_root`:
together they say the verdict applies the *complete* §5.5 per-link check.) -/
theorem walk_allow_link_facts (lp : String) (now : UInt64) :
    ∀ (links : List ResolvedLink) (d : Nat), walk lp now d links = .allow →
    ∀ link ∈ links, link.granteeResolvable = true ∧
      (link.isMultiSig = true ∨ link.sigValid = true) ∧
      temporalOk link.entity now = true := by
  intro links
  induction links with
  | nil => intro d _ link hl; exact absurd hl (by simp)
  | cons hd tl ih =>
    intro d h link hl
    obtain ⟨hg, hs, ht, hrest⟩ := walk_allow_head lp now d hd tl h
    cases hl with
    | head => exact ⟨hg, hs, ht⟩
    | tail _ hmem => exact ih (d + 1) hrest link hmem

/-- §5.7 delegation caveats are enforced on every edge an allowed chain traverses
(`checkDelegationCaveats` is the unnamed third conjunct of `edgeOk`). -/
theorem edgeOk_caveats (lp : String) (d : Nat) (child parent : ResolvedLink)
    (h : edgeOk lp d child parent = true) :
    checkDelegationCaveats parent.entity child.entity d = true := by
  unfold edgeOk at h
  split at h
  · simp only [Bool.and_eq_true] at h; exact h.2
  · exact absurd h (by simp)

#print axioms walk_allow_head
#print axioms walk_allow_link_facts
#print axioms edgeOk_caveats

-- ── HIGH: the §PR-8 dispatch frame split (the V2(a) invariant) ────────────────
-- The dispatch-side analogue of A-LEAN-3. In `checkResourceScope` the request
-- TARGET canonicalizes on the LOCAL frame and the GRANT's resource patterns on the
-- GRANTER frame. This is the V2(a) surface that FAILed 6-way pre-fix (a peer-local
-- resource cap wrongly authorized cross-peer, latent because granter == verifier
-- byte-collapses on self-issued caps). The invariant: a granter-framed grant
-- pattern provably cannot reach a DIFFERENT peer's namespace.

/-- The matcher forces the target's head: a literal (non-`*`) pattern head segment
`g` can only match a target whose first segment is exactly `g`. (Clean — no
`canonSegs`/`splitOn`.) -/
theorem matchesSeg_head_lit (g : String) (ct pt : List String) (hg : g ≠ "*")
    (h : matchesSeg ct (g :: pt) = true) : ct.head? = some g := by
  cases ct with
  | nil => rw [matchesSeg_nil_cons] at h; exact absurd h Bool.false_ne_true
  | cons c ct2 => rw [ms_lit hg, Bool.and_eq_true] at h; exact congrArg some (eq_of_beq h.1)

/-- `l.head? = some a` exposes the cons. -/
theorem head?_some_cons {α} {l : List α} {a : α} (h : l.head? = some a) : ∃ t, l = a :: t := by
  cases l with
  | nil => simp at h
  | cons b t => simp only [List.head?_cons, Option.some.injEq] at h; exact ⟨t, by rw [h]⟩

/-- **The V2(a) frame-split invariant (dispatch-side analogue of A-LEAN-3).** If the
grant's resource patterns are granter-framed — i.e. each canonicalizes to a head
segment equal to `granterPeer` (which is exactly what `canonSegs granterPeer` does
to a *relative* pattern, the §5.5a/§PR-8 fix) — then a target resolved into a
DIFFERENT peer's namespace (`ct.head? = some otherPeer`, `otherPeer ≠ granterPeer`)
is **not covered by any grant pattern.** A peer-relative grant cannot authorize a
foreign namespace; the byte-collapse that hid the 6-way bug (granter == verifier)
is the only case where the heads coincide.

`hframed` is the canonicalization contract — `canonSegs granterPeer p` roots a
relative `p` at `/{granterPeer}/…`. Proving it from `String.splitOn` internals is
mechanical stdlib plumbing (the same path-splitting boundary the running peer rides
on); the SECURITY LOGIC — framing ⇒ namespace isolation — is what is proved here. -/
theorem grantPattern_namespace_isolation
    (granterPeer otherPeer : String) (ct pats : List String)
    (hg : granterPeer ≠ "*") (hne : otherPeer ≠ granterPeer)
    (htgt : ct.head? = some otherPeer)
    (hframed : ∀ p ∈ pats, (canonSegs granterPeer p).head? = some granterPeer) :
    pats.any (fun p => matchesSeg ct (canonSegs granterPeer p)) = false := by
  rw [Bool.eq_false_iff, Ne, List.any_eq_true]
  rintro ⟨p, hp, hmatch⟩
  -- the grant pattern is granter-framed: canonSegs granterPeer p = granterPeer :: tl
  obtain ⟨tl, htl⟩ := head?_some_cons (hframed p hp)
  rw [htl] at hmatch
  -- matcher forces ct.head? = some granterPeer, contradicting otherPeer ≠ granterPeer
  have := matchesSeg_head_lit granterPeer ct tl hg hmatch
  rw [htgt] at this
  exact hne (Option.some.inj this)

/-- The resource gate's OWN deny-by-default: with no request targets, no resource
access is authorized (`checkResourceScope` returns `false` via the `!targets.isEmpty`
guard) — independent of the operations/handlers/peers deny-by-default. -/
theorem checkResourceScope_no_targets_deny (lp gp : String) (resource : EntityCore.Value)
    (s : Scope) (h : EntityCore.Model.mapGet resource "targets" = none) :
    checkResourceScope lp gp resource s = false := by
  unfold checkResourceScope; simp [h]

#print axioms matchesSeg_head_lit
#print axioms head?_some_cons
#print axioms grantPattern_namespace_isolation
#print axioms checkResourceScope_no_targets_deny

end EntityCore.Capability.Proofs
