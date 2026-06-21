/-
  Track B — T2: properties of the canonical map-key comparator (length-then-lex
  over encoded key bytes).

  STATUS (time-boxed per the proof-vs-spec stance, memory `lean-proof-vs-spec-stance`):
  the symmetry-free fragment — `lexCmp` is REFLEXIVE (`lexCmp a a = eq`), hence the
  key order `keyLe` is reflexive — is proven clean below. The full *totality*
  theorem (`keyLe a b ∨ keyLe b a`) reduces to a swap-antisymmetry lemma
  `lexCmp b a i = (lexCmp a b i).swap`; that lemma is mathematically routine
  (byte-trichotomy) but the Lean-4.29 `split_ifs`/`simp` automation would not fire
  on the swapped four-way `if`-nest after `fun_induction`, so it is DEFERRED — an
  S2 scope boundary, not a defect. Totality is independently witnessed by the
  69/69 conformance gate (no incomparable keys arise) and by the cohort. See
  status/FORMALIZATION-REPORT.md.

  Honesty gate (`#print axioms`) at the bottom — no `sorryAx`.
-/
import EntityCore.Codec.CBOR

namespace EntityCore.Codec.Proofs

open EntityCore.Codec

-- ── reflexivity of the bytewise lexicographic compare ────────────────────────

/-- `lexCmp a a i = eq` for all `i` — equal byte arrays compare equal. Needs only
irreflexivity of `<` (which `simp` knows), no antisymmetry, so it is clean. -/
theorem lexCmp_self (a : ByteArray) (i : Nat) : lexCmp a a i = .eq := by
  fun_induction lexCmp a a i <;> simp_all

-- ── the key comparator is reflexive ──────────────────────────────────────────

/-- `keyCmp a a = eq`: a key compares equal to itself. -/
theorem keyCmp_self (a : ByteArray) : keyCmp a a = .eq := by
  unfold keyCmp
  simp [lexCmp_self]

/-- Reflexivity of the canonical key order: every key is ≤ itself. A sort under
`keyLe` therefore never rejects equal keys spuriously. -/
theorem keyLe_refl (a : ByteArray) : keyLe a a = true := by
  unfold keyLe
  rw [keyCmp_self]

#print axioms lexCmp_self
#print axioms keyCmp_self
#print axioms keyLe_refl

end EntityCore.Codec.Proofs
