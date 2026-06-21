/-
  Track B — T3: shortest-float minimality + round-trip + Rule-4a specials.

  All theorems are about `encodeFloatBits : UInt64 → ByteArray` — the
  kernel-reducible bit core (S1 1a finding #2: `Float` is opaque, so the float
  proof MUST be at the bit level). The running encoder is
  `encodeFloatShortest d = encodeFloatBits d.toBits`, so these are theorems about
  the REAL running code modulo the one opaque `Float.toBits` boundary.

  Honesty gate (`#print axioms`) at the bottom — must report no `sorryAx`.
-/
import EntityCore.Codec.Float

namespace EntityCore.Codec.Float.Proofs

open EntityCore.Codec.Float

-- ── T3 round-trip soundness: the narrow gates only accept exact widenings ─────

/-- If the f16 gate accepts `h`, widening `h` recovers the original bits exactly.
This is what makes the shortest form a *value-preserving* (Rule 4) encoding. -/
theorem tryHalf_widens {bits : UInt64} {h : UInt16}
    (hh : tryHalf bits = some h) : widen16 h = bits := by
  simp only [tryHalf] at hh
  split at hh
  · rename_i hcond
    simp only [Option.some.injEq] at hh
    subst hh
    exact eq_of_beq hcond
  · simp at hh

/-- If the f32 gate accepts `g`, widening `g` recovers the original bits exactly. -/
theorem trySingle_widens {bits : UInt64} {g : UInt32}
    (hh : trySingle bits = some g) : widen32 g = bits := by
  simp only [trySingle] at hh
  split at hh
  · rename_i hcond
    simp only [Option.some.injEq] at hh
    subst hh
    exact eq_of_beq hcond
  · simp at hh

-- ── T3 minimality: the ladder picks the NARROWEST width that round-trips ──────

/-- A non-special value that the f16 gate accepts is emitted as f16. -/
theorem encode_uses_half {bits : UInt64} {h : UInt16}
    (hexp : (((bits >>> 52) &&& 0x7FF) == 0x7FF) = false)
    (ht : tryHalf bits = some h) :
    encodeFloatBits bits = ByteArray.mk #[0xF9] ++ be16 h := by
  simp [encodeFloatBits, hexp, ht]

/-- A non-special value the f16 gate rejects but the f32 gate accepts is emitted
as f32 — i.e. f32 is used only when no f16 round-trips. -/
theorem encode_uses_single {bits : UInt64} {g : UInt32}
    (hexp : (((bits >>> 52) &&& 0x7FF) == 0x7FF) = false)
    (h16 : tryHalf bits = none) (h32 : trySingle bits = some g) :
    encodeFloatBits bits = ByteArray.mk #[0xFA] ++ be32 g := by
  simp [encodeFloatBits, hexp, h16, h32]

/-- A non-special value that neither narrower gate accepts is emitted as f64 —
the minimality floor: f64 is used only when nothing narrower round-trips. -/
theorem encode_uses_double {bits : UInt64}
    (hexp : (((bits >>> 52) &&& 0x7FF) == 0x7FF) = false)
    (h16 : tryHalf bits = none) (h32 : trySingle bits = none) :
    encodeFloatBits bits = ByteArray.mk #[0xFB] ++ be64 bits := by
  simp [encodeFloatBits, hexp, h16, h32]

-- ── T3 Rule-4a specials (parametric over the whole special class) ─────────────

/-- Rule 4a, NaN: EVERY NaN bit pattern (exp all-ones, nonzero mantissa) — any
sign, any payload — normalizes to the canonical quiet NaN `F9 7E00`. -/
theorem encode_nan {bits : UInt64}
    (hexp : (((bits >>> 52) &&& 0x7FF) == 0x7FF) = true)
    (hmant : ((bits &&& 0xFFFFFFFFFFFFF) == 0) = false) :
    encodeFloatBits bits = ByteArray.mk #[0xF9] ++ be16 0x7E00 := by
  simp [encodeFloatBits, hexp, hmant]

/-- Rule 4a, ±Inf: an all-ones exponent with zero mantissa emits the f16 infinity
of the matching sign (`F9 7C00` / `F9 FC00`). -/
theorem encode_inf {bits : UInt64}
    (hexp : (((bits >>> 52) &&& 0x7FF) == 0x7FF) = true)
    (hmant : ((bits &&& 0xFFFFFFFFFFFFF) == 0) = true) :
    encodeFloatBits bits
      = ByteArray.mk #[0xF9] ++ be16 (if ((bits >>> 63) &&& 1) == 1 then 0xFC00 else 0x7C00) := by
  simp [encodeFloatBits, hexp, hmant]

-- Honesty gate: these must depend on no `sorryAx`.
#print axioms tryHalf_widens
#print axioms trySingle_widens
#print axioms encode_uses_half
#print axioms encode_uses_single
#print axioms encode_uses_double
#print axioms encode_nan
#print axioms encode_inf

end EntityCore.Codec.Float.Proofs
