/-
  Lean S1/1c spike — PROVE-VS-RUN.

  Validates the load-bearing 1a finding: Lean has NO extraction gap. The SAME
  pure `def` is both (a) the thing we prove a theorem about and (b) the thing the
  compiled `main` actually calls. There is no Coq→OCaml extraction step that could
  drift between "the proven model" and "the running code".

  Toy stand-in for the real codec (S2 does this for canonical CBOR): encode a
  `List Bool` to bytes, decode back. The round-trip is proved by induction (a real
  proof, not `rfl` on a one-liner), and `main` calls the very same `encode`.

  The `#print axioms` at the end is the honesty gate: it MUST report only the
  standard kernel axioms (or "no axioms"). If the proof were `sorry`'d, `sorryAx`
  would appear — so a green build here means the round-trip is genuinely proved.
-/

namespace Spike

/-- The pure, total encoder. This exact function is both proven and run. -/
def encode : List Bool → List UInt8
  | []      => []
  | b :: bs => (if b then 1 else 0) :: encode bs

/-- The pure, total decoder. -/
def decode : List UInt8 → List Bool
  | []      => []
  | x :: xs => (x != 0) :: decode xs

/-- Round-trip / left-inverse: decoding an encoding recovers the input.
    Proved by structural induction over the list — representative of the real
    codec round-trip theorem (T1), in miniature. -/
theorem decode_encode (bs : List Bool) : decode (encode bs) = bs := by
  induction bs with
  | nil => rfl
  | cons b bs ih =>
    simp only [encode, decode, ih]
    cases b <;> rfl

/-- Encode is injective on its whole domain (corollary of the left inverse). -/
theorem encode_injective : Function.Injective encode := by
  intro a b h
  have := congrArg decode h
  simpa [decode_encode] using this

end Spike

open Spike

def main : IO Unit := do
  -- main calls the EXACT `encode` that `decode_encode` is a theorem about.
  let sample := [true, false, true, true, false]
  let bytes  := encode sample
  IO.println s!"sample : {sample}"
  IO.println s!"encode : {bytes}"
  IO.println s!"decode : {decode bytes}"
  if decode bytes = sample then
    IO.println "round-trip OK at runtime (and PROVED for all inputs: see decode_encode)"
  else
    IO.eprintln "round-trip FAILED at runtime — impossible given decode_encode"

-- Honesty gate: must show only standard axioms (no `sorryAx`).
#print axioms Spike.decode_encode
#print axioms Spike.encode_injective
