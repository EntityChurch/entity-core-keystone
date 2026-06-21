/- Track B — the proof vector. `lake build EntityCoreProofs` IS the proof check:
a `sorry` or a failed proof fails the build. Core-Lean tactics only (no mathlib).
Each module ends with `#print axioms` honesty gates. -/
import EntityCoreProofs.FloatProofs
import EntityCoreProofs.SortProofs
import EntityCoreProofs.CapabilityProofs
