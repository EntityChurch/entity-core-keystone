/- Track B — the proof vector. `lake build EntityCoreProofs` IS the proof check:
a failed proof fails the build; a `sorry` does NOT (it is a warning and lake still
exits 0), which is why the gate grades `#print axioms` rather than the exit code --
see run-s2.sh. Core-Lean tactics only (no mathlib).
Each module ends with `#print axioms` honesty gates. -/
import EntityCoreProofs.FloatProofs
import EntityCoreProofs.SortProofs
import EntityCoreProofs.CapabilityProofs
