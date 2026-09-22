/-
  HOW TO RUN THIS -- the setup is part of the measurement.

    . tools/podman-caps.sh
    CODEC="ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release"
    podman run $PODMAN_RUN_CAPS --rm --network=none \
      -v "$PWD":/work:Z -v "$PWD/$CODEC":/codec:z,ro \
      -w /work/protocol-generator/lean -e LD_LIBRARY_PATH=/codec \
      localhost/entity-core-keystone/lean-toolchain:latest \
      sh -c 'lake build EntityCore >/dev/null 2>&1;
             lake env lean /work/protocol-generator/shared/diagnostics/a4-idscope-narrowing-witness.lean'

  MEASURED 2026-09-16 at keystone dev @ 458be817, against entity-core-formalization
  ROUTING-2026-09-16-b (their dev @ 6b111eb).  Routed back in
  docs/status/ROUTING-2026-09-16-d-entity-core-formalization-...

  EXPECTED OUTPUT -- a run that does not reproduce these has stopped measuring:
    pre=true id=false
    child_star_covers_get=true parent_slashstar_covers_get=false
    POSCTL_parent_slashstar_covers_slash_x=true
-/

import EntityCore.Capability
open EntityCore.Capability
def frame : String := "pA"
def canonSegsPre (frame path : String) : List String :=
  if path.startsWith "/" then splitSegs path else splitSegs ("/" ++ frame ++ "/" ++ path)
def scopeSubsetPre (cf pf : String) (c p : Scope) : Bool :=
  c.incl.all (fun cp => let cc := canonSegsPre cf cp
    p.incl.any (fun pp => matchesSeg cc (canonSegsPre pf pp)))
  && p.excl.all (fun pe => let cpe := canonSegsPre pf pe
       c.excl.any (fun ce => matchesSeg cpe (canonSegsPre cf ce)))

-- CLASS 2: universal child `*` under restricted parent `/*`.
-- pre ADMITTED it; `.id` refuses it. Is the refusal right? Only if the child
-- covers a value the parent does not.  Measure, do not argue.
def cStar : Scope := ⟨["*"], []⟩
def pSlashStar : Scope := ⟨["/*"], []⟩
#eval s!"pre={scopeSubsetPre frame frame cStar pSlashStar} id={scopeSubset .id frame frame cStar pSlashStar}"
#eval s!"child_star_covers_get={matchesScope frame "get" cStar .id} parent_slashstar_covers_get={matchesScope frame "get" pSlashStar .id}"
-- so `get` is authorized by the child and NOT by the parent => the pre-fix admit
-- was an escalation, and the narrowing closes it.
-- POSITIVE CONTROL: the parent must cover SOMETHING, or it is vacuous and the
-- comparison above is trivial.
#eval s!"POSCTL_parent_slashstar_covers_slash_x={matchesScope frame "/x" pSlashStar .id}"
