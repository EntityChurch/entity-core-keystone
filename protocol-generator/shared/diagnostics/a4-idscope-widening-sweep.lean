/-
  HOW TO RUN THIS -- the setup is part of the measurement.

    . tools/podman-caps.sh
    CODEC="ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release"
    podman run $PODMAN_RUN_CAPS --rm --network=none \
      -v "$PWD":/work:Z -v "$PWD/$CODEC":/codec:z,ro \
      -w /work/protocol-generator/lean -e LD_LIBRARY_PATH=/codec \
      localhost/entity-core-keystone/lean-toolchain:latest \
      sh -c 'lake build EntityCore >/dev/null 2>&1;
             lake env lean /work/protocol-generator/shared/diagnostics/a4-idscope-widening-sweep.lean'

  MEASURED 2026-09-16 at keystone dev @ 458be817, against entity-core-formalization
  ROUTING-2026-09-16-b (their dev @ 6b111eb).  Routed back in
  docs/status/ROUTING-2026-09-16-d-entity-core-formalization-...

  EXPECTED OUTPUT -- a run that does not reproduce these has stopped measuring:
    SWEEP pairs=576 disagree=30 narrowed=22 widened=8 widenedUnderStar=8 widenedOther=0
    WIDENED_NOT_UNDER_STAR: (empty)
    MUSTAGREE_plain pairs=25 disagree=0
    POSCTL_r11Pre=true r11Id=false
-/

import EntityCore.Capability
open EntityCore.Capability

/-! Widening entity-core-formalization's A-4 alphabet.

    Their ROUTING-2026-09-16-b §7 declines to claim the alphabet is the domain:
    twelve patterns, 1-2 segments, so "a disagreement that first appears at three
    namespaced segments is not visible here." This sweeps a larger alphabet against
    OUR definitions and asks one extra question their classifier does not: for every
    WIDENED pair, is the parent the universal `*`?

    That matters because a widening under a universal parent cannot admit a child the
    parent does not cover, whereas a widening under any other parent could. -/

def frame : String := "pA"

/-- `canonSegs`/`scopeSubset` as they stood at keystone `97bf1a05` -- re-transcribed
    here from `git show` rather than copied out of formalization's file, so this is a
    measurement of the artifact and not of our agreement with them. -/
def canonSegsPre (frame : String) (path : String) : List String :=
  if path.startsWith "/" then splitSegs path else splitSegs ("/" ++ frame ++ "/" ++ path)

def scopeSubsetPre (childFrame parentFrame : String) (child parent : Scope) : Bool :=
  child.incl.all (fun cp =>
    let cc := canonSegsPre childFrame cp
    parent.incl.any (fun pp => matchesSeg cc (canonSegsPre parentFrame pp)))
  && parent.excl.all (fun pe =>
       let cpe := canonSegsPre parentFrame pe
       child.excl.any (fun ce => matchesSeg cpe (canonSegsPre childFrame ce)))

def verdicts (cp pp : String) : Bool × Bool :=
  let c : Scope := ⟨[cp], []⟩
  let p : Scope := ⟨[pp], []⟩
  (scopeSubsetPre frame frame c p, scopeSubset .id frame frame c p)

/-- 24 patterns. Their twelve shapes plus three-segment namespaced forms, a
    trailing-slash form, an absolute trailing-star, an interior star at depth 3,
    the bare `/`, and the empty pattern. -/
def alphabet : List String :=
  [ "get", "put", "tree/get", "compute/apply", "abs/op"
  , "*", "*/get", "*/apply", "tree/*", "compute/*"
  , "/abs/op", "/*/get"
  , "a/b/c", "a/b/*", "a/*/c", "*/b/c", "/a/b/c", "/a/b/*", "/a/*/c"
  , "tree/", "/abs/", "/*", "", "/" ]

def pairsOf (xs : List String) : List (String × String) :=
  xs.flatMap (fun a => xs.map (fun b => (a, b)))

def allPairs : List (String × String) := pairsOf alphabet

def disagreements : List (String × String) :=
  allPairs.filter (fun q => let (pre, idv) := verdicts q.1 q.2; pre != idv)

def narrowed : List (String × String) :=
  disagreements.filter (fun q => (verdicts q.1 q.2).1)

def widened : List (String × String) :=
  disagreements.filter (fun q => !(verdicts q.1 q.2).1)

def widenedUnderStar : List (String × String) := widened.filter (fun q => q.2 == "*")
def widenedOther     : List (String × String) := widened.filter (fun q => q.2 != "*")

#eval s!"SWEEP pairs={allPairs.length} disagree={disagreements.length} narrowed={narrowed.length} widened={widened.length} widenedUnderStar={widenedUnderStar.length} widenedOther={widenedOther.length}"

#eval "WIDENED: " ++ String.intercalate " | " (widened.map (fun q => s!"{q.1} <= {q.2}"))
#eval "WIDENED_NOT_UNDER_STAR: " ++ String.intercalate " | " (widenedOther.map (fun q => s!"{q.1} <= {q.2}"))
#eval "NARROWED: " ++ String.intercalate " | " (narrowed.map (fun q => s!"{q.1} <= {q.2}"))

-- MUST-AGREE control: the star-free slash-free subset, the alphabet F50 survived in.
def plain : List String := ["get", "put", "tree/get", "compute/apply", "abs/op"]
def plainPairs : List (String × String) := pairsOf plain
#eval s!"MUSTAGREE_plain pairs={plainPairs.length} disagree={(plainPairs.filter (fun q => let (a,b) := verdicts q.1 q.2; a != b)).length}"

-- POSITIVE CONTROL: R11's witness must still exhibit the over-grant under
-- `scopeSubsetPre`, or `Pre` has stopped being the pre-artifact and every row above
-- is a sweep that is not comparing anything.
#eval s!"POSCTL_r11Pre={(verdicts "compute/apply" "*/apply").1} r11Id={(verdicts "compute/apply" "*/apply").2}"
