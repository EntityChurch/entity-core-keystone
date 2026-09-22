#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-kotlin. Container-bound, sealed-offline.
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
#   ./run-s2.sh          # gradle test (codec + corpus + type-registry suites)
#
# THIS GATE USED TO PASS WITHOUT RUNNING A SINGLE TEST. It was `gradle test --offline`
# and nothing else, and Gradle's whole design is to skip work it believes is current:
# on any invocation after the first, with sources unchanged, it prints
#
#     > Task :test UP-TO-DATE
#     BUILD SUCCESSFUL in 7s
#
# and exits 0 having executed zero tests. Measured 2026-09-02 by running it twice in a
# row. That is the same defect as swift's `swift test` (exit 0 for a suite that ran 35
# cases and for one that ran none) and smalltalk's empty SUnit reporting
# `failures=0 errors=0` — the fifth occurrence of the class in this repo, and the worst
# form of it, because the other two at least invoked a runner.
#
# Two changes, and BOTH are needed:
#   --rerun   forces the `test` task to execute even when Gradle thinks it is current.
#             Scoped to that task, unlike --rerun-tasks, so compilation still caches.
#   a COUNT   parsed from the JUnit XML and asserted against a floor. A gate whose
#             success message contains no number cannot distinguish "all green" from
#             "nothing ran", and --rerun alone would still pass a suite that silently
#             lost its test classes.
#
# The results directory is deleted first, so a stale XML from an earlier run can never
# satisfy the floor. Raise KOTLIN_TEST_FLOOR when tests are added; it is a floor, not
# an equality, so adding tests does not break the gate.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
FLOOR="${KOTLIN_TEST_FLOOR:-7}"

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/kotlin \
  entity-core-keystone/kotlin-toolchain:latest \
  bash -lc '
    set -eu
    rm -rf build/test-results/test
    gradle test --offline --rerun
    python3 - "'"$FLOOR"'" <<"PY"
import glob, sys, xml.etree.ElementTree as ET
floor = int(sys.argv[1])
tot = fail = err = skip = 0
files = sorted(glob.glob("build/test-results/test/*.xml"))
for f in files:
    r = ET.parse(f).getroot()
    tot += int(r.get("tests", 0)); fail += int(r.get("failures", 0))
    err += int(r.get("errors", 0)); skip += int(r.get("skipped", 0))
print(f"S2 kotlin: {len(files)} test classes, {tot} tests, "
      f"{fail} failures, {err} errors, {skip} skipped (floor {floor})")
if fail or err:
    sys.exit("FAIL: the suite reported failures or errors")
if tot < floor:
    sys.exit(f"FAIL: {tot} tests executed, floor is {floor} — a suite that ran "
             f"nothing exits 0 in Gradle, which is why this floor exists")
print("RESULT: PASS")
PY
  '
