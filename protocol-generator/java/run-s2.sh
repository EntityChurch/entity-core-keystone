#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds + tests the entity-core-protocol-java codec: the ECF wire-conformance
# corpus gate (69/69 byte-identical) + the uncovered-range / Ed448-KAT selftest,
# via JUnit 5 (surefire). Mounts the repo root so the vendored fixtures under
# protocol-generator/shared/ are reachable. Maven deps (JUnit, opt-in BouncyCastle)
# are pre-fetched into the image ~/.m2 at container BUILD time, so this runs `mvn -o`
# fully offline.
#
#   ./run-s2.sh           # full gate: mvn -o test (conformance + selftest)
#   ./run-s2.sh package   # mvn -o package (also produces the jar)
#
# THE COUNT IS ASSERTED, not just printed. Surefire prints `Tests run: 33` and Maven
# exits 0; it ALSO exits 0 when it finds no tests at all (failIfNoTests is not on by
# default), so a dropped test class or a mis-declared testSourceDirectory leaves this
# green. That is the class already fixed in swift, smalltalk and kotlin: if a gate's
# success message does not contain a number the gate cannot distinguish "all green"
# from "nothing ran". `clean` runs first, so a stale surefire report from an earlier
# run cannot satisfy the floor. Raise JAVA_TEST_FLOOR when tests are added; it is a
# floor, not an equality.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/java-toolchain:latest"
WORKDIR="/work/protocol-generator/java"
FLOOR="${JAVA_TEST_FLOOR:-33}"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    mvn -o -B "$@"
}

assert_count() {
  # -i, or the heredoc never reaches the container: `podman run` does not forward stdin
  # without it, so `python3 -` reads an empty script, prints nothing and exits 0. Caught
  # by the planted-floor test below, which is the entire reason to have one -- the first
  # cut of this counter was itself the vacuous gate it exists to prevent.
  podman run $PODMAN_RUN_CAPS --rm -i --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    python3 - "$FLOOR" <<'PY'
import glob, sys, xml.etree.ElementTree as ET
floor = int(sys.argv[1])
tot = fail = err = skip = 0
files = sorted(glob.glob("target/surefire-reports/TEST-*.xml"))
for f in files:
    r = ET.parse(f).getroot()
    tot += int(r.get("tests", 0)); fail += int(r.get("failures", 0))
    err += int(r.get("errors", 0)); skip += int(r.get("skipped", 0))
print(f"S2 java: {len(files)} test classes, {tot} tests, {fail} failures, "
      f"{err} errors, {skip} skipped (floor {floor})")
if fail or err:
    sys.exit("FAIL: the suite reported failures or errors")
if tot < floor:
    sys.exit(f"FAIL: {tot} tests executed, floor is {floor} — Maven exits 0 when it "
             f"finds no tests, which is why this floor exists")
print("RESULT: PASS")
PY
}

case "${1:-test}" in
  package) run clean package ;;
  *)       run clean test; assert_count ;;
esac
