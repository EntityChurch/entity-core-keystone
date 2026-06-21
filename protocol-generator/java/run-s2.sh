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
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/java-toolchain:latest"
WORKDIR="/work/protocol-generator/java"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    mvn -o -B "$@"
}

case "${1:-test}" in
  package) run clean package ;;
  *)       run clean test ;;
esac
