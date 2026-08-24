#!/usr/bin/env bash
# S2 codec seam — container-bound, offline (--network=none). Builds the C-ABI
# codec (libentitycore_codec.so) + the [ecodec] Pd external, then runs the
# codec-seam smoke gate: headless pd loads [ecodec] and does a real SHA-256
# round-trip through libentitycore_codec (the codec-seam GO gate).
#
#   ./run-s2.sh          # build the external + run the smoke gate
#   ./run-s2.sh external # build the [ecodec] external only
#   ./run-s2.sh clean     # remove build/
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/puredata-toolchain:latest"
WORKDIR="/work/protocol-generator/pd"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-smoke}" in
  external) run "make external" ;;
  clean)    run "make clean" ;;
  *)        run "make clean >/dev/null 2>&1; make smoke" ;;
esac
