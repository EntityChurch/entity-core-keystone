#!/usr/bin/env bash
# entity-core-protocol-forth — S3 peer machinery gate: the peer-layer foundation self-test
# + the two-peer loopback smoke, container-bound and sealed-offline (--network=none).
# Loopback is intra-container 127.0.0.1, which works under --network=none — so the WHOLE S3
# gate stays dependency-sealed and offline (no reference peer needed; unlike Rexx there is no
# co-process daemon — gforth owns the sockets + select loop + crypto in-process, A-FT-008).
#
#   ./run-s3.sh            # the full S3 gate: make s3 (selftest + smoke 6/6)
#   ./run-s3.sh smoke      # the two-peer loopback smoke only (6/6)
#   ./run-s3.sh selftest   # the peer-layer foundation self-test only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/forth-toolchain:latest"
WORKDIR="/work/protocol-generator/forth"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-all}" in
  smoke)    run "make smoke" ;;
  selftest) run "make selftest" ;;
  *)        run "make s3" ;;
esac
