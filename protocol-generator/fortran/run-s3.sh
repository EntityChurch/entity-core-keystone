#!/usr/bin/env bash
# entity-core-protocol-fortran — S3 peer machinery gate: the offline foundation self-test
# + the two-peer loopback smoke, container-bound and sealed-offline (--network=none).
# Loopback is intra-container 127.0.0.1 (works under --network=none), so the WHOLE S3 gate
# stays dependency-sealed. The single-threaded Fortran peer drives the C net-shim's one
# select() loop DIRECTLY via iso_c_binding (no co-process) — structural §7b store-safety.
#
#   ./run-s3.sh            # full S3 gate: make s3 (selftest + two-peer smoke)
#   ./run-s3.sh smoke      # the two-peer loopback smoke only
#   ./run-s3.sh selftest   # the offline foundation self-test only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/fortran-toolchain:latest"
WORKDIR="/work/protocol-generator/fortran"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-all}" in
  smoke)    run "make smoke" ;;
  selftest) run "make selftest" ;;
  *)        run "make clean >/dev/null 2>&1; make s3" ;;
esac
