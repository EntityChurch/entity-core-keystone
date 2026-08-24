#!/usr/bin/env bash
# entity-core-protocol-apl — S3 peer machinery gate: the offline foundation self-test + the
# two-peer loopback smoke, container-bound and sealed-offline (--network=none). Loopback is
# intra-container 127.0.0.1 (works under --network=none), so the WHOLE S3 gate stays
# dependency-sealed. Both peers are native GNU APL images on their own ⎕FIO select-pump (no
# C net-shim — A-APL-006); §7b store-safety is structural (one image, one thread).
#
#   ./run-s3.sh            # full S3 gate: make s3 (selftest + two-peer smoke)
#   ./run-s3.sh smoke      # the two-peer loopback smoke only
#   ./run-s3.sh selftest   # the offline foundation self-test only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/apl-toolchain:latest"
WORKDIR="/work/protocol-generator/apl"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-all}" in
  smoke)    run "make smoke" ;;
  selftest) run "make selftest" ;;
  *)        run "make clean >/dev/null 2>&1; make s3" ;;
esac
