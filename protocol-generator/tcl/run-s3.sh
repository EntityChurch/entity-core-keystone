#!/usr/bin/env bash
# S3 peer machinery — the peer-layer foundation self-test + the two-peer loopback
# smoke, container-bound and sealed-offline (--network=none). Loopback is
# intra-container localhost (127.0.0.1), which works under --network=none — so the
# WHOLE S3 gate stays dependency-sealed and offline.
#
#   ./run-s3.sh            # the full S3 gate: make s3 (selftest + smoke)
#   ./run-s3.sh smoke      # the two-peer loopback smoke only (12/12)
#   ./run-s3.sh selftest   # the peer-layer foundation self-test only (26/26)
#
# The single-threaded chan-event/vwait event loop (profile [async]) makes the §4.8
# store-safety MUST structural — there is no concurrency to race. Crypto (Ed25519 +
# SHA) crosses the C-ABI via the shim (make shim rebuilds it); everything else is
# pure Tcl in-repo (zero runtime package deps).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/tcl-toolchain:latest"
WORKDIR="/work/protocol-generator/tcl"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-all}" in
  smoke)    run "make smoke" ;;
  selftest) run "make selftest" ;;
  *)        run "make clean >/dev/null 2>&1; make s3" ;;
esac
