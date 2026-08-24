#!/usr/bin/env bash
# S3 peer machinery — the peer-layer foundation self-test + the two-peer loopback
# smoke, container-bound and sealed-offline (--network=none). Loopback is intra-
# container localhost (127.0.0.1), which works under --network=none — so the WHOLE S3
# gate stays dependency-sealed and offline.
#
#   ./run-s3.sh            # the full S3 gate: make s3 (selftest 31/31 + smoke 8/8)
#   ./run-s3.sh smoke      # the two-peer loopback smoke only (8/8)
#   ./run-s3.sh selftest   # the peer-layer foundation self-test only (31/31)
#
# The single-threaded Rexx peer drives a persistent `ecnet` C co-process (owning the
# real sockets + select() loop + §1.6 de-framing) over two FIFOs; the daemon ALSO
# carries the §9.1 crypto (A-RX-011: Regina cannot ADDRESS SYSTEM the eccrypto helper
# while a FIFO stream is open — the fork/exec corrupts the read — so the networked
# peer's crypto crosses the C-ABI inside the daemon over the same FIFO channel). One
# Rexx thread + one select loop give structural §7b store-safety.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/rexx-toolchain:latest"
WORKDIR="/work/protocol-generator/rexx"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-all}" in
  smoke)    run "make smoke" ;;
  selftest) run "make selftest" ;;
  *)        run "make clean >/dev/null 2>&1; make s3" ;;
esac
