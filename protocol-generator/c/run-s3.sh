#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke gate, container-bound and sealed
# offline (--network=none, loopback only). Boots a RESPONDER C peer on a localhost port
# and drives the §4.1 handshake + core ops from a second C peer acting as INITIATOR over
# real TCP, proving transport + handshake + register/dispatch/emit + capability gating +
# request_id demux end to end. A second scenario exercises the v7.74 Core Extensibility
# Boundary (register live-hook + §7a echo) under --debug-open-grants + --validate.
#
# Built + run under ASan/LSan/UBSan: a memory bug (leak / UAF / overflow / UB) anywhere
# in the peer FAILS the run — the C manual-memory conformance bonus.
#
#   ./run-s3.sh           # the two-peer loopback smoke gate (exits non-zero on FAIL)
#   ./run-s3.sh all       # smoke + the S2 codec regression (full make test)
#
# The c-toolchain image ships gcc + libsodium + libasan/libubsan, so this runs fully
# offline (no registry-pulled deps; CBOR/base58/varint/transport are hand-rolled in-repo).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/c-toolchain:latest"
WORKDIR="/work/protocol-generator/c"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-smoke}" in
  all)   run "make clean >/dev/null 2>&1; make smoke && make test" ;;
  *)     run "make clean >/dev/null 2>&1; make smoke" ;;
esac
