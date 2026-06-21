#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke test, container-bound and
# sealed-offline (--network=none, loopback only). Boots a RESPONDER Java peer on a
# localhost port and drives the §4.1 handshake + core ops from a second Java peer
# acting as INITIATOR over real TCP, proving transport + handshake +
# register/dispatch/emit + capability gating + request_id demux end-to-end. A
# second scenario exercises the v7.74 Core Extensibility Boundary (register
# live-hook + §7a echo) under --debug-open-grants + --validate.
#
#   ./run-s3.sh           # the two-peer loopback smoke gate (SmokeTest, exits non-zero on FAIL)
#   ./run-s3.sh all       # smoke + the S2 codec regression (full mvn test)
#
# Maven deps (JUnit, opt-in BouncyCastle) are pre-fetched into the image ~/.m2 at
# container BUILD time, so this runs `mvn -o` fully offline.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/java-toolchain:latest"
WORKDIR="/work/protocol-generator/java"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    mvn -o -B "$@"
}

case "${1:-smoke}" in
  all)   run clean test ;;
  *)     run clean test -Dtest=SmokeTest ;;
esac
