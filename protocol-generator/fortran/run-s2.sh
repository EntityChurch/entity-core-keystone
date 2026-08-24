#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds libentitycore_codec if absent (its CMake; libsodium is pre-installed in the
# fortran-toolchain image) and runs the pinned v0.8.0 corpus gate (69/69 byte-identical)
# via the hand-rolled pure-Fortran codec + the iso_c_binding crypto/base58 floor.
# Everything is offline: the codec/varint/harness are pure Fortran in-repo; crypto/base58
# ride libentitycore_codec (built from the vendored C-ABI, links the image libsodium).
#
#   ./run-s2.sh          # full gate: make test  (69-vector corpus conformance + unit suite)
#   ./run-s2.sh conf     # corpus conformance only
#   ./run-s2.sh unit     # unit suite only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/fortran-toolchain:latest"
WORKDIR="/work/protocol-generator/fortran"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-test}" in
  conf) run "make conf" ;;
  unit) run "make unit" ;;
  *)    run "make clean >/dev/null 2>&1; make test" ;;
esac
