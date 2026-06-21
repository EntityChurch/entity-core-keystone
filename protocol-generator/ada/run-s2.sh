#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds + runs the entity-core-protocol-ada codec: gprbuild against the
# committed entity_core_protocol.gpr, then the hand-rolled conformance harness
# (the ECF wire-conformance corpus gate, cohort baseline 69/69 byte-identical)
# and the self-test runner (N1-N4 + uncovered-range + crypto KATs).
#
# The fixture under protocol-generator/shared/test-vectors/v0.8.0/ is reached by
# mounting the repo root. The core toolchain (gcc-gnat + gprbuild +
# libsodium-devel) is dnf-installed at image BUILD time and there are NO Alire
# crate deps, so this runs fully offline under --network=none.
#
#   ./run-s2.sh            # build + conformance gate + self-tests
#   ./run-s2.sh build      # gprbuild only
#   ./run-s2.sh conf       # conformance harness only (assumes built)
#   ./run-s2.sh tests      # self-tests only (assumes built)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ada-toolchain:latest"
WORKDIR="/work/protocol-generator/ada"
VECTORS="/work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -c "$1"
}

BUILD='gprbuild -P entity_core_protocol.gpr -p'
CONF="./bin/run_conformance $VECTORS"
TESTS='./bin/run_tests'

case "${1:-all}" in
  build) run "$BUILD" ;;
  conf)  run "$CONF" ;;
  tests) run "$TESTS" ;;
  *)     run "$BUILD && echo '--- self-tests ---' && $TESTS && echo '--- conformance ---' && $CONF" ;;
esac
