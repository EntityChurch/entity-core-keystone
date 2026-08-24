#!/usr/bin/env bash
# S2 codec gate — container-bound, offline (--network=none). Builds the C-ABI
# codec + the EntityCodec Io addon, runs the seam smoke, then the pinned v0.8.0
# 71-vector corpus byte-identity gate.
#
#   ./run-s2.sh          # build + smoke + corpus
#   ./run-s2.sh smoke    # build + smoke only
#   ./run-s2.sh shell    # interactive container shell
#   ./run-s2.sh clean
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/io-toolchain:latest"
WORKDIR="/work/protocol-generator/io"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-s2}" in
  smoke) run "make smoke" ;;
  clean) run "make clean" ;;
  shell) podman run $PODMAN_RUN_CAPS --rm -it --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" bash ;;
  *)     run "make smoke && make s2" ;;
esac
