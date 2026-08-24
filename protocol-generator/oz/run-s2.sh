#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds the entity-codec-daemon (+ libentitycore_codec if absent) and runs the
# pinned v0.8.0 corpus gate (71/71 byte-identical) via the hand-rolled Oz harness.
#
#   ./run-s2.sh          # full gate: make s2 (71-vector corpus conformance)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/mozart-toolchain:latest"
WORKDIR="/work/protocol-generator/oz"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -lc "make s2"
