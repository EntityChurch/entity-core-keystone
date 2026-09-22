#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-cobol. Container-bound, sealed-offline.
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
# LD_LIBRARY_PATH is load-bearing: the unit binaries link libentitycore_codec.so
# and without it every one dies at startup with
#     error while loading shared libraries: libentitycore_codec.so
# which reads as a missing build rather than a missing path. Same value run-s4.sh
# exports; kept identical so the two cannot drift.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
CODEC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/cobol \
  -e LD_LIBRARY_PATH="$CODEC" \
  localhost/entity-core-keystone/cobol-toolchain:latest \
  bash -lc 'make test'
