#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-zig. Container-bound, sealed-offline.
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
#   ./run-s2.sh          # zig build test (in-file unit tests, leak-checked) + corpus
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/zig \
  entity-core-keystone/zig-toolchain:latest \
  bash -lc 'set -e
    echo "── unit tests (std.testing.allocator, leak-checked) ──"; zig build test
    echo "── ECF conformance corpus ──"; zig build conformance'
