#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-swift. Container-bound, sealed-offline.
#
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
# --security-opt label=disable is required, not cosmetic: swift-crypto's
# BoringSSL sources `#include` .cc.inc files out of .build/checkouts, and under
# the default SELinux label the compiler gets "Permission denied" on them —
# which surfaces as a BoringSSL compile error plus an llbuild SQLite assertion
# failure, neither of which points at the label.
#
#   ./run-s2.sh          # swift test
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/swift \
  entity-core-keystone/swift-toolchain:latest \
  bash -lc 'swift test'
