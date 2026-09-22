#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-kotlin. Container-bound, sealed-offline.
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
#   ./run-s2.sh          # gradle test (codec + corpus + type-registry suites)
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/kotlin \
  entity-core-keystone/kotlin-toolchain:latest \
  bash -lc 'gradle test --offline'
