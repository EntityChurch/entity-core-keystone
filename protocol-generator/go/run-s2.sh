#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-go. Container-bound, sealed-offline.
#
# Added 2026-09-02 with the rest of the S2 sweep coverage. The module lives in
# `src/`, not at the peer root, so a naive `go test ./...` from here reports
# "directory prefix . does not contain main module" — which reads as a broken
# checkout rather than a wrong working directory.
#
#   ./run-s2.sh          # go test ./... (codec + peer unit suites)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

# GOWORK=off: cmd/ is its own module with a local replace; without this the
# workspace forces -mod=mod errors. CGO_ENABLED=0 keeps the build hermetic.
podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/go/src \
  entity-core-keystone/go:latest \
  bash -lc 'CGO_ENABLED=0 GOWORK=off go test ./...'
