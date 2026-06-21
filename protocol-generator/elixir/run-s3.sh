#!/usr/bin/env bash
# S3 peer-machinery gate — container-bound (S1), sealed-offline (--network=none).
# Runs the full ExUnit suite (ECF 69/69 + agility 35 byte-pins + type-registry
# 53/53 + peer/smoke/reentry) and builds the standalone conformance host escript.
# Mounts the repo root so the vendored fixtures under protocol-generator/shared/
# are reachable.
#
#   ./run-s3.sh           # full gate (mix test + escript build)
#   ./run-s3.sh test      # ExUnit only
#   ./run-s3.sh escript    # build the host escript only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/beam:latest"
WORKDIR="/work/protocol-generator/elixir"

run() { podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" sh -c "$1"; }

case "${1:-all}" in
  test)    run "mix test" ;;
  escript) run "mix escript.build" ;;
  *)       run "mix test && mix escript.build" ;;
esac
