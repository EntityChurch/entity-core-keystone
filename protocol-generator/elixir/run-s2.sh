#!/usr/bin/env bash
# S2 codec conformance — container-bound (S1), sealed-offline (--network=none).
# Runs the ExUnit gate (ECF corpus 69/69 + agility byte-pins + selftest) and the
# standalone counter. Mounts the repo root so the vendored fixtures under
# protocol-generator/shared/ are reachable.
#
#   ./run-s2.sh           # full gate
#   ./run-s2.sh count     # standalone PASS/FAIL counts only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/beam:latest"
WORKDIR="/work/protocol-generator/elixir"

run() { podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" sh -c "$1"; }

case "${1:-test}" in
  count) run "mix run priv/conformance.exs" ;;
  *)     run "mix test" ;;
esac
