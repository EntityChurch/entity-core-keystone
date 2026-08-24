#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds the crypto shim (+ libentitycore_codec if absent) and runs the pinned
# v0.8.0 corpus gate (69/69 byte-identical) via the hand-rolled Tcl harness.
# Everything is offline: libsodium is pre-installed in the tcl-toolchain image;
# CBOR/base58/varint/harness are pure Tcl in-repo.
#
#   ./run-s2.sh          # full gate: make test (69-vector corpus conformance)
#   ./run-s2.sh spike    # the pure-Tcl high-risk-legs spike (no crypto shim)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/tcl-toolchain:latest"
WORKDIR="/work/protocol-generator/tcl"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-test}" in
  spike) run "make spike" ;;
  *)     run "make clean >/dev/null 2>&1; make test" ;;
esac
