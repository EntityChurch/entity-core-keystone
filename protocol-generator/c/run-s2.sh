#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds + tests the entity-core-protocol-c codec: the ECF wire-conformance corpus
# gate (69/69 byte-identical) + uncovered-range / Ed25519 RFC-8032 KAT self-tests,
# via the hand-rolled C harness (test/conformance.c) built under ASan/LSan/UBSan
# (memory bugs are test failures — the manual-memory conformance bonus). Mounts the
# repo root so the vendored fixtures under protocol-generator/shared/ are reachable.
# The build is fully offline: libsodium is pre-installed in the c-toolchain image
# and everything else (CBOR/base58/varint/harness) is hand-rolled in-repo.
#
#   ./run-s2.sh           # full gate: make test (conformance + selftests, ASan/LSan/UBSan)
#   ./run-s2.sh spike     # the S2 codec spike only (float + map_keys)
#   ./run-s2.sh all       # make all (also builds libentity_core_protocol.{a,so})
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/c-toolchain:latest"
WORKDIR="/work/protocol-generator/c"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-test}" in
  spike) run "make clean >/dev/null 2>&1; make spike" ;;
  all)   run "make clean >/dev/null 2>&1; make all" ;;
  *)     run "make clean >/dev/null 2>&1; make test" ;;
esac
