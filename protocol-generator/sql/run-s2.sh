#!/usr/bin/env bash
# S2 codec/crypto seam — container-bound, sealed-offline (--network=none), capped.
# Builds the thin C seam (src/host/ec_seam.c) over libentitycore_codec + the SQLite
# amalgamation, then runs the S2 GATE: the 71-vector ECF wire-conformance
# byte-identity differential vs the delegated codec (protocol-generator/shared/
# test-vectors/ecf-conformance/), N1–N4 self-tests, an Ed25519 RFC-8032 KAT, and the
# crypto-callable-FROM-SQL KAT (sha256/content_hash/ed25519_verify as SQLite
# application-defined functions — the tight-seam move). The build is fully offline:
# libentitycore_codec + sqlite3.c are baked into the sqlite-toolchain image.
#
#   ./run-s2.sh          # full S2 gate (make check)
#   ./run-s2.sh seam     # build the seam object only
#   ./run-s2.sh clean     # remove build/
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/sqlite-toolchain:latest"
WORKDIR="/work/protocol-generator/sql"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-check}" in
  seam)  run "make seam" ;;
  clean) run "make clean" ;;
  *)     run "make clean >/dev/null 2>&1; make check" ;;
esac
