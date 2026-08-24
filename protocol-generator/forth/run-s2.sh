#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds the codec C-ABI (libentitycore_codec) if absent and runs the pinned v0.8.0 corpus
# gate (69/69 byte-identical) via the hand-rolled Forth harness, PLUS the crypto accept-path
# unit test. Everything is offline: libsodium is pre-installed in the forth-toolchain image;
# CBOR/base58/varint/peer_id/harness are pure Forth in-repo; crypto crosses the C-ABI via
# gforth's in-process libcc c-function (no subprocess / co-process).
#
#   ./run-s2.sh          # full gate: make test (69-vector corpus) + crypto-accept
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/forth-toolchain:latest"
WORKDIR="/work/protocol-generator/forth"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

run "make clean >/dev/null 2>&1; make test && make int-boundary && make crypto-accept"
