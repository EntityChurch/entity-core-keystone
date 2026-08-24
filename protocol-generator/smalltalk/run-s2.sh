#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds the codec C-ABI (libentitycore_codec) if absent, loads the pure-Smalltalk codec into
# a fresh Pharo peer image, and runs the pinned v0.8.0 corpus gate (69/69 byte-identical) via
# the SUnit-backed harness, PLUS the uint64 int-boundary self-test and the crypto accept-path.
# Everything is offline: libsodium is pre-installed in the pharo-toolchain image;
# CBOR/base58/varint/peer_id/harness are pure Smalltalk in-repo; crypto crosses the C-ABI via
# Pharo's in-process UFFI (ffiCall:module:; no subprocess / co-process).
#
#   ./run-s2.sh          # full gate: make test (69-vector corpus) + int-boundary + crypto-accept + sunit
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/pharo-toolchain:latest"
WORKDIR="/work/protocol-generator/smalltalk"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

run "make clean >/dev/null 2>&1; make test && make int-boundary && make crypto-accept && make sunit"
