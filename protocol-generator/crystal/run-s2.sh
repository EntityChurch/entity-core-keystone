#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Runs the pinned v0.8.0 wire-conformance corpus gate (71/71 byte-identical) via
# the hand-rolled Crystal ECF codec, PLUS the fixed-width uint64 head-form
# self-test and the Ed25519 sign->verify accept-path unit. Everything is offline:
# libsodium is pre-installed (system lib) in the crystal-toolchain image; the
# codec/base58/varint/peer_id/harness are pure Crystal in-repo; SHA-256/512 are
# stdlib; Ed25519 crosses a direct in-process `lib`/`fun` binding to libsodium
# (no subprocess / co-process). The core peer has ZERO shard runtime deps.
#
#   ./run-s2.sh          # full gate: `crystal spec` (all green) in the container
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/crystal-toolchain:latest"
WORKDIR="/work/protocol-generator/crystal"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  sh -c 'crystal spec --no-color'
