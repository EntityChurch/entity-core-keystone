#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Runs the pinned v0.8.0 wire-conformance corpus gate (71/71 byte-identical) via
# the hand-rolled Odin harness, PLUS the fixed-width u64 [2^63,2^64-1] head-form
# self-test and the native core:crypto/ed25519 KAT accept-path unit.
#
# Everything is offline: the corpus is compiled IN via `#load` (no runtime file
# IO); CBOR/base58/varint/peer_id/hash/harness are pure Odin in-repo; crypto is
# native pure-Odin core:crypto/{ed25519,sha2} (no libsodium, no FFI for the
# floor). The container pulls ZERO third-party packages, so the run needs no
# network (profile [container].network_policy = build-network-then-offline).
#
#   ./run-s2.sh          # full gate: odin test test (71-vector corpus + head-form + crypto KAT)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/odin-toolchain:latest"
WORKDIR="/work/protocol-generator/odin"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  sh -c 'odin test test'
