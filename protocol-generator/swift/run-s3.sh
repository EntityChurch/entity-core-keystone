#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke (Sources/Smoke).
#
# WHY THIS FILE EXISTS. This peer already had the gate below; nothing SWEPT it. The S3
# axis (tools/run-axis-sweep.sh s3) drives `protocol-generator/*/run-s3.sh`, so a peer
# without that exact filename reads as NO-GATE — "a list of tests nobody runs", not a
# peer without tests. Two of this session's defects were dialer bugs the ORACLE cannot
# see (it is always the client), and both were caught by a per-peer gate; the axis is
# where that class is found, so the inventory has to be complete before the coverage
# number means anything. Added 2026-09-08.
#
#   ./run-s3.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

# --security-opt label=disable is required, not cosmetic, and this gate was missing it
# while its sibling run-s2.sh carried it with the reason written out: swift-crypto's
# BoringSSL sources `#include` .cc.inc files out of .build/checkouts, and under the
# default SELinux label the compiler gets "Permission denied" on them. Here it presented
# as SwiftPM refusing the checkouts outright ("the package at .../swift-crypto cannot be
# accessed") followed by "Source files for target EntityCoreProtocol should be located
# under 'Sources/EntityCoreProtocol'" — which reads as a broken package manifest and is
# a label problem. Bisected against HEAD before being called pre-existing: identical
# failure with every source file reverted, so it is this harness and not the peer.
#
# THIS IS THE STANDING "an axis's per-peer gates rot exactly where no cohort runner
# reaches" SHAPE, one level in: the gate EXISTS and is swept, and it had never been
# executed successfully on a host with SELinux enforcing, because the one flag that
# makes it work lives in the file next door.
podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work:Z \
  entity-core-keystone/swift-toolchain:latest \
  bash -lc 'cd /work/protocol-generator/swift && swift run -c release smoke'
