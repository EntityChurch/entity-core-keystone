#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke (test/run-smoke.ts -> dist/test/run-smoke.js).
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

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z \
  entity-core-keystone/node24:latest \
  bash -lc 'cd /work/protocol-generator/typescript && npm ci --offline >/dev/null 2>&1 || true; npm run --silent build && node dist/test/run-smoke.js'
