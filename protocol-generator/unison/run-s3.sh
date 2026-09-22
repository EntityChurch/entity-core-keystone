#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke (src/Smoke.u, driven by the ucm transcript).
#
# WHY THIS FILE EXISTS. This peer already had the gate below; nothing SWEPT it. The S3
# axis (tools/run-axis-sweep.sh s3) drives `protocol-generator/*/run-s3.sh`, so a peer
# without that exact filename reads as NO-GATE — "a list of tests nobody runs", not a
# peer without tests. Two of this session's defects were dialer bugs the ORACLE cannot
# see (it is always the client), and both were caught by a per-peer gate; the axis is
# where that class is found, so the inventory has to be complete before the coverage
# number means anything. Added 2026-09-08.
#
# THE SUCCESS MARKER IS THE RENDERED RESULT, NOT THE WORD "PASS". A ucm transcript ECHOES
# ITS OWN SOURCE, so grepping the output for PASS/FAIL matches the checker's own definition
# and is green whatever happened (the standing lesson from the 2026-09-02 S2 sweep). The
# transcript ends `run smokeMain` -> "SMOKE 8/8"; that string is the verdict.
#
#   ./run-s3.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z \
  localhost/entity-core-keystone/unison-toolchain:latest \
  bash -lc 'cd /work/protocol-generator/unison && cp -r transcripts /tmp/s3-tr && ucm transcript /tmp/s3-tr/smoke.md && grep -qF "SMOKE 8/8" /tmp/s3-tr/smoke.output.md && echo "unison S3 smoke: SMOKE 8/8"'
