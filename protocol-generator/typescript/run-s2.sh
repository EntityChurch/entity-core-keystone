#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-typescript. Container-bound,
# sealed-offline (--network=none), driven from the HOST like its cohort siblings.
#
# This peer had no run-s2.sh until 2026-09-02, and the absence hid a live defect:
# `npm test` ran `node --test dist/test/**` with NO BUILD STEP, so it tested
# whatever was last compiled. Measured — `dist/test/corpus.js` still named
# `test-vectors/v0.8.0/conformance-vectors-v1.cbor`, a directory and a filename
# both retired in the 2026-09-01 corpus de-versioning, while `test/corpus.ts`
# had been correctly updated the same day. The suite failed 2 of 65 against a
# day-old build of correct source. A `pretest` hook now compiles first; with it,
# 65/65 pass.
#
# The general shape is the standing stale-build-artifact rule, and it is the same
# one recorded for node-red (which rebuilds `dist/` only when `index.js` is
# MISSING, never when it is merely stale): a test script that does not build is
# a gate on the past.
#
#   ./run-s2.sh              # full suite (pretest builds, then node --test)
#   ./run-s2.sh conformance  # the ECF corpus runner only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/node24:latest"
WORKDIR="/work/protocol-generator/typescript"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT":/work:Z -v kc-npm:/npm-cache -w "$WORKDIR" "$IMAGE" \
    bash -lc "$1"
}

case "${1:-test}" in
  conformance) run 'npm run conformance' ;;
  *)           run 'npm test' ;;
esac
