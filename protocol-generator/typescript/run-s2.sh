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

# No -v kc-npm:/npm-cache. The dependency closure is baked into the image from
# THIS peer's own package-lock.json (containers/node24/Containerfile), so the run
# is sealed by construction rather than by a host-local volume somebody warmed
# once — the csharp/kc-nuget defect, closed here 2026-09-02. Mounting a volume at
# /npm-cache would SHADOW the baked closure and restore it.
run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$1"
}

# `npm ci --offline` first, and it is not decoration. Until 2026-09-02 this gate
# ran `npm test` directly and therefore depended on an UNTRACKED node_modules/
# already sitting in the working tree — measured from a clean tree it died with
# `tsc: command not found`, exit 127. That is the same class as the kc-npm volume
# this file just stopped mounting, one level down: the gate worked on the machine
# that had warmed it and nowhere else.
case "${1:-test}" in
  conformance) run 'npm ci --offline && npm run conformance' ;;
  *)           run 'npm ci --offline && npm test' ;;
esac
