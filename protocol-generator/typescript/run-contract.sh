#!/usr/bin/env bash
# Keystone peer contract — entity-core-protocol-typescript. Container-bound, sealed-offline.
#
# Builds the peer (its bare host is dist/test/host.js = runHost(argv, no-op)) and the
# contract host (a SEPARATE package, contract/host/), runs the shared wire driver against
# them, and runs the peer's local tests. It writes RAW EVIDENCE only:
#   $OUT/cases.json   the driver's case records
#   $OUT/local.txt    the node:test results in libtest line form (report.py extracts the
#                     contract tests), then `local tests exit <rc>`
# It never computes a verdict — tools/peer-contract/run.sh calls report.py for that.
#
#   tools/peer-contract/run.sh typescript          # the normal entry point
#   OUT=output/scratch/x ./run-contract.sh         # evidence only
#
# PEER_REL (default protocol-generator/typescript) lets tools/peer-contract/plant.py point
# this same script at a planted scratch copy, so a plant is measured by exactly the harness
# a real run uses. KPC_SKIP_LOCAL=1 skips the local tests. DRIVER overrides the driver binary.
#
# The contract host is compiled from a COPY of contract/host/ under contract/host/output/pkg,
# whose node_modules/entity-core-protocol-typescript is a link to the peer directory. Two
# reasons, both load-bearing: (a) it resolves the peer ONLY through the peer package's
# `exports` map — the embed.package observation — and (b) the link lives under an `output/`
# directory, which plant.py's copy skips; a link to an ancestor anywhere else in the tree
# would send that copy into unbounded recursion.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
PEER_REL="${PEER_REL:-protocol-generator/typescript}"
OUT="${OUT:-output/scratch/peer-contract/typescript}"
DRIVER="${DRIVER:-output/peer-contract/kpc-driver}"
mkdir -p "$REPO_ROOT/$OUT"
[ -x "$REPO_ROOT/$DRIVER" ] || { echo "run-contract: driver missing at $DRIVER — tools/peer-contract/run.sh builds it" >&2; exit 3; }

podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work:Z -w "/work/$PEER_REL" \
  -e KPC_SKIP_LOCAL="${KPC_SKIP_LOCAL:-0}" \
  entity-core-keystone/node24:latest \
  bash -c '
    set -eu
    PEER=/work/'"$PEER_REL"'
    OUT=/work/'"$OUT"'
    cd "$PEER"

    # Dependencies from the committed lockfile, offline (the closure is baked into the
    # image). Re-installed whenever the lockfile is newer than the install record.
    if [ ! -f node_modules/.package-lock.json ] || [ package-lock.json -nt node_modules/.package-lock.json ]; then
      npm ci --offline >/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; }
    fi
    # Always compile: a gate on a stale dist/ is a gate on the past. The compiler is run by
    # its package path, not node_modules/.bin/tsc: plant.py'"'"'s copy of this tree follows
    # symlinks, which turns .bin/tsc into a file whose relative require no longer resolves.
    TSC="node $PEER/node_modules/typescript/bin/tsc"
    $TSC -p tsconfig.json >>/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; }

    PKG="$PEER/contract/host/output/pkg"
    rm -rf "$PKG" && mkdir -p "$PKG/node_modules"
    cp -r contract/host/package.json contract/host/tsconfig.json contract/host/src "$PKG/"
    ln -s "$PEER" "$PKG/node_modules/entity-core-protocol-typescript"
    $TSC -p "$PKG/tsconfig.json" >>/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; }

    rm -rf /tmp/kpc && mkdir -p /tmp/kpc
    /work/'"$DRIVER"' \
      -host "node $PKG/dist/main.js" \
      -bare-host "node $PEER/dist/test/host.js" \
      -peer-package entity-core-protocol-typescript \
      -workdir /tmp/kpc -out "$OUT/cases.json"

    if [ "$KPC_SKIP_LOCAL" != "1" ]; then
      # No pipe: the test exit status is recorded, not swallowed (AGENTS.md: `cmd | tail`
      # reports tail'"'"'s exit code). A failing test is evidence, so it does not abort the run.
      rc=0
      node --test --test-reporter=tap "dist/test/**/*.test.js" >/tmp/local.tap 2>&1 || rc=$?
      # node:test TAP → the libtest lines report.py reads (`test NAME ... ok|FAILED|ignored`).
      node contract/tap-to-libtest.mjs </tmp/local.tap >"$OUT/local.txt"
      echo "local tests exit $rc" >>"$OUT/local.txt"
    fi
  '
