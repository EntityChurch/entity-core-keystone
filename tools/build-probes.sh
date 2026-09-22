#!/usr/bin/env bash
# build-probes.sh — build the standalone wire probes into output/s4-oracles/.
#
# WHY THIS FILE EXISTS. `tools/p47-probe` and `tools/put-probe` are cited by name
# in published findings as the instrument a number came from, and until now
# NOTHING IN THE TREE BUILT THEM — the binaries in `output/s4-oracles/` were made
# by hand and are gitignored. That is the shape AGENTS.md records as "a reproduce
# recipe that names a binary the repo has never contained": the number publishes,
# the means of reproducing it does not. One command, in the pinned container, no
# host writes.
#
#   tools/build-probes.sh              # all probes
#   tools/build-probes.sh put-probe    # one
#
# The probes are NOT oracles and never gate. They live beside the oracle binaries
# only because `run-cohort-census.sh --probe <name>` reads that directory, which
# is what lets a probe drop into all 46 peers' harnesses through `ORACLE=`.
set -euo pipefail

cd "$(dirname "$0")/.."
# shellcheck source=podman-caps.sh
. tools/podman-caps.sh

GO_IMAGE="${GO_IMAGE:-entity-core-keystone/go:latest}"
OUT="output/s4-oracles"
mkdir -p "$OUT"

probes=("$@")
if [ ${#probes[@]} -eq 0 ]; then
  probes=(p47-probe put-probe host-seam-probe)
fi

for p in "${probes[@]}"; do
  [ -f "tools/$p/main.go" ] || { echo "build-probes: no tools/$p/main.go" >&2; exit 2; }
  echo "build-probes: $p"
  podman run $PODMAN_RUN_CAPS --rm --security-opt label=disable \
    -v "$PWD":/work:Z -w "/work/tools/$p" \
    -e CGO_ENABLED=0 -e GOFLAGS= -e GOWORK=off -e GOCACHE=/tmp/gocache -e GOPATH=/tmp/gopath \
    "$GO_IMAGE" go build -o "/work/$OUT/$p" .
done

# Print what was produced, and its size — a build step that reports nothing
# cannot be told from one that built nothing.
ls -l "$OUT"/{p47-probe,put-probe,host-seam-probe} 2>/dev/null || true
echo "build-probes: ${#probes[@]} probe(s) built into $OUT/"
