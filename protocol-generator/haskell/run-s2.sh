#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-haskell. Container-bound,
# sealed-offline (--network=none), driven from the HOST like its 22 cohort
# siblings.
#
# This peer had no run-s2.sh until 2026-09-02, and that absence is the whole
# reason its gate rotted unnoticed: the S2 axis is swept by looking for
# `run-s2.sh`, so a peer without one is not measured and not reported missing
# either. Its S2 report claimed "offline ... verified GREEN" on the strength of
# a warm store in a gitignored `.cabal-home` that only one machine ever had, and
# that store had never been warmed for the TEST-suite closure — so the documented
# reproduce command could not run at all. The dependency closure now ships in
# the image (containers/ghc-toolchain/Containerfile), derived from this peer's
# own cabal.project.freeze, so this script needs no host state.
#
#   ./run-s2.sh          # full gate: the hspec `conformance` suite
#   ./run-s2.sh build    # build only
#
# The suite covers: the 71-vector ECF corpus, the crypto-agility corpus
# (including the §2.4a construct_reject negative half), the type-registry
# byte-diff, the uncovered-range selftests and the QuickCheck properties.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ghc-toolchain:latest"
WORKDIR="/work/protocol-generator/haskell"

# `-f dev` turns on -Werror. The distributed build deliberately keeps -Wall
# WITHOUT -Werror (a downstream GHC bump must not break a consumer); the gate is
# where warnings-as-errors belongs.
run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    sh -c "$1"
}

case "${1:-test}" in
  build) run 'cabal build --offline -f dev' ;;
  *)     run 'cabal test conformance --offline -f dev --test-show-details=direct' ;;
esac
