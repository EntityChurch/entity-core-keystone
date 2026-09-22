#!/usr/bin/env bash
# S2 wire-conformance gate runner for entity-core-protocol-julia.
# Runs the hand-rolled codec against the pinned v0.8.0 ECF corpus (71 vectors) inside the
# capped, offline julia-toolchain container. Exit 0 iff 71/71 byte-identical, 0 FAIL.
#
#   ./run-conformance.sh            # the 71-vector gate (default)
#   ./run-conformance.sh --tests    # the full Test-stdlib suite (self-tests + corpus)
#
# NOTE: uses `julia --project=. test/<file>.jl` directly, NOT `Pkg.test()` — Pkg.test tries to
# download the General registry (blocked by --network=none) even for a stdlib-only package
# (A-JULIA-009). The direct-file form is the offline-correct path.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

IMAGE="entity-core-keystone/julia-toolchain:latest"
FIXTURE="/work/protocol-generator/shared/test-vectors/ecf-conformance/conformance-vectors.cbor"

run_one() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT:/work:Z" -w /work/protocol-generator/julia \
    "$IMAGE" julia --project=. "$1" ${2:-}
}

if [ "${1:-}" = "--tests" ]; then
    # TWO ENTRY POINTS, BOTH GATED. `runtests.jl` is the CODEC suite; `spec_0_8_2_25.jl`
    # is the PEER-machinery one (§3.3's ladder, §6.3's path check + listing filter,
    # §5.4's scoped sentinel, §5.5a's typed subset, §4.11's refusal classification and
    # its emission over a real socket). Neither reaches the other's surface, and a suite
    # that is not in the axis entry point is a suite nobody runs.
    run_one test/runtests.jl
    echo "--- peer machinery (0.8.2.20..25) ---"
    run_one test/spec_0_8_2_25.jl
    exit 0
fi

run_one test/conformance.jl "$FIXTURE"
