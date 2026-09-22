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

if [ "${1:-}" = "--tests" ]; then
    ENTRY="test/runtests.jl"; ARG=""
else
    ENTRY="test/conformance.jl"; ARG="$FIXTURE"
fi

exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT:/work:Z" -w /work/protocol-generator/julia \
    "$IMAGE" julia --project=. "$ENTRY" $ARG
