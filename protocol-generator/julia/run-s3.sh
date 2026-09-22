#!/usr/bin/env bash
# S3 smoke gate for entity-core-protocol-julia. Two Julia peers handshake over real loopback TCP,
# exercise §6.5 auth-before-resolve (401 vs 404) and §6.11 request_id demux, on the single-threaded
# Task scheduler — inside the capped, offline julia-toolchain container. Exit 0 iff all legs PASS.
#
#   ./run-s3.sh
#
# Uses `julia --project=. src/smoke.jl` directly (A-JULIA-009: Pkg.test() would git-clone the
# General registry, blocked by --network=none, even for a stdlib-only package). Loopback works
# under --network=none (podman brings up `lo` in the container netns).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

IMAGE="entity-core-keystone/julia-toolchain:latest"

exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT:/work:Z" -w /work/protocol-generator/julia \
    "$IMAGE" julia --project=. src/smoke.jl
