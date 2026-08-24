#!/bin/sh
# S2 wire-conformance gate — entity-core-protocol-nim.
#
# Compiles the hand-rolled Nim codec + the conformance harness inside the
# nim-toolchain container (sealed offline, --network=none — the core floor is
# libsodium + hand-rolled Nim only, no nimble registry deps) and runs every
# v0.8.0 corpus vector through it, checking byte-identity. Reports the N/71 tally
# and the mandatory [2^63, 2^64-1] fixed-width head-form self-test (A-NIM-002).
# Exits non-zero on any FAIL.
#
# Invoke from the repo root:
#   sh protocol-generator/nim/run-wire-conformance.sh
# (resource caps are mandatory; sourced from tools/podman-caps.sh)

set -eu
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

CORPUS=/work/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor

# shellcheck disable=SC2086
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
  -w /work/protocol-generator/nim \
  entity-core-keystone/nim-toolchain:latest \
  nim c -r --mm:orc --overflowChecks:on -d:release --hints:off \
    -o:/tmp/tconformance tests/tconformance.nim "$CORPUS"
