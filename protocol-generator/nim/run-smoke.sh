#!/bin/sh
# S3 smoke gate — entity-core-protocol-nim peer machinery.
#
# Compiles + runs the S3 smoke scenario (src/smoke.nim) inside the nim-toolchain
# container: two Nim peers talk over real loopback TCP through the full machinery
# (asyncdispatch event loop, framing, dispatch, capability handshake). Asserts:
#   - handshake BOTH directions (A dials B, B dials A) — §4.1 legs 1-2,
#   - unknown handler on an AUTHENTICATED conn -> 404 handler_not_found,
#   - unknown handler on an UNAUTHENTICATED conn -> 401 (F31 auth-before-resolve),
#   - request_id demux: 8 concurrent in-flight EXECUTEs correlate (§6.11).
# Exits non-zero on any red leg.
#
# Loopback works under --network=none (the `lo` interface is always present); the
# peer floor is libsodium + hand-rolled/stdlib Nim, no nimble registry deps.
#
# Invoke from the repo root:
#   sh protocol-generator/nim/run-smoke.sh
# (resource caps are mandatory; sourced from tools/podman-caps.sh)

set -eu
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

# shellcheck disable=SC2086
podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
  -w /work/protocol-generator/nim \
  entity-core-keystone/nim-toolchain:latest \
  nim c -r --mm:orc --overflowChecks:on -d:release --hints:off \
    -o:/tmp/smoke_bin src/smoke.nim
