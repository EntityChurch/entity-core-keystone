#!/bin/sh
# S4 host-side launcher for entity-core-protocol-cobol — runs the conformance
# host + validate-peer INSIDE the cobol-toolchain container, WITH resource caps.
#
# The COBOL host is a long-running TCP server that buffers length-prefixed frames;
# a frame-handling bug (e.g. an oversize-frame buffer or a poll spin) must be
# bounded so it is OOM/pids-killed cleanly at the cap instead of taking the host
# down. NEVER run this peer's container without $PODMAN_RUN_CAPS.
#
#   ./run-s4-host.sh [validate-peer-args...]      # default: -profile core
#   VALIDATE=1 ./run-s4-host.sh                   # also exercise --validate handlers
#
set -eu
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

IMAGE="${IMAGE:-localhost/entity-core-keystone/cobol-toolchain:latest}"
CODEC="/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build"

exec podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z \
  -e "LD_LIBRARY_PATH=$CODEC" \
  -e "VALIDATE=${VALIDATE:-0}" -e "NOBUILD=${NOBUILD:-0}" -e "PORT=${PORT:-7777}" \
  "$IMAGE" \
  sh /work/protocol-generator/cobol/run-s4.sh "$@"
