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
#   VALIDATE=0 ./run-s4-host.sh                   # reproduce the pre-2026-08-30 measurement
#
# EVERY default here must match run-s4.sh's own default, because this launcher
# forwards them as explicit -e assignments and an explicit value always wins over
# the callee's `${VAR:-default}`. This line read `VALIDATE=${VALIDATE:-0}` against
# run-s4.sh's `${VALIDATE:-1}` from the day --validate became the default, so the
# capped, documented, human-facing entry point for this peer measured
# `312P/337W/0F/109S` and printed `Result: FAIL (un-allowlisted skips)` while the
# census — which invokes run-s4.sh directly and never sets the variable — measured
# the committed `315P/337W/0F/106S`. The three are t1_2_concurrent_reentry,
# validate_echo_dispatch and origination/dispatch_outbound_reentry, all of which
# SKIP with "target peer not run with --validate". Nothing was wrong with the peer
# and nothing was wrong with the census; the two entry points disagreed, and only
# the one nobody automated was wrong. Forwarding a variable is not neutral.
set -eu
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

IMAGE="${IMAGE:-localhost/entity-core-keystone/cobol-toolchain:latest}"
CODEC="/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build"

exec podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z \
  -e "LD_LIBRARY_PATH=$CODEC" \
  -e "VALIDATE=${VALIDATE:-1}" -e "NOBUILD=${NOBUILD:-0}" -e "PORT=${PORT:-7777}" \
  "$IMAGE" \
  sh /work/protocol-generator/cobol/run-s4.sh "$@"
