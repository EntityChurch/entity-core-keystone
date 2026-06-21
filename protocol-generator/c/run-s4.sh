#!/usr/bin/env bash
# S4 conformance harness — entity-core-protocol-c (peer #10 / C / C11 / POSIX).
#
# Runs entirely inside the c-toolchain container (the Go validate-peer oracle is a
# fedora:43 static ELF that runs there too, so oracle + peer share one loopback; stays
# sealed-offline with --network=none). Builds the hardened peer host (entity-peer-c, fully
# offline — gcc + libsodium baked into the image), launches it with --debug-open-grants
# (grant-gated categories need the degenerate default→* seed) + --validate (§7a
# system/validate/* + dispatch-outbound reentry handlers live), waits for its LISTENING
# readiness line, points validate-peer at it on port 7777, tears the host down.
#
# Invoke from the repo root:
#   ./protocol-generator/c/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the V7 v7.72/v7.75 §9.0 core-profile gate) + JSON out.
# Env overrides: ORACLE, PORT, NOBUILD (1=skip make), VALIDATE (1=on, 0=exercise SKIP path).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/c-toolchain:latest"
WORKDIR="/work/protocol-generator/c"
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
VALIDATE="${VALIDATE:-1}"
NOBUILD="${NOBUILD:-0}"
JSON_OUT="$WORKDIR/status/CONFORMANCE-REPORT.json"

VALIDATE_FLAG=""
[ "$VALIDATE" = "1" ] && VALIDATE_FLAG="--validate"

# Oracle args (default = the core-profile gate). Pass-through if caller supplies any.
if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$JSON_OUT"
fi

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    PORT="'"$PORT"'"; ORACLE="'"$ORACLE"'"; VFLAG="'"$VALIDATE_FLAG"'"; NOBUILD="'"$NOBUILD"'"
    # 1. Build the hardened peer host (offline).
    if [ "$NOBUILD" != "1" ]; then
      make entity-peer-c >/tmp/build.out 2>&1 || { echo "build failed:"; cat /tmp/build.out; exit 1; }
    fi
    # 2. Boot the host (peer). It prints "LISTENING <port>" then parks on the accept loop.
    # shellcheck disable=SC2086
    ./entity-peer-c --port "$PORT" --debug-open-grants $VFLAG \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID 2>/dev/null || true" EXIT INT TERM
    # 3. Wait for the LISTENING readiness line.
    i=0
    while [ "$i" -lt 300 ]; do
      if grep -q "^LISTENING" /tmp/host.out 2>/dev/null; then break; fi
      if ! kill -0 "$HOST_PID" 2>/dev/null; then echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
      i=$((i + 1)); sleep 0.1
    done
    head -2 /tmp/host.out
    # 4. Point the oracle at it — the profile IS the gate.
    "$ORACLE" -addr "127.0.0.1:$PORT" '"$*"' || true
  '
