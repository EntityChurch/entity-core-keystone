#!/usr/bin/env bash
# S4 conformance harness — entity-core-protocol-ada (peer #10 / 10th byte-compat impl).
#
# Runs entirely inside the ada-toolchain container (the Go validate-peer oracle is a
# fedora:43 static ELF that runs there too, so oracle + peer share one loopback; stays
# sealed-offline with --network=none). Builds the Ada peer (gprbuild, fully offline —
# GNAT + libsodium are baked into the image), launches the standalone Host with
# --debug-open-grants (grant-gated categories need the degenerate seed) + --validate
# (§7a system/validate/* conformance handlers live), waits for its LISTENING readiness
# line, points validate-peer at it, tears the host down.
#
# The Go oracle (validate-peer) is VENDORED READ-ONLY from the STAMPED v7.75 cohort
# baseline entity-core-go @ 62044c5 into output/s4-oracles/ (see CONFORMANCE-REPORT.md).
#
# Invoke from the repo root:
#   ./protocol-generator/ada/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the V7 v7.75 §9.0 core-profile gate) + JSON out.
# Env overrides: ORACLE, PORT (default 7778 — Ada's parallel-hazard port; C uses 7777),
#   NOBUILD (1=skip gprbuild), VALIDATE (1=on, 0=exercise SKIP path).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ada-toolchain:latest"
WORKDIR="/work/protocol-generator/ada"
PORT="${PORT:-7778}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
VALIDATE="${VALIDATE:-1}"
NOBUILD="${NOBUILD:-0}"
JSON_OUT="/work/protocol-generator/ada/status/CONFORMANCE-REPORT.json"

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
    # 1. Build the Ada peer (offline). The standalone Host main is bin/host.
    if [ "$NOBUILD" != "1" ]; then
      gprbuild -P entity_core_protocol.gpr -p >/tmp/build.out 2>&1 || { echo "build failed:"; cat /tmp/build.out; exit 1; }
    fi
    # 2. Boot the Host (peer). It prints "LISTENING <port>" then parks on the accept loop.
    # shellcheck disable=SC2086
    bin/host --port "$PORT" --debug-open-grants $VFLAG \
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
