#!/usr/bin/env bash
# entity-core-protocol-forth — S3 two-peer loopback smoke driver (run INSIDE the container).
# Launches a responder (bin/peer.fs) on an ephemeral port, scrapes its `LISTENING <port>`
# line, then runs the initiator (test/smoke.fs) against it. Loopback 127.0.0.1 works under
# --network=none, so the whole S3 gate stays offline + dependency-sealed.
set -uo pipefail

FORTH_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$FORTH_DIR"

CODEC_BUILD="../../ffi-generator/c-abi/entity-core-codec-ffi-c/build"
export LIBRARY_PATH="$CODEC_BUILD"
export LD_LIBRARY_PATH="$CODEC_BUILD"
export C_INCLUDE_PATH="../../ffi-generator/c-abi/spec"
export CPATH="../../ffi-generator/c-abi/spec"
# A-FT-005: clear the libcc wrapper cache so a stale .so never binds old symbols.
rm -rf "$HOME/.gforth/libcc-named" "$HOME/.gforth/libcc-tmp" 2>/dev/null || true

GFORTH="gforth -e \"warnings off\""

# ── boot the responder, capture LISTENING <port> ──
RESP_LOG="$(mktemp)"
gforth -e "warnings off" bin/peer.fs --port 0 --seed 11 >"$RESP_LOG" 2>&1 &
RESP_PID=$!
trap 'kill "$RESP_PID" 2>/dev/null; rm -f "$RESP_LOG"' EXIT

# wait for the LISTENING line (up to ~10s)
PORT=""
for i in $(seq 1 100); do
  PORT="$(grep -oE '^LISTENING [0-9]+' "$RESP_LOG" 2>/dev/null | awk '{print $2}' | head -1)"
  [ -n "$PORT" ] && break
  # responder died?
  kill -0 "$RESP_PID" 2>/dev/null || { echo "responder exited early:"; cat "$RESP_LOG"; exit 1; }
  sleep 0.1
done
if [ -z "$PORT" ]; then echo "responder never printed LISTENING:"; cat "$RESP_LOG"; exit 1; fi
echo "responder LISTENING on 127.0.0.1:$PORT"

# ── run the initiator ──
gforth -e "warnings off" test/smoke.fs "$PORT"
RC=$?

echo "--- responder log ---"; cat "$RESP_LOG"
exit "$RC"
