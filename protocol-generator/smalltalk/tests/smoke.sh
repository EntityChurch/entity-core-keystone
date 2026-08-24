#!/usr/bin/env bash
# entity-core-protocol-smalltalk — S3 two-peer loopback smoke driver (run INSIDE the container).
# Launches a responder (bin/peer.st against the peer image) on an ephemeral port, scrapes its
# `LISTENING <port>` line, then runs the initiator (tests/smoke.st) against it. Loopback
# 127.0.0.1 works under --network=none, so the whole S3 gate stays offline + dependency-sealed
# (no reference peer needed for S3; Pharo owns the sockets + the single-event-loop + crypto
# in-process via UFFI — A-ST native_sockets / in_process_ffi).
set -uo pipefail

ST_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ST_DIR"

CODEC_BUILD="../../ffi-generator/c-abi/entity-core-codec-ffi-c/build"
export LD_LIBRARY_PATH="$(cd "$CODEC_BUILD" && pwd):${LD_LIBRARY_PATH:-}"
PHARO="pharo --headless"
PEERIMG="entity-core.image"

if [ ! -f "$PEERIMG" ]; then
  echo "peer image $PEERIMG missing — run 'make image' first"; exit 1
fi

# ── boot the responder (seed 0x11, ephemeral port), capture LISTENING <port> ──
RESP_LOG="$(mktemp)"
EC_PEER_PORT=0 EC_PEER_SEED=11 $PHARO ./"$PEERIMG" eval "$(cat bin/peer.st)" >"$RESP_LOG" 2>&1 &
RESP_PID=$!
trap 'kill "$RESP_PID" 2>/dev/null; rm -f "$RESP_LOG"' EXIT

PORT=""
for i in $(seq 1 150); do
  PORT="$(grep -oE 'LISTENING [0-9]+' "$RESP_LOG" 2>/dev/null | awk '{print $2}' | head -1)"
  [ -n "$PORT" ] && break
  kill -0 "$RESP_PID" 2>/dev/null || { echo "responder exited early:"; cat "$RESP_LOG"; exit 1; }
  sleep 0.1
done
if [ -z "$PORT" ]; then echo "responder never printed LISTENING:"; cat "$RESP_LOG"; exit 1; fi
echo "responder LISTENING on 127.0.0.1:$PORT"

# ── run the initiator ──
EC_SMOKE_PORT="$PORT" $PHARO ./"$PEERIMG" eval "$(cat tests/smoke.st)"
RC=$?

echo "--- responder log ---"; cat "$RESP_LOG"
exit "$RC"
