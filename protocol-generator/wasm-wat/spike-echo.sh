#!/bin/sh
# spike-echo.sh — drive the increment-1 echo spike inside the wasm-wat toolchain container.
# Launches build/echo.wasm under WasmEdge, waits for its LISTENING line, then does a
# loopback echo round-trip via bash /dev/tcp and checks the bytes come back verbatim.
set -eu
PORT=7777
OUT=/tmp/echo.out
: > "$OUT"

wasmedge out/echo.wasm >"$OUT" 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM

# wait for readiness (or early exit)
i=0
while [ "$i" -lt 100 ]; do
  if grep -q '^LISTENING' "$OUT" 2>/dev/null; then break; fi
  if ! kill -0 "$SRV" 2>/dev/null; then
    echo "FAIL: server exited before LISTENING (proc_exit code = errno marker):"
    cat "$OUT"
    exit 1
  fi
  i=$((i + 1)); sleep 0.1
done
if ! grep -q '^LISTENING' "$OUT"; then echo "FAIL: no LISTENING after 10s"; cat "$OUT"; exit 1; fi
echo "readiness: LISTENING ok"

# echo round-trip via bash /dev/tcp
MSG="entity-core-wasm-wat-spike-0123456789"
GOT=$(bash -c '
  exec 3<>/dev/tcp/127.0.0.1/'"$PORT"'
  printf "%s" "'"$MSG"'" >&3
  head -c '"${#MSG}"' <&3
  exec 3<&-
')
if [ "$GOT" = "$MSG" ]; then
  echo "echo round-trip: PASS  (sent=${#MSG}B, recv=${#GOT}B, verbatim)"
  echo "SPIKE PASS — WASIX sockets drive from hand-authored WAT under WasmEdge."
else
  echo "FAIL: echo mismatch"
  echo "  sent: $MSG"
  echo "  got : $GOT"
  exit 1
fi
