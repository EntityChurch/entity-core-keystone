#!/bin/sh
# spike-frame.sh — stage-1 transport check for host.wat. Launch the peer, wait for LISTENING,
# send a [4-byte BE len][body] frame, read the framed response, verify the body echoes verbatim.
set -u
MOD="${1:-out/peer.wasm}"
PORT=7777
OUT=/tmp/peer.out
: > "$OUT"

wasmedge "$MOD" >"$OUT" 2>&1 &
SRV=$!
trap 'kill "$SRV" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 100 ]; do
  grep -q '^LISTENING' "$OUT" 2>/dev/null && break
  kill -0 "$SRV" 2>/dev/null || { echo "FAIL: peer exited before LISTENING:"; cat "$OUT"; exit 1; }
  i=$((i + 1)); sleep 0.1
done
grep -q '^LISTENING' "$OUT" || { echo "FAIL: no LISTENING"; cat "$OUT"; exit 1; }
echo "readiness: $(grep '^LISTENING' "$OUT")"

# body = 21 bytes; length prefix 00 00 00 15. Send, then read 4-byte len + body back.
GOT=$(bash -c '
  exec 3<>/dev/tcp/127.0.0.1/'"$PORT"'
  printf "\x00\x00\x00\x15wasm-wat-frame-spike!" >&3
  # read + discard the 4-byte length, then read the 21-byte body
  head -c 4 <&3 >/dev/null
  head -c 21 <&3
  exec 3<&-
')
if [ "$GOT" = "wasm-wat-frame-spike!" ]; then
  echo "framed round-trip: PASS  (len-prefixed frame echoed verbatim)"
  echo "STAGE-1 PASS — sockets + §1.6 framing + accept loop live on the WAT peer."
else
  echo "FAIL: frame mismatch"
  echo "  got: [$GOT]"
  exit 1
fi
