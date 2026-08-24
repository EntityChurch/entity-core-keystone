#!/usr/bin/env bash
# entity-core-protocol-rexx — S3 two-peer loopback smoke DRIVER.
#
# Launches two Rexx peer processes (a RESPONDER + an INITIATOR), each driving its own
# ecnet co-process daemon; they talk over REAL 127.0.0.1 loopback TCP (works under
# --network=none, so the whole gate stays sealed-offline). The responder writes its
# ephemeral bound port + peer_id to a file; the initiator dials it and runs the smoke
# scenario, printing PASS/FAIL. Env in: REXX, HELPER (eccrypto), NET (ecnet abs path),
# RESP + INIT (the concatenated combined .rex files, built by the Makefile).
set -uo pipefail

: "${REXX:=rexx}"
tag=$$
BASE_R="/tmp/ecnet-R.$tag"
BASE_I="/tmp/ecnet-I.$tag"
PORTFILE="$(mktemp)"

cleanup() {
  [ -n "${RPID:-}" ] && kill "$RPID" 2>/dev/null
  pkill -f "$NET $BASE_R" 2>/dev/null
  pkill -f "$NET $BASE_I" 2>/dev/null
  rm -f "$PORTFILE" "$BASE_R.cmd" "$BASE_R.evt" "$BASE_I.cmd" "$BASE_I.evt"
}
trap cleanup EXIT

# ── responder (seed 0x11, ephemeral port) ──
timeout 90 "$REXX" "$RESP" 11 0 "$BASE_R" 0 0 "$HELPER" "$NET" "$PORTFILE" &
RPID=$!

# wait for the responder to bind + publish its port
port=""
for _ in $(seq 1 300); do
  port="$(sed -n '1p' "$PORTFILE" 2>/dev/null)"
  [ -n "$port" ] && break
  sleep 0.1
done
peerid="$(sed -n '2p' "$PORTFILE" 2>/dev/null)"
if [ -z "$port" ] || [ "$port" = "-1" ]; then
  echo "SMOKE: responder failed to bind (port='$port')"
  exit 1
fi
echo "responder bound on 127.0.0.1:$port (peer_id ${peerid:0:12}...)"

# ── initiator (seed 0x22) ──
timeout 90 "$REXX" "$INIT" 22 "$port" "$BASE_I" 0 0 "$HELPER" "$NET" "$peerid"
rc=$?
exit $rc
