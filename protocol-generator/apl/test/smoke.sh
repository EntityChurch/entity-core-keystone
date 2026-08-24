#!/usr/bin/env bash
# entity-core-protocol-apl — S3 two-peer loopback smoke DRIVER.
#
# Launches two GNU APL peer processes (RESPONDER = bin/peer.apl + INITIATOR =
# test/s3_initiator.apl), each loading the full peer workspace (native ⎕FIO sockets — NO C
# net-shim, A-APL-006). They talk over REAL 127.0.0.1 loopback TCP (works under
# --network=none, so the whole gate stays sealed-offline). The responder writes its
# ephemeral bound port + peer_id to a file; the initiator dials it and runs the smoke
# scenario, printing PASS/FAIL. apl output is REDIRECTED to files, never piped (GNU APL
# hangs after )OFF on a pipe — A-APL-013).
set -uo pipefail

: "${APL:=apl}"
MODS="src/status.apl src/varint.apl src/cbor.apl src/ffi.apl src/entity.apl src/val.apl \
src/ent.apl src/identity.apl src/keystore.apl src/store.apl src/wire.apl src/capability.apl \
src/net.apl src/transport.apl src/coretypes.apl src/peer.apl"
LOAD=""; for m in $MODS; do LOAD="$LOAD -f $m"; done

PORTFILE="$(mktemp)"
RESPOUT="$(mktemp)"
INITOUT="$(mktemp)"
RPID=""
cleanup() { [ -n "$RPID" ] && kill "$RPID" 2>/dev/null; rm -f "$PORTFILE" "$RESPOUT" "$INITOUT"; }
trap cleanup EXIT

# ── responder (seed 0x11, ephemeral port) ──
$APL --script $LOAD -f bin/peer.apl -- --port 0 --seed 11 --port-file "$PORTFILE" </dev/null >"$RESPOUT" 2>&1 &
RPID=$!

port=""
for _ in $(seq 1 400); do
  port="$(sed -n '1p' "$PORTFILE" 2>/dev/null)"
  [ -n "$port" ] && break
  # if the responder died, bail early
  kill -0 "$RPID" 2>/dev/null || break
  sleep 0.1
done
peerid="$(sed -n '2p' "$PORTFILE" 2>/dev/null)"
if [ -z "$port" ] || [ "$port" = "-1" ]; then
  echo "SMOKE: responder failed to bind (port='$port')"
  echo "--- responder log ---"; cat "$RESPOUT"
  exit 1
fi
echo "responder bound on 127.0.0.1:$port (peer_id ${peerid:0:12}...)"

# ── initiator (seed 0x22) — output to a FILE, then grep (never a pipe) ──
$APL --script $LOAD -f test/s3_initiator.apl -- --port "$port" --seed 22 --peerid "$peerid" </dev/null >"$INITOUT" 2>&1
cat "$INITOUT"
grep -q 'SMOKE: PASS' "$INITOUT"
