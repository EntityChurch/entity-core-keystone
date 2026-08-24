#!/usr/bin/env bash
# entity-core-protocol-fortran — S3 two-peer loopback smoke DRIVER.
#
# Launches two compiled Fortran peer processes (a RESPONDER = bin/peer + an INITIATOR =
# test/s3_initiator), each linking the C net-shim + libentitycore_codec directly (no
# co-process — Fortran's first-class C interop, unlike the Rexx daemon-over-FIFOs). They
# talk over REAL 127.0.0.1 loopback TCP (works under --network=none, so the whole gate
# stays sealed-offline). The responder writes its ephemeral bound port + peer_id to a
# file; the initiator dials it and runs the smoke scenario, printing PASS/FAIL.
# Env in: CODEC_BUILD (lib dir), PEER (bin/peer), INIT (s3_initiator).
set -uo pipefail

: "${PEER:=build/peer}"
: "${INIT:=build/s3_initiator}"
: "${CODEC_BUILD:=../../ffi-generator/c-abi/entity-core-codec-ffi-c/build}"
export LD_LIBRARY_PATH="$CODEC_BUILD"

PORTFILE="$(mktemp)"
RPID=""
cleanup() { [ -n "$RPID" ] && kill "$RPID" 2>/dev/null; rm -f "$PORTFILE"; }
trap cleanup EXIT

# ── responder (seed 0x11, ephemeral port) ──
timeout 60 "$PEER" --port 0 --seed 11 --port-file "$PORTFILE" >/dev/null 2>&1 &
RPID=$!

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
timeout 60 "$INIT" --port "$port" --seed 22 --peerid "$peerid"
rc=$?
exit $rc
