#!/bin/sh
# capture.sh — dump ground-truth wire frames for a validate-peer category against the
# reference entity-peer, via the frame-aware tee-proxy. Throwaway dev aid (not the peer).
# Usage: sh tools/capture.sh <category> <maxframes>
set -e
CAT="${1:-connectivity}"
MAXF="${2:-2}"
CODEC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
ORA=/work/output/s4-oracles
NAME=conformance
KP="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KP"
printf '%s\n%s\n%s\n' '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KP/keypair"

cc -O0 -o /tmp/teeproxy tools/teeproxy.c

"$ORA/entity-peer" -addr 127.0.0.1:7810 -name "$NAME" >/tmp/e.out 2>&1 &
EP=$!
i=0; while [ $i -lt 60 ]; do grep -qi listening /tmp/e.out && break; i=$((i+1)); sleep 0.05; done

/tmp/teeproxy 7811 7810 "$MAXF" 2>/tmp/frames.hex &
TP=$!
sleep 0.2
"$ORA/validate-peer" -addr 127.0.0.1:7811 -category "$CAT" >/tmp/v.out 2>&1 || true
sleep 0.3
kill "$EP" "$TP" 2>/dev/null || true
echo "=== frames.hex ==="
cat /tmp/frames.hex
