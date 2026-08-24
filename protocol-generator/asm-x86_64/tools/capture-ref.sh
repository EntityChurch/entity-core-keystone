#!/bin/sh
# capture-ref.sh — throwaway: run the reference entity-peer behind teeproxy and point
# validate-peer at the proxy for a chosen category, dumping every frame to DUMPDIR.
# Usage (inside the toolchain container, from repo root mounted at /work):
#   sh /work/protocol-generator/asm-x86_64/tools/capture-ref.sh <category>
set -eu
CAT="${1:-authz}"
PROJ=/work/protocol-generator/asm-x86_64
ORACLE=/work/output/s4-oracles/validate-peer
REFPEER=/work/output/s4-oracles/entity-peer
CODEC_DIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
REFPORT=8801
PROXYPORT=8800
DUMP="$PROJ/output/scratch/capdump-$CAT"
rm -rf "$DUMP"; mkdir -p "$DUMP"

NAME=refcap
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

cc -O0 -o /tmp/teeproxy "$PROJ/tools/teeproxy.c"

rm -f /tmp/ref.ready
LD_LIBRARY_PATH="$CODEC_DIR" "$REFPEER" -addr "127.0.0.1:$REFPORT" -name "$NAME" -validate \
  -ready-file /tmp/ref.ready >/tmp/ref.out 2>/tmp/ref.err &
REFPID=$!
i=0
while [ "$i" -lt 100 ]; do
  if [ -f /tmp/ref.ready ]; then break; fi
  if ! kill -0 "$REFPID" 2>/dev/null; then echo "ref exited:"; cat /tmp/ref.err; exit 1; fi
  i=$((i+1)); sleep 0.1
done
echo "ref ready: $(cat /tmp/ref.ready)"
DUMPDIR="$DUMP" /tmp/teeproxy "$PROXYPORT" "$REFPORT" >/tmp/tee.out 2>/tmp/tee.err &
TEEPID=$!
trap 'kill "$REFPID" "$TEEPID" 2>/dev/null || true' EXIT INT TERM
sleep 0.5

"$ORACLE" -addr "127.0.0.1:$PROXYPORT" -profile core -category "$CAT" || true
sleep 0.3
echo "=== dump files ==="
ls -la "$DUMP"
