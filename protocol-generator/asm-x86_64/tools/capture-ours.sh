#!/bin/sh
# capture-ours.sh — throwaway: run OUR asm host behind teeproxy, point validate-peer at the
# proxy for a category, dumping frames. Mirror of capture-ref.sh but the upstream is our peer.
set -eu
CAT="${1:-format_agility}"
PROJ=/work/protocol-generator/asm-x86_64
ORACLE=/work/output/s4-oracles/validate-peer
CODEC_DIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
OURPORT=8811
PROXYPORT=8810
DUMP="$PROJ/output/scratch/ourdump-$CAT"
rm -rf "$DUMP"; mkdir -p "$DUMP"
cd "$PROJ"
[ "${NOBUILD:-0}" = "1" ] || make host >/dev/null

NAME=ourcap
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

cc -O0 -o /tmp/teeproxy "$PROJ/tools/teeproxy.c"
LD_LIBRARY_PATH="$CODEC_DIR" ./bin/host --port "$OURPORT" --name "$NAME" --validate \
  >/tmp/our.out 2>/tmp/our.err &
OURPID=$!
i=0
while [ "$i" -lt 100 ]; do
  grep -q '^LISTENING' /tmp/our.out 2>/dev/null && break
  kill -0 "$OURPID" 2>/dev/null || { echo "host exited:"; cat /tmp/our.err; exit 1; }
  i=$((i+1)); sleep 0.1
done
DUMPDIR="$DUMP" /tmp/teeproxy "$PROXYPORT" "$OURPORT" >/tmp/tee.out 2>/tmp/tee.err &
TEEPID=$!
trap 'kill "$OURPID" "$TEEPID" 2>/dev/null || true' EXIT INT TERM
sleep 0.3
if [ "$CAT" = "FULL" ]; then
  "$ORACLE" -addr "127.0.0.1:$PROXYPORT" -profile core 2>&1 | grep -iE "FAIL authz|^Summary" || true
else
  "$ORACLE" -addr "127.0.0.1:$PROXYPORT" -profile core -category "$CAT" 2>&1 | grep -iE "FAIL|PASS" | grep -v "count as" || true
fi
sleep 0.3
echo "=== dumps in $DUMP ==="
ls "$DUMP"
