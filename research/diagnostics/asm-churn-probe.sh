#!/bin/sh
# A1 probe: reproduce the asm host's connection-pressure failure and MEASURE what
# accumulates (children / fds), rather than theorising from the accept loop source.
set -u
PROJ=/work/protocol-generator/asm-x86_64
CODEC_DIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
NAME=conformance
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

cd "$PROJ"
LD_LIBRARY_PATH="$CODEC_DIR" ./bin/host --port 7777 --name $NAME --debug-open-grants --validate \
  >/tmp/host.out 2>/tmp/host.err &
HP=$!
trap 'kill $HP 2>/dev/null' EXIT
i=0; while [ $i -lt 100 ]; do grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
echo "host pid=$HP $(head -1 /tmp/host.out)"
echo "cycle | children | parent_fds | connect_rc"
n=0
while [ $n -lt 60 ]; do
  n=$((n+1))
  # bare TCP connect + immediate close, the churn shape without protocol traffic
  timeout 3 sh -c 'exec 3<>/dev/tcp/127.0.0.1/7777; exec 3<&-; exec 3>&-' 2>/dev/null
  rc=$?
  kids=$(ls /proc/$HP/task/$HP/children 2>/dev/null | wc -w)
  [ -r /proc/$HP/task/$HP/children ] && kids=$(wc -w < /proc/$HP/task/$HP/children)
  fds=$(ls /proc/$HP/fd 2>/dev/null | wc -l)
  procs=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
  if [ $((n % 5)) -eq 0 ] || [ $rc -ne 0 ]; then
    echo "$n | kids=$kids | parent_fds=$fds | all_procs=$procs | rc=$rc"
  fi
done
echo "--- final host.err (last 10) ---"; tail -10 /tmp/host.err
