#!/bin/sh
# A1 probe 2: run ONLY the concurrency category against the asm host while sampling
# the host process's children / fds / RSS, to see what (if anything) accumulates before
# t2_2_connection_churn hangs at cycle 29.
set -u
PROJ=/work/protocol-generator/asm-x86_64
CODEC_DIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
ORACLE=/work/output/s4-oracles/validate-peer
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
i=0; while [ $i -lt 100 ]; do grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
echo "host pid=$HP"

# sampler
( n=0
  while [ $n -lt 200 ]; do
    n=$((n+1))
    kill -0 $HP 2>/dev/null || { echo "SAMPLER: host pid $HP GONE at t=${n}s"; break; }
    kids=$(wc -w < /proc/$HP/task/$HP/children 2>/dev/null || echo -1)
    fds=$(ls /proc/$HP/fd 2>/dev/null | wc -l)
    procs=$(ls -d /proc/[0-9]* 2>/dev/null | wc -l)
    rss=$(awk '/VmRSS/{print $2}' /proc/$HP/status 2>/dev/null)
    echo "t=${n}s kids=$kids parent_fds=$fds all_procs=$procs rss_kb=$rss"
    sleep 1
  done ) > /tmp/sample.log 2>&1 &
SP=$!

echo "=== running -category concurrency -timeout 150s ==="
"$ORACLE" -addr 127.0.0.1:7777 -profile core -category concurrency -timeout 150s \
  -json-out /work/output/scratch/asm-hidden/asm-x86_64/concurrency-alone.json 2>&1 | grep -E '^\s+(t1|t2)_|Result:' | head -20
kill $SP 2>/dev/null
kill $HP 2>/dev/null
echo "=== sampler (every 10th line, then the last 5) ==="
awk 'NR%10==1' /tmp/sample.log
echo "..."
tail -5 /tmp/sample.log
