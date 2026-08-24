#!/bin/sh
# A1 probe 3: during t2_2, dump WHERE the persistently-stuck children are blocked
# (/proc/<pid>/syscall + wchan + their socket fds), to pin the hang to a syscall
# rather than inferring it from the accept-loop source.
set -u
PROJ=/work/protocol-generator/asm-x86_64
CODEC_DIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
ORACLE=/work/output/s4-oracles/validate-peer
NAME=conformance
KPDIR="${HOME:-/root}/.entity/peers/$NAME"; mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"
cd "$PROJ"
LD_LIBRARY_PATH="$CODEC_DIR" ./bin/host --port 7777 --name $NAME --debug-open-grants --validate \
  >/tmp/host.out 2>/tmp/host.err &
HP=$!
i=0; while [ $i -lt 100 ]; do grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
echo "host pid=$HP"
"$ORACLE" -addr 127.0.0.1:7777 -profile core -category concurrency -timeout 60s >/tmp/oracle.out 2>&1 &
OP=$!
sleep 25
echo "=== stuck children of $HP at t=25s ==="
for k in $(cat /proc/$HP/task/$HP/children 2>/dev/null); do
  echo "--- child $k ---"
  echo "  wchan   : $(cat /proc/$k/wchan 2>/dev/null)"
  echo "  syscall : $(cat /proc/$k/syscall 2>/dev/null)"
  echo "  state   : $(awk '/^State:/{print $2,$3}' /proc/$k/status 2>/dev/null)"
  echo "  age_s   : $(( $(awk '{print int($22/100)}' /dev/null 2>/dev/null || echo 0) ))"
  echo "  fds     : $(ls -l /proc/$k/fd 2>/dev/null | awk '{print $9"->"$11}' | tr '\n' ' ')"
done
sleep 8
echo "=== same children 8s later (still stuck?) ==="
for k in $(cat /proc/$HP/task/$HP/children 2>/dev/null); do
  echo "  child $k syscall=$(cat /proc/$k/syscall 2>/dev/null) wchan=$(cat /proc/$k/wchan 2>/dev/null)"
done
wait $OP 2>/dev/null
grep -E 't2_2|Result:' /tmp/oracle.out | head -5
kill $HP 2>/dev/null
