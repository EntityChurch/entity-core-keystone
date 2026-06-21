#!/bin/sh
# §10.2 origination-core probe — TypeScript target (A-role) against the Go
# entity-peer reference (B-role). Both run inside node24 (Go ELFs run there);
# shared loopback. Post-§7a resolution (2026-06-13): runOriginationCore is the
# dispatch_outbound_reentry probe — the validator mints a reentry capability,
# EXECUTEs system/validate/dispatch-outbound on the target, and the target
# originates an outbound EXECUTE back to the validator-as-B over the SAME inbound
# connection (§6.11 reentry; NOT a fresh dial to the reference). The reference is
# connected only to keep the gate's input shape (`-reference-peer required`)
# consistent with --profile full; otherwise unused under core. The target MUST
# run with --validate (dispatch-outbound live); absent it, the probe honest-SKIPs.
set -eu
TPORT="${TPORT:-7777}"   # target (TS)
RPORT="${RPORT:-7778}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
PROJ=/work/protocol-generator/typescript
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  npm ci --offline >/dev/null 2>&1
  npx tsc -p tsconfig.json
fi

# Reference Go peer (B-role), open-access.
"$REFPEER" --addr "127.0.0.1:$RPORT" --open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!
# Target TS host (A-role) — --validate makes system/validate/dispatch-outbound live.
node dist/test/host.js --port "$TPORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" "$REF_PID" 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 200 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "TS host exited:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
sleep 1   # give Go reference a moment to bind
echo "target(TS)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination "$@" || true
echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
