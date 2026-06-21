#!/bin/sh
# §10.2 origination-core probe — PHP target (A-role) against the Go entity-peer
# reference (B-role). Both run inside php-toolchain (Go ELFs run there); shared
# loopback, --network=none. Post-§7a resolution (2026-06-13): runOriginationCore is
# the dispatch_outbound_reentry probe — the validator mints a reentry capability,
# EXECUTEs system/validate/dispatch-outbound on the target, and the target originates
# an outbound EXECUTE back to the validator-as-B over the SAME inbound connection
# (§6.11 reentry; NOT a fresh dial to the reference). The reference is connected only
# to keep the gate's input shape (`-reference-peer required`) consistent with
# --profile full; otherwise unused under core. The target MUST run with --validate
# (dispatch-outbound live); absent it, the probe honest-SKIPs.
#
# There is NO compile step — the PHP peer is launched directly via `bin/peer`.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/php-toolchain:latest sh /work/protocol-generator/php/run-origination-core.sh
set -eu
TPORT="${TPORT:-7777}"   # target (PHP)
RPORT="${RPORT:-7778}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
PROJ=/work/protocol-generator/php
cd "$PROJ"

# Reference Go peer (B-role), open-access, on its own port.
"$REFPEER" --addr "127.0.0.1:$RPORT" --open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!
# Target PHP host (A-role) — --validate makes system/validate/dispatch-outbound live.
php "$PROJ/bin/peer" --port "$TPORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" "$REF_PID" 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 200 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "PHP host exited:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
sleep 1   # give the Go reference a moment to bind
echo "target(PHP)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination "$@" || true
echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
