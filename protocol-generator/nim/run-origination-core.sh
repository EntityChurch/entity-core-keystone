#!/bin/sh
# §10.2 origination-core probe — Nim target (A-role) against the Go entity-peer
# reference (B-role). Both run inside the nim-toolchain container (Go ELFs run
# there); shared loopback, sealed-offline with --network=none. Post-§7a resolution:
# runOriginationCore is the dispatch_outbound_reentry probe — the validator mints a
# reentry capability, EXECUTEs system/validate/dispatch-outbound on the target, and
# the target originates an outbound EXECUTE back to the validator-as-B over the SAME
# inbound connection (§6.11 reentry; NOT a fresh dial to the reference). The
# reference is connected only to keep the gate's input shape (-reference-peer
# required) consistent with --profile full. The target MUST run with --validate
# (dispatch-outbound live); absent it, the probe honest-SKIPs.
#
# Nim note: the §6.11 reentry seam is the transport.nim reader-demux (io.pending
# request_id → Future) + the OutboundSender closure the transport supplies to the
# dispatch chain (peer.nim validateDispatchOutbound). This gate is the cross-impl
# wire proof of that seam from the asyncdispatch single-event-loop idiom.
#
# Invoke from the repo root:
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/nim-toolchain:latest sh /work/protocol-generator/nim/run-origination-core.sh
set -eu
TPORT="${TPORT:-7788}"   # target (Nim)
RPORT="${RPORT:-7789}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
PROJ=/work/protocol-generator/nim
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  nim c --mm:orc --overflowChecks:on -d:release --hints:off \
    -o:/tmp/host src/host.nim >/tmp/nim-build.log 2>&1 \
    || { cat /tmp/nim-build.log; exit 1; }
fi

# Reference Go peer (B-role), open-access.
"$REFPEER" --addr "127.0.0.1:$RPORT" --open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!
# Target Nim host (A-role) — --validate makes system/validate/dispatch-outbound live.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

/tmp/host --port "$TPORT" --name "$NAME" --debug-open-grants --validate \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" "$REF_PID" 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 200 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Nim host exited:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
sleep 1   # give the Go reference a moment to bind
echo "target(Nim)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination "$@" || true
echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
