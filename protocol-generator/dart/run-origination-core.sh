#!/bin/sh
# §10.2 origination-core probe — Dart target (A-role) against the Go entity-peer
# reference (B-role). Both run inside dart-toolchain (Go ELFs run there); shared
# loopback, --network=none. Post-§7a resolution: runOriginationCore is the
# dispatch_outbound_reentry probe — the validator mints a reentry capability,
# EXECUTEs system/validate/dispatch-outbound on the target, and the target originates
# an outbound EXECUTE back to the validator-as-B over the SAME inbound connection
# (§6.11 reentry; NOT a fresh dial to the reference). The reference is connected only
# to keep the gate's input shape (`-reference-peer required`) consistent with
# --profile full; otherwise unused under core. The target MUST run with --validate
# (dispatch-outbound live); absent it, the probe honest-SKIPs.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/dart-toolchain:latest sh /work/protocol-generator/dart/run-origination-core.sh
set -eu
TPORT="${TPORT:-7787}"   # target (Dart)
RPORT="${RPORT:-7788}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
PROJ=/work/protocol-generator/dart
BUILD="${BUILD:-build-s4}"
PEER="$BUILD/peer"
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  dart pub get --offline >/tmp/build.out 2>&1 || { echo "pub get failed:"; cat /tmp/build.out; exit 1; }
  mkdir -p "$BUILD"
  dart compile exe bin/peer.dart -o "$PEER" >>/tmp/build.out 2>&1 || { echo "compile failed:"; cat /tmp/build.out; exit 1; }
fi

# Reference Go peer (B-role), open-access, on its own port.
"$REFPEER" --addr "127.0.0.1:$RPORT" --open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!
# Target Dart host (A-role) — --validate makes system/validate/dispatch-outbound live.
"$PEER" --port "$TPORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" "$REF_PID" 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 300 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Dart host exited:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
sleep 1   # give the Go reference a moment to bind
echo "target(Dart)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination "$@" || true
echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
