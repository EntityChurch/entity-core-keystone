#!/usr/bin/env bash
# §10.2 origination-core probe — Ada target (A-role) against the Go entity-peer
# reference (B-role). Both run inside ada-toolchain (Go ELFs run there); shared
# loopback, sealed-offline (--network=none).
#
# Post-§7a resolution (2026-06-13): runOriginationCore is the dispatch_outbound_reentry
# probe — the validator mints a reentry capability, EXECUTEs system/validate/dispatch-
# outbound on the target, and the target originates an outbound EXECUTE back to the
# validator-as-B over the SAME inbound connection (§6.11 reentry; NOT a fresh dial to the
# reference). The Go reference is connected only to keep the gate's input shape
# (`-reference-peer required`) consistent with --profile full; otherwise unused under
# core. The target MUST run with --validate (system/validate/dispatch-outbound live);
# absent it the probe honest-SKIPs — which is why the single-peer run-s4.sh honest-SKIPs
# origination.
#
# Ada note: the §6.11 outbound/reentry seam is the per-connection reader's
# Connection_Outbound (transport.adb) — writes the outbound EXECUTE on the same socket
# and demuxes the reply by request_id, while a reentry-only child task keeps the reader
# free. dispatch-outbound is a *generic relay* — it forwards the {value:X} params bytes
# verbatim and returns the downstream result entity verbatim.
#
# Invoke from the repo root:
#   ./protocol-generator/ada/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ada-toolchain:latest"
WORKDIR="/work/protocol-generator/ada"
TPORT="${TPORT:-7778}"   # target (Ada) — Ada's parallel-hazard port
RPORT="${RPORT:-7779}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
NOBUILD="${NOBUILD:-0}"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    TPORT="'"$TPORT"'"; RPORT="'"$RPORT"'"; ORACLE="'"$ORACLE"'"; REFPEER="'"$REFPEER"'"; NOBUILD="'"$NOBUILD"'"
    if [ "$NOBUILD" != "1" ]; then
      gprbuild -P entity_core_protocol.gpr -p >/tmp/build.out 2>&1 || { echo "build failed:"; cat /tmp/build.out; exit 1; }
    fi
    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Ada host (A-role) — --validate makes system/validate/dispatch-outbound live.
    bin/host --port "$TPORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Ada host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give Go reference a moment to bind
    echo "target(Ada)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
