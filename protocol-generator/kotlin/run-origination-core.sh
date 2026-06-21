#!/usr/bin/env bash
# §10.2 origination-core probe — Kotlin target (A-role) against the Go entity-peer
# reference (B-role). Both run inside kotlin-toolchain (Go ELFs run there); shared
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
# Kotlin note: the §6.11 outbound/reentry seam is kotlinx.coroutines — the Transport reader
# coroutine demuxes EXECUTE_RESPONSE by request_id via ConcurrentHashMap<requestId,
# CompletableDeferred>, dispatch runs per-EXECUTE coroutines, the outbound primitive is
# Peer.outboundDispatch over the inbound Conn. dispatch-outbound is a *generic relay* — it
# forwards the {value:X} params bytes verbatim and returns the downstream result entity
# verbatim. This gate is the cross-impl wire proof of that seam (A-KT-012 inner-200 scope).
#
# Invoke from the repo root:
#   ./protocol-generator/kotlin/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/kotlin-toolchain:latest"
WORKDIR="/work/protocol-generator/kotlin"
TPORT="${TPORT:-7777}"   # target (Kotlin)
RPORT="${RPORT:-7778}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
NOBUILD="${NOBUILD:-0}"
LAUNCHER="build/install/entity-core-protocol-kotlin/bin/entity-core-protocol-kotlin"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    TPORT="'"$TPORT"'"; RPORT="'"$RPORT"'"; ORACLE="'"$ORACLE"'"; REFPEER="'"$REFPEER"'"; NOBUILD="'"$NOBUILD"'"
    LAUNCHER="'"$LAUNCHER"'"
    if [ "$NOBUILD" != "1" ]; then
      gradle --offline --no-daemon -q installDist >/tmp/build.out 2>&1 || { echo "build failed:"; cat /tmp/build.out; exit 1; }
    fi
    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Kotlin host (A-role) — --validate makes system/validate/dispatch-outbound live.
    "$LAUNCHER" --port "$TPORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 600 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Kotlin host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give Go reference a moment to bind
    echo "target(Kotlin)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
