#!/usr/bin/env bash
# §10.2 origination-core probe — Pd target (A-role) against the Go entity-peer reference
# (B-role). Both run inside puredata-toolchain (the Go ELFs are CGO_ENABLED=0 static);
# shared loopback, sealed-offline (--network=none).
#
# runOriginationCore is the dispatch_outbound_reentry probe — the validator mints a reentry
# capability, EXECUTEs system/validate/dispatch-outbound on the target, and the target
# originates an outbound EXECUTE back to the validator-as-B over the SAME inbound connection
# (§6.11 reentry; NOT a fresh dial to the reference). The Go reference is connected only to
# keep the gate's input shape (`-reference-peer required`) consistent with --profile full.
# The target MUST run with the §7a scaffold live (EC_VALIDATE=1); absent it the probe
# honest-SKIPs — which is why the single-peer run-s4.sh honest-SKIPs origination.
#
# Pd note: the §6.11 outbound/reentry seam is [ecodec]'s outbound_serve — a bounded
# synchronous send+wait on the ONE inbound fd (single-threaded substrate; frames that are
# not the correlated response are handed back to the connection's assembler). dispatch-
# outbound is a *generic relay*: it forwards the {value:X} params bytes verbatim and
# returns the downstream result entity verbatim (RULINGS-CONCURRENCY-GATE-7b-MATRIX #2).
#
# Invoke from anywhere:
#   ./protocol-generator/pd/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/puredata-toolchain:latest"
WORKDIR="/work/protocol-generator/pd"
PATCH="${PATCH:-src/main.pd}"
TPORT="${TPORT:-15104}"   # target (Pd) — the patch's net_listen port
RPORT="${RPORT:-15105}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e PATCH="$PATCH" -e TPORT="$TPORT" -e RPORT="$RPORT" \
  -e ORACLE="$ORACLE" -e REFPEER="$REFPEER" \
  -e EC_OPEN_GRANTS=1 -e EC_VALIDATE=1 \
  -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -eu
    [ -x "$ORACLE" ] || { echo "oracle not found at $ORACLE — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    [ -x "$REFPEER" ] || { echo "entity-peer reference not found at $REFPEER — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    make external >/dev/null 2>&1
    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Pd peer (A-role) — EC_VALIDATE makes system/validate/dispatch-outbound live.
    pd -nogui -noaudio -stderr -path build -open "$PATCH" >build/orig-pd.log 2>&1 &
    PD_PID=$!
    trap "kill $PD_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "listening on TCP" build/orig-pd.log 2>/dev/null && break
      kill -0 "$PD_PID" 2>/dev/null || { echo "pd exited:"; cat build/orig-pd.log; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give the Go reference a moment to bind
    echo "target(Pd) on :$TPORT  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
