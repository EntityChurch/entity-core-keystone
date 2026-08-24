#!/usr/bin/env bash
# §10.2 origination-core probe — Io target (A-role) against the Go entity-peer
# reference (B-role). Both run inside io-toolchain (the Go ELFs are
# CGO_ENABLED=0 static); shared loopback, sealed-offline (--network=none).
#
# runOriginationCore is the dispatch_outbound_reentry probe: the validator mints
# a reentry capability, EXECUTEs system/validate/dispatch-outbound on the target,
# and the target originates an outbound EXECUTE back to the validator-as-B over
# the SAME inbound connection (§6.11 reentry). The Go reference keeps the gate's
# `-reference-peer required` input shape consistent with --profile full. The
# target MUST run with the §7a scaffold live (--validate); absent it the probe
# honest-SKIPs (which is why the single-peer run-s4 honest-SKIPs origination).
#
#   ./run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/io-toolchain:latest"
WORKDIR="/work/protocol-generator/io"
TPORT="${TPORT:-48620}"   # target (Io)
RPORT="${RPORT:-48621}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
EC_NAME="${EC_NAME:-conformance}"

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e TPORT="$TPORT" -e RPORT="$RPORT" -e ORACLE="$ORACLE" -e REFPEER="$REFPEER" -e EC_NAME="$EC_NAME" \
  -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -e
    [ -x "$ORACLE" ] || { echo "oracle not found — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    [ -x "$REFPEER" ] || { echo "entity-peer reference not found — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    make install-addon >/dev/null 2>&1
    KPDIR="${HOME:-/root}/.entity/peers/$EC_NAME"; mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    io src/main.io --port "$TPORT" --name "$EC_NAME" --validate --debug-open-grants >build/orig-peer.log 2>&1 &
    PD_PID=$!
    trap "kill $PD_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "listening on TCP" build/orig-peer.log 2>/dev/null && break
      kill -0 "$PD_PID" 2>/dev/null || { echo "peer exited:"; cat build/orig-peer.log; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1
    echo "target(Io) on :$TPORT  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
