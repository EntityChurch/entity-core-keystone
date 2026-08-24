#!/usr/bin/env bash
# §10.2 origination-core probe — Datalog target (A-role) against the Go entity-peer
# reference (B-role). Both run inside datalog-toolchain (the Go ELFs are
# CGO_ENABLED=0 static); shared loopback, sealed-offline (--network=none), capped.
#
# The origination category's `dispatch_outbound_reentry` probe: the validator mints a
# reentry capability, EXECUTEs system/validate/dispatch-outbound on the target, and the
# target originates an outbound EXECUTE back to the validator-as-B over the SAME inbound
# connection (§6.11 reentry; NOT a fresh dial to the reference). The reentry seam is
# `conn.outbound` in host.rs, driven by the dispatch_outbound handler (dispatch.rs). The
# target MUST run with the §7a scaffold live (--validate); absent it the probe honest-
# SKIPs — which is why the single-peer run-s4.sh honest-SKIPs origination under core.
# The Go reference is connected only to keep the gate's input shape (`-reference-peer`
# required) consistent.
#
# CARGO_TARGET_DIR is a named volume (kc-dl-target) — off the :Z bind mount (A-DL-009).
#
#   ./run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/datalog-toolchain:latest"
WORKDIR="/work/protocol-generator/datalog"
TPORT="${TPORT:-15204}"   # target (Datalog) listen port
RPORT="${RPORT:-15205}"   # reference (Go entity-peer)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
NAME="${PEERNAME:-conformance}"
TARGET_VOL="${TARGET_VOL:-kc-dl-target}"

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e TPORT="$TPORT" -e RPORT="$RPORT" -e ORACLE="$ORACLE" -e REFPEER="$REFPEER" -e NAME="$NAME" \
  -v "$REPO_ROOT":/work:Z -v "$TARGET_VOL":/tmp/dl-target -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -eu
    export CARGO_TARGET_DIR=/tmp/dl-target
    [ -x "$ORACLE" ] || { echo "oracle not found at $ORACLE — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    [ -x "$REFPEER" ] || { echo "entity-peer reference not found at $REFPEER — run tools/oracle-bootstrap.sh" >&2; exit 2; }

    # Provision the target identity (cohort 0x11×32 seed) at the standard location.
    KPDIR="${HOME:-/root}/.entity/peers/$NAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"

    cargo build --release --offline --bin entity-peer-datalog >/tmp/build.log 2>&1 \
      || { echo "build failed:"; cat /tmp/build.log; exit 1; }

    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Datalog peer (A-role) — --validate makes dispatch-outbound live.
    "$CARGO_TARGET_DIR/release/entity-peer-datalog" \
      --port "$TPORT" --name "$NAME" --debug-open-grants --validate \
      >/tmp/tgt.out 2>/tmp/tgt.err &
    TGT_PID=$!
    trap "kill $TGT_PID $REF_PID 2>/dev/null || true" EXIT INT TERM

    i=0; while [ "$i" -lt 150 ]; do
      grep -q "^LISTENING" /tmp/tgt.out 2>/dev/null && break
      kill -0 "$TGT_PID" 2>/dev/null || { echo "target exited:"; cat /tmp/tgt.err; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give the Go reference a moment to bind
    echo "target(Datalog) on :$TPORT  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
