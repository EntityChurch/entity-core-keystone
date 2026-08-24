#!/usr/bin/env bash
# §10.2 origination-core probe — the SQL peer (A-role) against the Go `entity-peer` reference
# (B-role). Both run inside sqlite-toolchain (the Go ELFs are CGO_ENABLED=0 static); shared
# loopback, sealed-offline (--network=none).
#
# `origination` is EXTENSION-only under --profile core (auto-allowlisted by the run-s4 gate);
# its core outbound legs are reference-peer-gated, so a single-peer run honest-SKIPs them.
# This script supplies the Go `entity-peer` as B and runs the origination category directly.
#
# The §6.11 dispatch_outbound_reentry probe: the validator mints a reentry capability, EXECUTEs
# system/validate/dispatch-outbound on the target (A), and A originates an outbound EXECUTE back
# to the validator-as-B over the SAME inbound connection (§6.11 reentry — NOT a fresh dial to the
# reference). A MUST run with --validate live (the §7a scaffold); absent it the probe honest-SKIPs.
#
# The SQL peer's §6.11 seam is a host-side request_id correlation map: dispatch-outbound sends the
# reentry EXECUTE non-blocking + records (orid→rid); the connection loop routes the reentry
# EXECUTE_RESPONSE (by request_id) back to a dispatch-outbound response — so many concurrent
# pipelined reentries interleave on the single fd (the non-actor/non-CSP host tax).
#
#   ./protocol-generator/sql/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/sqlite-toolchain:latest"
WORKDIR="/work/protocol-generator/sql"
TPORT="${TPORT:-15250}"   # target (SQL peer)
RPORT="${RPORT:-15251}"   # reference (Go entity-peer)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
EC_NAME="${EC_NAME:-conformance}"

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e TPORT="$TPORT" -e RPORT="$RPORT" -e ORACLE="$ORACLE" -e REFPEER="$REFPEER" -e EC_NAME="$EC_NAME" \
  -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -eu
    [ -x "$ORACLE" ]  || { echo "oracle not found at $ORACLE — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    [ -x "$REFPEER" ] || { echo "entity-peer reference not found at $REFPEER — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    KPDIR="${HOME:-/root}/.entity/peers/$EC_NAME"; mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    make peer >/tmp/build-orig.log 2>&1 || { echo "peer build failed:"; cat /tmp/build-orig.log; exit 1; }
    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target SQL peer (A-role) — --validate makes system/validate/dispatch-outbound live.
    /tmp/ec-sql-build/ec-sql-peer --name "$EC_NAME" --debug-open-grants --validate --port "$TPORT" >/tmp/peer-orig.log 2>&1 &
    A_PID=$!
    trap "kill $A_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    sleep 1
    kill -0 $A_PID 2>/dev/null   || { echo "SQL peer failed to start:"; cat /tmp/peer-orig.log; exit 1; }
    kill -0 $REF_PID 2>/dev/null || { echo "Go reference failed to start:"; cat /tmp/ref.err; exit 1; }
    echo "target(SQL) on :$TPORT  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
