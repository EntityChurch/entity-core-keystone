#!/usr/bin/env bash
# §10.2 origination-core probe — Python target (A-role) against the Go entity-peer
# reference (B-role). Both run inside python-toolchain (the Go ELFs run there);
# shared loopback, sealed-offline (--network=none).
#
# The origination category's substantive leg is dispatch_outbound_reentry — the
# validator mints a reentry capability, EXECUTEs system/validate/dispatch-outbound
# on the target, and the target originates an outbound EXECUTE back to the
# validator-as-B over the SAME inbound connection (§6.11 reentry; NOT a fresh dial
# to the reference). The Go reference is connected only to satisfy the gate's
# `-reference-peer required` input shape; it is otherwise unused under core. The
# target MUST run with --validate (so system/validate/dispatch-outbound is live);
# absent it the probe honest-SKIPs — which is why the single-peer run-s4.sh
# honest-SKIPs origination under --profile core.
#
# Python note: the §6.11 outbound/reentry seam is the thread-per-connection
# transport (the reader-demux pending {request_id => Condition} map + the
# per-inbound-EXECUTE thread + the reentry primitive wired onto the inbound
# connection). dispatch-outbound is a generic relay — it forwards the {value:X}
# params verbatim and returns the downstream result entity verbatim. This gate is
# the cross-impl wire proof of that seam.
#
# Oracle pin: entity-core-go @33f35fd (output/s4-oracles/{validate-peer,entity-peer},
# gitignored). The core image carries only `cryptography`; the host is driven with
# PYTHONPATH=src python -m entity_core.host.
#
# Invoke from the repo root:
#   ./protocol-generator/python/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="${IMAGE:-entity-core-keystone/python-toolchain:latest}"
WORKDIR="/work/protocol-generator/python"
TPORT="${TPORT:-7778}"   # target (Python) — Python's port; concurrent Rust S4 uses 7777
RPORT="${RPORT:-7779}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
PEERNAME="${PEERNAME:-conformance}"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    TPORT="'"$TPORT"'"; RPORT="'"$RPORT"'"; ORACLE="'"$ORACLE"'"; REFPEER="'"$REFPEER"'"; PEERNAME="'"$PEERNAME"'"
    KPDIR="${HOME:-/root}/.entity/peers/$PEERNAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"

    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Python host (A-role) — --validate makes system/validate/dispatch-outbound live.
    PYTHONPATH=src python -m entity_core.host \
      --port "$TPORT" --name "$PEERNAME" --debug-open-grants --validate \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill -9 $HOST_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Python host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give Go reference a moment to bind
    echo "target(Python)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
