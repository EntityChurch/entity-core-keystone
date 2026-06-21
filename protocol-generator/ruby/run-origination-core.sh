#!/usr/bin/env bash
# §10.2 origination-core probe — Ruby target (A-role) against the Go entity-peer
# reference (B-role). Both run inside ruby-toolchain (the Go ELFs run there);
# shared loopback, sealed-offline (--network=none).
#
# Post-§7a resolution (2026-06-13): the origination category's substantive leg is
# dispatch_outbound_reentry — the validator mints a reentry capability, EXECUTEs
# system/validate/dispatch-outbound on the target, and the target originates an
# outbound EXECUTE back to the validator-as-B over the SAME inbound connection
# (§6.11 reentry; NOT a fresh dial to the reference). The Go reference is
# connected only to satisfy the gate's `-reference-peer required` input shape;
# it is otherwise unused under core. The target MUST run with --validate (so
# system/validate/dispatch-outbound is live); absent it the probe honest-SKIPs —
# which is why the single-peer run-s4.sh honest-SKIPs origination under
# --profile core.
#
# Ruby note: the §6.11 outbound/reentry seam is the thread-per-connection
# transport (Transport.read_loop reader-demux via the pending {request_id =>
# Waiter} map + per-inbound-EXECUTE Thread + the Conn#outbound reentry primitive
# wired to Io#outbound on the inbound connection). dispatch-outbound is a generic
# relay — it forwards the {value:X} params verbatim and returns the downstream
# result entity verbatim. This gate is the cross-impl wire proof of that seam.
#
# Invoke from the repo root:
#   ./protocol-generator/ruby/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ruby-toolchain:latest"
WORKDIR="/work/protocol-generator/ruby"
TPORT="${TPORT:-7777}"   # target (Ruby) — Ruby's port; Go uses 7778
RPORT="${RPORT:-7778}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    TPORT="'"$TPORT"'"; RPORT="'"$RPORT"'"; ORACLE="'"$ORACLE"'"; REFPEER="'"$REFPEER"'"
    # Reference Go peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Ruby host (A-role) — --validate makes system/validate/dispatch-outbound live.
    ruby -Ilib exe/entity-core-peer --port "$TPORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill -9 $HOST_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Ruby host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give Go reference a moment to bind
    echo "target(Ruby)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
