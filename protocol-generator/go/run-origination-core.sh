#!/usr/bin/env bash
# §10.2 origination-core probe — Go target (A-role) against a Go entity-peer
# reference (B-role). Both run inside the go toolchain container (the Go ELFs run
# there too); shared loopback, sealed-offline (--network=none).
#
# Post-§7a resolution: runOriginationCore IS the dispatch_outbound_reentry probe —
# the validator mints a reentry capability, EXECUTEs system/validate/dispatch-
# outbound on the target, and the target originates an outbound EXECUTE back to
# the validator-as-B over the SAME inbound connection (§6.11 reentry; NOT a fresh
# dial to the reference). The Go reference entity-peer is connected only to keep
# the gate's input shape (`-reference-peer required`) consistent with --profile
# full; it is otherwise unused under core. The target MUST run with --validate
# (system/validate/dispatch-outbound live); absent it the probe honest-SKIPs —
# which is why the single-peer run-s4.sh honest-SKIPs origination.
#
# Go transport note: the §6.11 outbound/reentry seam is the native goroutine +
# channel build (transport.go reader-demux + request_id↔chan correlation under a
# pending mutex + transportIO.outbound). Each inbound EXECUTE dispatches on its
# own goroutine (N6) so the reentry leg does not stall the reader.
#
# Go uses loopback port 7778 (target); the Go reference entity-peer binds 7779.
#
# Invoke from the repo root:
#   ./protocol-generator/go/run-origination-core.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/go:latest"
WORKDIR="/work/protocol-generator/go"
TPORT="${TPORT:-7778}"   # target (Go peer)
RPORT="${RPORT:-7779}"   # reference (Go entity-peer)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"

podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT/protocol-generator":/work/protocol-generator:Z \
  -v "$REPO_ROOT/protocol-generator/go/output/s4-oracles":/work/output/s4-oracles:Z \
  -e GOFLAGS= -e GOTOOLCHAIN=local -e GOWORK=off \
  -e TPORT="$TPORT" -e RPORT="$RPORT" -e ORACLE="$ORACLE" -e REFPEER="$REFPEER" \
  -w "$WORKDIR/src" "$IMAGE" \
  bash -c '
    set -eu
    if [ "${NOBUILD:-0}" != "1" ]; then CGO_ENABLED=0 go build -o /tmp/go-host ./cmd/host; fi
    # Reference Go entity-peer (B-role), open-access.
    "$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
    REF_PID=$!
    # Target Go host (A-role) — --validate makes system/validate/dispatch-outbound live.
    /tmp/go-host --port "$TPORT" --debug-open-grants --validate \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID $REF_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 200 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Go host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    sleep 1   # give the Go reference a moment to bind
    echo "target(Go)=$(head -1 /tmp/host.out)  reference(Go entity-peer) on :$RPORT"
    "$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
      -profile core -category origination || true
    echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
  '
