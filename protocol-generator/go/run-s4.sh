#!/bin/sh
# S4 conformance harness — entity-core-protocol-go (CLEAN-ROOM peer).
#
# Runs inside the go toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF that runs there too, so oracle + peer share one loopback and the
# run stays sealed-offline with --network=none). Builds the peer host, launches
# it with --debug-open-grants, waits for its LISTENING line, points validate-peer
# at it, tears the host down.
#
# CLEAN-ROOM NOTE: the Go peer is built from the spec; the oracle binaries under
# output/s4-oracles/ are the conformance TOOL (built from entity-core-go 75c532e
# in an isolated temp dir, NOT read as source while building the peer). The peer
# is byte-VALIDATED against the oracle here, not derived from it.
#
# Go uses loopback port 7778 (Ruby uses 7777 — avoid collision in shared runs).
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none --security-opt label=disable \
#     -v "$PWD":/work:Z \
#     entity-core-keystone/go:latest \
#     sh /work/protocol-generator/go/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core. ORACLE/PORT/NOBUILD/VALIDATE env overrides.

set -eu
PORT="${PORT:-7778}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/go
cd "$PROJ/src"

if [ "${NOBUILD:-0}" != "1" ]; then
  # stdlib-only core peer; go.sum empty; builds offline (CGO off — no race here).
  CGO_ENABLED=0 go build -o /tmp/go-host ./cmd/host
fi
HOST_BIN=/tmp/go-host

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validate_echo_dispatch + dispatch_outbound_reentry
# probes run live instead of honest-SKIP. Off in production; on here. (VALIDATE=0
# exercises the SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"
"$HOST_BIN" --port "$PORT" --debug-open-grants $VALIDATE_FLAG \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 100 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
  i=$((i + 1)); sleep 0.1
done
head -1 /tmp/host.out

if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
