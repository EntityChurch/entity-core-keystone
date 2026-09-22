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
# output/s4-oracles/ are the conformance TOOL (built from entity-core-go at the pinned
# oracle content digest — tools/oracle-pin.env; the commit is internal, see README
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

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness — but that also swallowed a MISSING
# binary, and the script exited 0 having validated nothing. Measured 2026-08-23: a
# fresh clone with no sibling entity-core-go printed one "No such file or directory"
# line and exited 0, i.e. the documented Quick-start command appeared to succeed.
# $ORACLE is a CONTAINER path -- the repo root is mounted at /work -- so the existence
# test has to be made against the HOST path, or it can never pass. Measured 2026-08-27:
# in this form the guard rejected all 33 peers carrying it. It had never been executed.
ORACLE_HOST="$ORACLE"
case "$ORACLE_HOST" in
  /work/*) ORACLE_HOST="$(cd "$(dirname "$0")/../.." && pwd)/${ORACLE_HOST#/work/}" ;;
esac
[ -x "$ORACLE_HOST" ] || { echo "run-s4: ERROR conformance oracle not found at $ORACLE_HOST" >&2
  echo "  The oracle is a gitignored local tool built from the sibling entity-core-go" >&2
  echo "  repo. Clone it NEXT TO this one, then run tools/oracle-bootstrap.sh." >&2
  echo "  See the Quick start in README.md." >&2
  exit 3; }
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

# Provision the peer keypair at ~/.entity/peers/conformance/keypair (seed
# 0x11×32, base64 "ERER…") so the validator can co-sign AS the peer for the §3.6
# multisig accept-path probe (valid_2of3_peer_signed_accepted). The peer boots
# --name conformance and loads this same seed → matching peer_id.
KPDIR="${HOME:-/root}/.entity/peers/conformance"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

"$HOST_BIN" --port "$PORT" --name conformance --debug-open-grants $VALIDATE_FLAG \
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
