#!/bin/sh
# S4 conformance harness — entity-core-protocol-odin.
#
# Runs entirely inside the odin-toolchain container (the Go validate-peer oracle
# is a fedora:43 ELF that runs there too, so oracle + peer share one loopback;
# stays sealed-offline with --network=none). Builds the peer host, launches it
# with --debug-open-grants (+ --validate when CONFORMANCE=1), waits for its
# LISTENING line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root:
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/odin-toolchain:latest \
#     sh /work/protocol-generator/odin/run-s4.sh -profile core \
#        -json-out /work/protocol-generator/odin/status/CONFORMANCE-REPORT.json
#
# Default args: -profile core (the extension-free categories; the oracle
# auto-allowlists the §9.0 extension-carve-out skips). ORACLE/PORT/NOBUILD/
# CONFORMANCE env overrides.

set -eu
PORT="${PORT:-7777}"
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
PROJ=/work/protocol-generator/odin
cd "$PROJ"

# Build the host OUTSIDE the mounted tree (podman :Z + root-owned prior artifacts
# can block a re-link in place); run from /tmp.
HOST=/tmp/entity-core-peer
if [ "${NOBUILD:-0}" != "1" ]; then
  odin build host -out:"$HOST" -o:speed >/dev/null
else
  HOST="$PROJ/bin/entity-core-peer"
fi

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find
# the peer's keypair and co-sign AS the peer. The seed is a fixed 0x11 × 32
# (base64 "ERER…"), so the peer_id is deterministic and matches what the Go
# validator derives. NAME follows the Go entity-peer / peer-manager convention:
# ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

HOST_ARGS="--port $PORT --name $NAME --debug-open-grants"
# --validate enables the §7a conformance handlers so the validator's
# validate_echo_dispatch + dispatch_outbound_reentry probes run live instead of
# honest-SKIP. ON by default (cohort convention); CONFORMANCE=0 exercises SKIP.
if [ "${CONFORMANCE:-1}" = "1" ]; then
  HOST_ARGS="$HOST_ARGS --validate"
fi

# shellcheck disable=SC2086
"$HOST" $HOST_ARGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 100 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2
    cat /tmp/host.err >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.1
done
head -1 /tmp/host.out

if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
# NOTE: the S2 codec report is preserved at status/CONFORMANCE-REPORT-S2.{md,json};
# CONFORMANCE-REPORT.{md,json} is the S4 validate-peer result (the live gate).
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
