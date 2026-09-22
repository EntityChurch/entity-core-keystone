#!/bin/sh
# S4 conformance harness — entity-core-protocol-cobol.
#
# Runs inside the cobol-toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF that runs there too, sharing one loopback; stays sealed-offline
# with --network=none). Builds the host, launches it with --debug-open-grants,
# waits for its LISTENING line, points validate-peer at it, tears it down.
#
# DO NOT launch the container by hand without resource caps — the host is a
# long-running TCP server and an uncapped runaway can take the machine down.
# Use the capped host-side launcher instead (it sources tools/podman-caps.sh):
#
#   protocol-generator/cobol/run-s4-host.sh [validate-peer-args...]
#
# which runs, with $PODMAN_RUN_CAPS (memory + zero-swap + pids + cpus):
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
#     -e LD_LIBRARY_PATH=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build \
#     localhost/entity-core-keystone/cobol-toolchain:latest \
#     sh /work/protocol-generator/cobol/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core. ORACLE/PORT/NOBUILD/VALIDATE env overrides.

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
PROJ=/work/protocol-generator/cobol
CODEC="${CODEC:-/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build}"
export LD_LIBRARY_PATH="$CODEC${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  make host >/tmp/cobol-build.log 2>&1 || { cat /tmp/cobol-build.log; exit 1; }
fi

VALIDATE_FLAG=""; [ "${VALIDATE:-0}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the standard on-disk identity so the multisig accept-path probe can
# co-sign as the peer. Seed 0x11x32 (base64 "ERER…") == host default => peer_id
# unchanged. NAME follows the Go entity-peer / peer-manager convention.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

build/host --port "$PORT" --name "$NAME" --debug-open-grants $VALIDATE_FLAG \
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
