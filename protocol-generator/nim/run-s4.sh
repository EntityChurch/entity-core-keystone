#!/bin/sh
# S4 conformance harness — entity-core-protocol-nim.
#
# Runs entirely inside the nim-toolchain container (the Go validate-peer oracle is
# a fedora:43 ELF that runs there too, so oracle + peer share one loopback; stays
# sealed-offline with --network=none). Builds the host (nim c), launches it with
# --debug-open-grants (+ --validate when VALIDATE=1), waits for its LISTENING
# line, points validate-peer at it, tears the host down.
#
# DO NOT launch the container uncapped — the host is a long-running TCP server and
# an uncapped runaway can take the machine down. Invoke from the repo root with
# $PODMAN_RUN_CAPS (memory + zero-swap + pids + cpus):
#
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/nim-toolchain:latest sh /work/protocol-generator/nim/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (the oracle auto-allowlists the §9.0 extension
# carve-out skips). ORACLE/PORT/NOBUILD/VALIDATE env overrides. PORT defaults to
# 7788 so a sibling S4 run in the same tree does not collide on loopback.

set -eu
PORT="${PORT:-7788}"
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
PROJ=/work/protocol-generator/nim
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  # --overflowChecks:on keeps the fixed-width uint64 head-form trap live (the
  # keystone Nim posture); -d:release for the throughput the §7b concurrency
  # category needs. TCP_NODELAY (transport.setNoDelay) fixes the Nagle churn.
  nim c --mm:orc --overflowChecks:on -d:release --hints:off \
    -o:/tmp/host src/host.nim >/tmp/nim-build.log 2>&1 \
    || { cat /tmp/nim-build.log; exit 1; }
fi

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validator's validate_echo_dispatch + origination-core
# dispatch_outbound_reentry probes run live instead of honest-SKIP. ON by default
# (cohort convention); set VALIDATE=0 to exercise the SKIP path. (Off in
# production, where dispatch-outbound is a standing outbound originator.)
# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can
# find the peer's keypair and co-sign AS the peer — genuine K-of-N, not env-skip.
# Seed is a fixed 0x11 x 32 (base64 "ERER…"), so the peer_id is deterministic and
# matches what the Go validator derives. NAME follows the Go entity-peer /
# peer-manager convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

HOST_ARGS="--port $PORT --name $NAME --debug-open-grants"
if [ "${VALIDATE:-1}" = "1" ]; then
  HOST_ARGS="$HOST_ARGS --validate"
fi

# shellcheck disable=SC2086
/tmp/host $HOST_ARGS >/tmp/host.out 2>/tmp/host.err &
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
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true

# SURFACE THE STDERR OF THE PEER ITSELF. /tmp/host.err is a path INSIDE a --rm
# container, so without this the dying words of the peer are discarded with the
# container and a mid-run abort leaves a log reading only "connection refused".
# That is not hypothetical: the zig intermittent survived four investigations
# reported as "no crash, empty stderr" until this line existed on that harness,
# and then produced a stack trace on the first reproduction. Emitted on stderr so
# it cannot be mistaken for oracle output, and only when non-empty so a clean run
# stays quiet.
if [ -s /tmp/host.err ]; then
  echo "--- peer stderr (/tmp/host.err) ---" >&2
  cat /tmp/host.err >&2
fi
