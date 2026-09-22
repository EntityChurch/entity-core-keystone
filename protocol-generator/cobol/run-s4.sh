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
# Default args: -profile core. ORACLE/PORT/NOBUILD/VALIDATE env overrides
# (VALIDATE defaults to 1).
#
# JSON_OUT — WHERE A BARE RUN WRITES ITS REPORT (changed 2026-09-08)
# A bare `./run-s4.sh` used to default `-json-out` to this peer's TRACKED
# status/CONFORMANCE-REPORT.json — the signed-off record the matrix publishes — so a
# human diagnostic run silently republished a number nobody had reviewed. The default is
# now a scratch path. To refresh the tracked report, MEASURE it deliberately:
#     tools/run-cohort-census.sh --to-status <peer>       (preferred)
#     JSON_OUT=<path> ./run-s4.sh                          (explicit)

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

# --validate ON by default, as every other peer's harness has it. It gates the
# system/validate/* conformance handlers, and without them four concurrency
# checks (t1_2 reentry, t1_3, t1_4, t2_1) SKIP rather than run — a coverage gap
# that reads as a clean report. Set VALIDATE=0 to reproduce the old measurement.
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

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
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
reap_host() {
  if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
  [ -n "${HOST_PID:-}" ] || return 0
  kill -0 "$HOST_PID" 2>/dev/null || return 0
  kill -TERM "$HOST_PID" 2>/dev/null || true
  # Poll rather than a bare wait: a peer that ignores TERM is bounded at ~5s and then
  # killed, instead of hanging the run forever.
  j=0
  while [ "$j" -lt 50 ]; do
    kill -0 "$HOST_PID" 2>/dev/null || return 0
    j=$((j + 1))
    sleep 0.1
  done
  kill -KILL "$HOST_PID" 2>/dev/null || true
  wait "$HOST_PID" 2>/dev/null || true
}
trap reap_host EXIT INT TERM

i=0
while [ "$i" -lt 100 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
  i=$((i + 1)); sleep 0.1
done
head -1 /tmp/host.out

if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "${JSON_OUT:-/tmp/ec-s4-cobol.json}"
fi
. /work/protocol-generator/shared/tools/refpeer.sh
refpeer_up
"$ORACLE" -addr "127.0.0.1:$PORT" $REFPEER_FLAG "$@" || true

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
