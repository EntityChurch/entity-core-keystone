#!/bin/sh
# S4 conformance harness — entity-core-protocol-crystal.
#
# Runs entirely inside the crystal-toolchain container (Ubuntu-based; the Go
# validate-peer oracle is a static ELF that runs there too, so oracle + peer
# share one loopback and stay sealed-offline with --network=none). Builds the
# host, launches it with --debug-open-grants (+ --validate when CONFORMANCE=1),
# waits for its LISTENING line, points validate-peer at it, tears it down.
#
# Invoke from the repo root:
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/crystal-toolchain:latest \
#     sh /work/protocol-generator/crystal/run-s4.sh \
#        -profile core -json-out /work/protocol-generator/crystal/status/CONFORMANCE-REPORT.json
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
[ -x "$ORACLE" ] || { echo "run-s4: ERROR conformance oracle not found at $ORACLE" >&2
  echo "  The oracle is a gitignored local tool built from the sibling entity-core-go" >&2
  echo "  repo. Clone it NEXT TO this one, then run tools/oracle-bootstrap.sh." >&2
  echo "  See the Quick start in README.md." >&2
  exit 3; }
PROJ=/work/protocol-generator/crystal
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  # --release: LLVM optimizations. The §7b throughput is fixed by TCP_NODELAY
  # (socket.tcp_nodelay = true on every socket) — Nagle/delayed-ACK on the small
  # request/response frames is the real bottleneck, not codec overhead.
  crystal build --release bin/entity-core-peer.cr -o /tmp/host >/dev/null 2>&1 \
    || crystal build bin/entity-core-peer.cr -o /tmp/host
fi

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validator's validate_echo_dispatch + origination-core
# dispatch_outbound_reentry probes run live instead of honest-SKIP. ON by default
# (cohort convention); set CONFORMANCE=0 to exercise the SKIP path.
# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find
# the peer's keypair and co-sign AS the peer. The seed is a fixed 0x11 x 32
# (base64 "ERER..."), so the peer_id is deterministic. NAME follows the Go
# entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

HOST_ARGS="--port $PORT --name $NAME --debug-open-grants"
if [ "${CONFORMANCE:-1}" = "1" ]; then
  HOST_ARGS="$HOST_ARGS --validate"
fi

# Graceful reap: SIGTERM the host, then WAIT for it to actually exit (the host
# handles TERM by closing its listener → clean scheduler-intact exit 0). We poll
# for exit rather than fire-and-forget so the process is fully gone before the
# script returns (deterministic teardown; no port left half-bound for a re-run).
reap_host() {
  [ -n "${HOST_PID:-}" ] || return 0
  kill -0 "$HOST_PID" 2>/dev/null || return 0
  kill -TERM "$HOST_PID" 2>/dev/null || true
  j=0
  while [ "$j" -lt 50 ]; do
    kill -0 "$HOST_PID" 2>/dev/null || return 0
    j=$((j + 1))
    sleep 0.1
  done
  # still alive after ~5s → hard kill (should not happen on a clean shutdown)
  kill -KILL "$HOST_PID" 2>/dev/null || true
  wait "$HOST_PID" 2>/dev/null || true
}

# shellcheck disable=SC2086
/tmp/host $HOST_ARGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'reap_host' EXIT INT TERM

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

# Reap the host cleanly HERE (before the EXIT trap fires) so its stderr is
# complete and any shutdown crash surfaces in /tmp/host.err rather than being
# lost to a late kill. NOT masked — surfaced.
reap_host
if [ -s /tmp/host.err ]; then
  echo "=== host stderr ===" >&2
  cat /tmp/host.err >&2
fi
