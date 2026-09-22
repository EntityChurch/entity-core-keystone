#!/bin/sh
# S4 conformance harness — entity-core-protocol-oz.
#
# Runs entirely inside the mozart-toolchain container (fedora:43): the Go
# validate-peer oracle is a static ELF that runs there too, so oracle + peer
# share one loopback and the whole run stays sealed-offline (--network=none).
# Builds the peer (ozc -c the functors + gcc the entity-codec-daemon), launches
# the native Open.socket host on a 47xxx port (chosen to avoid the parallel Io
# build), waits for its LISTENING line, points validate-peer at it, tears down.
#
# Invoke from the repo root (the oracle binaries are pin-verified in
# output/s4-oracles/):
#   ./run-s4.sh                # drives podman for you
#   podman run ... sh /work/protocol-generator/oz/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core. Pass args to override (e.g. a single -category).
# ORACLE / PORT / VALIDATE / ORACLE_TIMEOUT are env overrides.
set -eu

if [ ! -d /work/protocol-generator/oz ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/mozart-toolchain:latest"
  # Forward this script's OWN documented env overrides across the container
  # boundary. Without this an ORACLE= set by the caller is silently DROPPED and
  # the inner run falls back to the real validator -- the run then SUCCEEDS and
  # writes a perfectly good conformance report where a probe report was expected.
  # Measured 2026-09-06: 5 of these 8 harnesses did exactly that during the §6.3
  # put-admission sweep. `${VAR:+...}` so an unset var adds no flag and the inner
  # default still decides -- forwarding, never policy.
  exec podman run ${ORACLE:+-e ORACLE="$ORACLE"} ${JSON_OUT:+-e JSON_OUT="$JSON_OUT"} ${NOBUILD:+-e NOBUILD="$NOBUILD"} ${VALIDATE:+-e VALIDATE="$VALIDATE"} \
    $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/oz "$IMAGE" sh /work/protocol-generator/oz/run-s4.sh "$@"
fi

PORT="${PORT:-47951}"
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
PROJ=/work/protocol-generator/oz
DAEMON="$PROJ/build/eccodecd"

cd "$PROJ"

# Build the peer + daemon (offline; libsodium is in the image).
make host >/tmp/ozbuild.out 2>&1 || { echo "oz peer build failed:" >&2; cat /tmp/ozbuild.out >&2; exit 1; }

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validate_echo_dispatch + dispatch_outbound_reentry
# probes run live instead of honest-SKIP. Off in production; on here.
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find
# the peer's keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer. The
# seed (0x11 x 32, base64 "ERER...") matches the launcher default, so peer_id is
# unchanged. NAME follows the Go entity-peer / peer-manager convention.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

ozengine "$PROJ/build/host.ozf" \
  --port "$PORT" --name "$NAME" --daemon "$DAEMON" \
  --debug-open-grants $VALIDATE_FLAG >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
cleanup() {
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
trap cleanup EXIT INT TERM

# Wait up to 30s for the readiness line (ozengine startup + daemon spawn + bind).
i=0
while [ "$i" -lt 300 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1
  fi
  i=$((i + 1)); sleep 0.1
done
if ! grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then
  echo "host never reached LISTENING within 30s:" >&2; cat /tmp/host.err >&2; exit 1
fi
head -1 /tmp/host.out

# Default args: the full --profile core run with the JSON report alongside.
# -timeout widened (the crypto crosses an Open.pipe to the co-process per op, so
# each request is several IPC round-trips — the same budget-exhaustion cascade the
# Rexx/dart/prolog peers widen for).
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout "${ORACLE_TIMEOUT:-10m}" -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
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
