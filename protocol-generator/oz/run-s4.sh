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
  exec podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/oz "$IMAGE" sh /work/protocol-generator/oz/run-s4.sh "$@"
fi

PORT="${PORT:-47951}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
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
cleanup() { kill "$HOST_PID" 2>/dev/null || true; }
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

"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
