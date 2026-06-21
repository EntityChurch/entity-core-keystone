#!/bin/sh
# S4 conformance harness — entity-core-protocol-dart (REACH peer; Dart 3 axis).
#
# Runs entirely INSIDE the dart-toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF binary that runs there too, so oracle + peer share one loopback and the
# run stays sealed-offline: --network=none). AOT-compiles the Dart host offline
# (`dart pub get --offline` then `dart compile exe bin/peer.dart`; cryptography_plus /
# crypto / transitives are pre-fetched into the image's PUB_CACHE at container BUILD
# time), provisions the persistent `conformance` identity on disk (so the validator's
# multisig accept-path probe can co-sign AS the peer), launches the host with
# --name conformance --debug-open-grants (grant-gated categories need the degenerate
# seed) + --validate (§7a system/validate/* conformance handlers live), waits for its
# LISTENING readiness line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/dart-toolchain:latest sh /work/protocol-generator/dart/run-s4.sh [validate-peer-args...]
#
# Default validate-peer args: -profile core (all core-profile categories; the oracle
# auto-allowlists the §9.0 extension-carve-out skips). Pass args to override (e.g. a
# single -category, or -failures-only). ORACLE / PORT / NOBUILD / VALIDATE are env overrides.
#
# PORT default 7787 — distinct from PHP's 7777 / cpp's 7777 (belt-and-suspenders).
set -eu

PORT="${PORT:-7787}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/dart
BUILD="${BUILD:-build-s4}"
PEER="$BUILD/peer"

cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  # Offline dep resolution + fresh AOT compile of the host (per profile [build]).
  dart pub get --offline >/tmp/build.out 2>&1 || { echo "pub get failed:"; cat /tmp/build.out; exit 1; }
  mkdir -p "$BUILD"
  dart compile exe bin/peer.dart -o "$PEER" >>/tmp/build.out 2>&1 || { echo "compile failed:"; cat /tmp/build.out; exit 1; }
fi

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validate_echo_dispatch + dispatch_outbound_reentry probes
# run live instead of honest-SKIP. Off in production; on here. (VALIDATE=0 to exercise
# the SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find the
# peer's keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer — exercising
# genuine K-of-N instead of env-skipping. The seed (0x11 × 32, base64 "ERER…") matches
# the host default identity, so peer_id (2KHoAk…) is unchanged. NAME follows the Go
# entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

"$PEER" --port "$PORT" --name "$NAME" --debug-open-grants $VALIDATE_FLAG >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

# Wait up to 30s for the readiness line (AOT exe boots fast; generous margin).
i=0
while [ "$i" -lt 300 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then
    break
  fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2
    cat /tmp/host.err >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.1
done
head -2 /tmp/host.out

# Default args: the full --profile core run. -timeout 5m: the default 1m budget
# is consumed by the long real-time categories (security ~20s + concurrency's
# sustained-load/churn ~50s) before the later categories surface; the wider window
# lets every core category run to completion (full 665 total, none budget-skipped).
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout 5m -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi

"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
