#!/bin/sh
# S4 conformance harness — entity-core-protocol-smalltalk (#26).
#
# Runs entirely inside the pharo-toolchain container (fedora:43): the Go validate-peer
# oracle is a static CGO_ENABLED=0 ELF that runs there too, so oracle + peer share one
# loopback and the whole run stays sealed-offline (--network=none — intra-container
# 127.0.0.1 works under it). Like Forth there is NO co-process daemon: the Pharo VM owns
# the sockets + the single-event-loop + crypto in-process via UFFI (A-ST native_sockets /
# in_process_ffi), so the peer is a single `pharo entity-core.image bin/peer.st` process.
# Launches it with EC_PEER_NAME=conformance + --debug-open-grants + --validate (via env),
# waits for its LISTENING line, points validate-peer at it, tears down.
#
# Invoke from the repo root (the oracle binary is a gitignored local tool, prepared by the
# overseer via tools/oracle-bootstrap.sh — do NOT rebuild it):
#   ./run-s4.sh                    # the full --profile core gate (drives podman for you)
#   ./run-s4.sh -category multisig # a single category
#
# Default validate-peer args: -profile core. ORACLE / PORT / PEERNAME / ORACLE_TIMEOUT are
# env overrides. When NOT already inside the container (no /work), re-exec self under podman.
set -eu

if [ ! -d /work/protocol-generator/smalltalk ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/pharo-toolchain:latest"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/smalltalk "$IMAGE" sh /work/protocol-generator/smalltalk/run-s4.sh "$@"
fi

PORT="${PORT:-7777}"
CODEC_SRC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD="$CODEC_SRC/build"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/smalltalk
NAME="${PEERNAME:-conformance}"
BASEIMG=/opt/pharo/image
PEERIMG="$PROJ/entity-core.image"

cd "$PROJ"

# Build libentitycore_codec if absent (offline; libsodium is in the toolchain image).
[ -f "$CODEC_BUILD/libentitycore_codec.so" ] || \
  ( cd "$CODEC_SRC" && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null )
export LD_LIBRARY_PATH="$CODEC_BUILD:${LD_LIBRARY_PATH:-}"

# Build the peer image (load the Tonel packages into a fresh base image + snapshot). The
# live-image model (A-ST-010): the classes must be compile-time visible to bin/peer.st, so
# the harness runs against the SNAPSHOTTED peer image, not the load eval.
make image >/tmp/img.out 2>&1 || { echo "make image failed:" >&2; tail -20 /tmp/img.out >&2; exit 1; }

# Provision the peer's persistent identity at ~/.entity/peers/NAME/keypair so the validator's
# multisig accept-path probe (valid_2of3_peer_signed_accepted) can load the peer's keypair and
# co-sign AS the peer — exercising genuine K-of-N. The seed (0x11 x32, PEM base64 "ERER…")
# matches the launcher default so peer_id is unchanged.
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# --validate enables the §7a conformance handlers (system/validate/{echo,dispatch-outbound}).
# --debug-open-grants seeds the degenerate default→* connection grant (grant-gated categories
# need it). Off in production; on here. Options travel via ENV (a headless `eval` appends argv
# to the source — the A-ST bin convention).
EC_PEER_PORT="$PORT" EC_PEER_NAME="$NAME" EC_PEER_VALIDATE=1 EC_PEER_OPEN_GRANTS=1 \
  pharo --headless "$PEERIMG" bin/peer.st \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
cleanup() { kill "$HOST_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Wait up to 30s for the readiness line (image boot + UFFI warm).
i=0
while [ "$i" -lt 300 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "host exited before LISTENING:" >&2; grep -vi 'warning\|undeclared' /tmp/host.err | tail >&2; exit 1; }
  i=$((i + 1)); sleep 0.1
done
grep -q '^LISTENING' /tmp/host.out 2>/dev/null || { echo "host never reached LISTENING within 30s:" >&2; grep -vi 'warning\|undeclared' /tmp/host.err | tail >&2; exit 1; }
head -1 /tmp/host.out

# Default args: the full --profile core run, JSON alongside. -timeout is an OPERATOR budget
# (the real gate is the per-request cap). This peer crosses libffi for crypto per op and
# concurrency streams many tree.gets — widen the overall budget as the cohort does.
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout "${ORACLE_TIMEOUT:-10m}" -json-out "${JSON_OUT:-$PROJ/status/CONFORMANCE-REPORT.json}"
fi

"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
