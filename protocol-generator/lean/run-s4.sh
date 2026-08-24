#!/bin/sh
# S4 conformance harness — entity-core-protocol-lean.
#
# Runs entirely inside the lean-toolchain container (the Go validate-peer oracle
# is a fedora:43 ELF that runs there too, so oracle + peer share one loopback).
# The rust codec .so must be built first (libentitycore_codec, for crypto) — this
# harness does not build it, only stages + mounts it. Builds the peer host, launches
# it with --debug-open-grants --validate, waits for the LISTENING line, points
# validate-peer at it, tears the host down.
#
# Invoke from the repo root — bare `./run-s4.sh` self-relaunches inside the
# container, same convention as every other peer's harness (mounts the repo at
# /work, not the previous one-off /repo):
#   ./protocol-generator/lean/run-s4.sh [validate-peer-args...]
#
# Requires the codec .so already built at
# ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release/libentitycore_codec.so
# (build it in containers/cargo first if missing — this harness errors out with that
# path rather than silently failing if it isn't there).
#
# Default args: -profile core. ORACLE/PORT/NOBUILD/VALIDATE env overrides.
# Set INCONTAINER=1 to skip the self-relaunch (already inside the container).

set -eu

CODEC_DIR_HOST_REL="ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release"

if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  [ -f "$HOSTREPO/$CODEC_DIR_HOST_REL/libentitycore_codec.so" ] || {
    echo "codec not built: $HOSTREPO/$CODEC_DIR_HOST_REL/libentitycore_codec.so missing" >&2
    echo "build it first, e.g. inside containers/cargo:" >&2
    echo "  podman run \$PODMAN_RUN_CAPS --rm -v \"$HOSTREPO\":/work:Z -w /work/ffi-generator/c-abi/entity-core-codec-ffi-rust localhost/entity-core-keystone/cargo:latest cargo build --release" >&2
    exit 2
  }
  exec podman run $PODMAN_RUN_CAPS --rm \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z \
    -v "$HOSTREPO/$CODEC_DIR_HOST_REL":/codec:z,ro \
    -w /work/protocol-generator/lean -e LD_LIBRARY_PATH=/codec \
    localhost/entity-core-keystone/lean-toolchain:latest sh /work/protocol-generator/lean/run-s4.sh "$@"
fi

# Keep HOME consistent across keypair provisioning, the host (IO.getEnv "HOME"),
# and validate-peer (os.UserHomeDir → scans ~/.entity/peers/*/keypair).
export HOME="${HOME:-/root}"
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/lean
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  lake build host
fi

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validate_echo_dispatch + dispatch_outbound_reentry
# probes run live instead of honest-SKIP. Off in production; on here. (VALIDATE=0
# exercises the SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find
# the peer's keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer —
# exercising genuine K-of-N instead of env-skipping. The seed (0x11 × 32, base64
# "ERER…") is re-derived to the same peer_id by the host's FFI seed→pubkey, so
# peer_id is unchanged. NAME follows the Go entity-peer / peer-manager convention:
# ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

./.lake/build/bin/host --port "$PORT" --name "$NAME" --debug-open-grants $VALIDATE_FLAG >/tmp/host.out 2>/tmp/host.err &
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
  set -- -profile core -json-out "${JSON_OUT:-$PROJ/status/CONFORMANCE-REPORT.json}"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
