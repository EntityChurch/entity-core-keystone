#!/bin/sh
# S4 conformance harness — entity-core-protocol-lean.
#
# Runs entirely inside the lean-toolchain container (the Go validate-peer oracle
# is a fedora:43 ELF that runs there too, so oracle + peer share one loopback).
# The rust codec .so must be mounted at /codec (libentitycore_codec, for crypto).
# Builds the peer host, launches it with --debug-open-grants --validate, waits for
# the LISTENING line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root (stage the codec .so first):
#   mkdir -p /tmp/lean-codec-mount && cp \
#     ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release/libentitycore_codec.so \
#     /tmp/lean-codec-mount/
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm -v "$PWD":/repo:z -v /tmp/lean-codec-mount:/codec:z,ro \
#     -w /repo/protocol-generator/lean -e LD_LIBRARY_PATH=/codec \
#     localhost/entity-core-keystone/lean-toolchain:latest sh run-s4.sh [validate-peer-args...]
#
# Default args: -profile core. ORACLE/PORT/NOBUILD/VALIDATE env overrides.

set -eu
# Keep HOME consistent across keypair provisioning, the host (IO.getEnv "HOME"),
# and validate-peer (os.UserHomeDir → scans ~/.entity/peers/*/keypair).
export HOME="${HOME:-/root}"
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/repo/output/s4-oracles/validate-peer}"
PROJ=/repo/protocol-generator/lean
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
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
