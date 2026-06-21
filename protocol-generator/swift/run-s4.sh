#!/bin/sh
# S4 conformance harness — entity-core-protocol-swift (peer #7).
#
# Runs entirely inside the swift-toolchain container (the Go validate-peer oracle
# is a fedora:43 ELF that runs there too, so oracle + peer share one loopback;
# stays sealed-offline with --network=none after the S2 resolve). Builds the peer,
# launches the host with --debug-open-grants (+ --validate when CONFORMANCE=1),
# waits for its LISTENING line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/swift-toolchain:latest sh /work/protocol-generator/swift/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core. ORACLE/PORT/NOBUILD/CONFORMANCE env overrides.

set -eu
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/swift
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  # release build (the shipped posture). The §7b throughput is fixed by
  # TCP_NODELAY (Socket.setNoDelay) on the small request/response frames; the
  # store is an `actor`, so the §7b store-race that bit Zig/CL is structurally
  # impossible (compiler-enforced).
  swift build -c release >/dev/null
fi
HOST=./.build/release/entity-peer-swift

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validator's validate_echo_dispatch + origination-core
# dispatch_outbound_reentry probes run live instead of honest-SKIP. ON by default
# (cohort convention); set CONFORMANCE=0 to exercise the SKIP path. (Off in
# production, where dispatch-outbound is a standing outbound originator.)
# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find
# the peer's keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer —
# exercising genuine K-of-N instead of env-skipping. The seed (0x11 × 32, base64
# "ERER…") gives a stable §1.5 peer_id that the Go validator matches. NAME follows
# the Go entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair.
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

# shellcheck disable=SC2086
"$HOST" $HOST_ARGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 200 ]; do
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
