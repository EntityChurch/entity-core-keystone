#!/bin/sh
# S4 conformance harness — entity-core-protocol-haskell.
#
# Runs inside the ghc-toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF that runs there too, so oracle + peer share one loopback; stays
# sealed-offline with --network=none against the warm .cabal-home store). Builds
# the peer host, launches it with --debug-open-grants, waits for its LISTENING
# line, points validate-peer at it, tears the host down.
#
# Invoke from the repo root (note: CABAL_DIR points at the warm workspace store
# per the A-HS-005 offline pattern):
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none \
#     -e CABAL_DIR=/work/protocol-generator/haskell/.cabal-home \
#     -v "$PWD":/work:Z \
#     entity-core-keystone/ghc-toolchain:latest \
#     sh /work/protocol-generator/haskell/run-s4.sh [validate-peer-args...]
#
# Default args: -profile core (all core-profile categories). ORACLE/PORT/NOBUILD/
# VALIDATE env overrides.

set -eu
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/haskell
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  cabal build exe:host --offline
fi
HOST_BIN="$(find dist-newstyle -name host -type f -path '*/build/host/host' | head -1)"

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validate_echo_dispatch + dispatch_outbound_reentry
# probes run live instead of honest-SKIP. Off in production; on here. (VALIDATE=0
# to exercise the SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find
# the peer's keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer —
# exercising genuine K-of-N instead of env-skipping. The seed (0x11 × 32, base64
# "ERER…") matches the host default, so peer_id is unchanged. NAME follows the Go
# entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

"$HOST_BIN" --port "$PORT" --name "$NAME" --debug-open-grants $VALIDATE_FLAG +RTS -N -RTS \
  >/tmp/host.out 2>/tmp/host.err &
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
