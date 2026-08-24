#!/bin/sh
# S4 conformance harness — entity-core-protocol-julia.
#
# Runs entirely inside the julia-toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF that runs there too, so oracle + peer share one loopback; stays sealed-
# offline with --network=none). Loads the peer (bin/peer.jl), launches the host with
# --debug-open-grants (+ --validate when CONFORMANCE=1), waits for its LISTENING line,
# points validate-peer at it, tears the host down.
#
# DO NOT launch the container by hand without resource caps (the host is a long-running
# TCP server). Use the capped host-side launcher (run-s4-host.sh), which sources
# tools/podman-caps.sh and runs, with $PODMAN_RUN_CAPS:
#
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
#     entity-core-keystone/julia-toolchain:latest sh /work/protocol-generator/julia/run-s4.sh [args...]
#
# Default args: -profile core (all core-profile categories; the oracle auto-allowlists
# the §9.0 extension-carve-out skips). ORACLE/PORT/NOBUILD/CONFORMANCE env overrides.

set -eu
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/julia
cd "$PROJ"

# Precompile once (JIT warm) — offline, stdlib-only + system libsodium via ccall.
if [ "${NOBUILD:-0}" != "1" ]; then
  julia --project=. -e 'include("src/EntityCore.jl"); using .EntityCore; println("ok")' >/tmp/julia-build.log 2>&1 \
    || { cat /tmp/julia-build.log; exit 1; }
fi

# --validate enables the §7a conformance handlers (system/validate/{echo,dispatch-outbound})
# so the validator's validate_echo_dispatch probe runs live. ON by default (cohort
# convention); set CONFORMANCE=0 to exercise the SKIP path.
# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can co-sign AS
# the peer. Seed 0x11 × 32 (base64 "ERER…") == the host default => peer_id deterministic.
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
julia --project=. bin/peer.jl $HOST_ARGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 300 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2
    cat /tmp/host.err >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.2
done
head -1 /tmp/host.out

if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
