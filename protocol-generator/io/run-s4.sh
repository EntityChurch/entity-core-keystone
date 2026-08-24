#!/usr/bin/env bash
# S4 conformance harness — drive the REAL Go `validate-peer` oracle against the
# real Io peer over loopback TCP, fully offline (--network=none). Higher-bar
# live-peer oracle. The oracle (output/s4-oracles/validate-peer, a static
# CGO_ENABLED=0 ELF) runs INSIDE the io-toolchain image alongside the peer;
# provenance is tools/oracle-pin.env (cc1970f).
#
#   ./run-s4.sh                          # -profile core (the full gate)
#   ./run-s4.sh -category connectivity   # a single category
#   ./run-s4.sh -profile core -verbose
#
# The peer is launched via `io src/main.io --port <p> --name conformance
# --validate --debug-open-grants`; the persistent identity (cohort 0x11×32 seed,
# PEM base64 "ERER…") is provisioned at ~/.entity/peers/conformance/keypair so
# the validator's multisig accept-path probe can co-sign AS the peer.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/io-toolchain:latest"
WORKDIR="/work/protocol-generator/io"
PORT="${ECPORT:-48610}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
EC_NAME="${EC_NAME:-conformance}"

# default: the full core gate with a generous wall-clock (the in-process FFI
# crypto + single-threaded poll loop make the concurrency/security categories
# slow; -timeout keeps a slow category from starving the ones that follow it).
if [ "$#" -eq 0 ]; then set -- -profile core -timeout 15m; fi

podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e ORACLE="$ORACLE" -e PORT="$PORT" -e EC_NAME="$EC_NAME" \
  -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -e
    [ -x "$ORACLE" ] || { echo "oracle not found at $ORACLE — run tools/oracle-bootstrap.sh" >&2; exit 2; }
    make install-addon >/dev/null 2>&1
    # provision the persistent conformance identity (cohort 0x11×32 seed)
    KPDIR="${HOME:-/root}/.entity/peers/$EC_NAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    io src/main.io --port "$PORT" --name "$EC_NAME" --validate --debug-open-grants >build/s4-peer.log 2>&1 &
    PEER=$!
    trap "kill $PEER 2>/dev/null || true" EXIT
    # wait for the readiness line
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "listening on TCP" build/s4-peer.log 2>/dev/null && break
      kill -0 "$PEER" 2>/dev/null || { echo "peer exited:"; cat build/s4-peer.log; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    "$ORACLE" -addr "127.0.0.1:$PORT" "$@"
  ' bash "$@"
