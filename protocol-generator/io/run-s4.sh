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

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness -- but that also swallows a MISSING
# binary, and the script would exit 0 having validated nothing.
# $ORACLE is a CONTAINER path -- the repo root is mounted at /work -- so the existence
# test has to be made against the HOST path, or it can never pass. Measured 2026-08-27:
# in this form the guard rejected all 33 peers carrying it. It had never been executed.
ORACLE_HOST="$ORACLE"
case "$ORACLE_HOST" in
  /work/*) ORACLE_HOST="$(cd "$(dirname "$0")/../.." && pwd)/${ORACLE_HOST#/work/}" ;;
esac
[ -x "$ORACLE_HOST" ] || { echo "run-s4: ERROR conformance oracle not found at $ORACLE_HOST" >&2
  echo "  The oracle is a gitignored local tool built from the sibling entity-core-go" >&2
  echo "  repo. Clone it NEXT TO this one, then run tools/oracle-bootstrap.sh." >&2
  echo "  See the Quick start in README.md." >&2
  exit 3; }
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
    io src/main.io --port "$PORT" --name "$EC_NAME" --validate --debug-open-grants >build/s4-peer.log 2>build/s4-peer.err &
    PEER=$!
    # Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
    # trap returns while the peer still owns the listening socket and a second invocation
    # in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
    # accepting connections AFTER the harness had exited: elixir >400ms (and the next run
    # did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
    # property of the peer runtime, not of the harness, which is why every peer carries
    # this and not only the ones that were seen to fail.
    reap_host() {
      if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
      [ -n "${PEER:-}" ] || return 0
      kill -0 "$PEER" 2>/dev/null || return 0
      kill -TERM "$PEER" 2>/dev/null || true
      # Poll rather than a bare wait: a peer that ignores TERM is bounded at ~5s and then
      # killed, instead of hanging the run forever.
      j=0
      while [ "$j" -lt 50 ]; do
        kill -0 "$PEER" 2>/dev/null || return 0
        j=$((j + 1))
        sleep 0.1
      done
      kill -KILL "$PEER" 2>/dev/null || true
      wait "$PEER" 2>/dev/null || true
    }
    trap reap_host EXIT
    # wait for the readiness line
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "listening on TCP" build/s4-peer.log 2>/dev/null && break
      kill -0 "$PEER" 2>/dev/null || { echo "peer exited:"; cat build/s4-peer.log build/s4-peer.err; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    . /work/protocol-generator/shared/tools/refpeer.sh
    refpeer_up
    rc=0; "$ORACLE" -addr "127.0.0.1:$PORT" $REFPEER_FLAG "$@" || rc=$?

    # SURFACE THE STDERR OF THE PEER ITSELF. build/s4-peer.err is a path INSIDE a --rm
    # container, so without this the dying words of the peer are discarded with the
    # container and a mid-run abort leaves a log reading only "connection refused".
    # That is not hypothetical: the zig intermittent survived four investigations
    # reported as "no crash, empty stderr" until this line existed on that harness,
    # and then produced a stack trace on the first reproduction. Emitted on stderr so
    # it cannot be mistaken for oracle output, and only when non-empty so a clean run
    # stays quiet.
    if [ -s build/s4-peer.err ]; then
      echo "--- peer stderr (build/s4-peer.err) ---" >&2
      cat build/s4-peer.err >&2
    fi
    exit "$rc"
  ' bash "$@"
