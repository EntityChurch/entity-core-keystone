#!/usr/bin/env bash
# S4 conformance harness — drive the REAL `validate-peer` oracle against the real
# Datalog peer over loopback TCP, fully offline. The higher-bar live-peer oracle:
# a real entity-core initiator does the §4.1 handshake against our peer and drives
# the full core-profile surface. Container-bound (datalog-toolchain), CAPPED
# ($PODMAN_RUN_CAPS), OFFLINE (--network=none). The Go validate-peer is a fedora:43
# static ELF that runs INSIDE the datalog-toolchain image alongside the peer, so
# oracle + peer share one loopback and the run stays sealed-offline.
#
# CARGO_TARGET_DIR is container-local (/tmp), NOT the :Z bind mount (A-DL-009:
# SELinux denies ld writing Ascent's proc-macro dylib onto the relabelled volume).
#
#   ./run-s4.sh                       # the full --profile core gate (the binary gate)
#   ./run-s4.sh -category authz       # a single category (the §5.2 DENY paths)
#   ./run-s4.sh -profile core -verbose
#
# The Cargo target dir is a NAMED podman volume (kc-dl-target) mounted at
# /tmp/dl-target — container-managed storage (NOT the :Z bind mount, so A-DL-009's
# SELinux ld denial does not apply), giving fast incremental rebuilds across runs.
#
# The peer launches with --debug-open-grants (grant-gated categories need the
# degenerate default→* seed) --validate (the §7a system/validate/* handlers, OFF in
# production) --name conformance (loads the persistent identity from
# ~/.entity/peers/conformance/keypair — provisioned below with the cohort's
# deterministic 0x11×32 seed so the validator's multisig accept-path probe can
# co-sign AS the peer).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/datalog-toolchain:latest"
WORKDIR="/work/protocol-generator/datalog"
PORT="${PORT:-7737}"
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
NAME="${PEERNAME:-conformance}"
TARGET_VOL="${TARGET_VOL:-kc-dl-target}"

# Default oracle args: the full --profile core gate (the profile IS the gate).
if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$WORKDIR/status/CONFORMANCE-REPORT.json"
fi

# Oracle args ("$@") ride into the container shell as positional parameters (bash -lc
# '…' bash "$@") — no string interpolation, so args stay intact.
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -e ORACLE="$ORACLE" -e PORT="$PORT" -e NAME="$NAME" \
  -v "$REPO_ROOT":/work:Z -v "$TARGET_VOL":/tmp/dl-target -w "$WORKDIR" "$IMAGE" \
  bash -lc '
    set -eu
    export CARGO_TARGET_DIR=/tmp/dl-target
    [ -x "$ORACLE" ] || { echo "oracle not found at $ORACLE — run tools/oracle-bootstrap.sh" >&2; exit 2; }

    # Provision the peer identity at the standard on-disk location (the Go
    # entity-peer / peer-manager convention: ~/.entity/peers/NAME/keypair). The
    # seed 0x11×32 (base64 "ERER…") matches the cohort default so the validator can
    # look up the keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer for
    # the K-of-N accept-path probe.
    KPDIR="${HOME:-/root}/.entity/peers/$NAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"

    cargo build --release --offline --bin entity-peer-datalog >/tmp/build.log 2>&1 \
      || { echo "build failed:"; cat /tmp/build.log; exit 1; }

    "$CARGO_TARGET_DIR/release/entity-peer-datalog" \
      --port "$PORT" --name "$NAME" --debug-open-grants --validate \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill $HOST_PID 2>/dev/null || true" EXIT INT TERM

    # Wait up to 15s for the LISTENING readiness line.
    i=0
    while [ "$i" -lt 150 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "host exited before LISTENING:"; cat /tmp/host.err; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    head -1 /tmp/host.out

    "$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true

    # SURFACE THE STDERR OF THE PEER ITSELF. /tmp/host.err is a path INSIDE a --rm
    # container, so without this the dying words of the peer are discarded with the
    # container and a mid-run abort leaves a log reading only "connection refused".
    # That is not hypothetical: the zig intermittent survived four investigations
    # reported as "no crash, empty stderr" until this line existed on that harness,
    # and then produced a stack trace on the first reproduction. Emitted on stderr so
    # it cannot be mistaken for oracle output, and only when non-empty so a clean run
    # stays quiet.
    if [ -s /tmp/host.err ]; then
      echo "--- peer stderr (/tmp/host.err) ---" >&2
      cat /tmp/host.err >&2
    fi
  ' bash "$@"
