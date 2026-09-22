#!/usr/bin/env bash
# Phase S4 — conformance. Points the Go `validate-peer` oracle at a live Python
# peer and runs `--profile core` (the keystone gate). The Go validate-peer is a
# fedora:43 ELF binary; it runs INSIDE the python-toolchain container alongside
# the peer so oracle + peer share one loopback and the run stays sealed-offline
# (--network=none, loopback only). The peer binds 127.0.0.1:7778 (Python's port;
# the concurrent Rust S4 uses 7777) and is started with --debug-open-grants
# (grant-gated categories need it) + --validate (the §7a system/validate/*
# conformance handlers).
#
#   ./run-s4.sh            # validate-peer --profile core; writes status/CONFORMANCE-REPORT.json
#
# Oracle pin: entity-core-go at the pinned oracle digest, vendored + built into
# output/s4-oracles/{validate-peer,entity-peer} (gitignored). See
# status/PHASE-S4.md for the build isolation procedure. The §10.2 origination-
# core probe (reference-peer-gated) runs separately via ./run-origination-core.sh.
#
# The core image carries only the runtime dep `cryptography` (no pytest); the host
# is driven directly with `PYTHONPATH=src python -m entity_core.host` (the S3
# convention).
#
# The gate (binary): `Result: PASS` with summary.failed == 0 AND the expected
# total (N·0F @ <content digest>) — a skip is not a pass.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="${IMAGE:-entity-core-keystone/python-toolchain:latest}"
WORKDIR="/work/protocol-generator/python"
PORT="${PORT:-7778}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness — but that also swallowed a MISSING
# binary, and the script exited 0 having validated nothing. Measured 2026-08-23: a
# fresh clone with no sibling entity-core-go printed one "No such file or directory"
# line and exited 0, i.e. the documented Quick-start command appeared to succeed.
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
JSON_OUT="${JSON_OUT:-/work/protocol-generator/python/status/CONFORMANCE-REPORT.json}"
# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can
# find the peer's keypair and co-sign AS the peer — exercising genuine K-of-N
# instead of env-skipping. The seed (0x11 x 32, base64 "ERER…") matches the cohort
# conformance seed → peer_id 2KHoAk…. NAME follows the Go entity-peer /
# peer-manager convention: ~/.entity/peers/NAME/keypair.
PEERNAME="${PEERNAME:-conformance}"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    PORT="'"$PORT"'"; ORACLE="'"$ORACLE"'"; JSON_OUT="'"$JSON_OUT"'"; PEERNAME="'"$PEERNAME"'"
    KPDIR="${HOME:-/root}/.entity/peers/$PEERNAME"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"

    PYTHONPATH=src python -m entity_core.host \
      --port "$PORT" --name "$PEERNAME" --debug-open-grants --validate \
      >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill -9 $HOST_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Python host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    echo "$(head -1 /tmp/host.out)"
    rc=0; "$ORACLE" -addr "127.0.0.1:$PORT" -profile core -json-out "$JSON_OUT" || rc=$?

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
    exit "$rc"
  '
