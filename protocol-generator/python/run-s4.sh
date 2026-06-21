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
# Oracle pin: entity-core-go @33f35fd, vendored + built into
# output/s4-oracles/{validate-peer,entity-peer} (gitignored). See
# status/PHASE-S4.md for the build isolation procedure. The §10.2 origination-
# core probe (reference-peer-gated) runs separately via ./run-origination-core.sh.
#
# The core image carries only the runtime dep `cryptography` (no pytest); the host
# is driven directly with `PYTHONPATH=src python -m entity_core.host` (the S3
# convention).
#
# The gate (binary): `Result: PASS` with summary.failed == 0 AND the expected
# total (N·0F @ 33f35fd) — a skip is not a pass.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="${IMAGE:-entity-core-keystone/python-toolchain:latest}"
WORKDIR="/work/protocol-generator/python"
PORT="${PORT:-7778}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
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
    "$ORACLE" -addr "127.0.0.1:$PORT" -profile core -json-out "$JSON_OUT"
  '
