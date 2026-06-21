#!/usr/bin/env bash
# Phase S4 — conformance. Points the Go `validate-peer` oracle at a live Ruby
# peer and runs `--profile core` (the keystone gate). The Go validate-peer is a
# fedora:43 ELF binary; it runs INSIDE the ruby-toolchain container alongside the
# peer so oracle + peer share one loopback and the run stays sealed-offline
# (--network=none, loopback only). The peer binds 127.0.0.1:7777 (Ruby's port;
# Go uses 7778) and is started with --debug-open-grants (grant-gated categories
# need it) + --validate (the §7a system/validate/* conformance handlers).
#
#   ./run-s4.sh            # validate-peer --profile core; writes status/CONFORMANCE-REPORT.json
#
# Oracle pin: entity-core-go @75c532e, vendored + built into
# output/s4-oracles/{validate-peer,entity-peer} (gitignored). See
# status/PHASE-S4.md for the build isolation procedure. The §10.2 origination-
# core probe (reference-peer-gated) runs separately via ./run-origination-core.sh.
#
# The gate (binary): `Result: PASS` with summary.failed == 0.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ruby-toolchain:latest"
WORKDIR="/work/protocol-generator/ruby"
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
JSON_OUT="${JSON_OUT:-/work/protocol-generator/ruby/status/CONFORMANCE-REPORT.json}"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    PORT="'"$PORT"'"; ORACLE="'"$ORACLE"'"; JSON_OUT="'"$JSON_OUT"'"
    ruby -Ilib exe/entity-core-peer --port "$PORT" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    trap "kill -9 $HOST_PID 2>/dev/null || true" EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Ruby host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    echo "$(head -1 /tmp/host.out)"
    "$ORACLE" -addr "127.0.0.1:$PORT" -profile core -json-out "$JSON_OUT"
  '
