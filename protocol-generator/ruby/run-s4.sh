#!/usr/bin/env bash
# Phase S4 — conformance. Points the Go `validate-peer` oracle at a live Ruby
# peer and runs `--profile core` (the keystone gate). The Go validate-peer is a
# fedora:43 ELF binary; it runs INSIDE the ruby-toolchain container alongside the
# peer so oracle + peer share one loopback and the run stays sealed-offline
# (--network=none, loopback only). The peer binds 127.0.0.1:7777 (Ruby's port;
# Go uses 7778) and is started with --debug-open-grants (grant-gated categories
# need it) + --validate (the §7a system/validate/* conformance handlers).
#
#   ./run-s4.sh            # validate-peer --profile core; writes the JSON report (scratch by default; see JSON_OUT below)
#
# Oracle pin: entity-core-go at the pinned oracle digest, vendored + built into
# output/s4-oracles/{validate-peer,entity-peer} (gitignored). See
# status/PHASE-S4.md for the build isolation procedure. The §10.2 origination-
# core probe (reference-peer-gated) runs separately via ./run-origination-core.sh.
#
# The gate (binary): `Result: PASS` with summary.failed == 0.
#
# JSON_OUT — WHERE A BARE RUN WRITES ITS REPORT (changed 2026-09-08)
# A bare `./run-s4.sh` used to default `-json-out` to this peer's TRACKED
# status/CONFORMANCE-REPORT.json — the signed-off record the matrix publishes — so a
# human diagnostic run silently republished a number nobody had reviewed. The default is
# now a scratch path. To refresh the tracked report, MEASURE it deliberately:
#     tools/run-cohort-census.sh --to-status <peer>       (preferred)
#     JSON_OUT=<path> ./run-s4.sh                          (explicit)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ruby-toolchain:latest"
WORKDIR="/work/protocol-generator/ruby"
PORT="${PORT:-7777}"
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
JSON_OUT="${JSON_OUT:-/tmp/ec-s4-ruby.json}"

podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
  bash -c '
    set -eu
    PORT="'"$PORT"'"; ORACLE="'"$ORACLE"'"; JSON_OUT="'"$JSON_OUT"'"
    # Provision the peer keypair at ~/.entity/peers/conformance/keypair (seed
    # 0x11×32, base64 "ERER…") so the validator can co-sign AS the peer for the
    # §3.6 multisig accept-path probe (valid_2of3_peer_signed_accepted). The peer
    # boots --name conformance and loads this same seed → matching peer_id.
    KPDIR="${HOME:-/root}/.entity/peers/conformance"
    mkdir -p "$KPDIR"
    printf "%s\n%s\n%s\n" \
      "-----BEGIN ENTITY PRIVATE KEY-----" \
      "ERERERERERERERERERERERERERERERERERERERERERE=" \
      "-----END ENTITY PRIVATE KEY-----" > "$KPDIR/keypair"
    ruby -Ilib exe/entity-core-peer --port "$PORT" --name conformance --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
    HOST_PID=$!
    # Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
    # trap returns while the peer still owns the listening socket and a second invocation
    # in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
    # accepting connections AFTER the harness had exited: elixir >400ms (and the next run
    # did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
    # property of the peer runtime, not of the harness, which is why every peer carries
    # this and not only the ones that were seen to fail.
    reap_host() {
      if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
      [ -n "${HOST_PID:-}" ] || return 0
      # SIGKILL is preserved from the original teardown, which chose -9 deliberately; the
      # fix here is the wait, which is what makes the port released before we return.
      kill -9 "$HOST_PID" 2>/dev/null || true
      wait "$HOST_PID" 2>/dev/null || true
    }
    trap reap_host EXIT INT TERM
    i=0; while [ "$i" -lt 300 ]; do
      grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
      kill -0 "$HOST_PID" 2>/dev/null || { echo "Ruby host exited:"; cat /tmp/host.err >&2; exit 1; }
      i=$((i+1)); sleep 0.1
    done
    echo "$(head -1 /tmp/host.out)"
    # Forward the CALLER ARGS. This line used to hardcode the profile and json-out and
    # drop "$@", so `run-s4.sh -category connectivity` silently ran the whole 756-check
    # suite AND rewrote the tracked, signed-off CONFORMANCE-REPORT.json -- a diagnostic
    # run overwriting the record it is meant to be diagnosed against. The trailing
    # `bash "$@"` after the -c script is what carries argv across the podman boundary
    # with its quoting intact (sql/io/pd/datalog already did it that way -- the word
    # bash is argv[0], and the caller args land as $1.. inside the block).
    if [ "$#" -eq 0 ]; then set -- -profile core -json-out "$JSON_OUT"; fi
    . /work/protocol-generator/shared/tools/refpeer.sh
    refpeer_up
    rc=0; "$ORACLE" -addr "127.0.0.1:$PORT" $REFPEER_FLAG "$@" || rc=$?

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
  ' bash "$@"
