#!/usr/bin/env bash
# run-s4.sh — S4 conformance gate for the Prolog peer. Points the Go
# `validate-peer` oracle (a fedora ELF, entity-core-go at the pinned oracle digest, vendored into
# output/s4-oracles/) at a LIVE Prolog peer host and runs `--profile core` (the
# keystone gate). Oracle + peer share ONE loopback inside the prolog-toolchain
# container, sealed-offline (--network=none) — the established S4 isolation rule.
#
# Steps (all in-container):
#   1. Build libentitycore_codec.so (C-ABI v1.1) + the SWI foreign shim (S2 floor).
#   2. Provision the peer's persistent identity at ~/.entity/peers/NAME/keypair
#      (seed 0x11×32, base64 "ERER…") so the validator's multisig accept-path
#      probe (valid_2of3_peer_signed_accepted) can co-sign AS the peer (§3.6 K-of-N).
#   3. Boot the Prolog host (--port --debug-open-grants --validate), wait for its
#      `LISTENING …` line.
#   4. validate-peer -addr 127.0.0.1:PORT -profile core -json-out … ; tear down.
#
# Oracle pin: entity-core-go at the pinned oracle digest (BuildID 482ee754…). The §10.2 origination-
# core probe (reference-peer-gated) runs separately via ./run-origination-core.sh.
#
# Invoke from the repo root (the mount point /work) on the host:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z -w /work \
#     entity-core-keystone/prolog-toolchain:latest \
#     protocol-generator/prolog/run-s4.sh
#
# The gate (binary): `Result: PASS` with summary.failed == 0.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # repo root (/work)
PEER="$ROOT/protocol-generator/prolog"
CABI="$ROOT/ffi-generator/c-abi/entity-core-codec-ffi-c"
BUILD="$PEER/build"
PORT="${PORT:-7777}"
NAME="${PEERNAME:-conformance}"
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
JSON_OUT="${JSON_OUT:-$PEER/status/CONFORMANCE-REPORT.json}"

echo "=============================================================="
echo " S4 conformance gate — entity-core-protocol-prolog"
echo " oracle: entity-core-go at the pinned oracle digest ($ORACLE)"
echo "=============================================================="
swipl --version
echo

# ── 1. Build the C-ABI codec library + foreign shim (S2 floor) ──────────────
echo "── [1/3] building libentitycore_codec + SWI foreign shim ──"
CODEC_BUILD="$BUILD/cabi"
mkdir -p "$CODEC_BUILD"
cmake -S "$CABI" -B "$CODEC_BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$CODEC_BUILD" --target entitycore_codec -j"$(nproc)" >/dev/null
SO="$(find "$CODEC_BUILD" -name 'libentitycore_codec.so' | head -1)"
test -n "$SO" || { echo "FATAL: libentitycore_codec.so not built"; exit 1; }
SODIR="$(dirname "$SO")"
swipl-ld -shared -o "$PEER/prolog/ec_codec_pl" "$PEER/c/ec_codec_pl.c" -L"$SODIR" -lentitycore_codec
export LD_LIBRARY_PATH="$SODIR:${LD_LIBRARY_PATH:-}"
echo "    codec + shim built; LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo

# ── 2. Provision the peer's persistent identity (§3.6 multisig accept-path) ──
echo "── [2/3] provisioning peer keypair (~/.entity/peers/$NAME/keypair) ──"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"
echo "    keypair at $KPDIR/keypair (seed 0x11×32)"
echo

# ── 3. Boot the host + run validate-peer --profile core ─────────────────────
echo "── [3/3] booting host + validate-peer --profile core ──"
test -x "$ORACLE" || { echo "FATAL: oracle not found/executable: $ORACLE"; exit 1; }
mkdir -p "$(dirname "$JSON_OUT")"

swipl -q -g host_main -t 'halt(0)' "$PEER/prolog/ec_host.pl" -- \
  --port "$PORT" --name "$NAME" --debug-open-grants --validate \
  >/tmp/host.out 2>/tmp/host.err &
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

i=0; while [ "$i" -lt 600 ]; do
  grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Prolog host exited before LISTENING:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
grep -q "^LISTENING" /tmp/host.out 2>/dev/null || { echo "host never reached LISTENING"; cat /tmp/host.err >&2; exit 1; }
head -1 /tmp/host.out

RC=0
# Forward the CALLER ARGS. This line used to hardcode its whole argument list and drop
# "$@", so `run-s4.sh -category connectivity` silently ran the full 756-check suite and
# rewrote the tracked, signed-off CONFORMANCE-REPORT.json -- a diagnostic run
# overwriting the record it is meant to be diagnosed against. 38 of 46 peers already
# honoured "$@"; this is one of the three that did not.
#
# -timeout stays inside the DEFAULT rather than ahead of "$@", so a caller supplying
# args gets the oracle's own budget and can set whatever it needs. That is safe in the
# direction that matters: this 180s was written against an older 60s oracle default and
# the current pin defaults to 10m (verified: `validate-peer -h`), so dropping it widens
# the budget rather than starving a category.
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout "${ORACLE_TIMEOUT:-180s}" -json-out "$JSON_OUT"
fi
. /work/protocol-generator/shared/tools/refpeer.sh
refpeer_up
"$ORACLE" -addr "127.0.0.1:$PORT" $REFPEER_FLAG "$@" || RC=$?

echo
echo "=== host stderr (tail) ==="
tail -20 /tmp/host.err 2>/dev/null || true
echo "=============================================================="
echo " validate-peer exit rc=$RC ; JSON: $JSON_OUT"
exit "$RC"
