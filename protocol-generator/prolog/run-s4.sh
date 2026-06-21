#!/usr/bin/env bash
# run-s4.sh — S4 conformance gate for the Prolog peer. Points the Go
# `validate-peer` oracle (a fedora ELF, entity-core-go @75c532e, vendored into
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
# Oracle pin: entity-core-go @75c532e (BuildID 482ee754…). The §10.2 origination-
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
JSON_OUT="${JSON_OUT:-$PEER/status/CONFORMANCE-REPORT.json}"

echo "=============================================================="
echo " S4 conformance gate — entity-core-protocol-prolog"
echo " oracle: entity-core-go @75c532e ($ORACLE)"
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
trap 'kill -9 $HOST_PID 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 600 ]; do
  grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Prolog host exited before LISTENING:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
grep -q "^LISTENING" /tmp/host.out 2>/dev/null || { echo "host never reached LISTENING"; cat /tmp/host.err >&2; exit 1; }
head -1 /tmp/host.out

RC=0
# -timeout: the per-run budget. security (~20s) + concurrency (~38s) blow the
# default; give the full core sweep ample headroom so no category budget-SKIPs.
"$ORACLE" -addr "127.0.0.1:$PORT" -profile core -timeout "${ORACLE_TIMEOUT:-180s}" \
  -json-out "$JSON_OUT" || RC=$?

echo
echo "=== host stderr (tail) ==="
tail -20 /tmp/host.err 2>/dev/null || true
echo "=============================================================="
echo " validate-peer exit rc=$RC ; JSON: $JSON_OUT"
exit "$RC"
