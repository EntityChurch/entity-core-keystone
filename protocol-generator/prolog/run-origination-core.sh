#!/usr/bin/env bash
# §10.2 origination-core probe — Prolog target (A-role) against the Go entity-peer
# reference (B-role). Both run inside the prolog-toolchain container (the Go ELFs
# run there too); shared loopback, sealed-offline (--network=none).
#
# Under --profile core the origination category's substantive leg is
# dispatch_outbound_reentry — the validator mints a reentry capability, EXECUTEs
# system/validate/dispatch-outbound on the target, and the target originates an
# outbound EXECUTE back to the validator-as-B over the SAME inbound connection
# (§6.11 reentry; NOT a fresh dial). The Go reference is connected only to satisfy
# the gate's `-reference-peer required` input shape. The target MUST run with
# --validate so system/validate/dispatch-outbound is live; absent it the probe
# honest-SKIPs (which is why the single-peer run-s4.sh SKIPs origination).
#
# Oracle pin: entity-core-go @75c532e (output/s4-oracles/{validate-peer,entity-peer}).
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z -w /work \
#     entity-core-keystone/prolog-toolchain:latest \
#     protocol-generator/prolog/run-origination-core.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PEER="$ROOT/protocol-generator/prolog"
CABI="$ROOT/ffi-generator/c-abi/entity-core-codec-ffi-c"
BUILD="$PEER/build"
TPORT="${TPORT:-7777}"   # target (Prolog)
RPORT="${RPORT:-7778}"   # reference (Go)
NAME="${PEERNAME:-conformance}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"

echo "── building codec + shim (S2 floor) ──"
CODEC_BUILD="$BUILD/cabi"; mkdir -p "$CODEC_BUILD"
cmake -S "$CABI" -B "$CODEC_BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$CODEC_BUILD" --target entitycore_codec -j"$(nproc)" >/dev/null
SO="$(find "$CODEC_BUILD" -name 'libentitycore_codec.so' | head -1)"
SODIR="$(dirname "$SO")"
swipl-ld -shared -o "$PEER/prolog/ec_codec_pl" "$PEER/c/ec_codec_pl.c" -L"$SODIR" -lentitycore_codec
export LD_LIBRARY_PATH="$SODIR:${LD_LIBRARY_PATH:-}"

KPDIR="${HOME:-/root}/.entity/peers/$NAME"; mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# Reference Go peer (B-role), open-access.
"$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!
# Target Prolog host (A-role) — --validate makes system/validate/dispatch-outbound live.
swipl -q -g host_main -t 'halt(0)' "$PEER/prolog/ec_host.pl" -- \
  --port "$TPORT" --name "$NAME" --debug-open-grants --validate >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill -9 $HOST_PID $REF_PID 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 600 ]; do
  grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Prolog host exited:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
sleep 1   # give the Go reference a moment to bind
echo "target(Prolog)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination || true
echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
