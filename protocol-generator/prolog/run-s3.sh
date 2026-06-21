#!/usr/bin/env bash
# run-s3.sh — S3 peer-machinery gate for the Prolog peer. Runs INSIDE the
# prolog-toolchain container (S1: builds run in containers, not on the host),
# sealed-offline (--network=none, loopback only).
#
# Steps:
#   1. Build libentitycore_codec.so (C-ABI v1.1) + the SWI foreign shim (S2 floor).
#   2. Type-registry gate: render all 53 core types (§9.5) + diff content_hash
#      against the canonical type-registry-vectors-v1.diag (53/53 byte-identical).
#   3. Two-peer loopback smoke gate (11/11): boot a responder peer, drive the §4.1
#      handshake + core ops over real loopback TCP from an initiator peer.
#
# Invoke from the repo root (the mount point /work) on the host:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z -w /work \
#     entity-core-keystone/prolog-toolchain:latest \
#     protocol-generator/prolog/run-s3.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # repo root (/work)
PEER="$ROOT/protocol-generator/prolog"
CABI="$ROOT/ffi-generator/c-abi/entity-core-codec-ffi-c"
DIAG="$ROOT/protocol-generator/shared/test-vectors/v0.8.0/type-registry-vectors-v1.diag"
BUILD="$PEER/build"

echo "=============================================================="
echo " S3 peer-machinery gate — entity-core-protocol-prolog"
echo "=============================================================="
swipl --version
echo

# ── 1. Build the C-ABI codec library + foreign shim ─────────────────────────
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

# ── 2. Type-registry gate (53/53) ────────────────────────────────────────────
echo "── [2/3] type-registry (53 core types, §9.5) ──"
set +e
swipl -q -g run_type_registry_main -t 'halt(2)' "$PEER/test/type_registry.pl" -- "$DIAG"
TR_RC=$?
set -e
echo

# ── 3. Two-peer loopback smoke gate (11/11) ──────────────────────────────────
echo "── [3/3] two-peer loopback smoke (11 checks) ──"
set +e
swipl -q -g run_smoke_main -t 'halt(2)' "$PEER/test/smoke.pl"
SMOKE_RC=$?
set -e
echo

echo "=============================================================="
echo " type-registry rc=$TR_RC   smoke rc=$SMOKE_RC"
if [ "$TR_RC" -eq 0 ] && [ "$SMOKE_RC" -eq 0 ]; then
    echo " S3 GATE: GREEN"
    exit 0
else
    echo " S3 GATE: RED (see failures above)"
    exit 1
fi
