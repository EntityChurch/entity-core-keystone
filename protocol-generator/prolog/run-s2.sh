#!/usr/bin/env bash
# run-s2.sh — S2-FFI build + gate for the Prolog peer. Runs INSIDE the
# prolog-toolchain container (S1: builds run in containers, not on the host).
#
# Steps:
#   1. Build libentitycore_codec.{so,a} from the C-ABI CMake (libsodium static).
#   2. Compile the SWI foreign shim c/ec_codec_pl.c → ec_codec_pl.so with
#      swipl-ld, linking -lentitycore_codec.
#   3. Run the 69-vector wire-conformance corpus through the foreign codec.
#   4. Run the crypto KAT (Ed25519/Ed448/SHA-256/384) pins.
#
# Invoke from the repo root (the mount point /work) on the host:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none -v "$PWD":/work:Z -w /work \
#     entity-core-keystone/prolog-toolchain:latest \
#     protocol-generator/prolog/run-s2.sh
#
# All paths are relative to the repo root (/work).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # repo root (/work)
PEER="$ROOT/protocol-generator/prolog"
CABI="$ROOT/ffi-generator/c-abi/entity-core-codec-ffi-c"
CORPUS="$ROOT/protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"
BUILD="$PEER/build"

echo "=============================================================="
echo " S2-FFI build + gate — entity-core-protocol-prolog"
echo "=============================================================="
swipl --version
echo "openssl: $(openssl version)"
echo

# ── 1. Build the C-ABI codec library ────────────────────────────────────────
echo "── [1/4] building libentitycore_codec (C-ABI v1.1) ──"
CODEC_BUILD="$BUILD/cabi"
mkdir -p "$CODEC_BUILD"
cmake -S "$CABI" -B "$CODEC_BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$CODEC_BUILD" --target entitycore_codec -j"$(nproc)" >/dev/null
SO="$(find "$CODEC_BUILD" -name 'libentitycore_codec.so' | head -1)"
test -n "$SO" || { echo "FATAL: libentitycore_codec.so not built"; exit 1; }
echo "    built: $SO"
echo

# ── 2. Compile the SWI foreign shim ─────────────────────────────────────────
echo "── [2/4] compiling SWI foreign shim (ec_codec_pl.so) ──"
SODIR="$(dirname "$SO")"
swipl-ld -shared -o "$PEER/prolog/ec_codec_pl" \
    "$PEER/c/ec_codec_pl.c" \
    -L"$SODIR" -lentitycore_codec
echo "    built: $PEER/prolog/ec_codec_pl.so"
# the shim dlopens libentitycore_codec at runtime; expose its dir.
export LD_LIBRARY_PATH="$SODIR:${LD_LIBRARY_PATH:-}"
echo "    LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo

# ── 3. Wire-conformance gate (69 vectors) ───────────────────────────────────
echo "── [3/4] wire-conformance corpus (69 vectors) ──"
set +e
swipl -q -g run_conformance_tests -t 'halt(2)' \
      "$PEER/test/run_conformance.pl" "$CORPUS"
CONF_RC=$?
set -e
echo

# ── 4. Crypto KAT gate ──────────────────────────────────────────────────────
echo "── [4/4] crypto KAT (Ed25519 / Ed448 / SHA-256 / SHA-384) ──"
set +e
swipl -q -g run_kats -t 'halt(2)' "$PEER/test/agility_kat.pl"
KAT_RC=$?
set -e
echo

echo "=============================================================="
echo " conformance rc=$CONF_RC   kat rc=$KAT_RC"
if [ "$CONF_RC" -eq 0 ] && [ "$KAT_RC" -eq 0 ]; then
    echo " S2-FFI GATE: GREEN"
    exit 0
else
    echo " S2-FFI GATE: RED (see failures above)"
    exit 1
fi
