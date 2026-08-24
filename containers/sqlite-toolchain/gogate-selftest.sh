#!/usr/bin/env bash
# GO-gate self-test driver — compiles gogate-selftest.c against the pinned SQLite
# amalgamation + libentitycore_codec, then runs it. Baked into the sqlite-toolchain
# image build (RUN gogate-selftest.sh) so the image is only valid if the S1 gate is
# green; also runnable standalone inside the image for re-verification.
#
# Proves, headless: (1) recursive CTE (§5.5 chain-walk primitive), (2) ec_sha256
# callable FROM SQL as an app-defined function (FFI seam + crypto-in-SQL), (3) an
# 8-bit-clean loopback TCP echo incl. 0x00/0xFF. FATAL (exit 1) on any failure.
set -euo pipefail

SQLITE_PREFIX="${SQLITE_PREFIX:-/opt/sqlite}"
CODEC_PREFIX="${CODEC_PREFIX:-/opt/codec}"
SRC="${1:-/usr/local/lib/gogate-selftest.c}"
BIN="$(mktemp)"

gcc -O2 -std=c11 -o "$BIN" \
    "$SRC" \
    "${SQLITE_PREFIX}/sqlite3.c" \
    -I"${SQLITE_PREFIX}" \
    -I"${CODEC_PREFIX}/include" \
    -L"${CODEC_PREFIX}/lib" -lentitycore_codec \
    -lpthread -ldl -lm

export LD_LIBRARY_PATH="${CODEC_PREFIX}/lib:${LD_LIBRARY_PATH:-}"
"$BIN"
RC=$?
rm -f "$BIN"
exit $RC
