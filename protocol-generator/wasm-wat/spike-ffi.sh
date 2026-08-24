#!/bin/sh
# spike-ffi.sh — run the increment-2 codec-seam KAT (SHA-256("abc")) under WasmEdge and
# interpret the exit code. Proves the compiled Rust codec.wasm links into the hand-authored
# WAT interior over one shared memory on a stock runtime (no native host, no Component Model).
set -u
MOD="${1:-out/ffismoke.combined.wasm}"

wasmedge "$MOD"
rc=$?
case "$rc" in
  0)  echo "codec-seam KAT: PASS  (ec_sha256(\"abc\") == known digest, via merged codec.wasm)"
      echo "SPIKE PASS — hand-authored WAT + compiled Rust codec share one memory on stock WasmEdge." ;;
  10) echo "FAIL: ec_sha256 returned a nonzero (codec) error"; exit 1 ;;
  20) echo "FAIL: digest mismatch — the seam is wired but the bytes are wrong (memory/ABI issue)"; exit 1 ;;
  *)  echo "FAIL: unexpected exit $rc (trap/instantiation error — likely shared-memory or import wiring)"; exit 1 ;;
esac
