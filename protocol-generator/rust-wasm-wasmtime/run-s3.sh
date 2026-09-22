#!/usr/bin/env bash
# run-s3.sh — S3 (two-peer loopback interop) gate for the rust-wasm-wasmtime peer.
#
# THIS PEER HAS NO PEER MACHINERY OF ITS OWN, AND THAT IS A CLAIM THIS SCRIPT CHECKS
# RATHER THAN ASSERTS. It is a thin seam over `rust`, so the dialer and the dispatch
# chain the S3 axis exists to drive ARE rust's, and running a second copy of rust's
# smoke here would measure rust twice and this peer not at all.
#
# But "it inherits" is exactly the shape of claim this repo keeps finding stale, and a
# NO-GATE row is indistinguishable from a peer that simply has no gate yet — which is how
# 28 peers sat outside the S3 axis while two of them carried a broken dialer nothing ran.
# So, exactly as this peer's run-s2.sh already does for the codec:
#
#   1. VERIFY THE INHERITANCE EDGE still exists. Fork the machinery into this seam and
#      this gate goes RED — which is the point, because at that moment the peer would
#      have an unmeasured dialer.
#   2. Run rust's S3 gate and report its verdict as this peer's.
#
# Invoke from the HOST, like every sibling:  ./run-s3.sh
# No container re-exec here: rust/run-s3.sh drives its own.
set -euo pipefail

PEER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(cd "$PEER/../rust" && pwd)"

echo "=============================================================="
echo " S3 peer-machinery gate — entity-core-protocol-rust-wasm-wasmtime"
echo " (inherited from rust; the edge is verified below)"
echo "=============================================================="

echo "── [1/2] inheritance edge ──"
if ! grep -q 'entity-core-protocol-rust = { path = "../rust" }' "$PEER/Cargo.toml"; then
  echo "    RED: rust-wasm-wasmtime no longer path-depends on ../rust unmodified."
  echo "    This peer was treated as having no peer machinery of its own BECAUSE of that edge."
  exit 1
fi
echo "    OK: path-depends on ../rust unmodified (Cargo.toml)"
echo

echo "── [2/2] delegating to rust/run-s3.sh ──"
# No pipe: a `| tail` here would report tail's exit status, not the gate's.
set +e
"$PARENT/run-s3.sh"
rc=$?
set -e
echo
if [ "$rc" -eq 0 ]; then
  echo " S3 GATE: GREEN (inherited from rust; edge verified)"
else
  echo " S3 GATE: RED (inherited from rust; rust/run-s3.sh exited $rc)"
fi
exit "$rc"
