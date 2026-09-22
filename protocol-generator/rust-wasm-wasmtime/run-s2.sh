#!/usr/bin/env bash
# run-s2.sh — S2 (codec / crypto-agility) gate for the rust-wasm-wasmtime peer.
#
# THIS PEER HAS NO CODEC OF ITS OWN, AND THAT IS A CLAIM THIS SCRIPT CHECKS RATHER THAN
# ASSERTS. It is a thin wasm AOT transport seam over `rust`: Cargo.toml takes the native Rust peer's
# library as an unmodified path dependency and cross-compiles it to wasm (the AOT
# column measures codegen + runtime, never a different interior).
# So the codec measured on the S2 axis IS rust's, and running a second copy of
# rust's corpus here would measure rust twice and this peer not at all.
#
# But "it inherits" is exactly the shape of claim this repo keeps finding to be stale --
# an exclusion that suppresses its own falsifier is permanent by construction, which is
# how `apl` sat out three cohort-wide fix passes behind an UNMEASURABLE label that had
# been false for days. So rather than a per-peer exclusion in the sweep (invisible) or a
# NO-GATE row (indistinguishable from a peer that simply has no gate yet), this file:
#
#   1. VERIFIES THE INHERITANCE EDGE still exists in the tree. If someone forks the
#      codec into this seam, the edge check fails and this gate goes RED -- which is the
#      whole point, because at that moment the peer would have an unmeasured codec.
#   2. Runs rust's S2 gate and reports its verdict as this peer's.
#
# Invoke from the HOST, like every sibling:  ./run-s2.sh
# No container re-exec here: rust/run-s2.sh drives its own.
set -euo pipefail

PEER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(cd "$PEER/../rust" && pwd)"

echo "=============================================================="
echo " S2 codec gate — entity-core-protocol-rust-wasm-wasmtime"
echo " (inherited from rust; the edge is verified below)"
echo "=============================================================="

echo "── [1/2] inheritance edge ──"
if ! grep -q 'entity-core-protocol-rust = { path = "../rust" }' "$PEER/Cargo.toml"; then
  echo "    RED: rust-wasm-wasmtime no longer path-depends on ../rust unmodified."
  echo "    This peer was treated as having no codec of its own BECAUSE of that edge."
  echo "    If the seam now carries its own codec it needs its own S2 gate, not this one."
  exit 1
fi
echo "    OK: path-depends on ../rust unmodified (Cargo.toml)"
echo

echo "── [2/2] delegating to rust/run-s2.sh ──"
# No pipe: a `| tail` here would report tail's exit status, not the gate's.
set +e
bash "$PARENT/run-s2.sh" "$@"
rc=$?
set -e
echo
echo "=============================================================="
if [ "$rc" -eq 0 ]; then
  echo " S2 GATE: GREEN (inherited from rust, edge verified)"
  exit 0
fi
echo " S2 GATE: RED (inherited from rust, rc=$rc)"
exit 1
