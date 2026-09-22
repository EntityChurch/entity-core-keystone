#!/usr/bin/env bash
# run-s2.sh — S2 (codec / crypto-agility) gate for the hand-authored WAT peer.
#
# WHY THIS FILE EXISTS. tools/run-s2-sweep.sh reported this peer NO-GATE, under the
# standing explanation that the hand-authored peers "probably have no separate codec
# suite". That was a hypothesis, and it was wrong. Three authored test MODULES sit in
# src/ and have their own Makefile targets; none was on any swept path:
#
#   wire-test      canonical-CBOR reader/writer round-trip, authored in WAT. THE codec
#                  gate for this peer.
#   identity-test  peer_id + identity_hash KAT across the codec seam.
#   dispatch-test  the §5.2 `peers` grant dimension (peers_scope_ok / is_peer_id_seg),
#                  for which the conformance oracle has ZERO vectors -- so this is the
#                  only regression guard for it in this peer.
#
# Each target runs its merged module under wasmedge and fails on a non-zero exit; the
# assert id IS the exit code (see each src/*-test.wat header for the code table).
#
# Invoke from the HOST, like every sibling:
#   ./run-s2.sh
# It relaunches itself inside the wasm-wat-toolchain container. INCONTAINER=1 skips the
# relaunch. A run-s2.sh that only works inside the container is the prolog trap: a host
# sweep gets `wat2wasm: command not found`, which reads as a broken toolchain and points
# the reader at the tree instead of at the invocation.
set -euo pipefail

if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z -w /work/protocol-generator/wasm-wat \
    entity-core-keystone/wasm-wat-toolchain:latest \
    bash /work/protocol-generator/wasm-wat/run-s2.sh "$@"
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "=============================================================="
echo " S2 codec gate — entity-core-protocol-wasm-wat"
echo "=============================================================="

rc_all=0
run_gate() {
  local name="$1"
  echo "── ${name} ──"
  # No pipe: `make ... | tail` reports tail's status, not make's.
  set +e
  make "$name"
  local rc=$?
  set -e
  echo "    ${name}: rc=${rc}"
  [ "$rc" -ne 0 ] && rc_all=1
  echo
  return 0
}

run_gate ffi-smoke
run_gate wire-test
run_gate identity-test
run_gate dispatch-test

echo "=============================================================="
if [ "$rc_all" -eq 0 ]; then
  echo " S2 GATE: GREEN (ffi seam + wire round-trip + identity KAT + peers scope)"
  exit 0
fi
echo " S2 GATE: RED (see the per-gate rc above)"
exit 1
