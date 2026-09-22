#!/usr/bin/env bash
# run-s2.sh — S2 (codec / crypto-agility) gate for the asm-x86_64 peer.
#
# WHY THIS FILE EXISTS. This peer had a real, substantial codec test surface and no
# entry point on the swept path, so tools/run-s2-sweep.sh reported it NO-GATE and the
# standing explanation was "the hand-authored peers probably have no separate codec
# suite". That was a hypothesis, and it was wrong: `make diff` is an L2 native-codec
# DIFFERENTIAL against the 3-way-locked (Go x Rust x Python) conformance corpus --
# status/PHASE-L2.md records it at 71 corpus vectors + 4 synthetic, 0 FAIL -- which is
# exactly the axis S2 measures. It had simply never been wired to a cohort runner.
#
# The four gates, and what each is FOR (they do not overlap):
#   ffi-smoke        the asm -> C-ABI seam itself (ec_sha256 KAT). If this is red the
#                    other three are measuring nothing.
#   diff             the native canonical-CBOR encoder vs the pinned corpus goldens.
#                    THE codec gate for this peer.
#   parse-test       ec_peerid_parse accept + reject. The corpus has no peer-id PARSE
#                    vector (peer_id.N are encode_equal only), so nothing else covers it.
#   peers-scope-test the §5.2 `peers` grant dimension, which the conformance oracle has
#                    ZERO vectors for (shared/findings/peers-grant-dimension-oracle-gap.md).
#
# Invoke from the HOST, like every sibling:
#   ./run-s2.sh
# It relaunches itself inside the asm-x86_64-toolchain container. INCONTAINER=1 skips
# the relaunch. A run-s2.sh that only works inside the container is the prolog trap:
# a host sweep gets `as: command not found`, which reads as a broken toolchain and
# points the reader at the tree instead of at the invocation.
set -euo pipefail

if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z -w /work/protocol-generator/asm-x86_64 \
    entity-core-keystone/asm-x86_64-toolchain:latest \
    bash /work/protocol-generator/asm-x86_64/run-s2.sh "$@"
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

echo "=============================================================="
echo " S2 codec gate — entity-core-protocol-asm-x86_64"
echo "=============================================================="
as --version | head -1
cc --version | head -1
echo

rc_all=0
run_gate() {
  local name="$1"
  echo "── ${name} ──"
  # No pipe: `make ... | tail` would report tail's status, which is the defect that
  # once made a five-peer verification loop print rc=0 for two peers that had failed.
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
run_gate diff
run_gate parse-test
run_gate peers-scope-test

echo "=============================================================="
if [ "$rc_all" -eq 0 ]; then
  echo " S2 GATE: GREEN (ffi-smoke + corpus differential + peerid parse + peers scope)"
  exit 0
fi
echo " S2 GATE: RED (see the per-gate rc above)"
exit 1
