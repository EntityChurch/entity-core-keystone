#!/usr/bin/env bash
# run-s2.sh — S2 (codec / crypto-agility) gate for the turbowarp peer.
#
# THIS PEER HAS NO CODEC OF ITS OWN, AND THAT IS A CLAIM THIS SCRIPT CHECKS RATHER THAN
# ASSERTS. It is a thin block-graph seam over `typescript`: its harness builds and loads the
# TypeScript peer's engine out of protocol-generator/typescript.
# So the codec measured on the S2 axis IS typescript's, and running a second copy of
# typescript's corpus here would measure typescript twice and this peer not at all.
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
#   2. Runs typescript's S2 gate and reports its verdict as this peer's.
#
# Invoke from the HOST, like every sibling:  ./run-s2.sh
# No container re-exec here: typescript/run-s2.sh drives its own.
set -euo pipefail

PEER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(cd "$PEER/../typescript" && pwd)"

echo "=============================================================="
echo " S2 codec gate — entity-core-protocol-turbowarp"
echo " (inherited from typescript; the edge is verified below)"
echo "=============================================================="

echo "── [1/2] inheritance edge ──"
# ANCHOR THE WHOLE ASSIGNMENT, NOT THE SUBSTRING. `grep -q 'protocol-generator/typescript'`
# is satisfied by `protocol-generator/typescriptX` -- so the check was vacuous against
# exactly the mutation it exists to catch, which is what planting it showed (2026-09-08).
# The gate matched, exit 0, "edge verified". Match the full quoted assignment.
if ! grep -qF 'TS="/work/protocol-generator/typescript"' "$PEER/run-s4.sh"; then
  echo "    RED: turbowarp no longer builds its engine from the typescript peer."
  echo "    This peer was treated as having no codec of its own BECAUSE of that edge."
  echo "    If the seam now carries its own codec it needs its own S2 gate, not this one."
  exit 1
fi
echo "    OK: builds its engine from the typescript peer (run-s4.sh)"
echo

echo "── [2/2] delegating to typescript/run-s2.sh ──"
# No pipe: a `| tail` here would report tail's exit status, not the gate's.
set +e
bash "$PARENT/run-s2.sh" "$@"
rc=$?
set -e
echo
echo "=============================================================="
if [ "$rc" -eq 0 ]; then
  echo " S2 GATE: GREEN (inherited from typescript, edge verified)"
  exit 0
fi
echo " S2 GATE: RED (inherited from typescript, rc=$rc)"
exit 1
