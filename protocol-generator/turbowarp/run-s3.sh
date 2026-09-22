#!/usr/bin/env bash
# run-s3.sh — S3 (two-peer loopback interop) gate for the turbowarp peer.
#
# THIS PEER HAS NO PEER MACHINERY OF ITS OWN, AND THAT IS A CLAIM THIS SCRIPT CHECKS
# RATHER THAN ASSERTS. It is a thin seam over `typescript`, so the dialer and the dispatch
# chain the S3 axis exists to drive ARE typescript's, and running a second copy of typescript's
# smoke here would measure typescript twice and this peer not at all.
#
# But "it inherits" is exactly the shape of claim this repo keeps finding stale, and a
# NO-GATE row is indistinguishable from a peer that simply has no gate yet — which is how
# 28 peers sat outside the S3 axis while two of them carried a broken dialer nothing ran.
# So, exactly as this peer's run-s2.sh already does for the codec:
#
#   1. VERIFY THE INHERITANCE EDGE still exists. Fork the machinery into this seam and
#      this gate goes RED — which is the point, because at that moment the peer would
#      have an unmeasured dialer.
#   2. Run typescript's S3 gate and report its verdict as this peer's.
#
# Invoke from the HOST, like every sibling:  ./run-s3.sh
# No container re-exec here: typescript/run-s3.sh drives its own.
set -euo pipefail

PEER="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT="$(cd "$PEER/../typescript" && pwd)"

echo "=============================================================="
echo " S3 peer-machinery gate — entity-core-protocol-turbowarp"
echo " (inherited from typescript; the edge is verified below)"
echo "=============================================================="

echo "── [1/2] inheritance edge ──"
# ANCHOR THE WHOLE ASSIGNMENT, NOT THE SUBSTRING. `grep -q 'protocol-generator/typescript'`
# is satisfied by `protocol-generator/typescriptX` -- so the check was vacuous against
# exactly the mutation it exists to catch, which is what planting it showed (2026-09-08).
# The gate matched, exit 0, "edge verified". Match the full quoted assignment.
if ! grep -qF 'TS="/work/protocol-generator/typescript"' "$PEER/run-s4.sh"; then
  echo "    RED: turbowarp no longer builds its engine from ../typescript."
  echo "    This peer was treated as having no peer machinery of its own BECAUSE of that edge."
  exit 1
fi
echo "    OK: builds its engine from ../typescript (run-s4.sh)"
echo

echo "── [2/2] delegating to typescript/run-s3.sh ──"
# No pipe: a `| tail` here would report tail's exit status, not the gate's.
set +e
"$PARENT/run-s3.sh"
rc=$?
set -e
echo
if [ "$rc" -eq 0 ]; then
  echo " S3 GATE: GREEN (inherited from typescript; edge verified)"
else
  echo " S3 GATE: RED (inherited from typescript; typescript/run-s3.sh exited $rc)"
fi
exit "$rc"
