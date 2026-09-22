#!/usr/bin/env bash
# run-s2.sh — S2 (codec / crypto-agility) gate for the Unison peer.
#
# WHY THIS FILE EXISTS. tools/run-s2-sweep.sh reported this peer NO-GATE under the
# standing explanation that the hand-authored / managed-runtime peers "probably have no
# separate codec suite". That was a hypothesis and it was wrong: two UCM transcripts
# under transcripts/ are exactly an S2 surface, and neither was on any swept path.
#
#   conformance.md  the ECF conformance CORPUS driven through this peer's codec, with a
#                   sha256 check that the corpus bytes are the ones we think they are.
#                   THE codec gate for this peer.
#   selftest.md     the pinned-invariant units (N1-N4 + fixed-width), which cover the
#                   reject paths a corpus of accept-vectors structurally cannot.
#
# TWO THINGS THIS SCRIPT HAS TO DO THAT A `make test` WOULD NOT:
#
# 1. NOT REWRITE THE TRACKED OUTPUTS. `ucm transcript X.md` writes X.output.md beside
#    it, and transcripts/{conformance,selftest}.output.md are COMMITTED. A gate that
#    dirties the tree every time it runs is a gate people stop running, so the
#    transcripts are copied to a scratch dir and driven from there. cwd stays at the
#    peer root so the `load src/*.u` lines still resolve.
#
# 2. READ THE OUTPUT, NOT THE EXIT CODE. `ucm transcript` exits 0 for a transcript that
#    ran to completion even when the watches inside it printed FAIL -- the assertions
#    are TEXT, not process status. Gating on rc alone would be a gate that passes a red
#    suite, which is the smalltalk `make sunit` defect (it asserted nothing about the
#    counts and reported success beside failures=3). So: require the corpus summary to
#    show every vector passing AND sha_ok, require the failing-id list to be empty, and
#    require no FAIL line anywhere.
#
# Invoke from the HOST, like every sibling:
#   ./run-s2.sh
# It relaunches itself inside the unison-toolchain container. INCONTAINER=1 skips it.
set -euo pipefail

if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z -w /work/protocol-generator/unison \
    localhost/entity-core-keystone/unison-toolchain:latest \
    bash /work/protocol-generator/unison/run-s2.sh "$@"
fi

cd "$(dirname "${BASH_SOURCE[0]}")"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "=============================================================="
echo " S2 codec gate — entity-core-protocol-unison"
echo "=============================================================="

rc_all=0

run_transcript() {
  local name="$1"
  echo "── ${name}.md ──"
  cp "transcripts/${name}.md" "$WORK/${name}.md"
  set +e
  ucm transcript "$WORK/${name}.md" >"$WORK/${name}.ucm" 2>&1
  local rc=$?
  set -e
  local out="$WORK/${name}.output.md"
  if [ "$rc" -ne 0 ] || [ ! -f "$out" ]; then
    echo "    ${name}: ucm rc=${rc}, no output produced"
    tail -30 "$WORK/${name}.ucm" || true
    rc_all=1
    echo
    return 0
  fi
  # The assertions are TEXT, and a ucm transcript ECHOES ITS OWN SOURCE into the output --
  # including the line that DEFINES the checker, `(if ok then "PASS " else "FAIL ")`. A bare
  # search for FAIL therefore matches every transcript, always, and reports a green suite as
  # red. Match the RESULT shape instead: a rendered watch is a quoted "FAIL <label>", so the
  # definition (quote, FAIL, space, quote) cannot match while every real result does.
  local n_pass n_fail
  n_pass=$(grep -cE '"PASS [^"]+"' "$out" || true)
  n_fail=$(grep -cE '"FAIL [^"]+"' "$out" || true)
  # ALWAYS PRINT THE COUNT: a transcript that asserted nothing prints the same word as one
  # that asserted everything, and only the count separates them.
  echo "    ${name}: ${n_pass} pass, ${n_fail} fail"
  if [ "$n_fail" -ne 0 ]; then
    grep -nE '"FAIL [^"]+"' "$out" | head -20 | sed 's/^/        /'
    rc_all=1
  fi
  if [ "$n_pass" -eq 0 ] && [ "$n_fail" -eq 0 ]; then
    echo "        RED: the transcript produced NO assertions at all"
    rc_all=1
  fi
  echo
  return 0
}

run_transcript selftest

# conformance.md additionally reports a machine-checkable summary; assert on it rather
# than on the absence of a word, so a transcript that silently ran ZERO vectors is RED.
# ("PASS n/m sha_ok=true vectors=m" -- a gate that examined nothing prints the same
# word as one that examined every vector; the count is what tells them apart.)
run_transcript conformance
CONF_OUT="$WORK/conformance.output.md"
if [ -f "$CONF_OUT" ]; then
  echo "── corpus summary ──"
  SUMMARY="$(grep -oE 'PASS [0-9]+/[0-9]+[^"]*' "$CONF_OUT" | tail -1 || true)"
  echo "    ${SUMMARY:-<no summary line found>}"
  got="$(printf '%s' "$SUMMARY" | sed -nE 's|^PASS ([0-9]+)/([0-9]+).*|\1|p')"
  want="$(printf '%s' "$SUMMARY" | sed -nE 's|^PASS ([0-9]+)/([0-9]+).*|\2|p')"
  if [ -z "$got" ] || [ -z "$want" ]; then
    echo "    RED: no parseable corpus summary — the gate examined nothing"
    rc_all=1
  elif [ "$want" -eq 0 ]; then
    echo "    RED: corpus reported 0 vectors — the gate examined nothing"
    rc_all=1
  elif [ "$got" != "$want" ]; then
    echo "    RED: ${got}/${want} corpus vectors passed"
    rc_all=1
  else
    echo "    OK: ${got}/${want} corpus vectors"
  fi
  if ! grep -q 'sha_ok=true' "$CONF_OUT"; then
    echo "    RED: corpus sha256 mismatch (sha_ok != true) — the vendored bytes moved"
    rc_all=1
  fi
  echo
fi

echo "=============================================================="
if [ "$rc_all" -eq 0 ]; then
  echo " S2 GATE: GREEN (ECF corpus + pinned-invariant self-tests)"
  exit 0
fi
echo " S2 GATE: RED (see above)"
exit 1
