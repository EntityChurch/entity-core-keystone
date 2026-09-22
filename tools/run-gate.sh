#!/usr/bin/env bash
# run-gate.sh — THE gate. Every verification axis, one command, one verdict.
#
# WHY THIS EXISTS
#   Until 2026-09-03 there was no such command. `make check` was `lint` plus a
#   `test` target that printed a paragraph explaining that per-language
#   verification happens somewhere else. So "run the gate" meant a person
#   remembering four different runners, and three of the four had no runner at
#   all until 2026-09-02. That is how a tree publishing 46 of 46 at `756 · 0F`
#   was simultaneously carrying 21 failures on two unswept axes.
#
#   There is no "re-run S2" or "re-run S3" as a separate act. There is this.
#
# WHAT IT RUNS, AND WHERE EACH PIECE GETS ITS AUTHORITY
#   Provenance matters here because keystone does not author conformance
#   (GUIDE-CONFORMANCE.md §7.0: "entity-core-keystone authors none of these").
#   Three of the four axes are consumption of somebody else's ground truth:
#
#     lint         our own static gates (spec-data pins, published anchors,
#                  link integrity, coherence, container recipes, harness shape)
#     S2           architecture's ECF + crypto-agility fixture corpora, vendored
#                  byte-identical and digest-pinned (guide §2, §6), plus our own
#                  DERIVED type-registry drift target (labelled non-normative)
#     S4           the validate-peer oracle, --profile core, authored by
#                  entity-core-go (guide §7.0 row 1), pinned by content digest
#     origination  THE SAME ORACLE — `-category origination -reference-peer`.
#                  Not a separate suite: it is the category a single-peer census
#                  structurally cannot reach, because it needs a second peer.
#     S3           OURS. Hand-written loopback smoke assertions, 17 of 18 with no
#                  oracle behind them. Legitimate under the guide's third row
#                  (impl-internal tests, "that repo, its own concern") but it is
#                  NOT conformance and must not be reported as though it were.
#                  See docs/STATUS.md for the open question about replacing it
#                  with the oracle's own live-peer matrix (`validate-peer -peers`,
#                  guide §7 — a surface this repo has never once run).
#
# WALL CLOCK
#   The census dominates: ~2-4 h for 46 peers. The three sweeps are minutes each
#   once the images are warm. `--sweeps-only` skips the census when you want the
#   fast three; it is a convenience, not a gate, and it says so in its verdict.
#
# THE SWEEPS RUN SEQUENTIALLY AND NOTHING ELSE MAY TOUCH THE TREE
#   Every peer container mounts the repo root with `:Z`, a PRIVATE SELinux label.
#   Two containers doing that concurrently relabel each other's mount. Measured:
#   a 3-peer census running alongside a sweep produced a false RED on kotlin and
#   a 20-minute false hang on java, both green in isolation. Do not parallelise
#   these, and do not run anything else against the tree while this runs.
#
# EXIT
#   0  every axis green
#   1  at least one axis failed — the summary names which
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

SWEEPS_ONLY=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --sweeps-only) SWEEPS_ONLY=1; shift ;;
    -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
done

OUT="$REPO_ROOT/output/scratch/gate"
mkdir -p "$OUT"

declare -a NAMES=() RESULTS=() DETAILS=()
overall=0

stage() { # <label> <logfile> <command...>
  local label="$1" log="$2"; shift 2
  echo
  echo "=============================================================="
  echo "GATE STAGE: $label"
  echo "=============================================================="
  "$@" 2>&1 | tee "$log"
  local rc=${PIPESTATUS[0]}   # never the tee -- a `cmd | tee` reports tee.
  NAMES+=("$label")
  if [ "$rc" -eq 0 ]; then RESULTS+=("GREEN"); else RESULTS+=("FAILED"); overall=1; fi
  # Carry the sweep's own count line into the summary, so this gate cannot print
  # a verdict without printing how many things produced it.
  # [a-z0-9-], not [a-z-]: the axis keys are `s2` and `s3`, and a character class
  # with no digit in it silently matched only `origination-sweep`. The verdict
  # printed two axes with no count beside them, which is this repo's own
  # examined-zero-things defect committed inside the summary that exists to
  # prevent it. Caught by running the gate, not by reading it.
  DETAILS+=("$(grep -hoE '[a-z0-9-]+-sweep: [0-9]+ peer\(s\) attempted — .*' "$log" | tail -1)")
  return 0
}

stage "lint (static gates)"        "$OUT/lint.log"        make lint
stage "S2 codec / crypto-agility"  "$OUT/s2.log"          bash tools/run-axis-sweep.sh s2 --gate
stage "S3 loopback interop"        "$OUT/s3.log"          bash tools/run-axis-sweep.sh s3 --gate
stage "origination (oracle)"       "$OUT/origination.log" bash tools/run-axis-sweep.sh origination --gate

if [ "$SWEEPS_ONLY" -eq 0 ]; then
  stage "S4 conformance census"    "$OUT/s4.log"          bash tools/run-cohort-census.sh
fi

echo
echo "=============================================================="
echo "GATE VERDICT"
echo "=============================================================="
i=0
while [ "$i" -lt "${#NAMES[@]}" ]; do
  printf '  %-32s %s\n' "${NAMES[$i]}" "${RESULTS[$i]}"
  [ -n "${DETAILS[$i]}" ] && printf '      %s\n' "${DETAILS[$i]}"
  i=$((i + 1))
done
echo "  logs: output/scratch/gate/"

if [ "$SWEEPS_ONLY" -eq 1 ]; then
  echo
  echo "  INCOMPLETE — --sweeps-only skipped the S4 conformance census."
  echo "  This is NOT the gate. Nothing may be published from this run."
fi

echo
if [ "$overall" -eq 0 ]; then
  echo "GATE: GREEN"
else
  echo "GATE: FAILED"
fi
exit "$overall"
