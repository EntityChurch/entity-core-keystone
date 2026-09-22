#!/usr/bin/env bash
# run-s2-sweep.sh — the S2 (codec / crypto-agility) axis, swept across the whole
# roster.
#
# WHY THIS EXISTS
#   `run-cohort-census.sh` drives S4 (`validate-peer --profile core`) across all
#   46 peers, and `check-set-gate.py` / `tier-status.py` gate the numbers that
#   come out of it. Nothing did the same for S2. The consequence, measured
#   2026-09-02: while CONFORMANCE-MATRIX.md published 46 of 46 at `756 · 0F`,
#   FOUR peers were red or unrunnable on the codec axis and had been for a long
#   time, and nobody could have known:
#
#     haskell    S2 unrunnable at all — the image vendored no Hackage closure, so
#                `cabal test` could not resolve hspec/QuickCheck offline; and the
#                peer had no run-s2.sh, so no sweep would have found it anyway.
#                Once runnable: 1 real FAIL (the inverted agility vector).
#     smalltalk  `make sunit` died compiling its own driver (a single Pharo doit
#                that both loaded a class and referenced it by global name), and
#                the target asserted nothing about the suite's counts regardless.
#     ocaml      `test/selftest.exe` had been FAILING on a stale §7a expectation;
#                no run-s2.sh existed and the only host-invocable script was an
#                inside-container one that never builds it.
#     prolog     run-s2.sh existed but was inside-container-only, so a host sweep
#                got `swipl: command not found` — indistinguishable from a broken
#                toolchain.
#
#   Three of those four are ABSENCE defects: not a red gate, but no gate on the
#   swept path. That is why this script reports NO-GATE as a first-class outcome
#   rather than skipping quietly — an exclusion that suppresses its own falsifier
#   is permanent by construction.
#
# THE ROSTER IS THE SOURCE OF TRUTH, AND THERE ARE NO PER-PEER EXCLUSIONS HERE.
#   Every peer in tools/peer-tiers.tsv is attempted. A peer can leave this sweep
#   only by leaving the roster, where its absence is visible as backlog. (The
#   `apl` census exclusion is the standing lesson: the one peer nobody could
#   measure was the one peer the census refused to attempt, and it measured
#   0-FAIL on the first try once asked.)
#
# THIS SWEEP REUSES EACH PEER'S BUILD CACHE, AND THAT CAN LIE IN BOTH DIRECTIONS.
#   Every run-s2.sh builds incrementally. Measured while building this script: a
#   false RED for `elixir`, because `mix` compares SOURCE mtime to ARTIFACT mtime
#   at ONE-SECOND granularity and treats equal as up-to-date. A file restored
#   within the same second as the compile that produced the .beam is never
#   recompiled — `lib/entity_core/hash.ex` and its `.beam` both read 07:57:15,
#   and the sweep ran the previous build's code while the source on disk was
#   correct. `mix compile --force` did not help (it rebuilt a different env);
#   only `rm -rf _build` did.
#
#   The direction that matters is the other one: the same mechanism produces a
#   false GREEN after a fix. The standing rule applies — compare the artifact's
#   mtime against the source's before trusting a verdict from a peer you just
#   edited (`stat -c %Y`), and when a result contradicts what you just changed,
#   suspect the cache before the code.
#
# USAGE
#   tools/run-s2-sweep.sh                 # every peer on the roster
#   tools/run-s2-sweep.sh --tier M1,M2    # only those tiers
#   tools/run-s2-sweep.sh haskell ocaml   # named peers
#   tools/run-s2-sweep.sh --gate          # exit non-zero if any gate is RED
#
#   Logs land in output/scratch/s2-sweep/<peer>.log (gitignored); the summary
#   goes to stdout and to output/scratch/s2-sweep/SUMMARY.tsv.
#
# EXIT
#   0  no RED gates (NO-GATE peers are reported, and do not fail the run unless
#      --gate-missing is given — see the note on permanently-red gates below)
#   1  at least one peer's S2 gate FAILED
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$REPO_ROOT/output/scratch/s2-sweep"
TIMEOUT="${S2_TIMEOUT:-1800}"

TIER_SEL=""
GATE=0
GATE_MISSING=0
NAMED=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tier) TIER_SEL="$2"; shift 2 ;;
    --tier=*) TIER_SEL="${1#*=}"; shift ;;
    --gate) GATE=1; shift ;;
    --gate-missing) GATE=1; GATE_MISSING=1; shift ;;
    -h|--help) sed -n '2,50p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) NAMED+=("$1"); shift ;;
  esac
done

roster_peers() {
  awk -F'\t' -v want="$1" '
    /^#/ || /^peer\t/ || NF < 3 { next }
    {
      if (want != "") { ok=0; n=split(want, T, ","); for (i=1;i<=n;i++) if ($2==T[i]) ok=1; if (!ok) next }
      print $1
    }' "$REPO_ROOT/tools/peer-tiers.tsv"
}

if [ "${#NAMED[@]}" -gt 0 ]; then
  PEERS=("${NAMED[@]}")
else
  mapfile -t PEERS < <(roster_peers "$TIER_SEL")
fi

if [ "${#PEERS[@]}" -eq 0 ]; then
  echo "s2-sweep: ERROR no peers selected — check --tier against tools/peer-tiers.tsv" >&2
  exit 2
fi

mkdir -p "$OUT"
SUMMARY="$OUT/SUMMARY.tsv"
: > "$SUMMARY"

n_green=0 n_red=0 n_nogate=0
red_peers=() nogate_peers=()

printf '%-22s %-8s %s\n' PEER RESULT SECONDS
printf '%-22s %-8s %s\n' '----------------------' '--------' '-------'

for p in "${PEERS[@]}"; do
  script="$REPO_ROOT/protocol-generator/$p/run-s2.sh"
  if [ ! -f "$script" ]; then
    printf '%-22s %-8s %s\n' "$p" "NO-GATE" "-"
    printf '%s\t%s\t%s\n' "$p" "NO-GATE" "-" >> "$SUMMARY"
    n_nogate=$((n_nogate + 1)); nogate_peers+=("$p")
    continue
  fi
  start=$(date +%s)
  # No pipe: a `cmd | tail` here would report tail's exit status, which is the
  # exact defect that once made a verification loop print rc=0 for two peers
  # that had failed outright.
  timeout "$TIMEOUT" bash "$script" > "$OUT/$p.log" 2>&1
  rc=$?
  secs=$(( $(date +%s) - start ))
  if [ "$rc" -eq 0 ]; then
    printf '%-22s %-8s %s\n' "$p" "GREEN" "${secs}s"
    printf '%s\t%s\t%s\n' "$p" "GREEN" "$secs" >> "$SUMMARY"
    n_green=$((n_green + 1))
  else
    printf '%-22s %-8s %s (rc=%s)\n' "$p" "RED" "${secs}s" "$rc"
    printf '%s\t%s\t%s\trc=%s\n' "$p" "RED" "$secs" "$rc" >> "$SUMMARY"
    n_red=$((n_red + 1)); red_peers+=("$p")
  fi
done

total=$(( n_green + n_red + n_nogate ))
echo
# ALWAYS PRINT THE COUNT. A gate that examined zero things prints the same word
# as one that examined forty-six; the count is the only thing that tells them
# apart, and this repo has shipped that exact defect twice.
echo "s2-sweep: $total peer(s) attempted — ${n_green} GREEN, ${n_red} RED, ${n_nogate} NO-GATE"
[ "$n_red" -gt 0 ]    && echo "  RED:     ${red_peers[*]}"
[ "$n_nogate" -gt 0 ] && echo "  NO-GATE: ${nogate_peers[*]}"
echo "  logs:    output/scratch/s2-sweep/<peer>.log"

if [ "$GATE" -eq 1 ]; then
  # RED fails. NO-GATE is REPORTED but does not fail by default, on the same
  # reasoning check-set-gate.py applies to disclosed debt: a gate held
  # permanently red by known backlog gets ignored, which is worse than no gate.
  # Peers gain gates one at a time and rejoin the gated set automatically, so
  # this ratchets one way. Use --gate-missing to require full coverage.
  [ "$n_red" -gt 0 ] && exit 1
  if [ "$GATE_MISSING" -eq 1 ] && [ "$n_nogate" -gt 0 ]; then exit 1; fi
fi
exit 0
