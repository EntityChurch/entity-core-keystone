#!/usr/bin/env bash
# run-axis-sweep.sh — sweep ONE per-peer verification axis across the whole roster.
#
# WHY THIS EXISTS, AND WHY IT IS AXIS-PARAMETERIZED RATHER THAN COPIED
#   This repo has four per-peer verification axes. For months only ONE of them
#   (S4 conformance) had a cohort runner, and the consequence is recorded twice
#   in AGENTS.md: on 2026-09-02 the S2 axis turned out to have four peers red or
#   unrunnable while CONFORMANCE-MATRIX.md published 46 of 46 at `756 · 0F`, and
#   five of the nine peers filed as "no codec suite" had an authored one, four of
#   those red. Every one of those defects was invisible for the same structural
#   reason: nobody ran that axis across the cohort, so nobody could know.
#
#   `run-s2-sweep.sh` fixed that for S2 and left S3 and origination-core in the
#   same state it had just diagnosed. A second copy of this script per axis would
#   be a second authority per axis — the standing one-copy rule (`AGENTS.md`, the
#   superseded-corpus entry). So the axis table below is DATA, adding an axis is
#   one row, and there is exactly one sweep engine.
#
# THE AXIS INVENTORY IS THE POINT. An axis that is not in this table has no
# cohort runner, which is an exclusion nobody declared — the `apl` lesson one
# level up. If you add a per-peer `run-*.sh` convention, add it here in the same
# commit or it will be discovered by accident months later.
#
# THE ROSTER IS THE SOURCE OF TRUTH, AND THERE ARE NO PER-PEER EXCLUSIONS HERE.
#   Every peer in tools/peer-tiers.tsv is attempted. A peer can leave a sweep
#   only by leaving the roster, where its absence is visible as backlog.
#
# NO-GATE IS A FIRST-CLASS OUTCOME, NOT A SKIP. A peer with no script on the
#   swept path is REPORTED with a count, because a sweep that silently skips what
#   it cannot find reproduces the exact hole it exists to close. It does not fail
#   the run by default (a gate held permanently red by known backlog gets
#   ignored, which is worse than no gate); `--gate-missing` requires coverage.
#
# RUN A SWEEP ALONE. NOTHING ELSE MAY TOUCH THE REPO MOUNT WHILE IT RUNS.
#   Every peer container mounts the repo root with `:Z`, which asks podman to
#   apply a PRIVATE SELinux label to the whole tree. Two containers doing that
#   concurrently relabel each other's mount out from under them. Measured while
#   building this script, running a 3-peer census alongside the first S3 sweep:
#   `kotlin` reported `Failed to release lock on Build Output Cleanup Cache >
#   Permission denied` and `java` HUNG for twenty minutes in an 8-way virtual-
#   thread demux. Both are GREEN in isolation, java in 2 seconds. A false RED is
#   the cheap direction; the expensive one is that it looks exactly like the real
#   defect this axis exists to find, and it cost an hour of chasing a peer that
#   was fine. If a result surprises you, re-run that peer ALONE before believing it.
#
# THIS SWEEP REUSES EACH PEER'S BUILD CACHE, AND THAT CAN LIE IN BOTH DIRECTIONS.
#   Measured while building the S2 sweep: a false RED for `elixir`, because `mix`
#   compares source mtime to artifact mtime at ONE-SECOND granularity and treats
#   equal as up-to-date. The direction that matters is the other one — the same
#   mechanism produces a false GREEN after a fix. When a result contradicts what
#   you just changed, suspect the cache before the code (`stat -c %Y` both sides).
#
# USAGE
#   tools/run-axis-sweep.sh --list                 # the axis inventory
#   tools/run-axis-sweep.sh s3                     # one axis, every roster peer
#   tools/run-axis-sweep.sh origination --tier M1
#   tools/run-axis-sweep.sh s2 haskell ocaml
#   tools/run-axis-sweep.sh s3 --gate              # exit 1 on any RED
#   tools/run-axis-sweep.sh all                    # every axis in the table
#
#   Logs land in output/scratch/<axis>-sweep/<peer>.log (gitignored); the summary
#   goes to stdout and to output/scratch/<axis>-sweep/SUMMARY.tsv.
#
# EXIT
#   0  no RED gates
#   1  at least one peer's gate FAILED (or --gate-missing with NO-GATE peers)
#   2  usage error / no peers selected
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# THE AXIS INVENTORY. One row per axis: <key> <per-peer script> <description>
# ORIGINATION WAS RETIRED 2026-09-03 AND THAT IS THE POINT OF THE TABLE. It was
# never an axis: `--profile core -reference-peer` runs its three checks inside the
# ordinary census, and the separate harness existed on 31 peers only because the
# census had never passed the flag -- so 15 peers had no coverage of it at all. A
# separate harness that exists because a flag was never passed is a workaround with
# a directory. The 31 scripts are deleted; the checks now run for all 46.
#
# S4 is deliberately ABSENT and that is not an oversight: it has its own runner
# (`run-cohort-census.sh`) plus three gates on the numbers it produces, because
# an S4 result is a published measurement and needs comparability enforcement
# this script does not do. Every OTHER axis belongs here.
#
# THE ffi-generator ARM IS ALSO ABSENT, AND UNTIL 2026-09-04 THAT *WAS* AN
# OVERSIGHT. This table sweeps `protocol-generator/*`; the FFI arm is not
# peer-scoped, so it fell outside every sweep and every `make lint` gate while
# 34 peers linked the artifact it builds. The codec leak fixed that day had been
# on the per-request path of every consumer for months and was found by accident,
# while measuring an unrelated peer. It now has its own runner --
# `ffi-generator/c-abi/run-ffi-gate.sh` -- for the same reason S4 does: it is not
# per-peer. It is listed by `--list` so the inventory stays complete, which is the
# whole point of this table. AN ARM THAT IS IN NO INVENTORY IS AN EXCLUSION NOBODY
# DECLARED, and "it isn't peer-scoped" is a reason to give it a runner, not a
# reason to leave it out of the list.
# ---------------------------------------------------------------------------
axis_script() {
  case "$1" in
    s2)          echo "run-s2.sh" ;;
    s3)          echo "run-s3.sh" ;;
    *)           return 1 ;;
  esac
}
axis_desc() {
  case "$1" in
    s2)          echo "codec / crypto-agility corpus gate" ;;
    s3)          echo "two-direction loopback interop against the Go reference peer" ;;
  esac
}
# EVERY AXIS NAMES ITS AUTHORITY. GUIDE-CONFORMANCE.md §7.0 recognises exactly
# three kinds of artifact -- an oracle check authored by entity-core-go, a fixture
# corpus authored by architecture, and an impl-internal unit test which is "that
# repo, its own concern" -- and says outright that "entity-core-keystone authors
# none of these". An axis that cannot name an authority is NOT conformance and
# must not be reported as though it were.
axis_authority() {
  case "$1" in
    s2)          echo "ARCHITECTURE — vendored fixture corpora, digest-pinned (guide §2, §6); plus our DERIVED type-registry drift target" ;;
    s3)          echo "OURS — hand-written assertions, 17 of 18 with no oracle behind them; impl-internal (guide §7.0 row 3), NOT conformance" ;;
    origination) echo "entity-core-go ORACLE — validate-peer -category origination -reference-peer; the category a single-peer census cannot reach" ;;
  esac
}
ALL_AXES="s2 s3"

TIER_SEL=""
GATE=0
GATE_MISSING=0
AXIS=""
NAMED=()
# 600s, not 1800s. A hang costs the sweep its whole budget and tells you nothing
# more at 30 minutes than at 10 — the first S3 sweep spent 34 of its ~50 minutes
# inside two peers that were never going to finish. Raise it with AXIS_TIMEOUT for
# a peer whose cold build genuinely needs longer.
TIMEOUT="${AXIS_TIMEOUT:-600}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --list)
      printf '%-14s %-46s %s\n' AXIS SCRIPT DESCRIPTION
      printf '%-14s %-46s %s\n' '-------------' '---------------------------------------------' '-----------'
      for a in $ALL_AXES; do
        printf '%-14s %-46s %s\n' "$a" "protocol-generator/*/$(axis_script "$a")" "$(axis_desc "$a")"
        printf '%-14s %-46s authority: %s\n' '' '' "$(axis_authority "$a")"
      done
      printf '%-14s %-46s %s\n' 's4' 'protocol-generator/*/run-s4.sh' 'conformance — has its own runner: tools/run-cohort-census.sh'
      printf '%-14s %-46s authority: %s\n' '' '' 'entity-core-go ORACLE — validate-peer --profile core, pinned by content digest'
      printf '%-14s %-46s %s\n' 'ffi' 'ffi-generator/c-abi/run-ffi-gate.sh' 'codec C-ABI arm (not peer-scoped) — has its own runner'
      printf '%-14s %-46s authority: %s\n' '' '' 'ARCHITECTURE for the ECF corpus (C impl only); OURS for the C-ABI spec, the cross-impl differential and the leak gate'
      exit 0 ;;
    --tier) TIER_SEL="$2"; shift 2 ;;
    --tier=*) TIER_SEL="${1#*=}"; shift ;;
    --gate) GATE=1; shift ;;
    --gate-missing) GATE=1; GATE_MISSING=1; shift ;;
    -h|--help) sed -n '2,60p' "$0"; exit 0 ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *)
      if [ -z "$AXIS" ]; then AXIS="$1"; else NAMED+=("$1"); fi
      shift ;;
  esac
done

if [ -z "$AXIS" ]; then
  echo "run-axis-sweep: ERROR no axis named. Try --list." >&2
  exit 2
fi

# `all` runs every axis in the table, sequentially, and ORs their exit codes.
if [ "$AXIS" = "all" ]; then
  overall=0
  for a in $ALL_AXES; do
    echo "=============================================================="
    echo "AXIS: $a — $(axis_desc "$a")"
    echo "=============================================================="
    args=("$a")
    [ -n "$TIER_SEL" ] && args+=(--tier "$TIER_SEL")
    [ "$GATE" -eq 1 ] && args+=(--gate)
    [ "$GATE_MISSING" -eq 1 ] && args+=(--gate-missing)
    bash "$0" "${args[@]}" "${NAMED[@]+"${NAMED[@]}"}" || overall=1
    echo
  done
  exit "$overall"
fi

SCRIPT_NAME="$(axis_script "$AXIS")" || {
  echo "run-axis-sweep: ERROR unknown axis '$AXIS'. Try --list." >&2
  exit 2
}

OUT="$REPO_ROOT/output/scratch/${AXIS}-sweep"

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
  echo "$AXIS-sweep: ERROR no peers selected — check --tier against tools/peer-tiers.tsv" >&2
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
  script="$REPO_ROOT/protocol-generator/$p/$SCRIPT_NAME"
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
# apart, and this repo has shipped that exact defect four times.
echo "$AXIS-sweep: $total peer(s) attempted — ${n_green} GREEN, ${n_red} RED, ${n_nogate} NO-GATE"
[ "$n_red" -gt 0 ]    && echo "  RED:     ${red_peers[*]}"
[ "$n_nogate" -gt 0 ] && echo "  NO-GATE: ${nogate_peers[*]}"
echo "  logs:    output/scratch/${AXIS}-sweep/<peer>.log"

if [ "$GATE" -eq 1 ]; then
  [ "$n_red" -gt 0 ] && exit 1
  if [ "$GATE_MISSING" -eq 1 ] && [ "$n_nogate" -gt 0 ]; then exit 1; fi
fi
exit 0
