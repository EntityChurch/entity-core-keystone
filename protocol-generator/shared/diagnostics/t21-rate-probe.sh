#!/usr/bin/env bash
# t21-rate-probe — measure the RATE of a concurrency/t2_1_sustained_load failure.
#
# WHY THIS EXISTS. AGENTS.md: "FLAKY" AND "LOAD" ARE NOT DIAGNOSES — THEY ARE THE NAMES WE
# GIVE A RACE WE HAVE NOT LOOKED FOR YET. RE-RUN N TIMES AND COUNT. A single green re-run is
# one sample from a distribution nobody has measured, and a 0-of-N is a rate estimate too,
# whose confidence is bounded by N (the 2026-09-02 zig entry: a published churn "0/22" was
# really 2/22 once resampled).
#
# AND THE SETUP IS THE MEASUREMENT, WHICH IS WHY THIS IS A FILE AND NOT A COMMAND. The
# 2026-09-02 zig probe produced an honest 5-in-60 and was never saved; the same source would
# not reproduce at all that afternoon, and the only surviving evidence of how the morning had
# measured it was a port number in a log. A rate without its setup is an anecdote with a
# denominator.
#
#   protocol-generator/shared/diagnostics/t21-rate-probe.sh <peer> <N> [label]
#
# CONDITIONS THIS WAS AUTHORED UNDER (2026-09-16, ocaml, the 0.8.2.25 closing census):
#   - Full `--profile core` via the peer's OWN run-s4.sh, never a hand-rolled invocation, and
#     never `-category concurrency` alone. AGENTS.md, the `c` lesson: driving a category
#     directly is right for COVERAGE and wrong for a RACE — an isolated category is a
#     different heap, and `c`'s heap-corruption race was 0 of 20 isolated against 1 of 10 on
#     the full profile. t2_1's mechanism here is Hashtbl growth across the whole suite's
#     accumulated store, so the full run is the only faithful regime.
#   - Serial. One measurement at a time; a concurrent run manufactures failures that read as
#     peer defects.
#   - Reports to a scratch path, NEVER to status/. A probe must not republish a signed-off
#     record.
#
# Prints a per-run line and a final `<hits> of <N>` count. The count is the deliverable:
# cite the rate, never an adjective.
set -u
cd "$(dirname "$0")/../../.." || exit 2
REPO="$PWD"
PEER="${1:?usage: t21-rate-probe.sh <peer> <N> [label]}"
N="${2:?usage: t21-rate-probe.sh <peer> <N> [label]}"
LABEL="${3:-run}"
CHECK="concurrency/t2_1_sustained_load"
OUT="$REPO/output/scratch/t21-probe"
mkdir -p "$OUT"

# Refuse to start while another container holds this repo mount: two `:Z` relabels of one
# host path collide, and the loser's REPORT WRITE fails while every check still passes.
if podman ps --format '{{.ID}} {{.Image}} {{.Mounts}}' 2>/dev/null | grep -q "$REPO"; then
  echo "t21-rate-probe: REFUSING TO START — another container holds $REPO" >&2
  podman ps --format '  {{.ID}} {{.Image}}' 2>/dev/null | head >&2
  echo "  Set T21_IGNORE_HOLDERS=1 to override (you will be measuring contention)." >&2
  [ "${T21_IGNORE_HOLDERS:-0}" = 1 ] || exit 4
fi

hits=0
# NOTE ON THE DESTINATION. `--probe NAME` is NOT an output-directory selector -- it selects a
# different ORACLE BINARY at output/s4-oracles/NAME and exits 2 if none is there. Checked
# before relying on it. So this drives the ordinary census destination (gitignored scratch,
# never status/) and copies the artifact out per run, asserting FRESHNESS: a run that loses
# its report write to contention leaves the previous run's JSON in place, well-formed and
# carrying no run identity, and counting it would be counting the same sample twice.
for i in $(seq 1 "$N"); do
  json="$OUT/$PEER-$LABEL-$i.json"
  src="$REPO/output/scratch/census/$PEER.json"
  rm -f "$json"
  t0=$(date +%s)
  CONCURRENCY=1 "$REPO/tools/run-cohort-census.sh" "$PEER" \
    >"$OUT/$PEER-$LABEL-$i.log" 2>&1
  mt=$(stat -c %Y "$src" 2>/dev/null || echo 0)
  if [ "$mt" -ge "$t0" ]; then cp "$src" "$json"; fi
  # Classify by what the ARTIFACT contains, not by the exit code: five harnesses propagate
  # the oracle's rc=1 for the un-allowlisted `connect_ping_before_hello` skip on a 0-FAIL run.
  sev=$(python3 - "$json" "$CHECK" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception: print("NO-REPORT"); raise SystemExit
for c in d.get("checks",[]):
    if f"{c['category']}/{c['name']}"==sys.argv[2]: print(c["severity"]); break
else: print("ABSENT")
PY
)
  case "$sev" in
    PASS) verdict="pass" ;;
    NO-REPORT|ABSENT) verdict="UNMEASURED ($sev)" ;;
    *) verdict="HIT ($sev)"; hits=$((hits+1)) ;;
  esac
  printf '%s %-10s run %2d/%s: %s\n' "$PEER" "$LABEL" "$i" "$N" "$verdict"
done
echo
echo "$PEER $LABEL: $hits of $N runs failed $CHECK"
