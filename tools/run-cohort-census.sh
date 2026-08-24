#!/usr/bin/env bash
# run-cohort-census.sh — re-run every peer's `run-s4.sh --profile core` against
# the PINNED oracle (tools/oracle-pin.env / output/s4-oracles/validate-peer) and
# collect one JSON report per peer under output/scratch/census/.
#
# Why this exists: no cohort-wide driver existed before this (2026-07-28) run —
# every prior sweep drove each peer's run-s4.sh by hand. This is the durable,
# re-runnable version, one commit after AGENTS.md's "the anchor has to actually
# re-run on demand" lesson.
#
# Every run-s4.sh accepts `-profile core -json-out <path>` as CLI passthrough
# EXCEPT python/ruby/prolog, which read the JSON_OUT env var instead (no "$@"
# forwarding in those three) — handled per-peer below.
#
# ---------------------------------------------------------------------------
# TWO DESTINATIONS, ONE DISPATCH TABLE (--to-status, added 2026-08-22)
# ---------------------------------------------------------------------------
# By DEFAULT this script writes only to output/scratch/census/ and never touches
# a peer's tracked status/CONFORMANCE-REPORT.json. That default is deliberate and
# unchanged: a cohort census must not silently rewrite 45 peers' signed-off
# records, and output/ is gitignored so a census leaves the tree clean.
#
# But "never writes them" plus "output/ is gitignored" had a consequence nobody
# had measured until 2026-08-22: the tracked per-peer reports drifted a full
# oracle pin behind the matrix, cohort-wide — 38 peers at the retired de8f807
# 740-check set, 4 at 682, none at the current 755 — while CONFORMANCE-MATRIX.md
# §1 published fresh census numbers. A clone showed each peer's own committed
# report disagreeing with its published row, and no tool could refresh them
# because the only cohort driver structurally refused to.
#
# `--to-status` is that missing capability. It is an EXPLICIT opt-in, never the
# default, and it reuses this file's per-peer dispatch table verbatim rather than
# duplicating it — a second copy of the image/flag/timeout mapping is exactly how
# the two destinations would drift apart again.
#
#   Refreshing a tracked report is a MEASUREMENT, not a file copy. Never
#   hand-copy output/scratch/census/<peer>.json onto a tracked status report:
#   that fabricates the provenance this separation exists to protect. Re-run.
#
# Enforcement that the drift does not silently return: `tools/check-set-gate.py
# --tracked` gates the tracked reports against the pinned check set.
#
# Usage:
#   tools/run-cohort-census.sh                 # every peer except apl (blocked, see AGENTS.md §8)
#   tools/run-cohort-census.sh go rust python   # a subset
#   tools/run-cohort-census.sh --to-status go rust   # refresh TRACKED status reports
#   tools/run-cohort-census.sh --to-status --tier M1,M2
#   CONCURRENCY=2 tools/run-cohort-census.sh    # default 1 (see below)
#
# CONCURRENCY defaults to 1, deliberately: every run-s4.sh bind-mounts the repo
# root with `:Z` (an EXCLUSIVE SELinux relabel). Two containers relabeling the
# SAME host path at once race — measured directly (2026-07-28): running
# go+c+python+sql concurrently produced spurious failures (c's build hit
# `Permission denied` mid-`make`, sql's oracle binary transiently failed its `-x`
# check, python's venv transiently lost its module path) that vanished when the
# same three peers were re-run serially. Do not raise CONCURRENCY above 1 without
# first solving the shared-`:Z`-mount race (e.g. per-run worktree copies); a
# "faster" concurrent run that silently manufactures FAILs is worse than a slow
# correct one on a conformance anchor.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
. tools/podman-caps.sh
OUT="$REPO_ROOT/output/scratch/census"
LOGS="$REPO_ROOT/output/scratch/census-logs"
mkdir -p "$OUT" "$LOGS"
CONCURRENCY="${CONCURRENCY:-1}"

# Destination mode: "census" (default, gitignored scratch) or "status" (the peer's
# TRACKED status/CONFORMANCE-REPORT.json). See the --to-status block in the header.
DEST="${DEST:-census}"

# Container-visible path this peer's report should be written to.
jout_for() {
  if [ "$DEST" = "status" ]; then
    echo "/work/protocol-generator/$1/status/CONFORMANCE-REPORT.json"
  else
    echo "/work/output/scratch/census/$1.json"
  fi
}

# Host-side path for the same report (for the post-run summary read).
hostout_for() {
  if [ "$DEST" = "status" ]; then
    echo "$REPO_ROOT/protocol-generator/$1/status/CONFORMANCE-REPORT.json"
  else
    echo "$OUT/$1.json"
  fi
}

# Mode A: self-contained run-s4.sh (embeds its own podman run) — invoke directly.
run_direct() {
  local peer="$1"; shift
  ./protocol-generator/"$peer"/run-s4.sh "$@"
}

# Mode A peers that ignore CLI args and read JSON_OUT instead.
run_direct_envjson() {
  local peer="$1"
  JSON_OUT="$(jout_for "$peer")" \
    ./protocol-generator/"$peer"/run-s4.sh
}

# Mode B: no self-relaunch — construct the documented podman invocation.
run_podman() {
  local peer="$1"; local image="$2"; shift 2
  podman run $PODMAN_RUN_CAPS --rm "$@" \
    -v "$REPO_ROOT":/work:Z "$image" \
    sh /work/protocol-generator/"$peer"/run-s4.sh -profile core \
    -json-out "$(jout_for "$peer")"
}

# Same peer, with an explicit -timeout (see the run_direct case-statement note above).
run_podman_timeout() {
  local peer="$1"; local image="$2"; local budget="$3"; shift 3
  podman run $PODMAN_RUN_CAPS --rm "$@" \
    -v "$REPO_ROOT":/work:Z "$image" \
    sh /work/protocol-generator/"$peer"/run-s4.sh -profile core -timeout "$budget" \
    -json-out "$(jout_for "$peer")"
}

census_one() {
  local peer="$1"
  local log="$LOGS/$peer.log"
  local jout; jout="$(jout_for "$peer")"
  echo "=== $peer starting $(date -u +%H:%M:%S) [dest=$DEST] ===" > "$log"
  local rc=0
  case "$peer" in
    # ---- Mode A: self-contained, CLI passthrough ----
    # NOTE: passing explicit args here overrides EVERY default the script would
    # otherwise substitute (the `if [ "$#" -eq 0 ]` pattern is all-or-nothing) —
    # including a peer's own bumped `-timeout` default. Measured 2026-07-28: this
    # silently starved oz/rexx back to the oracle's 60s default and produced a
    # spurious NEW budget_exhausted (679/681-total short run) that vanished once
    # their historical bump (10m) was passed explicitly. forth/fortran/io/
    # smalltalk (also on AGENTS.md's nine-inflated-timeout list) empirically did
    # NOT need theirs to reach the full 719 — but pass it anyway for parity with
    # the historical measurement conditions, not because this run needs it.
    ada|c|common-lisp|datalog|java|kotlin|pd|sql|unison)
      run_direct "$peer" -profile core -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    forth|smalltalk|oz|rexx)
      run_direct "$peer" -profile core -timeout 10m -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    fortran)
      run_direct "$peer" -profile core -timeout 5m -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    io)
      run_direct "$peer" -profile core -timeout 15m -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    lean)
      INCONTAINER=0 run_direct "$peer" -profile core -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    # ---- Mode A: JSON_OUT env only (no "$@" forwarding) ----
    python|ruby)
      run_direct_envjson "$peer" >>"$log" 2>&1; rc=$? ;;
    # ---- Mode B: external podman run, per-peer image + extra flags ----
    asm-arm64)
      run_podman "$peer" entity-core-keystone/asm-arm64-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    asm-x86_64)
      run_podman "$peer" entity-core-keystone/asm-x86_64-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    riscv64)
      run_podman "$peer" entity-core-keystone/riscv64-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    cobol)
      run_podman "$peer" localhost/entity-core-keystone/cobol-toolchain:latest --network=none \
        -e LD_LIBRARY_PATH=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build >>"$log" 2>&1; rc=$? ;;
    cpp)
      run_podman "$peer" entity-core-keystone/cpp-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    crystal)
      run_podman "$peer" entity-core-keystone/crystal-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    csharp)
      run_podman "$peer" entity-core-keystone/dotnet9:latest -v kc-nuget:/nuget >>"$log" 2>&1; rc=$? ;;
    dart)
      run_podman_timeout "$peer" entity-core-keystone/dart-toolchain:latest 5m --network=none >>"$log" 2>&1; rc=$? ;;
    elixir)
      run_podman "$peer" entity-core-keystone/beam:latest --network=none >>"$log" 2>&1; rc=$? ;;
    go)
      run_podman "$peer" entity-core-keystone/go:latest --network=none --security-opt label=disable >>"$log" 2>&1; rc=$? ;;
    haskell)
      run_podman "$peer" entity-core-keystone/ghc-toolchain:latest --network=none \
        -e CABAL_DIR=/work/protocol-generator/haskell/.cabal-home >>"$log" 2>&1; rc=$? ;;
    julia)
      run_podman "$peer" entity-core-keystone/julia-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    nim)
      run_podman "$peer" entity-core-keystone/nim-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    node-red)
      run_podman "$peer" entity-core-keystone/node24:latest --network=none >>"$log" 2>&1; rc=$? ;;
    ocaml)
      run_podman "$peer" entity-core-keystone/ocaml-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    odin)
      run_podman "$peer" entity-core-keystone/odin-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    php)
      run_podman "$peer" entity-core-keystone/php-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    prolog)
      podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w /work \
        -e JSON_OUT="$jout" entity-core-keystone/prolog-toolchain:latest \
        protocol-generator/prolog/run-s4.sh >>"$log" 2>&1; rc=$? ;;
    rust)
      run_podman "$peer" entity-core-keystone/rust-toolchain:latest --network=none --security-opt label=disable >>"$log" 2>&1; rc=$? ;;
    rust-wasm)
      podman run $PODMAN_RUN_CAPS --rm --network=none \
        -v "$REPO_ROOT":/work:Z -v kc-rw-cargo:/cargo:Z localhost/entity-core-keystone/rust-wasm-toolchain:latest \
        sh -c "NOBUILD=1 sh /work/protocol-generator/$peer/run-s4.sh -profile core -json-out $jout" >>"$log" 2>&1; rc=$? ;;
    rust-wasm-wasmtime)
      podman run $PODMAN_RUN_CAPS --rm --network=none \
        -v "$REPO_ROOT":/work:Z -v kc-rw-cargo:/cargo:Z localhost/entity-core-keystone/rust-wasm-wasmtime-toolchain:latest \
        sh -c "NOBUILD=1 sh /work/protocol-generator/$peer/run-s4.sh -profile core -json-out $jout" >>"$log" 2>&1; rc=$? ;;
    swift)
      run_podman "$peer" entity-core-keystone/swift-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    tcl)
      run_podman "$peer" entity-core-keystone/tcl-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    turbowarp)
      run_podman "$peer" entity-core-keystone/node24:latest -v kc-npm:/root/.npm >>"$log" 2>&1; rc=$? ;;
    typescript)
      run_podman "$peer" entity-core-keystone/node24:latest --network=none -v kc-npm:/npm-cache >>"$log" 2>&1; rc=$? ;;
    wasm-wat)
      run_podman "$peer" entity-core-keystone/wasm-wat-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    zig)
      run_podman "$peer" entity-core-keystone/zig-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    apl)
      echo "SKIP: apl blocked pending the 1.9->2.0 cool-down decision (AGENTS.md §8)" >>"$log"; rc=125 ;;
    *)
      echo "unknown peer: $peer" >>"$log"; rc=127 ;;
  esac
  echo "=== $peer done rc=$rc $(date -u +%H:%M:%S) ===" >> "$log"
  local hostout; hostout="$(hostout_for "$peer")"
  if [ -f "$hostout" ]; then
    local summary
    summary=$(python3 -c "import json,sys; d=json.load(open('$hostout')); s=d.get('summary',{}); print(f\"{s.get('total','?')}\/{s.get('passed','?')}\/{s.get('warned','?')}\/{s.get('failed','?')}\/{s.get('skipped','?')}\")" 2>/dev/null || echo "unparseable")
    echo "$peer: rc=$rc P/W/F/S total=$summary"
  else
    echo "$peer: rc=$rc NO JSON PRODUCED (see $log)"
  fi
}
export -f census_one run_direct run_direct_envjson run_podman run_podman_timeout jout_for hostout_for
export REPO_ROOT OUT LOGS PODMAN_RUN_CAPS DEST

# ---------------------------------------------------------------------------
# Peer selection. The maintenance-tier policy (CONFORMANCE-MATRIX.md §4) exists so
# that a re-pin does NOT mean a 45-peer census every time. `--tier` makes that
# policy one command instead of a hand-typed peer list:
#
#   tools/run-cohort-census.sh --tier M1        # the lockstep gate — 5 peers
#   tools/run-cohort-census.sh --tier M1,M2     # after M1 converges
#   tools/run-cohort-census.sh --stale          # only peers behind the current pin
#   tools/run-cohort-census.sh go rust          # explicit, unchanged
#   tools/run-cohort-census.sh                  # everything, unchanged
#
# The roster is tools/peer-tiers.tsv — the single canonical home for the
# assignment. `apl` is excluded everywhere (upstream-blocked, standing policy).
# ---------------------------------------------------------------------------
roster_peers() {  # $1 = comma-separated tier list, or "" for all; "--stale" handled by caller
  awk -F'\t' -v want="$1" -v ref="$2" '
    /^#/ || /^peer\t/ || NF < 3 { next }
    $1 == "apl" { next }
    {
      if (want != "") { ok=0; n=split(want, T, ","); for (i=1;i<=n;i++) if ($2==T[i]) ok=1; if (!ok) next }
      if (ref != "" && $3 == ref) next        # --stale: skip peers already at the pin
      print $1
    }' "$REPO_ROOT/tools/peer-tiers.tsv"
}

TIER_SEL=""; STALE_ONLY=""
ARGS=()
while [ "$#" -gt 0 ]; do
  case "$1" in
    --tier) TIER_SEL="$2"; shift 2 ;;
    --tier=*) TIER_SEL="${1#--tier=}"; shift ;;
    --stale) STALE_ONLY=1; shift ;;
    --to-status) DEST=status; shift ;;
    *) ARGS+=("$1"); shift ;;
  esac
done
export DEST

CUR_REF="$(awk -F= '/^ref[ \t]*=/{gsub(/[ \t]/,"",$2); print $2; exit}' "$REPO_ROOT/tools/oracle-pin.env")"

# PREFLIGHT — is the INSTALLED oracle the pinned one? (added 2026-08-23)
#
# `ref` above is used only as a LABEL: it stamps the roster and names the run. Nothing
# here ever compared it to the binary that actually executes, so a census could run a
# stale or wrong oracle end-to-end and stamp all 45 rows "@ c1b0708" regardless.
# Measured the same day in a genuine fresh clone: oracle-bootstrap warned and installed
# a cc1970f build anyway, and that binary is missing all three CAP checks that are this
# release's entire finding — every peer would have come back green.
#
# check-set-gate.py does catch it afterwards, from the reports' executed digest, and
# this script already runs it. But it catches it as "42 peers are not comparable",
# which reads as a peer problem and sends you looking in the wrong place after a
# multi-hour run. Ask the cheap question first, before spending the hours.
PIN_CS="$(awk -F'= *' '/^check_set_digest/{print $2; exit}' "$REPO_ROOT/tools/oracle-pin.env" | awk '{print $1}')"
PROV="$REPO_ROOT/output/s4-oracles/PROVENANCE.txt"
if [ -n "$PIN_CS" ] && [ -f "$PROV" ]; then
  HAVE_CS="$(awk -F'= *' '/^check_set_digest/{print $2; exit}' "$PROV" | awk '{print $1}')"
  if [ -n "$HAVE_CS" ] && [ "$HAVE_CS" != "$PIN_CS" ]; then
    echo "census: ERROR the installed oracle is not the pinned oracle — refusing to run." >&2
    echo "  installed (output/s4-oracles/PROVENANCE.txt): $HAVE_CS" >&2
    echo "  pinned    (tools/oracle-pin.env):             $PIN_CS" >&2
    echo "  A census against this binary would produce numbers that are not comparable" >&2
    echo "  to CONFORMANCE-MATRIX.md, and would stamp the roster '@ $CUR_REF' anyway." >&2
    echo "  Run tools/oracle-bootstrap.sh (it now refuses a mismatched build too)." >&2
    exit 3
  fi
elif [ ! -f "$PROV" ]; then
  echo "census: WARN no output/s4-oracles/PROVENANCE.txt — cannot confirm the installed" >&2
  echo "  oracle matches the pin. Run tools/oracle-bootstrap.sh first." >&2
fi

PEERS=("${ARGS[@]+"${ARGS[@]}"}")
if [ "${#PEERS[@]}" -eq 0 ]; then
  if [ -n "$STALE_ONLY" ]; then
    mapfile -t PEERS < <(roster_peers "$TIER_SEL" "$CUR_REF")
    echo "census: --stale -> peers not already measured at $CUR_REF${TIER_SEL:+ in tier(s) $TIER_SEL}"
  else
    mapfile -t PEERS < <(roster_peers "$TIER_SEL" "")
  fi
fi

if [ "${#PEERS[@]}" -eq 0 ]; then
  echo "census: nothing to run${TIER_SEL:+ for tier(s) $TIER_SEL} — every selected peer is already at $CUR_REF"
  exit 0
fi
echo "census: ${#PEERS[@]} peer(s)${TIER_SEL:+, tier(s) $TIER_SEL} @ oracle $CUR_REF"

printf '%s\n' "${PEERS[@]}" | xargs -P "$CONCURRENCY" -I{} bash -c 'census_one "$@"' _ {}

# ---------------------------------------------------------------------------
# Check-set gate — a census is a COMPARISON, and a comparison is only valid if
# every peer was scored on the same checks. The one way that silently stops
# being true is the global -timeout expiring mid-suite: the oracle then stops
# emitting the remaining categories and records them as severity SKIP, which is
# indistinguishable in `summary` from a legitimate --profile core carve-out.
# (asm-x86_64/asm-arm64/riscv64 ran 699 checks to the cohort's 740 for four
# consecutive censuses before anyone noticed — hiding 2 core FAILs each.)
#
# This runs automatically so a non-comparable census cannot be reported as one.
# It does not gate the peers' PASS/FAIL — it gates whether their numbers may be
# placed side by side at all.
# ---------------------------------------------------------------------------
echo
echo "=============================================================="
# Gate ONLY the peers this run produced. A tier run must not inherit an unrelated
# peer's stale deviation from a previous full census — otherwise `--tier M1` exits
# non-zero because of a probe nobody re-ran, and the exit code stops meaning anything.
GATE_FILES=()
for peer in "${PEERS[@]}"; do
  f="$(hostout_for "$peer")"
  [ -f "$f" ] && GATE_FILES+=("$f")
done
if [ "${#GATE_FILES[@]}" -eq 0 ]; then
  echo "check-set gate: no reports produced — nothing to gate"; gate_rc=2
else
  "$REPO_ROOT/tools/check-set-gate.py" "${GATE_FILES[@]}"
  gate_rc=$?
fi
if [ "$gate_rc" -ne 0 ]; then
  echo
  echo "!! CENSUS NOT COMPARABLE — see above. Do not publish these numbers as a cohort"
  echo "!! comparison until every peer reports the pinned check set."
fi

# ---------------------------------------------------------------------------
# Stamp the roster. `tools/peer-tiers.tsv` records the oracle pin each peer's
# CURRENT verdict was measured at — that is what makes "which tiers are caught
# up" a question with an exact answer (tools/tier-status.py). Updating it by hand
# is how a tier policy quietly rots, so the census does it: every peer that
# produced a report this run is stamped with the current ref.
#
# Only the pin column moves. Tier and note are hand-maintained and never touched.
# ---------------------------------------------------------------------------
STAMPED=$(printf '%s\n' "${PEERS[@]}" | while read -r peer; do
  [ -f "$(hostout_for "$peer")" ] && echo "$peer"
done | tr '\n' ' ')
if [ -n "$STAMPED" ]; then
  TSV="$REPO_ROOT/tools/peer-tiers.tsv"
  awk -F'\t' -v OFS='\t' -v ref="$CUR_REF" -v list=" $STAMPED " '
    /^#/ || /^peer\t/ || NF < 3 { print; next }
    { if (index(list, " " $1 " ")) $3 = ref; print }
  ' "$TSV" > "$TSV.tmp" && mv "$TSV.tmp" "$TSV"
  echo
  echo "roster stamped @ $CUR_REF: $(echo "$STAMPED" | wc -w) peer(s)"
  echo "  (tools/peer-tiers.tsv — review with 'git diff tools/peer-tiers.tsv')"
fi

echo
"$REPO_ROOT/tools/tier-status.py" || true
exit "$gate_rc"
