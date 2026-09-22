#!/usr/bin/env bash
# cold-build-gate.sh — build EVERY container image from scratch, no cache.
#
# WHY THIS EXISTS
#   Every image in this tree is a recipe an adopter has to be able to run. Nothing we
#   had ever asked whether they still build. The layer cache and the already-present
#   local images mean a broken recipe stays invisible on the machine that authored it,
#   and surfaces only for the person who pulls the repo -- which is the one audience
#   that cannot ask us about it.
#
#   Two rot mechanisms, both silent, both previously found only by accident:
#     1. A pinned dnf NVR is superseded and vanishes from the rolling repo
#        ("No match for argument"). Hit this on 2026-07-27 across eleven images, and
#        again hours later on clang. FIXED STRUCTURALLY: every pinned RPM now comes
#        from Koji's permanent archive (tools/koji-pin.py), which retains every NVR
#        forever. This gate is what proves that claim stays true.
#     2. A base image tag is republished under the same name. FIXED: all bases are
#        digest-pinned. Same deal -- the gate is the proof.
#
#   A pin nobody re-checks is a claim, not an anchor.
#
# USAGE
#   tools/cold-build-gate.sh                 # all images, --no-cache
#   tools/cold-build-gate.sh c-toolchain go  # named images only
#   KEEP=1 tools/cold-build-gate.sh          # keep images (default: prune what we built)
#   CACHED=1 tools/cold-build-gate.sh        # allow the layer cache (fast, weaker signal)
#
# Exits non-zero if any image fails to build.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
. "$REPO_ROOT/tools/podman-caps.sh"

CACHE_FLAG="--no-cache"
[ "${CACHED:-0}" = "1" ] && CACHE_FLAG=""

if [ "$#" -gt 0 ]; then
  IMAGES=("$@")
else
  # `base` first: odin-toolchain builds FROM it.
  IMAGES=(base)
  for d in containers/*/Containerfile; do
    n="$(basename "$(dirname "$d")")"
    [ "$n" = "base" ] || IMAGES+=("$n")
  done
fi

LOG_DIR="$REPO_ROOT/output/scratch/cold-build"
mkdir -p "$LOG_DIR"

pass=0; fail=0; failed=()
printf '%-32s %-8s %-10s %s\n' IMAGE RESULT SECONDS NOTE
printf '%s\n' "----------------------------------------------------------------------"

for img in "${IMAGES[@]}"; do
  cf="containers/$img/Containerfile"
  if [ ! -f "$cf" ]; then
    printf '%-32s %-8s %-10s %s\n' "$img" "SKIP" "-" "no Containerfile"
    continue
  fi
  log="$LOG_DIR/$img.log"
  start=$(date +%s)
  # shellcheck disable=SC2086
  if podman build $CACHE_FLAG $PODMAN_BUILD_CAPS \
       -t "entity-core-keystone/$img:latest" -f "$cf" . >"$log" 2>&1; then
    dur=$(( $(date +%s) - start ))
    printf '%-32s %-8s %-10s %s\n' "$img" "OK" "$dur" ""
    pass=$((pass + 1))
  else
    dur=$(( $(date +%s) - start ))
    # surface the most useful line: dnf rot has a signature worth naming outright
    note="$(grep -m1 -E 'No match for argument|Error:|error:|manifest unknown|not found' "$log" | cut -c1-60)"
    printf '%-32s %-8s %-10s %s\n' "$img" "FAIL" "$dur" "${note:-see $log}"
    fail=$((fail + 1)); failed+=("$img")
  fi
done

printf '%s\n' "----------------------------------------------------------------------"
echo "$pass built, $fail failed   (logs: $LOG_DIR)"
if [ "$fail" -ne 0 ]; then
  echo
  echo "FAILED: ${failed[*]}"
  echo "If the cause is 'No match for argument', a pinned NVR has rotted: convert it"
  echo "with  python3 tools/koji-pin.py resolve containers/<image>"
  exit 1
fi
