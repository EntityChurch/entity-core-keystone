#!/usr/bin/env bash
# run.sh — drive `arc-probe` against a generated peer, with the ONE launch change
# the measurement requires and no others.
#
# WHY THIS FILE EXISTS, AND WHY IT IS NOT JUST A COMMAND. AGENTS.md: "a reproduction
# is a measurement setup, not a command — and if the probe script is not kept, the
# rate cannot be re-measured, only re-argued." The setup here has one non-obvious
# precondition that decides the whole result, so it is encoded rather than
# remembered:
#
#   EVERY `run-s4.sh` IN THE COHORT LAUNCHES ITS PEER WITH `--debug-open-grants` —
#   the degenerate `default → *` seed policy. Under it the caller's grant covers
#   every path, so no target is outside it, and the F68 composition has NOTHING TO
#   BYPASS. A probe run against the census configuration reports the guard holding
#   on every peer, for a reason that has nothing to do with the guard.
#
# So this script takes the peer's OWN harness, removes exactly that one flag, and
# points `ORACLE=` at the probe. Nothing else about the launch differs from the
# measured census configuration — which is what lets a result be attributed to the
# peer rather than to a hand-rolled invocation (the standing rule: compare against
# the harness the number actually came from, never a hand-rolled call of the same
# tool).
#
# Without the flag the peer falls back to the §6.9a discovery floor, which is a
# REAL, conformant, shipped grant — not a synthetic narrow one authored for this
# probe. That matters: the result is about the peers as they ship.
#
#   tools/arc-probe/run.sh python                 # one peer
#   tools/arc-probe/run.sh python csharp ocaml    # several
#
# NOBUILD is forwarded from the environment when set, because the two wasm peers
# cannot build under --network=none (their cargo build reaches index.crates.io)
# and `run-cohort-census.sh` measures them from their committed artifact for the
# same reason. Forwarding it GENERALLY rather than special-casing those two keeps
# the decision at the call site, where it is visible — a per-peer build mode
# buried in the measurement tooling is how the `apl` exclusion survived for
# months. Before using it, check the artifact against its source:
#   find <peer>/src ../rust/src -newer <peer>/out/peer.wasm -name '*.rs' | wc -l
#
# Reports land in output/scratch/arc/<peer>.json (gitignored).
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="$REPO/output/scratch/arc"
# Two levels below the repo root, because every harness resolves REPO_ROOT as
# `dirname($0)/../..`. A patched copy at any other depth computes the wrong root
# and dies on its own `podman-caps.sh` source line.
PATCHED="$REPO/output/arc-harness"
mkdir -p "$OUT" "$PATCHED"

[ -x "$REPO/output/s4-oracles/arc-probe" ] || {
  echo "run.sh: build it first — tools/build-probes.sh arc-probe" >&2; exit 2; }

failed=""
for peer in "$@"; do
  src="$REPO/protocol-generator/$peer/run-s4.sh"
  [ -f "$src" ] || { echo "run.sh: no harness for '$peer' — SKIPPED" >&2; failed="$failed $peer"; continue; }

  # The single edit. Asserted, not assumed: a harness that does not carry the flag
  # is either already floor-launched or has changed shape, and either way the
  # operator needs to know rather than get a silently-different measurement.
  if ! grep -q -- '--debug-open-grants' "$src"; then
    echo "run.sh: $peer — harness does not carry --debug-open-grants; refusing to" >&2
    echo "        guess at its grant configuration. Read it and say what it launches." >&2
    failed="$failed $peer"
    continue
  fi
  dst="$PATCHED/$peer-run-s4.sh"
  sed 's/--debug-open-grants//g' "$src" > "$dst"
  chmod +x "$dst"

  echo "=== $peer ==="
  # Some harnesses re-exec themselves into their container and some expect to be
  # invoked INSIDE it already (AGENTS.md records the split, and the container-only
  # ones fail from the host as `cd: /work/...: No such file or directory`, which
  # reads as a broken tree rather than as a wrong invocation). Discriminate on
  # whether the script EXECUTES podman, not on whether the word appears — every
  # harness names its own `podman run` line in a header comment.
  if grep -vE '^[[:space:]]*#' "$dst" | grep -q 'podman run'; then
    ORACLE=/work/output/s4-oracles/arc-probe ${NOBUILD:+NOBUILD="$NOBUILD"} \
      bash "$dst" -json-out "/work/output/scratch/arc/$peer.json" -peer "$peer" || true
  else
    # The image-name pattern carries `_` and the capture is guarded, and BOTH
    # halves are the same defect. `asm-x86_64-toolchain` is the one image in the
    # cohort whose name contains an underscore; a class of `[a-z0-9.-]` misses it,
    # `grep` exits 1, and under `set -o pipefail` the ASSIGNMENT fails — so
    # `set -e` kills the script before the `[ -n "$img" ]` guard written to report
    # exactly this can run. A guard that cannot execute is not a guard, and its
    # silence is total: the roster run printed the peer header and stopped, taking
    # the 17 peers after it with it, and the only trace was a bare non-zero exit.
    img="$(grep -oE 'entity-core-keystone/[A-Za-z0-9._-]+:latest' "$src" | head -1 || true)"
    if [ -z "$img" ]; then
      echo "run.sh: $peer is container-only and names no image — SKIPPED" >&2
      failed="$failed $peer"
      continue
    fi
    # shellcheck source=../podman-caps.sh
    . "$REPO/tools/podman-caps.sh"
    podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
      -v "$REPO":/work:Z -w /work \
      -e ORACLE=/work/output/s4-oracles/arc-probe ${NOBUILD:+-e NOBUILD="$NOBUILD"} \
      "$img" bash "/work/output/arc-harness/$peer-run-s4.sh" \
      -json-out "/work/output/scratch/arc/$peer.json" -peer "$peer" || true
  fi
done

# A roster run that stops at peer 29 and reports nothing is worse than one that
# records a failure, so the loop continues and the skips are NAMED here. Silent
# truncation reads as "covered everything" when it did not.
if [ -n "$failed" ]; then
  echo "run.sh: NOT MEASURED —$failed" >&2
fi
