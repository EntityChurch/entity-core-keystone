#!/usr/bin/env bash
# run.sh — drive `pa-probe` against a generated peer, in the peer's OWN census
# configuration and with NO edit to its harness.
#
# WHY THIS FILE EXISTS, AND WHY IT IS NOT JUST A COMMAND. AGENTS.md: "a reproduction
# is a measurement setup, not a command — and if the probe script is not kept, the
# rate cannot be re-measured, only re-argued."
#
# AND WHY IT DIFFERS FROM `tools/arc-probe/run.sh`, WHICH IS THE PART WORTH READING.
# That script removes exactly `--debug-open-grants` from the peer's harness, because
# under the degenerate `default -> *` seed policy an AUTHORIZATION probe has nothing
# to bypass. §4.11 IS NOT AN AUTHORIZATION SURFACE. Every arm here is refused before
# any authority is consulted — at the length prefix, at the decoder, or at the
# root-type test — so the seed policy cannot change any answer, and removing the flag
# would measure the peers in a configuration nobody ships them in for no gain. The
# launch configuration is part of the measurement either way, so it is stated rather
# than inherited: THIS PROBE RUNS THE PEER EXACTLY AS THE CENSUS DOES.
#
# The one place that reasoning is load-bearing rather than merely tidy: the positive
# control (P0) sends a well-formed EXECUTE and asserts only that it is ANSWERED, never
# that it is ALLOWED. That is what lets one control serve both configurations, and it
# is why an unauthorized 403 is a passing control here.
#
#   tools/pa-probe/run.sh python                 # one peer
#   tools/pa-probe/run.sh python cobol forth     # several
#
# NOBUILD is forwarded from the environment when set, because the two wasm peers
# cannot build under --network=none (their cargo build reaches index.crates.io) and
# `run-cohort-census.sh` measures them from their committed artifact for the same
# reason. Before using it, check the artifact against its source:
#   find <peer>/src ../rust/src -newer <peer>/out/peer.wasm -name '*.rs' | wc -l
#
# Reports land in output/scratch/pa/<peer>.json (gitignored).
set -euo pipefail

cd "$(dirname "$0")/../.."
REPO="$PWD"
OUT="$REPO/output/scratch/pa"
mkdir -p "$OUT"

[ -x "$REPO/output/s4-oracles/pa-probe" ] || {
  echo "run.sh: build it first — tools/build-probes.sh pa-probe" >&2; exit 2; }

# ONE MEASUREMENT AT A TIME. Two runs that both write output/scratch and both allocate
# ports produce failures that look like peer defects — `crystal` dying inside its own
# compiler, `odin` unable to write its own JSON — and the census learned this the
# expensive way. Asked ONCE per sweep rather than per peer: 46 identical refusals are
# noise, and the hazard is a property of the run.
holders="$(for c in $(podman ps -q 2>/dev/null); do
  m="$(podman inspect "$c" --format '{{range .Mounts}}{{.Source}} {{end}}' 2>/dev/null || true)"
  case "$m" in *"$REPO"*) echo "$c";; esac
done)"
if [ -n "$holders" ] && [ "${SWEEP_IGNORE_HOLDERS:-0}" != "1" ]; then
  echo "run.sh: REFUSING TO START — another container holds this repo:" >&2
  for c in $holders; do
    echo "    $c $(podman inspect "$c" --format '{{.Config.Image}}' 2>/dev/null)" >&2
  done
  echo "  Set SWEEP_IGNORE_HOLDERS=1 to proceed anyway (results may be contended)." >&2
  exit 4
fi

failed=""
for peer in "$@"; do
  src="$REPO/protocol-generator/$peer/run-s4.sh"
  [ -f "$src" ] || { echo "run.sh: no harness for '$peer' — SKIPPED" >&2; failed="$failed $peer"; continue; }

  echo "=== $peer ==="
  # Some harnesses re-exec themselves into their container and some expect to be
  # invoked INSIDE it already. Discriminate on whether the script EXECUTES podman, not
  # on whether the word appears — every harness names its own `podman run` line in a
  # header comment, and matching text would send the container-only ones through the
  # host path where they fail as `cd: /work/...: No such file or directory`, which
  # reads as a broken tree rather than as a wrong invocation.
  if grep -vE '^[[:space:]]*#' "$src" | grep -q 'podman run'; then
    ORACLE=/work/output/s4-oracles/pa-probe ${NOBUILD:+NOBUILD="$NOBUILD"} \
      bash "$src" -json-out "/work/output/scratch/pa/$peer.json" -peer "$peer" >/dev/null 2>&1 || true
  else
    # The image-name class carries `_`: `asm-x86_64-toolchain` is the one image in the
    # cohort whose name contains an underscore, and a class of `[a-z0-9.-]` misses it,
    # `grep` exits 1, and under `set -o pipefail` the ASSIGNMENT fails — so `set -e`
    # kills the script BEFORE the guard written to report exactly that can run. Hence
    # `|| true` on the capture: the explicit guard is what reports.
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
      -e ORACLE=/work/output/s4-oracles/pa-probe ${NOBUILD:+-e NOBUILD="$NOBUILD"} \
      "$img" bash "/work/protocol-generator/$peer/run-s4.sh" \
      -json-out "/work/output/scratch/pa/$peer.json" -peer "$peer" >/dev/null 2>&1 || true
  fi

  # CLASSIFY BY ARTIFACT, NEVER BY EXIT CODE OR BY MTIME. A harness that drops the
  # ORACLE override at its container boundary runs the REAL validator, exits 0, and
  # writes a perfectly good 778-check conformance report where a probe report was
  # expected — eight peers did exactly that and nothing said so. The discriminator is
  # one key: a probe report has `cases`, a conformance report has `checks`.
  f="$OUT/$peer.json"
  if [ ! -f "$f" ]; then
    echo "run.sh: $peer — NO REPORT WRITTEN" >&2; failed="$failed $peer"; continue
  fi
  if ! grep -q '"cases"' "$f"; then
    echo "run.sh: $peer — the report is not a pa-probe report (the ORACLE override was" >&2
    echo "        dropped at this harness's container boundary)" >&2
    failed="$failed $peer"; continue
  fi
  python3 - "$f" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
print(f"  trusted={d['trusted']}  {d['summary']}")
for c in d["cases"]:
    if c["role"] == "measurement" and not c["conforms"].startswith("yes"):
        print(f"    {c['id']}: {c['conforms'][:110]}")
PY
done

# A roster run that stops partway and reports nothing is worse than one that records a
# failure, so the loop continues and the skips are NAMED here.
if [ -n "$failed" ]; then
  echo "run.sh: NOT MEASURED —$failed" >&2
fi
