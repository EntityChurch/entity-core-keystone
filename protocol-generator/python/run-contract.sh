#!/usr/bin/env bash
# Keystone peer contract — entity-core-protocol-python. Container-bound, sealed-offline.
#
# Builds the peer and the contract host (a separate package, contract/host/) as WHEELS with
# the stdlib builder contract/wheel.py (the image carries no build backend), installs them with
# `pip install --no-index` into the container's venv — so pip resolves the host's one declared
# dependency from the peer's wheel and nothing else — runs the shared wire driver against the
# INSTALLED hosts from a directory with no source tree on sys.path, and runs the peer's local
# contract tests. It writes RAW EVIDENCE only:
#   $OUT/cases.json   the driver's case records
#   $OUT/local.txt    pytest's output, then every test re-rendered as a libtest line
#                     (`test <name> ... ok|FAILED|ignored`, which report.py reads), then
#                     `local tests exit <rc>`
# It never computes a verdict — tools/peer-contract/run.sh calls report.py for that.
#
#   tools/peer-contract/run.sh python          # the normal entry point
#   OUT=output/scratch/x ./run-contract.sh     # evidence only
#
# PEER_REL (default protocol-generator/python) lets tools/peer-contract/plant.py point this same
# script at a planted scratch copy, so a plant is measured by exactly the harness a real run uses.
# KPC_SKIP_LOCAL=1 skips the local tests (plants measure the driver cases).
# DRIVER (default output/peer-contract/kpc-driver) is the prebuilt shared driver.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
PEER_REL="${PEER_REL:-protocol-generator/python}"
OUT="${OUT:-output/scratch/peer-contract/python}"
DRIVER="${DRIVER:-output/peer-contract/kpc-driver}"
mkdir -p "$REPO_ROOT/$OUT"
[ -x "$REPO_ROOT/$DRIVER" ] || { echo "run-contract: driver missing at $DRIVER — tools/peer-contract/run.sh builds it" >&2; exit 3; }

podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work -w "/work/$PEER_REL" \
  -e KPC_SKIP_LOCAL="${KPC_SKIP_LOCAL:-0}" -e PYTHONDONTWRITEBYTECODE=1 -e PYTHONUNBUFFERED=1 \
  entity-core-keystone/python-toolchain:latest \
  bash -c '
    set -eu
    PEER=/work/'"$PEER_REL"'
    OUT=/work/'"$OUT"'
    WHEELS="$PEER/output/contract"
    rm -rf "$WHEELS" && mkdir -p "$WHEELS"

    # The two packages, built from their own pyproject.toml, then installed the way a
    # third party installs them: no index, no source tree, the dependency resolved by pip.
    python "$PEER/contract/wheel.py" "$PEER" "$WHEELS" >/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; }
    python "$PEER/contract/wheel.py" "$PEER/contract/host" "$WHEELS" >>/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; }
    pip install --no-index --no-cache-dir --disable-pip-version-check --find-links "$WHEELS" \
      entity-core-protocol-python-contract-host >>/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; }

    rm -rf /tmp/kpc && mkdir -p /tmp/kpc
    # cwd /tmp/kpc: `python -m` puts the cwd on sys.path, and no source tree may be there.
    unset PYTHONPATH
    (cd /tmp/kpc && /work/'"$DRIVER"' \
      -host "python -m kpc_host" \
      -bare-host "python -m entity_core.host" \
      -peer-package entity-core-protocol-python \
      -workdir /tmp/kpc -out "$OUT/cases.json")

    if [ "$KPC_SKIP_LOCAL" != "1" ]; then
      # The local tests run against the SOURCE of this tree (PYTHONPATH=src wins over the
      # installed wheel). The contract test functions are named with the requirement prefix
      # report.py matches (embed_create__…); pyproject.toml tells pytest to collect them.
      # No pipe: the test exit status is recorded, not swallowed (AGENTS.md: `cmd | tail`
      # reports tail'"'"'s exit code). A failing test is evidence, so it does not abort the run.
      rc=0
      PYTHONPATH=src python -m pytest tests -p no:cacheprovider -rA \
        --junitxml=/tmp/kpc/junit.xml >"$OUT/local.txt" 2>&1 || rc=$?
      python "$PEER/contract/junit_to_libtest.py" /tmp/kpc/junit.xml >>"$OUT/local.txt" 2>&1 || true
      echo "local tests exit $rc" >>"$OUT/local.txt"
    fi
  '
