#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-python. Container-bound,
# sealed-offline (--network=none), driven from the HOST like its cohort siblings.
#
# Added 2026-09-02 with the rest of the S2 sweep coverage. Until then this peer's
# test suite could not run in its own toolchain image at all: the tests
# `import pytest`, pytest was declared only as a pyproject `dev` extra, and the
# image installed the RUNTIME closure only. The image now carries the test
# closure too, hash-pinned from the peer's own requirements-dev.txt.
#
# PYTHONPATH=src is not optional: this is a PEP 517 src-layout project and the
# package is not installed into the venv, so without it every test module dies
# with `ModuleNotFoundError: No module named 'entity_core'` — which reads as a
# broken image rather than a missing path.
#
#   ./run-s2.sh          # the full pytest suite
#   ./run-s2.sh codec    # the codec/conformance tests only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/python-toolchain:latest"
WORKDIR="/work/protocol-generator/python"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT":/work:Z -w "$WORKDIR" -e PYTHONPATH=src "$IMAGE" \
    bash -lc "$1"
}

case "${1:-test}" in
  codec) run 'python -m pytest tests/conformance -q' ;;
  *)     run 'python -m pytest tests -q' ;;
esac
