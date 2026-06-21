#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Loads the entity-core ASDF system + the hand-rolled harness, runs the ECF
# corpus gate (69/69 byte-identical) + the uncovered-range/Ed448-KAT selftest.
# Mounts the repo root so the vendored fixtures under protocol-generator/shared/
# are reachable. Deps (ironclad 0.61) are pre-installed at container-build time,
# so the dev loop runs fully offline.
#
#   ./run-s2.sh           # full gate (conformance + selftest); exits non-zero on FAIL
#   ./run-s2.sh conform   # ECF corpus PASS/FAIL counts only
#   ./run-s2.sh self      # uncovered-range + Ed448 KAT selftest only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/common-lisp-toolchain:latest"
WORKDIR="/work/protocol-generator/common-lisp"

# NOTE: `(require :asdf)` MUST be its own --eval, evaluated before any form that
# names the ASDF package — the reader resolves `asdf:...` at read time, before a
# preceding form in the SAME --eval string executes.
run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    sbcl --non-interactive \
      --eval '(require :asdf)' \
      --eval '(load #p"/opt/quicklisp/setup.lisp")' \
      --eval '(push (truename ".") asdf:*central-registry*)' \
      --eval '(handler-bind ((warning (function muffle-warning))) (asdf:load-system :entity-core/test))' \
      --eval "$1"
}

case "${1:-test}" in
  conform) run '(entity-core/test::run-conformance)' ;;
  self)    run '(format t "failures: ~a~%" (entity-core/test::run-selftest))' ;;
  *)       run '(entity-core/test:run-all)' ;;
esac
