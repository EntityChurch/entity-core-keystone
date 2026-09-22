#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-ocaml. Container-bound,
# sealed-offline (--network=none), driven from the HOST like its cohort siblings.
#
# This peer had no run-s2.sh until 2026-09-02. Its harnesses existed —
# test/conformance.ml, test/selftest.ml, test/type_registry.ml and the guarded
# test/agility.ml — but the only host-invocable entry point was run-agility.sh,
# and that one re-execs nothing: it is an INSIDE-container script, so running it
# from the host fails at `missing /work/... — build the FFI codec first` while
# the file plainly exists on disk. ($SODIR is a container path; /work is the
# repo's mount point and does not exist on the host.) The S2 axis is swept by
# looking for `run-s2.sh`, so this peer was neither measured nor reported as
# missing, and its transcribed agility pins went unchecked against a corpus that
# had been superseded upstream.
#
#   ./run-s2.sh          # ECF corpus + selftests + type registry + agility
#   ./run-s2.sh agility  # the crypto-agility harness only
#
# FFI impl selection is inherited by run-agility.sh: FFI=c (default) or FFI=rust.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ocaml-toolchain:latest"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT":/work:Z "$IMAGE" sh -c "$1"
}

# type_registry.exe takes the .diag corpus as argv(1) and dies with
# Invalid_argument("index out of bounds") without it — pass it explicitly.
VEC=/work/protocol-generator/shared/test-vectors
CORE='set -e
      cd /work/protocol-generator/ocaml
      eval "$(opam env --switch=ec-ocaml)"
      dune build test/conformance.exe test/selftest.exe test/type_registry.exe
      echo "── ECF conformance corpus ──";  dune exec test/conformance.exe
      echo "── uncovered-range selftests ──"; dune exec test/selftest.exe
      echo "── type-registry byte-diff ──"
      dune exec test/type_registry.exe -- '"$VEC"'/type-registry/type-registry-vectors.diag'

AGILITY='sh /work/protocol-generator/ocaml/run-agility.sh'

case "${1:-all}" in
  agility) run "$AGILITY" ;;
  *)       run "$CORE" && run "$AGILITY" ;;
esac
