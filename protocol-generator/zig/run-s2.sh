#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-zig. Container-bound, sealed-offline.
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
#   ./run-s2.sh          # zig build test (in-file unit tests, leak-checked) + corpus
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/zig \
  entity-core-keystone/zig-toolchain:latest \
  bash -lc 'set -e
    # A GATE WHOSE SUCCESS MESSAGE CONTAINS NO NUMBER CANNOT DISTINGUISH "all green"
    # FROM "nothing ran" (AGENTS.md, ratified; seven occurrences). A bare `zig build
    # test` prints NOTHING and exits 0 both when 42 tests pass and when a mis-declared
    # root module leaves zero of them reachable. `--summary all` prints the count;
    # ZIG_TEST_FLOOR asserts it, so a suite that silently loses tests goes red.
    ZIG_TEST_FLOOR=42
    echo "── unit tests (std.testing.allocator, leak-checked) ──"
    zig build test --summary all 2>&1 | tee /tmp/zig-test.out
    n=$(sed -n "s/.*; \([0-9]\+\)\/\([0-9]\+\) tests passed.*/\1/p" /tmp/zig-test.out | head -1)
    [ -n "$n" ] || { echo "run-s2: could not read the executed test count"; exit 1; }
    [ "$n" -ge "$ZIG_TEST_FLOOR" ] || { echo "run-s2: only $n tests ran, floor is $ZIG_TEST_FLOOR"; exit 1; }
    echo "unit tests executed: $n (floor $ZIG_TEST_FLOOR)"
    echo "── ECF conformance corpus ──"; zig build conformance'
