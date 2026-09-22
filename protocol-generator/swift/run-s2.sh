#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-swift. Container-bound, sealed-offline.
#
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
# --security-opt label=disable is required, not cosmetic: swift-crypto's
# BoringSSL sources `#include` .cc.inc files out of .build/checkouts, and under
# the default SELinux label the compiler gets "Permission denied" on them —
# which surfaces as a BoringSSL compile error plus an llbuild SQLite assertion
# failure, neither of which points at the label.
#
# THE COUNT IS ASSERTED, NOT JUST PRINTED. `swift test` exits 0 for a suite that
# ran 69 cases and for one that ran none — a dropped test file, a mis-declared
# target, or a filter that matches nothing all leave this gate green. That is the
# gate-that-examined-zero-things shape the charter names, and the enforcement it
# asks for is one line: require the executed count to be at or above the floor.
#
# About the "0 tests in 0 suites" line at the end of the output: that is the
# swift-testing runner, which Swift 6 runs alongside XCTest. This package has no
# `@Test` functions — all five test files are XCTestCase — so it correctly reports
# an empty run. It is not a broken target and not a silent skip; the 69 XCTest
# cases below it are the suite. If swift-testing cases are ever added, that line
# changes and the XCTest floor here still holds.
#
#   ./run-s2.sh          # swift test + count assertion
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"

# RAISED 35 -> 69 with the 0.8.2.20/.21/.24/.25 scope-algebra suite
# (Tests/EntityCoreProtocolTests/ScopeAlgebraTests.swift, 34 cases). A floor left at
# the old number would pass a tree that silently dropped the whole new file, which is
# the one thing this line exists to catch.
FLOOR="${SWIFT_TEST_FLOOR:-69}"

# No pipe: `cmd | tee` reports the EXIT STATUS OF TEE, which is how a failing gate
# reads as green (written down twice in AGENTS.md, re-created twice anyway).
out="$(podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/swift \
  entity-core-keystone/swift-toolchain:latest \
  bash -lc 'swift test' 2>&1)" || { echo "$out"; echo "run-s2: swift test FAILED" >&2; exit 1; }
echo "$out"

ran="$(printf '%s\n' "$out" |
  sed -n "s/.*Executed \([0-9]\{1,\}\) tests\{0,1\}, with 0 failures.*/\1/p" | tail -1)"
if [ -z "$ran" ]; then
  echo "run-s2: could not find an 'Executed N tests, with 0 failures' line — not green" >&2
  exit 1
fi
if [ "$ran" -lt "$FLOOR" ]; then
  echo "run-s2: executed $ran XCTest cases, floor is $FLOOR — the suite SHRANK" >&2
  exit 1
fi
echo "run-s2: OK — $ran XCTest cases executed, 0 failures (floor $FLOOR)"
