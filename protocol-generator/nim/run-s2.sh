#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-nim. Container-bound, sealed-offline.
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
# NOT `nimble test`: nimble refuses to parse this package's own version string —
#   Error: Version may only consist of numbers and the '.' character but found '-'
# because the peer is at `0.1.0-pre` and nimble's packageparser rejects the
# pre-release hyphen. The nimble task's compile line is invoked directly instead,
# which is what that task would have run.
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
podman run $PODMAN_RUN_CAPS --rm --network=none \
  -v "$REPO_ROOT":/work:Z -w /work/protocol-generator/nim \
  entity-core-keystone/nim-toolchain:latest \
  bash -lc 'set -e
    echo "── ECF conformance corpus ──"
    nim c -d:release --hints:off --path:src -o:tests/tconformance_bin tests/tconformance.nim
    ./tests/tconformance_bin ../shared/test-vectors/ecf-conformance/conformance-vectors.cbor
    echo "── multisig accept-path ──"
    nim c -d:release --hints:off --path:src -o:tests/tmultisig_bin tests/tmultisig.nim
    ./tests/tmultisig_bin
    echo "── spec 0.8.2.20 → .25 (ladder / path check / sentinel scope / §4.11) ──"
    # Asserts its own executed COUNT against a floor: a gate whose success message
    # carries no number cannot tell "all green" from "nothing ran".
    nim c --mm:orc --overflowChecks:on -d:release --hints:off --path:src \
      -o:tests/tspec0825_bin tests/tspec0825.nim
    ./tests/tspec0825_bin'
