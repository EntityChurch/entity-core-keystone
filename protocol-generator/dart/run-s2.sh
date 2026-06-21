#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds + tests the entity-core-protocol-dart native ECF codec: the
# wire-conformance corpus gate (69/69 byte-identical) + the uncovered-range /
# Ed25519 RFC-8032 self-tests, via the hand-rolled package:test harness. Mounts
# the repo root so the vendored fixtures under protocol-generator/shared/ are
# reachable. Fully offline: cryptography_plus + crypto + test are pre-fetched
# into the image PUB_CACHE; everything else (ECF codec / base58 / varint /
# harness) is hand-rolled in-repo. `dart pub get --offline` resolves the lock.
#
#   ./run-s2.sh           # full gate: dart analyze + dart test (conformance + selftests)
#   ./run-s2.sh test      # dart test only (skip analyze)
#   ./run-s2.sh web       # dart2js web-int round-trip smoke (A-DART-006)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/dart-toolchain:latest"
WORKDIR="/work/protocol-generator/dart"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-all}" in
  test)
    run "dart pub get --offline && dart test"
    ;;
  web)
    # Compile the codec to JS (dart2js) and EXECUTE it under node — the real
    # web-truncation proof (A-DART-006): the [2^63, 2^64-1] uint64 band must
    # encode byte-identically under JS-number semantics, which only holds because
    # the head-form carrier is BigInt. node ships in the image as a test-time JS
    # runtime (not a peer dep).
    run "dart pub get --offline && \
         dart compile js -o /tmp/web_int_smoke.js tool/web_int_smoke.dart && \
         node /tmp/web_int_smoke.js"
    ;;
  *)
    run "dart pub get --offline && \
         dart analyze --fatal-infos && \
         dart test"
    ;;
esac
