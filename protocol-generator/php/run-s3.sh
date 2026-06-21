#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke + the genuine-multisig K-of-N
# accept-path + the 53/53 type-registry gates, container-bound and sealed-offline
# (--network=none). Loopback is intra-container localhost (127.0.0.1), which works
# under --network=none — so the WHOLE S3 gate stays dependency-sealed and offline.
#
#   ./run-s3.sh           # the full S3 gate (the entire PHPUnit suite + S2 codec)
#   ./run-s3.sh smoke     # the two-peer loopback smoke only (SmokeTest, 12/12)
#   ./run-s3.sh units     # offline unit gates only (multisig + type-registry)
#
# ext-sodium + ext-gmp are bundled in the php-toolchain image; PHPUnit is vendored
# at image build time; the peer + codec are hand-rolled in-repo (zero runtime
# Composer deps). The single-thread stream_select event loop (A-PHP-005) makes the
# §4.8 store-safety MUST structural — there is no concurrency to race.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/php-toolchain:latest"
WORKDIR="/work/protocol-generator/php"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

INSTALL='composer install --no-interaction --prefer-dist 2>/dev/null'

case "${1:-all}" in
  smoke)
    run "$INSTALL && vendor/bin/phpunit tests/SmokeTest.php"
    ;;
  units)
    run "$INSTALL && vendor/bin/phpunit --testdox tests/MultiSigCapabilityTest.php tests/TypeRegistryTest.php"
    ;;
  *)
    run "$INSTALL && vendor/bin/phpunit --testdox"
    ;;
esac
