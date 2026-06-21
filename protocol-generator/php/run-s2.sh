#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Runs the entity-core-protocol-php native ECF codec gate: the wire-conformance
# corpus (69/69 byte-identical: 64 encode_equal + 5 decode_reject) + the codec
# spike (the GMP uint64 [2^63,2^64-1] band, the f16/f32/f64 float ladder,
# length-first map ordering) + the Ed25519/ECF crypto self-tests — all via the
# PHPUnit suite under tests/. Mounts the repo root so the vendored fixtures under
# protocol-generator/shared/ are reachable. Fully offline: ext-sodium + ext-gmp +
# stdlib hash() are bundled in the php-toolchain image; PHPUnit is vendored at
# image build time; the codec/base58/varint/harness are hand-rolled in-repo.
#
#   ./run-s2.sh           # full gate: composer install (offline) + phpunit
#   ./run-s2.sh spike     # the codec spike + crypto self-tests only
#   ./run-s2.sh conf      # the corpus byte-identity test only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/php-toolchain:latest"
WORKDIR="/work/protocol-generator/php"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

# Composer install is offline: the dev bundle (PHPUnit) is already in the image's
# composer cache from the network-on build step; --no-interaction resolves it from
# there. Core peer has ZERO runtime Composer deps.
INSTALL='composer install --no-interaction --prefer-dist 2>/dev/null'

case "${1:-test}" in
  spike)
    run "$INSTALL && vendor/bin/phpunit --testdox tests/CodecSpikeTest.php tests/CryptoKatTest.php"
    ;;
  conf)
    run "$INSTALL && vendor/bin/phpunit --testdox tests/ConformanceTest.php"
    ;;
  *)
    run "$INSTALL && vendor/bin/phpunit --testdox"
    ;;
esac
