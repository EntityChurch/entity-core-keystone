#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke + the genuine-multisig + type-registry
# gates, container-bound. The CORE unit gates (codec 69/69, multisig K-of-N accept-path,
# 53/53 type-registry) run sealed-offline (--network=none). The two-peer loopback SMOKE
# needs localhost TCP, so it runs with a netns (loopback only) — the §4.1 handshake +
# register/dispatch/emit + capability gating + request_id demux + the §6.11
# dispatch-outbound reentry, end-to-end over real TCP between two Kotlin peers.
#
#   ./run-s3.sh           # the two-peer loopback smoke gate (SmokeTest; netns for loopback)
#   ./run-s3.sh units     # offline unit gates only (codec + multisig + type-registry)
#   ./run-s3.sh all       # everything (full `gradle test`); smoke needs the netns
#
# Gradle deps (kotlin-stdlib, kotlinx-coroutines, kotlin-test, JUnit-5) are pre-fetched
# into the image's gradle caches at container BUILD time, so this runs `gradle --offline`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/kotlin-toolchain:latest"
WORKDIR="/work/protocol-generator/kotlin"

# sealed-offline run (codec/multisig/type-registry — no sockets)
run_offline() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    gradle --offline --no-daemon "$@"
}

# loopback-TCP run (the two-peer smoke); a netns is needed for 127.0.0.1 sockets, but the
# image stays dependency-sealed (deps pre-fetched; --offline). Loopback flows only.
run_loopback() {
  podman run $PODMAN_RUN_CAPS --rm -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    gradle --offline --no-daemon "$@"
}

case "${1:-smoke}" in
  units) run_offline test --tests "*MultiSigCapabilityTest" --tests "*TypeRegistryTest" \
                        --tests "*ConformanceTest" ;;
  all)   run_loopback clean test ;;
  *)     run_loopback test --tests "*SmokeTest" ;;
esac
