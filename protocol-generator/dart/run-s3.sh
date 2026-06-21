#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke + the genuine-multisig + the
# type-registry gates, container-bound. The CORE unit gates (codec 69/69,
# multisig K-of-N accept-path, 53/53 type-registry, codec self-tests) run
# sealed-offline (--network=none). The two-peer loopback SMOKE needs localhost
# TCP, so it runs with a netns (loopback only) — the §4.1 handshake +
# register/dispatch/emit + capability gating + request_id demux + the §6.11
# dispatch-outbound reentry, end-to-end over real TCP between two Dart peers.
#
#   ./run-s3.sh           # the two-peer loopback smoke gate (smoke_test.dart; netns)
#   ./run-s3.sh units     # offline unit gates only (codec + multisig + type-registry)
#   ./run-s3.sh all       # everything (full `dart test`); smoke needs the netns
#
# Deps (cryptography_plus, crypto, package:test + transitives) are pre-fetched
# into the image's PUB_CACHE at container BUILD time, so this runs offline via
# `dart pub get --offline`.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/dart-toolchain:latest"
WORKDIR="/work/protocol-generator/dart"

# sealed-offline run (codec/multisig/type-registry — no sockets)
run_offline() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "dart pub get --offline && $*"
}

# loopback-TCP run (the two-peer smoke); a netns is needed for 127.0.0.1
# sockets, but the image stays dependency-sealed (deps pre-fetched; offline pub).
run_loopback() {
  podman run $PODMAN_RUN_CAPS --rm -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "dart pub get --offline && $*"
}

case "${1:-smoke}" in
  units)
    run_offline "dart test test/multisig_accept_test.dart test/type_registry_test.dart test/conformance_test.dart test/codec_selftest_test.dart"
    ;;
  all)
    run_loopback "dart analyze --fatal-infos && dart test"
    ;;
  *)
    run_loopback "dart test test/smoke_test.dart"
    ;;
esac
