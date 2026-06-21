#!/usr/bin/env bash
# S3 peer machinery — the two-peer loopback smoke test, container-bound and
# sealed-offline (--network=none, loopback only). Boots a RESPONDER Ruby peer on
# a localhost port and drives the §4.1 handshake + core ops from a second Ruby
# peer acting as INITIATOR over real TCP, proving transport + handshake +
# register/dispatch/emit + capability gating + request_id demux end-to-end. A
# second scenario exercises the v7.74 Core Extensibility Boundary (register
# live-hook + §7a echo) under --debug-open-grants + --validate.
#
#   ./run-s3.sh           # the two-peer loopback smoke gate (exits non-zero on FAIL)
#   ./run-s3.sh all       # smoke + the S2 codec + agility regression (full rake test)
#
# The core peer has ZERO runtime gem deps; Minitest + Rake are stdlib default
# gems vendored into the image bundle at build time, so this runs fully offline.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/ruby-toolchain:latest"
WORKDIR="/work/protocol-generator/ruby"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    sh -c "bundle install --local >/dev/null 2>&1; $*"
}

case "${1:-smoke}" in
  all) run "bundle exec rake test" ;;
  *)   run "bundle exec ruby -Ilib -Itest test/smoke_test.rb" ;;
esac
