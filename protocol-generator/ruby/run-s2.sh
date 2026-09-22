#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-ruby. Container-bound,
# sealed-offline (--network=none), driven from the HOST like its cohort siblings.
#
# This peer had no run-s2.sh until 2026-09-02. Its S2 content was reachable only
# as a side effect of `run-s3.sh all` ("smoke + the S2 codec + agility
# regression"), which is not where anyone looks for it: the S2 axis is swept by
# looking for `run-s2.sh`, so this peer was neither measured on that axis nor
# reported as missing from it.
#
#   ./run-s2.sh          # codec + conformance + agility + multisig (rake test, minus smoke)
#   ./run-s2.sh agility  # the crypto-agility corpus only
#   ./run-s2.sh all      # every suite including the S3 two-peer loopback smoke
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

# S2 is the codec axis: everything except the S3 loopback smoke, which needs the
# two-peer transport and belongs to run-s3.sh.
S2_TESTS='test/codec_test.rb test/conformance_test.rb test/agility_test.rb test/multisig_test.rb'

case "${1:-test}" in
  agility) run "bundle exec ruby -Ilib -Itest test/agility_test.rb" ;;
  all)     run "bundle exec rake test" ;;
  *)       run "for f in $S2_TESTS; do echo \"── \$f ──\"; bundle exec ruby -Ilib -Itest \"\$f\" || exit 1; done" ;;
esac
