#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-csharp. Container-bound, driven
# from the HOST like its cohort siblings.
#
# This peer had no run-s2.sh until 2026-09-02, which is why its S2 axis was never
# swept: the sweep looks for `run-s2.sh`, so a peer without one is neither
# measured nor reported as missing. Its crypto-agility harness in particular had
# been carrying transcribed pins from a superseded corpus — passing, because the
# peer computed the same wrong thing the test expected.
#
#   ./run-s2.sh          # ECF corpus (71) + unit tests (51) + agility harness (24)
#   ./run-s2.sh agility  # agility harness only
#
# NETWORK: none, like every sibling. This used to say the opposite, and named the gap
# rather than papering over it: `dotnet restore` reaches nuget.org for the service index
# even when every package is already cached, so this peer ran with a network namespace
# and a host-local `kc-nuget` podman volume. That made csharp the one peer whose
# conformance run was not reproducible on a machine that had not already populated the
# volume -- measured 2026-09-02 on a clean run: NU1301, no build, no report.
#
# Closed the way ghc-toolchain vendors Hackage and python-toolchain vendors pip: the
# dotnet9 image seeds /opt/nuget at BUILD time from this peer's own packages.lock.json
# with --locked-mode, then re-restores against an empty source list to prove the closure
# is complete. An unsatisfiable lockfile now fails the image build, which is the right
# place to find out.
#
# -p:UseAppHost=false: building an apphost wants the
# Microsoft.NETCore.App.Host.fedora.43-x64 pack, which is published for neither
# the SDK's bundled library-packs nor nuget.org. The managed dll runs fine under
# `dotnet`; the native launcher is not something a conformance harness needs.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/dotnet9:latest"
WORKDIR="/work/protocol-generator/csharp"
NOAPPHOST="-p:UseAppHost=false"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none \
    -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -c "$1"
}

case "${1:-all}" in
  agility)
    run "dotnet run --project test/EntityCore.Protocol.Agility $NOAPPHOST" ;;
  *)
    run "set -e
         echo '── ECF conformance corpus ──'
         dotnet run --project test/EntityCore.Protocol.Conformance $NOAPPHOST
         echo '── unit tests ──'
         dotnet test test/EntityCore.Protocol.Tests $NOAPPHOST
         echo '── crypto-agility corpus ──'
         dotnet run --project test/EntityCore.Protocol.Agility $NOAPPHOST" ;;
esac
