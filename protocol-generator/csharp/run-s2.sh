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
#   ./run-s2.sh          # ECF corpus (71) + unit tests (34) + agility harness
#   ./run-s2.sh agility  # agility harness only
#
# NETWORK: on, unlike most siblings. `dotnet restore` reaches nuget.org for the
# service index and vulnerability data even when every package is already in the
# cache volume, so --network=none fails at restore rather than at download. The
# packages themselves are pinned by the committed packages.lock.json and cached
# in the `kc-nuget` podman volume. Sealing this peer offline means vendoring the
# NuGet closure into the image the way ghc-toolchain now vendors the Hackage one;
# that is a real gap and it is named here rather than papered over with a
# comment claiming offline operation.
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
  podman run $PODMAN_RUN_CAPS --rm \
    -v "$REPO_ROOT":/work:Z -v kc-nuget:/nuget -w "$WORKDIR" "$IMAGE" \
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
