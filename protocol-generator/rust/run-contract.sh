#!/usr/bin/env bash
# Keystone peer contract — entity-core-protocol-rust. Container-bound, sealed-offline.
#
# Builds the bare host and the contract host (a separate package, contract/host/), runs the shared
# wire driver against them, and runs the peer's local contract tests. It writes RAW EVIDENCE only:
#   $OUT/cases.json   the driver's case records
#   $OUT/local.txt    the libtest output of `cargo test` (report.py extracts the contract tests)
# It never computes a verdict — tools/peer-contract/run.sh calls report.py for that.
#
#   tools/peer-contract/run.sh rust            # the normal entry point
#   OUT=output/scratch/x ./run-contract.sh     # evidence only
#
# PEER_REL (default protocol-generator/rust) lets tools/peer-contract/plant.py point this same
# script at a planted scratch copy, so a plant is measured by exactly the harness a real run uses.
# KPC_SKIP_LOCAL=1 skips the local tests (plants measure the driver cases).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
PEER_REL="${PEER_REL:-protocol-generator/rust}"
OUT="${OUT:-output/scratch/peer-contract/rust}"
DRIVER="${DRIVER:-output/peer-contract/kpc-driver}"
TARGET_REL="${CARGO_TARGET_REL:-}"
mkdir -p "$REPO_ROOT/$OUT"
[ -x "$REPO_ROOT/$DRIVER" ] || { echo "run-contract: driver missing at $DRIVER — tools/peer-contract/run.sh builds it" >&2; exit 3; }

podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work:Z -w "/work/$PEER_REL" \
  -e KPC_SKIP_LOCAL="${KPC_SKIP_LOCAL:-0}" -e TARGET_REL="$TARGET_REL" \
  entity-core-keystone/rust-toolchain:latest \
  bash -c '
    set -eu
    PEER=/work/'"$PEER_REL"'
    OUT=/work/'"$OUT"'
    VENDOR=/work/protocol-generator/rust/output/vendor
    [ -d "$VENDOR" ] || { echo "run-contract: vendored crate mirror missing at $VENDOR (cargo vendor output/vendor, once)" >&2; exit 3; }
    export CARGO_HOME=/tmp/cargo-home
    mkdir -p "$CARGO_HOME"
    printf "[source.crates-io]\nreplace-with = \"v\"\n[source.v]\ndirectory = \"%s\"\n" "$VENDOR" > "$CARGO_HOME/config.toml"
    if [ -n "$TARGET_REL" ]; then export CARGO_TARGET_DIR=/work/$TARGET_REL; fi
    T="${CARGO_TARGET_DIR:-$PEER/target}"
    HT="${CARGO_TARGET_DIR:-$PEER/contract/host/target}"

    cargo build --offline --release --bin entity-peer-host >/tmp/build.log 2>&1 || { cat /tmp/build.log >&2; exit 1; }
    (cd contract/host && cargo build --offline --release >>/tmp/build.log 2>&1) || { cat /tmp/build.log >&2; exit 1; }

    rm -rf /tmp/kpc && mkdir -p /tmp/kpc
    /work/'"$DRIVER"' \
      -host "$HT/release/kpc-host" \
      -bare-host "$T/release/entity-peer-host" \
      -peer-package entity-core-protocol-rust \
      -workdir /tmp/kpc -out "$OUT/cases.json"

    if [ "$KPC_SKIP_LOCAL" != "1" ]; then
      # No pipe: the test exit status is recorded, not swallowed (AGENTS.md: `cmd | tail`
      # reports tail'"'"'s exit code). A failing test is evidence, so it does not abort the run.
      rc=0; cargo test --offline >"$OUT/local.txt" 2>&1 || rc=$?
      echo "local tests exit $rc" >>"$OUT/local.txt"
    fi
  '
