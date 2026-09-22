#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-rust. Container-bound, sealed-offline.
#
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
# `cargo test --offline` on its own FAILS here with "no matching package named
# ed25519-dalek found / location searched: crates.io index" — which reads as a
# missing dependency and is not one. The crate closure lives in the gitignored
# `output/vendor` mirror (a plain `cargo vendor`), and cargo only looks there
# once crates-io is source-replaced. Same setup run-s4.sh does; kept identical
# so the two cannot drift.
#
#   ./run-s2.sh          # cargo test (codec + peer unit suites)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
PROJ=/work/protocol-generator/rust

podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
  -v "$REPO_ROOT":/work:Z -w "$PROJ" \
  entity-core-keystone/rust-toolchain:latest \
  bash -lc '
    set -eu
    [ -d '"$PROJ"'/output/vendor ] || {
      echo "run-s2: ERROR vendored crate mirror missing at output/vendor" >&2
      echo "  It is gitignored offline material, not a dependency change." >&2
      echo "  Recreate with: cargo vendor output/vendor   (needs network, once)" >&2
      exit 3; }
    export CARGO_HOME=/tmp/cargo-home
    mkdir -p "$CARGO_HOME"
    cat > "$CARGO_HOME/config.toml" <<EOF
[source.crates-io]
replace-with = "vendored-sources"
[source.vendored-sources]
directory = "'"$PROJ"'/output/vendor"
EOF
    cargo test --offline'
