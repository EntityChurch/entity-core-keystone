#!/usr/bin/env bash
# S2 codec seam — the Datalog peer's codec/crypto FFI layer over libentitycore_codec.
# Container-bound (datalog-toolchain), CAPPED (tools/podman-caps.sh → $PODMAN_RUN_CAPS),
# OFFLINE (--network=none). The codec lives entirely behind the C-ABI: this script
# builds the Rust seam crate (ascent closure pinned in Cargo.lock at S2), runs the
# seam KAT/N1–N4 unit tests, then the wire-conformance GATE (byte-identity vs the
# pinned v0.8.0 corpus). No green report → no advance.
#
#   ./run-s2.sh          # build + full test (the S2 gate: KAT/N1–N4 + 71-vector corpus)
#   ./run-s2.sh gate     # tests only (assumes the crate is already built)
#   ./run-s2.sh lint     # cargo fmt --check + clippy -D warnings (the Rust floor)
#   ./run-s2.sh clean     # cargo clean
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/datalog-toolchain:latest"
WORKDIR="/work/protocol-generator/datalog"

# Offline: the datalog-toolchain image pre-populated /cargo with ascent 0.8.0's full
# closure during the GO-gate build, so --network=none + --offline resolves + builds.
# CARGO_TARGET_DIR is a container-local path (NOT the :Z bind mount): the host is
# SELinux-enforcing and ld denies "set dynamic section sizes" when writing shared
# objects (ascent's proc-macro dylib) onto the relabelled volume. Cargo.lock is still
# written next to Cargo.toml on the mount (a plain file write) → persists to the host.
CARGO_ENV="export CARGO_TARGET_DIR=/tmp/dl-target"
run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$CARGO_ENV; $*"
}

case "${1:-all}" in
  gate)  run "cargo test --release --offline -- --nocapture" ;;
  lint)  run "cargo fmt --check && cargo clippy --release --offline --all-targets -- -D warnings" ;;
  clean) run "cargo clean" ;;
  *)     run "cargo build --release --offline && cargo test --release --offline -- --nocapture" ;;
esac
