#!/usr/bin/env bash
# S3 smoke gate — the Datalog peer's live wire surface. Container-bound
# (datalog-toolchain), CAPPED ($PODMAN_RUN_CAPS), OFFLINE (--network=none). Two legs,
# both inside ONE capped container run (the Go entity-peer is a fedora:43 ELF that runs
# in the same image + loopback namespace, so the run stays sealed-offline):
#
#   LEG 1 — loopback gate (deterministic, in-tree): two Datalog peers over real TCP →
#           §4.1 handshake BOTH legs + AUTHORIZED 404 + 8-way request_id demux (N7) +
#           teardown. The Ascent §5/§6.6 authority interior is load-bearing end-to-end.
#           This is `cargo test --test loopback`.
#   LEG 2 — cross-impl interop: the Datalog peer (INITIATOR) dials the reference
#           `entity-core-go entity-peer` (RESPONDER, -open-access -validate) and
#           completes the handshake + an authorized 404 — proving byte-level wire
#           interop with an independent implementation.
#
# CARGO_TARGET_DIR is container-local (/tmp), NOT the :Z bind mount (A-DL-009: SELinux
# denies ld writing Ascent's proc-macro dylib onto the relabelled volume). Cargo.lock
# persists to the host (a plain file write next to Cargo.toml).
#
#   ./run-s3.sh          # build + both legs (the S3 gate)
#   ./run-s3.sh loopback # leg 1 only
#   ./run-s3.sh lint     # fmt --check + clippy -D warnings
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/datalog-toolchain:latest"
WORKDIR="/work/protocol-generator/datalog"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "export CARGO_TARGET_DIR=/tmp/dl-target; $*"
}

LOOPBACK='cargo test --release --offline --test loopback -- --nocapture'

# Leg 2 in-container script: build the peer + interop bin, boot the Go reference peer,
# wait for LISTENING, run the interop driver, tear down.
INTEROP='
set -e
cargo build --release --offline --bin entity-peer-datalog --bin interop >/dev/null
PORT=7601
/work/output/s4-oracles/entity-peer -addr 127.0.0.1:$PORT -open-access -validate >/tmp/ref.out 2>&1 &
REF=$!
trap "kill $REF 2>/dev/null || true" EXIT
for i in $(seq 1 100); do
  ss -ltn 2>/dev/null | grep -q ":$PORT " && break
  kill -0 $REF 2>/dev/null || { echo "reference peer exited early:"; cat /tmp/ref.out; exit 1; }
  sleep 0.1
done
/tmp/dl-target/release/interop --connect 127.0.0.1:$PORT
'

case "${1:-all}" in
  loopback) run "$LOOPBACK" ;;
  interop)  run "$INTEROP" ;;
  lint)     run "cargo fmt --check && cargo clippy --release --offline --all-targets -- -D warnings" ;;
  clean)    run "cargo clean" ;;
  *)
    run "cargo build --release --offline && $LOOPBACK"
    run "$INTEROP"
    ;;
esac
