#!/usr/bin/env bash
# GO-gate self-test — baked into the datalog-toolchain image build (and runnable
# standalone in the image). Asserts the S1 feasibility gate for the Datalog peer
# (protocol-generator/datalog/) in its FAITHFUL host: Rust + Ascent (embedded
# bottom-up Datalog) + libentitycore_codec (the C-ABI codec/crypto seam):
#
#   1. The Ascent engine evaluates a RECURSIVE §5.5 delegation-closure rule to
#      fixpoint (bottom-up, set-oriented, terminating — the SecPAL/Binder shape).
#   2. The host reaches libentitycore_codec — an ec_sha256("abc") known-answer test.
#   3. An 8-bit-clean TCP echo incl. 0x00 / 0xFF (host-owned binary transport).
#
# FATAL (exit 1) on any failure: the image is valid only if all three pass. The
# checks live in the Rust binary (containers/datalog-toolchain/gogate/) so the gate
# runs in the exact substrate the peer will use.
set -eu

GOGATE_DIR="${GOGATE_DIR:-/opt/gogate}"
export ENTITY_CODEC_DIR="${ENTITY_CODEC_DIR:-/opt/entity-codec}"
export LD_LIBRARY_PATH="${ENTITY_CODEC_DIR}:${LD_LIBRARY_PATH:-}"

echo "== building GO-gate crate (cargo, fetches ascent =0.8.0) =="
cd "$GOGATE_DIR"
cargo build --release --offline 2>/dev/null || cargo build --release

echo "== running GO-gate =="
exec ./target/release/datalog-gogate
