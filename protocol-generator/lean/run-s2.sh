#!/usr/bin/env bash
# S2 codec conformance — entity-core-protocol-lean. Container-bound,
# sealed-offline (--network=none), driven from the HOST like its cohort siblings.
#
# Added 2026-09-02 with the rest of the S2 sweep coverage.
#
# The codec .so mount at /codec is load-bearing, not incidental: lakefile links
# the executables with `-L/codec -lentitycore_codec`, so without the bind mount
# `lake build` fails at the LINK step with
#     ld.lld: error: unable to find library -lentitycore_codec
# after compiling every module successfully — which reads as a toolchain fault
# rather than a missing mount. Same mount run-s4.sh makes; kept identical so the
# two cannot drift.
#
#   ./run-s2.sh          # build + the ECF corpus + the selftest binary
#   ./run-s2.sh build    # lake build only
# Set INCONTAINER=1 to skip the self-relaunch (already inside).
set -eu

CODEC_DIR_HOST_REL="ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release"
CORPUS=/work/protocol-generator/shared/test-vectors/ecf-conformance/conformance-vectors.cbor

if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  [ -f "$HOSTREPO/$CODEC_DIR_HOST_REL/libentitycore_codec.so" ] || {
    echo "run-s2: ERROR codec not built: $CODEC_DIR_HOST_REL/libentitycore_codec.so" >&2
    echo "  build it first, inside containers/cargo:" >&2
    echo "  podman run \$PODMAN_RUN_CAPS --rm -v \"$HOSTREPO\":/work:Z \\" >&2
    echo "    -w /work/ffi-generator/c-abi/entity-core-codec-ffi-rust \\" >&2
    echo "    localhost/entity-core-keystone/cargo:latest cargo build --release" >&2
    exit 2; }
  exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z \
    -v "$HOSTREPO/$CODEC_DIR_HOST_REL":/codec:z,ro \
    -w /work/protocol-generator/lean -e LD_LIBRARY_PATH=/codec \
    localhost/entity-core-keystone/lean-toolchain:latest \
    sh /work/protocol-generator/lean/run-s2.sh "$@"
fi

cd /work/protocol-generator/lean
lake build
[ "${1:-test}" = "build" ] && exit 0
echo "── ECF conformance corpus ──"
.lake/build/bin/conformance "$CORPUS"
echo "── uncovered-range selftests ──"
.lake/build/bin/selftest
