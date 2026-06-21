#!/usr/bin/env bash
# S2 codec conformance — container-bound, sealed-offline (--network=none).
# Builds + tests the entity-core-protocol-cpp native ECF codec: the wire-conformance
# corpus gate (69/69 byte-identical) + uncovered-range / Ed25519 RFC-8032 self-tests,
# via the hand-rolled CTest harness (test/conformance.cpp) built under ASan/LSan/UBSan
# (memory/UB bugs are test failures). Mounts the repo root so the vendored fixtures
# under protocol-generator/shared/ are reachable. The build is fully offline:
# libsodium is pre-installed in the cpp-toolchain image and everything else
# (CBOR/base58/varint/harness) is hand-rolled in-repo.
#
#   ./run-s2.sh           # full gate: cmake build + ctest (conformance + spike)
#   ./run-s2.sh spike     # the S2 codec spike only (float + map_keys)
#   ./run-s2.sh clang     # the clang++ cross-compiler ASan/UBSan pass
#   ./run-s2.sh xcheck    # the optional FFI byte-for-byte cross-check (needs the
#                         # sibling C-ABI .so built under build-xcheck/)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMAGE="entity-core-keystone/cpp-toolchain:latest"
WORKDIR="/work/protocol-generator/cpp"
VEC="../shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor"

run() {
  podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w "$WORKDIR" "$IMAGE" \
    bash -lc "$*"
}

case "${1:-test}" in
  spike)
    run "cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug >/dev/null &&
         cmake --build build --target conformance >/dev/null &&
         ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./build/conformance $VEC --spike"
    ;;
  clang)
    run "CXX=clang++ cmake -S . -B build-clang -G Ninja -DCMAKE_BUILD_TYPE=Debug >/dev/null &&
         cmake --build build-clang --target conformance >/dev/null &&
         ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./build-clang/conformance $VEC"
    ;;
  xcheck)
    # Builds the sibling C-ABI codec .so, then the cross-check against it.
    run "(cd /work/ffi-generator/c-abi/entity-core-codec-ffi-c &&
            cmake -S . -B build-xcheck -G Ninja >/dev/null && cmake --build build-xcheck >/dev/null) &&
         cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug \
            -DEC_FFI_XCHECK_LIBDIR=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build-xcheck >/dev/null &&
         cmake --build build --target ffi_xcheck >/dev/null &&
         ./build/ffi_xcheck"
    ;;
  *)
    run "cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug >/dev/null &&
         cmake --build build >/dev/null &&
         ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1 ./build/conformance $VEC &&
         echo '--- ctest ---' &&
         ctest --test-dir build --output-on-failure"
    ;;
esac
