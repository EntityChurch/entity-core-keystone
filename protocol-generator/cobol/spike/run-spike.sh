#!/usr/bin/env bash
# COBOL feasibility spike runner (decision D2). Compiles + runs the four
# go/no-go probes inside the cobol-toolchain container. Throwaway exploration:
# a "no" on any probe is itself a finding for SPIKE-FINDINGS.md.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
. "$REPO_ROOT/tools/podman-caps.sh"
IMG="entity-core-keystone/cobol-toolchain:latest"
CODEC_C="ffi-generator/c-abi/entity-core-codec-ffi-c/build"

podman run $PODMAN_RUN_CAPS --rm \
  -v "$REPO_ROOT":/work:z \
  -w /work/protocol-generator/cobol/spike \
  -e LD_LIBRARY_PATH="/work/$CODEC_C" \
  "$IMG" bash -ec '
    echo "=== cobc ==="; cobc --version | head -1; echo

    echo "=== PROBE 1: recursion (RECURSIVE + LOCAL-STORAGE) ==="
    cobc -x -free -o /tmp/p1 p1-recursion.cob && /tmp/p1; echo

    echo "=== PROBE 2: variable-length byte buffers + CBOR byte parse ==="
    cobc -x -free -o /tmp/p2 p2-varlen.cob && /tmp/p2; echo

    echo "=== PROBE 3: uint64 integer head-form vs decimal/PIC model ==="
    echo "--- 3a: default (binary-truncate ON) ---"
    cobc -x -free -o /tmp/p3a p3-uint64.cob && /tmp/p3a; echo
    echo "--- 3b: -fno-binary-truncate (full 8-byte range) ---"
    cobc -x -free -fno-binary-truncate -o /tmp/p3b p3-uint64.cob && /tmp/p3b; echo

    echo "=== PROBE 4: C-ABI FFI to libentitycore_codec (ec_sha256) ==="
    cobc -x -free -fstatic-call -o /tmp/p4 p4-ffi.cob \
        -L"/work/'"$CODEC_C"'" -lentitycore_codec && /tmp/p4; echo

    echo "=== spike complete ==="
'
