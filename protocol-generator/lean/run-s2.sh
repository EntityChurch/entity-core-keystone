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
    -e INCONTAINER=1 -e PROOF_FLOOR="${PROOF_FLOOR:-}" \
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

# ── the proofs: THE proof check, and until 2026-09-03 nothing ran it ──────────
# `lake build EntityCoreProofs` is called "the proof check" in three keystone
# documents (profile.toml, status/PHASE-S2.md, status/PHASE-S3.md) and was
# invoked by NOTHING -- no Makefile, no harness, no CI. run-s2.sh built the peer
# target; run-s4.sh builds `host`. Neither builds the proofs. Found by
# entity-core-formalization (HANDOFF-2026-08-30-LEAN-PROOF-GATE) and verified here.
#
# AND EXIT 0 IS NOT THE CHECK. Measured by formalization in this same pinned
# toolchain: a `sorry` is a WARNING -- lake prints "Build completed successfully"
# and exits 0 -- and a hand-written `axiom` substituted for a proof exits 0 with
# no warning at all. Only a proof that fails to TYPE-CHECK is non-zero. So a gate
# that trusts the exit code catches one failure mode in three, and the two it
# misses are the two a proof check exists for.
#
# What is asserted instead is the AXIOM SET each theorem depends on, which the
# `#print axioms` lines at the bottom of each proof module already emit:
#   - no declaration may depend on `sorryAx` (a hole) or on any axiom outside the
#     Lean-standard three (propext, Classical.choice, Quot.sound);
#   - and the COUNT of graded declarations must meet a floor, because a build that
#     emitted no axiom lines at all would otherwise pass every name check
#     vacuously -- this repo has shipped that defect six times.
echo "── proofs (EntityCoreProofs: build + axiom grading) ──"
# 37 → 40 on 2026-09-06: the three §5.5a companion theorems adopted from
# entity-core-formalization's hframed proposal (absolute-form isolation, absolute-form
# frame-independence, wildcard peer-agnosticism). The floor tracks reality or it stops
# being a floor.
PROOF_FLOOR="${PROOF_FLOOR:-}"; [ -n "$PROOF_FLOOR" ] || PROOF_FLOOR=40
proof_log=$(mktemp)
lake build EntityCoreProofs >"$proof_log" 2>&1 || {
  echo "run-s2: ERROR EntityCoreProofs failed to build" >&2; cat "$proof_log" >&2; rm -f "$proof_log"; exit 1; }
graded=$(grep -c "depends on axioms" "$proof_log" || true)
bad=$(grep "depends on axioms" "$proof_log" | grep -cE "sorryAx|Classical\.em|nativeDecide" || true)
# the axiom lines wrap, so scan the JOINED text for anything outside the standard three
stray=$(tr '\n' ' ' <"$proof_log" | grep -oE "depends on axioms: \[[^]]*\]" \
        | grep -vE "^depends on axioms: \[(propext|Classical\.choice|Quot\.sound)(, *(propext|Classical\.choice|Quot\.sound))*\]$" \
        | wc -l)
rm -f "$proof_log"
if [ "$graded" -lt "$PROOF_FLOOR" ]; then
  echo "run-s2: ERROR only $graded declaration(s) graded, floor is $PROOF_FLOOR." >&2
  echo "  A proof module that stopped emitting #print axioms passes every name" >&2
  echo "  check vacuously. Lower the floor deliberately or restore the gate lines." >&2
  exit 1
fi
if [ "$bad" -ne 0 ] || [ "$stray" -ne 0 ]; then
  echo "run-s2: ERROR $bad declaration(s) carry a hole, $stray carry a non-standard axiom." >&2
  exit 1
fi
echo "   proofs OK — $graded declarations graded, all on the Lean-standard axiom set"
