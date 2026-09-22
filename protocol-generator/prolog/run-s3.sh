#!/usr/bin/env bash
# run-s3.sh — S3 peer-machinery gate for the Prolog peer. Runs INSIDE the
# prolog-toolchain container (S1: builds run in containers, not on the host),
# sealed-offline (--network=none, loopback only).
#
# Steps:
#   1. Build libentitycore_codec.so (C-ABI v1.1) + the SWI foreign shim (S2 floor).
#   2. Type-registry gate: render all 53 core types (§9.5) + diff content_hash
#      against the canonical type-registry-vectors.diag (53/53 byte-identical).
#   3. Two-peer loopback smoke gate (11/11): boot a responder peer, drive the §4.1
#      handshake + core ops over real loopback TCP from an initiator peer.
#
# Invoke from the HOST, like every sibling:
#   ./run-s3.sh
# It relaunches itself inside the prolog-toolchain container. Set INCONTAINER=1
# to skip the relaunch (already inside).
#
# This script was inside-container ONLY until 2026-09-02, and the S3 cohort sweep
# caught it the first time one existed: `swipl: command not found`, rc=127, which
# reads as a broken toolchain rather than as a wrong invocation. That is the
# identical defect fixed in this peer's run-s2.sh EARLIER THE SAME DAY — the
# sibling one file over was never checked, which is the charter's own "harden one
# anchor, check its siblings the same day" rule failing on its own terms.
set -euo pipefail

if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z -w /work \
    entity-core-keystone/prolog-toolchain:latest \
    bash /work/protocol-generator/prolog/run-s3.sh "$@"
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"   # repo root (/work)
PEER="$ROOT/protocol-generator/prolog"
CABI="$ROOT/ffi-generator/c-abi/entity-core-codec-ffi-c"
DIAG="$ROOT/protocol-generator/shared/test-vectors/type-registry/type-registry-vectors.diag"
BUILD="$PEER/build"

echo "=============================================================="
echo " S3 peer-machinery gate — entity-core-protocol-prolog"
echo "=============================================================="
swipl --version
echo

# ── 1. Build the C-ABI codec library + foreign shim ─────────────────────────
echo "── [1/4] building libentitycore_codec + SWI foreign shim ──"
CODEC_BUILD="$BUILD/cabi"
mkdir -p "$CODEC_BUILD"
cmake -S "$CABI" -B "$CODEC_BUILD" -DCMAKE_BUILD_TYPE=Release >/dev/null
cmake --build "$CODEC_BUILD" --target entitycore_codec -j"$(nproc)" >/dev/null
SO="$(find "$CODEC_BUILD" -name 'libentitycore_codec.so' | head -1)"
test -n "$SO" || { echo "FATAL: libentitycore_codec.so not built"; exit 1; }
SODIR="$(dirname "$SO")"
swipl-ld -shared -o "$PEER/prolog/ec_codec_pl" "$PEER/c/ec_codec_pl.c" -L"$SODIR" -lentitycore_codec
export LD_LIBRARY_PATH="$SODIR:${LD_LIBRARY_PATH:-}"
echo "    codec + shim built; LD_LIBRARY_PATH=$LD_LIBRARY_PATH"
echo

# ── 2. Type-registry gate (53/53) ────────────────────────────────────────────
echo "── [2/4] type-registry (53 core types, §9.5) ──"
set +e
swipl -q -g run_type_registry_main -t 'halt(2)' "$PEER/test/type_registry.pl" -- "$DIAG"
TR_RC=$?
set -e
echo

# ── 3. The 0.8.2.20 -> 0.8.2.25 scope-algebra units ──────────────────────────
# A SEPARATE STEP WITH ITS OWN EXIT CODE, not a section of the smoke: these are pure
# relations and need no socket, so folding them into a run that opens listeners would
# make a unit failure indistinguishable from a transport one. The COUNT is printed by
# the runner and asserted by it -- a gate whose success message carries no number cannot
# distinguish "all green" from "nothing ran".
echo "── [3/4] scope-algebra units (section 3.3 / 5.2 / 5.5a / 6.3) ──"
set +e
swipl -q -g run_spec0825_main -t 'halt(2)' "$PEER/test/spec0825.pl"
SPEC_RC=$?
set -e
echo

# ── 3b. The 0.8.2.31 section 1.4 PD-2 outbound sub-dispatch gate ─────────────
# ITS OWN STEP AND ITS OWN EXIT CODE, for the same reason as [3/4] above.
#
# THIS IS THE ONLY THING THAT MEASURES THE RULE. Section 6.8 states that its
# confused-deputy substitution is WIRE-INVISIBLE -- "both readings produce a well-formed
# response and differ only in which authority was consulted" -- so the oracle's
# dispatch_outbound_* checks going green is not evidence for it. The discriminating input
# is a VALID credential presented to a handler whose own grant does not cover the request,
# and nothing on the wire drives one. Deleting this step does not turn a number red; it
# silently stops measuring a security rule.
echo "── [3b/4] section 1.4 PD-2 outbound sub-dispatch gate (0.8.2.31) ──"
set +e
swipl -q -g run_spec0831_main -t 'halt(2)' "$PEER/test/spec0831.pl"
PD2_RC=$?
set -e
echo

# ── 4. Two-peer loopback smoke gate ──────────────────────────────────────────
echo "── [4/4] two-peer loopback smoke ──"
set +e
swipl -q -g run_smoke_main -t 'halt(2)' "$PEER/test/smoke.pl"
SMOKE_RC=$?
set -e
echo

echo "=============================================================="
echo " type-registry rc=$TR_RC   spec-0825 rc=$SPEC_RC   spec-0831 rc=$PD2_RC   smoke rc=$SMOKE_RC"
# EVERY rc REACHES THIS CONDITION. A step whose exit code is printed and not tested is a
# gate that cannot go red -- the shape recorded on smalltalk, whose sibling make targets
# each printed their own "FAILED" verdict while nothing read it and the target exited 0.
if [ "$TR_RC" -eq 0 ] && [ "$SPEC_RC" -eq 0 ] && [ "$PD2_RC" -eq 0 ] && [ "$SMOKE_RC" -eq 0 ]; then
    echo " S3 GATE: GREEN"
    exit 0
else
    echo " S3 GATE: RED (see failures above)"
    exit 1
fi
