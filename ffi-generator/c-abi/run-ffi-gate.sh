#!/usr/bin/env bash
# run-ffi-gate.sh — the cohort runner for the ffi-generator arm.
#
# WHY THIS EXISTS
#   `tools/run-axis-sweep.sh` sweeps the four per-peer verification axes across
#   `protocol-generator/*`.  The ffi-generator arm is not peer-scoped, so it was
#   in NO sweep and NO `make lint` gate — while 34 peers link the artifact it
#   builds.  That is the standing rule ("an axis with a per-peer harness and no
#   cohort runner is one nobody is measuring") applied to a whole ARM, and the
#   codec leak fixed on 2026-09-04 is the proof: it was on the per-request path
#   of every consumer for months and was found by accident, while measuring a
#   peer, because nothing here was ever run on a schedule.
#
#   S4 is likewise absent from the axis table and that is not an oversight — it
#   has its own runner.  This is that, for this arm.
#
# WHAT IT ASSERTS, AND WHY EACH ONE PRINTS A COUNT
#   A gate whose success message contains no number cannot tell "all green" from
#   "nothing ran" (AGENTS.md, the examined-zero-things class, now at six
#   occurrences).  Every stage below prints what it examined and fails on a floor.
#
#     [1] build both impls
#     [2] C regression_test                  — floor on tests run
#     [3] C conformance_harness vs the vendored ECF corpus — floor on vectors
#     [4] abi_differential C<->Rust          — floor on probes, plus the export
#                                              parity report (which symbols each
#                                              impl exports, and which of them
#                                              this differential actually drives)
#     [5] LEAK GATE: ASan/LSan over the exported ABI only, valid AND malformed
#                    inputs.  This is the stage that would have caught the leak.
#                    A CONTROL is not run here (it needs the pre-fix tree); the
#                    control lives in conformance/leak-probe-with-control.sh and is
#                    cited in the FFI status doc.
#
# WHAT IT DOES NOT ASSERT, STATED RATHER THAN IMPLIED
#   The Rust impl has NO independent conformance harness in this tree.  Its
#   README documents `./target/release/conformance_harness` and a "69/69" result;
#   there is no `[[bin]]` in its Cargo.toml and `src/bin` has never existed in
#   git history, so that recipe cannot run and that number is not reproducible
#   here.  The Rust impl's only verification is stage [4], which is a MUTUAL
#   check against C — a defect both impls shared would pass it.  Driving the
#   corpus through the ABI (so one harness can grade either impl against
#   architecture's fixture rather than against its sibling) is the owed fix; it
#   is named in ffi-generator/c-abi/status/ and it is not done.
#
# Run from the repo root, on the HOST (it drives podman itself):
#   ffi-generator/c-abi/run-ffi-gate.sh
#
# EXIT  0 all stages met their floors · 1 a stage failed · 2 usage/setup

set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CABI="$ROOT/ffi-generator/c-abi"
CIMPL="$CABI/entity-core-codec-ffi-c"
RIMPL="$CABI/entity-core-codec-ffi-rust"
CORPUS=/work/protocol-generator/shared/test-vectors/ecf-conformance/conformance-vectors.cbor
CAPS="--memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4"
CIMG=localhost/entity-core-keystone/c-toolchain:latest
RIMG=localhost/entity-core-keystone/cargo:latest

# Floors. Raise them when a suite legitimately grows; NEVER lower one to make a
# run green — that is the "raise -timeout to turn the report green" move in a
# different costume.
FLOOR_REGRESSION="${FLOOR_REGRESSION:-12}"
FLOOR_CORPUS="${FLOOR_CORPUS:-71}"
FLOOR_DIFFERENTIAL="${FLOOR_DIFFERENTIAL:-101}"

fail=0
stage() { printf '\n\033[1m── [%s] %s\033[0m\n' "$1" "$2"; }
bad()   { printf '  FAIL: %s\n' "$1"; fail=1; }
good()  { printf '  ok: %s\n' "$1"; }

cd "$ROOT" || exit 2

stage 1 "build both impls"
podman run $CAPS --rm --network=none -v "$ROOT":/work:Z -w /work "$CIMG" bash -c '
  cmake -S /work/ffi-generator/c-abi/entity-core-codec-ffi-c -B /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build \
        -DCMAKE_BUILD_TYPE=Release >/dev/null 2>&1
  cmake --build /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build -j4 >/dev/null 2>&1
' || bad "C impl build"
[ -f "$CIMPL/build/libentitycore_codec.so" ] && good "C .so present" || bad "C .so absent"

# The Rust impl has no vendored crate closure, so this needs the network. Say so
# rather than failing silently on an air-gapped host: a stage that cannot run is
# reported, never skipped quietly.
if podman run $CAPS --rm -v "$ROOT":/work:Z -v kc-cargo:/cargo "$RIMG" \
     sh -c "cd /work/ffi-generator/c-abi/entity-core-codec-ffi-rust && cargo build --release --locked" >/dev/null 2>&1; then
  good "Rust .so built"
else
  bad "Rust impl build FAILED — note it has no vendored crate closure (kc-cargo is a host-local volume, --offline does not resolve); this stage needs the network"
fi

stage 2 "C regression_test (floor: $FLOOR_REGRESSION)"
OUT=$(podman run $CAPS --rm --network=none -v "$ROOT":/work:Z "$CIMG" \
        /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build/regression_test 2>&1)
N=$(printf '%s\n' "$OUT" | grep -cE '^\s*(ok|PASS)')
printf '  tests observed: %s\n' "$N"
[ "$N" -ge "$FLOOR_REGRESSION" ] && good "regression_test $N >= $FLOOR_REGRESSION" \
  || bad "regression_test ran $N, floor $FLOOR_REGRESSION"
printf '%s\n' "$OUT" | grep -qiE '\bFAIL\b' && bad "regression_test reported a FAIL"

stage 3 "C conformance_harness vs the vendored ECF corpus (floor: $FLOOR_CORPUS)"
OUT=$(podman run $CAPS --rm --network=none -v "$ROOT":/work:Z "$CIMG" \
        /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build/conformance_harness "$CORPUS" 2>&1)
# Parse the harness's OWN count off its `# RESULT: PASS (71/71)` line rather
# than counting output lines. The first cut here counted lines matching
# `^\s*(ok|PASS)` -- which this harness never emits, since it prints a per-
# category table -- so it reported 0 vectors against a 71/71 run. The floor is
# the only reason that was visible, which is the whole argument for having one.
N=$(printf '%s\n' "$OUT" | sed -n 's/^# RESULT: [A-Z]* (\([0-9]*\)\/[0-9]*).*/\1/p')
N="${N:-0}"
printf '  vectors observed: %s\n' "$N"
printf '%s\n' "$OUT" | grep '^# RESULT' | sed 's/^/  /'
[ "$N" -ge "$FLOOR_CORPUS" ] && good "corpus $N >= $FLOOR_CORPUS" \
  || bad "corpus ran $N, floor $FLOOR_CORPUS"
printf '%s\n' "$OUT" | grep -q '^# RESULT: PASS' && good "corpus PASS" \
  || bad "corpus did not report PASS"

stage 4 "abi_differential C<->Rust + export parity (floor: $FLOOR_DIFFERENTIAL probes)"
OUT=$(podman run $CAPS --rm --network=none -v "$ROOT":/work:Z -w /work/ffi-generator/c-abi/conformance "$CIMG" \
        bash -c 'gcc -std=c11 -O2 -Wall -Wextra -o /tmp/diff abi_differential.c -ldl && \
          /tmp/diff /work/ffi-generator/c-abi/entity-core-codec-ffi-c/build/libentitycore_codec.so \
                    /work/ffi-generator/c-abi/entity-core-codec-ffi-rust/target/release/libentitycore_codec.so' 2>&1)
printf '%s\n' "$OUT" | sed -n '/export parity/,/export asymmetries/p' | sed 's/^/  /'
N=$(printf '%s\n' "$OUT" | grep -c '^  ok   ')
printf '  probes observed: %s\n' "$N"
[ "$N" -ge "$FLOOR_DIFFERENTIAL" ] && good "differential $N >= $FLOOR_DIFFERENTIAL" \
  || bad "differential ran $N, floor $FLOOR_DIFFERENTIAL"
printf '%s\n' "$OUT" | grep -q '^# RESULT: PASS' && good "differential PASS" \
  || bad "differential did not report PASS"

stage 5 "LEAK GATE — ASan/LSan over the exported ABI (valid + malformed input)"
OUT=$(podman run $CAPS --rm --network=none -v "$ROOT":/work:Z -w /work/ffi-generator/c-abi/conformance "$CIMG" bash -c '
  set -e
  cmake -S /work/ffi-generator/c-abi/entity-core-codec-ffi-c -B /tmp/asan -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" >/dev/null 2>&1
  LOG=$(cmake --build /tmp/asan --target entitycore_codec -j4 2>&1)
  # "Built target" prints whether or not anything compiled -- assert the compiles.
  NC=$(printf "%s\n" "$LOG" | grep -c "Building C object")
  echo "asan-objects-compiled=$NC"
  [ "$NC" -ge 4 ] || { echo "FATAL: nothing rebuilt under ASan"; exit 3; }
  gcc -std=c11 -O1 -g -fsanitize=address -o /tmp/probe abi_leak_probe.c -ldl
  ASAN_OPTIONS=detect_leaks=1:exitcode=23 /tmp/probe /tmp/asan/libentitycore_codec.so 2>&1
  echo "probe-exit=$?"' 2>&1)
printf '%s\n' "$OUT" | grep -E 'asan-objects-compiled|ABI GAP|ABI:|impl:|probe-exit' | sed 's/^/  /'
NLEAK=$(printf '%s\n' "$OUT" | grep -c 'Direct leak\|Indirect leak')
printf '  leak records: %s\n' "$NLEAK"
[ "$NLEAK" -eq 0 ] && good "no leaks through the exported ABI" || {
  bad "$NLEAK leak record(s) through the exported ABI"
  printf '%s\n' "$OUT" | grep -A6 'Direct leak' | head -14 | sed 's/^/    /'; }

printf '\n\033[1m══ ffi-generator gate: %s ══\033[0m\n' "$([ $fail -eq 0 ] && echo PASS || echo FAIL)"
exit $fail
