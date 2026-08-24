#!/usr/bin/env bash
# run-cohort-census.sh — re-run every peer's `run-s4.sh --profile core` against
# the PINNED oracle (tools/oracle-pin.env / output/s4-oracles/validate-peer) and
# collect one JSON report per peer under output/scratch/census/, WITHOUT ever
# writing to a peer's tracked status/CONFORMANCE-REPORT.json.
#
# Why this exists: no cohort-wide driver existed before this (2026-07-28) run —
# every prior sweep drove each peer's run-s4.sh by hand. This is the durable,
# re-runnable version, one commit after AGENTS.md's "the anchor has to actually
# re-run on demand" lesson.
#
# Every run-s4.sh accepts `-profile core -json-out <path>` as CLI passthrough
# EXCEPT python/ruby/prolog, which read the JSON_OUT env var instead (no "$@"
# forwarding in those three) — handled per-peer below.
#
# Usage:
#   tools/run-cohort-census.sh                 # every peer except apl (blocked, see AGENTS.md §8)
#   tools/run-cohort-census.sh go rust python   # a subset
#   CONCURRENCY=2 tools/run-cohort-census.sh    # default 1 (see below)
#
# CONCURRENCY defaults to 1, deliberately: every run-s4.sh bind-mounts the repo
# root with `:Z` (an EXCLUSIVE SELinux relabel). Two containers relabeling the
# SAME host path at once race — measured directly (2026-07-28): running
# go+c+python+sql concurrently produced spurious failures (c's build hit
# `Permission denied` mid-`make`, sql's oracle binary transiently failed its `-x`
# check, python's venv transiently lost its module path) that vanished when the
# same three peers were re-run serially. Do not raise CONCURRENCY above 1 without
# first solving the shared-`:Z`-mount race (e.g. per-run worktree copies); a
# "faster" concurrent run that silently manufactures FAILs is worse than a slow
# correct one on a conformance anchor.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"
. tools/podman-caps.sh
OUT="$REPO_ROOT/output/scratch/census"
LOGS="$REPO_ROOT/output/scratch/census-logs"
mkdir -p "$OUT" "$LOGS"
CONCURRENCY="${CONCURRENCY:-1}"

# Mode A: self-contained run-s4.sh (embeds its own podman run) — invoke directly.
run_direct() {
  local peer="$1"; shift
  ./protocol-generator/"$peer"/run-s4.sh "$@"
}

# Mode A peers that ignore CLI args and read JSON_OUT instead.
run_direct_envjson() {
  local peer="$1"
  JSON_OUT="/work/output/scratch/census/$peer.json" \
    ./protocol-generator/"$peer"/run-s4.sh
}

# Mode B: no self-relaunch — construct the documented podman invocation.
run_podman() {
  local peer="$1"; local image="$2"; shift 2
  podman run $PODMAN_RUN_CAPS --rm "$@" \
    -v "$REPO_ROOT":/work:Z "$image" \
    sh /work/protocol-generator/"$peer"/run-s4.sh -profile core \
    -json-out /work/output/scratch/census/"$peer".json
}

# Same peer, with an explicit -timeout (see the run_direct case-statement note above).
run_podman_timeout() {
  local peer="$1"; local image="$2"; local budget="$3"; shift 3
  podman run $PODMAN_RUN_CAPS --rm "$@" \
    -v "$REPO_ROOT":/work:Z "$image" \
    sh /work/protocol-generator/"$peer"/run-s4.sh -profile core -timeout "$budget" \
    -json-out /work/output/scratch/census/"$peer".json
}

census_one() {
  local peer="$1"
  local log="$LOGS/$peer.log"
  local jout="/work/output/scratch/census/$peer.json"
  echo "=== $peer starting $(date -u +%H:%M:%S) ===" > "$log"
  local rc=0
  case "$peer" in
    # ---- Mode A: self-contained, CLI passthrough ----
    # NOTE: passing explicit args here overrides EVERY default the script would
    # otherwise substitute (the `if [ "$#" -eq 0 ]` pattern is all-or-nothing) —
    # including a peer's own bumped `-timeout` default. Measured 2026-07-28: this
    # silently starved oz/rexx back to the oracle's 60s default and produced a
    # spurious NEW budget_exhausted (679/681-total short run) that vanished once
    # their historical bump (10m) was passed explicitly. forth/fortran/io/
    # smalltalk (also on AGENTS.md's nine-inflated-timeout list) empirically did
    # NOT need theirs to reach the full 719 — but pass it anyway for parity with
    # the historical measurement conditions, not because this run needs it.
    ada|c|common-lisp|datalog|java|kotlin|pd|sql|unison)
      run_direct "$peer" -profile core -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    forth|smalltalk|oz|rexx)
      run_direct "$peer" -profile core -timeout 10m -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    fortran)
      run_direct "$peer" -profile core -timeout 5m -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    io)
      run_direct "$peer" -profile core -timeout 15m -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    lean)
      INCONTAINER=0 run_direct "$peer" -profile core -json-out "$jout" >>"$log" 2>&1; rc=$? ;;
    # ---- Mode A: JSON_OUT env only (no "$@" forwarding) ----
    python|ruby)
      run_direct_envjson "$peer" >>"$log" 2>&1; rc=$? ;;
    # ---- Mode B: external podman run, per-peer image + extra flags ----
    asm-arm64)
      run_podman "$peer" entity-core-keystone/asm-arm64-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    asm-x86_64)
      run_podman "$peer" entity-core-keystone/asm-x86_64-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    riscv64)
      run_podman "$peer" entity-core-keystone/riscv64-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    cobol)
      run_podman "$peer" localhost/entity-core-keystone/cobol-toolchain:latest --network=none \
        -e LD_LIBRARY_PATH=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build >>"$log" 2>&1; rc=$? ;;
    cpp)
      run_podman "$peer" entity-core-keystone/cpp-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    crystal)
      run_podman "$peer" entity-core-keystone/crystal-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    csharp)
      run_podman "$peer" entity-core-keystone/dotnet9:latest -v kc-nuget:/nuget >>"$log" 2>&1; rc=$? ;;
    dart)
      run_podman_timeout "$peer" entity-core-keystone/dart-toolchain:latest 5m --network=none >>"$log" 2>&1; rc=$? ;;
    elixir)
      run_podman "$peer" entity-core-keystone/beam:latest --network=none >>"$log" 2>&1; rc=$? ;;
    go)
      run_podman "$peer" entity-core-keystone/go:latest --network=none --security-opt label=disable >>"$log" 2>&1; rc=$? ;;
    haskell)
      run_podman "$peer" entity-core-keystone/ghc-toolchain:latest --network=none \
        -e CABAL_DIR=/work/protocol-generator/haskell/.cabal-home >>"$log" 2>&1; rc=$? ;;
    julia)
      run_podman "$peer" entity-core-keystone/julia-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    nim)
      run_podman "$peer" entity-core-keystone/nim-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    node-red)
      run_podman "$peer" entity-core-keystone/node24:latest --network=none >>"$log" 2>&1; rc=$? ;;
    ocaml)
      run_podman "$peer" entity-core-keystone/ocaml-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    odin)
      run_podman "$peer" entity-core-keystone/odin-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    php)
      run_podman "$peer" entity-core-keystone/php-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    prolog)
      podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z -w /work \
        -e JSON_OUT="$jout" entity-core-keystone/prolog-toolchain:latest \
        protocol-generator/prolog/run-s4.sh >>"$log" 2>&1; rc=$? ;;
    rust)
      run_podman "$peer" entity-core-keystone/rust-toolchain:latest --network=none --security-opt label=disable >>"$log" 2>&1; rc=$? ;;
    rust-wasm)
      podman run $PODMAN_RUN_CAPS --rm --network=none \
        -v "$REPO_ROOT":/work:Z -v kc-rw-cargo:/cargo:Z localhost/entity-core-keystone/rust-wasm-toolchain:latest \
        sh -c "NOBUILD=1 sh /work/protocol-generator/$peer/run-s4.sh -profile core -json-out $jout" >>"$log" 2>&1; rc=$? ;;
    rust-wasm-wasmtime)
      podman run $PODMAN_RUN_CAPS --rm --network=none \
        -v "$REPO_ROOT":/work:Z -v kc-rw-cargo:/cargo:Z localhost/entity-core-keystone/rust-wasm-wasmtime-toolchain:latest \
        sh -c "NOBUILD=1 sh /work/protocol-generator/$peer/run-s4.sh -profile core -json-out $jout" >>"$log" 2>&1; rc=$? ;;
    swift)
      run_podman "$peer" entity-core-keystone/swift-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    tcl)
      run_podman "$peer" entity-core-keystone/tcl-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    turbowarp)
      run_podman "$peer" entity-core-keystone/node24:latest -v kc-npm:/root/.npm >>"$log" 2>&1; rc=$? ;;
    typescript)
      run_podman "$peer" entity-core-keystone/node24:latest --network=none -v kc-npm:/npm-cache >>"$log" 2>&1; rc=$? ;;
    wasm-wat)
      run_podman "$peer" entity-core-keystone/wasm-wat-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    zig)
      run_podman "$peer" entity-core-keystone/zig-toolchain:latest --network=none >>"$log" 2>&1; rc=$? ;;
    apl)
      echo "SKIP: apl blocked pending the 1.9->2.0 cool-down decision (AGENTS.md §8)" >>"$log"; rc=125 ;;
    *)
      echo "unknown peer: $peer" >>"$log"; rc=127 ;;
  esac
  echo "=== $peer done rc=$rc $(date -u +%H:%M:%S) ===" >> "$log"
  if [ -f "$OUT/$peer.json" ]; then
    local summary
    summary=$(python3 -c "import json,sys; d=json.load(open('$OUT/$peer.json')); s=d.get('summary',{}); print(f\"{s.get('total','?')}\/{s.get('passed','?')}\/{s.get('warned','?')}\/{s.get('failed','?')}\/{s.get('skipped','?')}\")" 2>/dev/null || echo "unparseable")
    echo "$peer: rc=$rc P/W/F/S total=$summary"
  else
    echo "$peer: rc=$rc NO JSON PRODUCED (see $log)"
  fi
}
export -f census_one run_direct run_direct_envjson run_podman run_podman_timeout
export REPO_ROOT OUT LOGS PODMAN_RUN_CAPS

PEERS=("$@")
if [ "${#PEERS[@]}" -eq 0 ]; then
  PEERS=(ada asm-arm64 asm-x86_64 c cobol common-lisp cpp crystal csharp dart datalog \
    elixir forth fortran go haskell io java julia kotlin lean nim node-red ocaml odin \
    oz pd php prolog python rexx riscv64 ruby rust rust-wasm rust-wasm-wasmtime \
    smalltalk sql swift tcl turbowarp typescript unison wasm-wat zig)
fi

printf '%s\n' "${PEERS[@]}" | xargs -P "$CONCURRENCY" -I{} bash -c 'census_one "$@"' _ {}
