#!/usr/bin/env bash
# Drives abi_leak_probe.c across: the pre-fix C tree (CONTROL, must leak),
# the current C tree, and whatever .so is handed in $EXTRA_SO (the Rust impl).
# Runs inside containers/c-toolchain.
set -u
cd /work/ffi-generator/c-abi/conformance

C_SRC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c
C_PRE=/work/output/scratch/prefix-codec/ffi-generator/c-abi/entity-core-codec-ffi-c

build_asan_so() {  # $1=src $2=tag  -> echoes the .so path
  local b=/tmp/asanso-$2
  rm -rf "$b"
  cmake -S "$1" -B "$b" -DCMAKE_BUILD_TYPE=Debug \
    -DCMAKE_C_FLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O1" \
    -DCMAKE_SHARED_LINKER_FLAGS="-fsanitize=address" >/dev/null 2>&1 || return 1
  local log; log="$(cmake --build "$b" --target entitycore_codec -j4 2>&1)"
  local n; n=$(printf '%s\n' "$log" | grep -c 'Building C object')
  echo "  [$2] compiled $n objects" >&2
  [ "$n" -ge 4 ] || { echo "  [$2] FATAL: nothing rebuilt" >&2; return 1; }
  echo "$b/libentitycore_codec.so"
}

echo "── compiling the probe ─────────────────────────────────────────"
gcc -std=c11 -O1 -g -fsanitize=address -o /tmp/probe-asan abi_leak_probe.c -ldl || exit 3
gcc -std=c11 -O2 -o /tmp/probe-rss abi_leak_probe.c -ldl || exit 3
echo "  ok"

export ASAN_OPTIONS="detect_leaks=1:exitcode=23"

run_asan() {  # $1=so $2=label
  echo
  echo "── ASan/LSan: $2 ───────────────────────────────────────────────"
  /tmp/probe-asan "$1" >/tmp/p.out 2>/tmp/p.err
  local rc=$?
  local n; n=$(grep -c 'Direct leak\|Indirect leak' /tmp/p.err)
  local b; b=$(grep -oE 'SUMMARY: AddressSanitizer: [0-9]+ byte' /tmp/p.err | grep -oE '[0-9]+' | head -1)
  grep '^impl:' /tmp/p.err | sed 's/^/  /'
  echo "  exit=$rc  leak-records=$n  leaked-bytes=${b:-0}"
  if [ "$n" -gt 0 ]; then
    echo "  --- leak stacks (library frames only) ---"
    grep -E 'in (ec_|ev_|rd_|xmalloc|xcalloc|ecbuf|encode_|hash_|codec\.c|ecf\.c)' /tmp/p.err \
      | sed 's/^ */    /' | sort | uniq -c | sort -rn | head -12
  fi
  return $rc
}

run_rss() {  # $1=so $2=label $3=passes
  echo
  echo "── RSS growth: $2 ($3 passes) ──────────────────────────────────"
  /tmp/probe-rss "$1" --rss "$3" 2>/tmp/r.err | sed 's/^/  /'
  grep '^impl:' /tmp/r.err | sed 's/^/  /'
}

echo
echo "###############################################################"
echo "# 1. CONTROL: pre-fix C impl -- MUST show leaks, or the probe"
echo "#    has measured nothing."
echo "###############################################################"
if SO=$(build_asan_so "$C_PRE" pre); then run_asan "$SO" "C pre-fix (CONTROL)"; fi

echo
echo "###############################################################"
echo "# 2. C impl at HEAD"
echo "###############################################################"
if SO=$(build_asan_so "$C_SRC" head); then run_asan "$SO" "C HEAD"; fi

echo
echo "###############################################################"
echo "# 3. RSS growth through the shipped release .so"
echo "###############################################################"
[ -f "$C_SRC/build/libentitycore_codec.so" ] && run_rss "$C_SRC/build/libentitycore_codec.so" "C release" 20000
if [ -n "${EXTRA_SO:-}" ] && [ -f "$EXTRA_SO" ]; then
  run_rss "$EXTRA_SO" "Rust release" 20000
else
  echo "  (no EXTRA_SO given -- Rust impl not measured in this run)"
fi
