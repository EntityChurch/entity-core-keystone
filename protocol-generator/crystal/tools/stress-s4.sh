#!/bin/sh
set -u
PROJ=/work/protocol-generator/crystal
cd "$PROJ"
# Build the release host ONCE; stress runs reuse it (NOBUILD=1).
echo "building release host..."
crystal build --release bin/entity-core-peer.cr -o /tmp/host 2>/tmp/build.err || {
  echo "release build failed, trying debug"; crystal build bin/entity-core-peer.cr -o /tmp/host; }
echo "host built."

RUNS="${RUNS:-22}"
crash=0
verdict_fail=0
no_summary=0
i=1
while [ "$i" -le "$RUNS" ]; do
  # each run reaps the host itself (graceful TERM + wait); capture its output
  NOBUILD=1 PORT=$((7800 + i)) sh "$PROJ/run-s4.sh" -profile core > /tmp/run.$i.log 2>&1
  # 1) mid-run crash marker in host stderr (surfaced by run-s4 as "=== host stderr ===")
  if grep -qiE 'execution_context|NilAssertionError|Unhandled exception|Invalid memory access|fiber' /tmp/run.$i.log; then
    crash=$((crash + 1))
    echo "RUN $i: CRASH marker found:"
    grep -iE 'execution_context|NilAssertionError|Unhandled exception|Invalid memory access|fiber' /tmp/run.$i.log | head -3
  fi
  # 2) verdict present and 0 failed?
  SUMMARY=$(grep -E '^Summary:' /tmp/run.$i.log | tail -1)
  if [ -z "$SUMMARY" ]; then
    no_summary=$((no_summary + 1))
    echo "RUN $i: NO Summary line (verdict lost)"
    tail -5 /tmp/run.$i.log
  else
    FAILED=$(echo "$SUMMARY" | sed -n 's/.*, \([0-9]*\) failed.*/\1/p')
    if [ "$FAILED" != "0" ]; then
      verdict_fail=$((verdict_fail + 1))
      echo "RUN $i: $SUMMARY  <-- NONZERO FAIL"
    fi
  fi
  printf 'run %2d: %s\n' "$i" "$SUMMARY"
  i=$((i + 1))
done

echo "=================================================="
echo "RUNS=$RUNS  crash_markers=$crash  no_summary=$no_summary  verdict_fail=$verdict_fail"
echo "=================================================="
