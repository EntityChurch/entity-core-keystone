#!/bin/sh
# harness-teardown-probe.sh — does a peer still own the listening socket AFTER its
# run-s4.sh has exited?
#
# THIS IS THE MEASUREMENT SETUP BEHIND THE NUMBERS IN AGENTS.md AND tools/teardown-gate.py.
# It is committed for the reason the zig probe beside it is: a rate, or a latency, is a
# claim about a setup, and a setup that was not kept can only be re-argued.
#
# WHY IT MEASURES THE MECHANISM AND NOT THE SYMPTOM. The reported symptom was "a
# back-to-back invocation in the same container cannot rebind the port". That symptom is
# a RACE between two durations — how long the old peer takes to die, and how long the
# next invocation takes to reach its bind — so it is absent on any peer whose build step
# happens to be slow, and absent on any peer whose runtime happens to die fast. Measured
# 2026-09-02: it did NOT reproduce on go (5 of 5 clean) or on zig (10 of 10 clean at a
# full --profile core), which are the first two peers anyone would test. Only one of the
# two durations is a property of the harness, so measure that one directly.
#
# RESULTS AT THE FIRE-AND-FORGET TRAP (before tools/teardown-gate.py existed), ms between
# the harness exiting and the port refusing a connection:
#
#   rexx       never   the ecnet daemon was not reaped at all; run 2 onward exited 1
#   elixir     >400    run 2 exited 1, run 3 succeeded, alternating
#   julia        ~88
#   smalltalk     ~4
#   crystal        0   this peer already had the correct teardown
#   zig, go        0
#
# AFTER: every one of the above measures 0-1ms, which is the cost of the date(1) fork
# between the harness exiting and the first probe connect.
#
# A CONNECT, NOT A PROCESS CHECK, IS THE RIGHT INSTRUMENT HERE. `kill -0` cannot see the
# rexx case at all (the socket is held by a reparented co-process daemon, not by the
# harness child), and a TIME_WAIT socket does not accept, so a successful connect means
# a live listener and nothing else.
#
# Run it INSIDE the peer toolchain image, for a peer whose run-s4.sh does not itself
# re-exec into podman (for those, the port lives in a container this probe cannot see —
# run the harness twice from the host instead and read the exit codes):
#
#   podman run $PODMAN_RUN_CAPS --rm --network=none --security-opt label=disable \
#     -v "$PWD":/work:Z entity-core-keystone/beam:latest \
#     sh /work/protocol-generator/shared/diagnostics/harness-teardown-probe.sh \
#        /work/protocol-generator/elixir 7777 5
set -u
PEER="${1:?peer dir, e.g. /work/protocol-generator/elixir}"
PORT="${2:?the port that peer binds}"
RUNS="${3:-3}"
SCRIPT="${4:-run-s4.sh}"

listening() { (exec 3<>"/dev/tcp/127.0.0.1/$PORT") 2>/dev/null; }

# -category connectivity keeps each run to a couple of seconds. The teardown path is
# identical whatever the oracle was asked, and passing explicit args keeps the tracked
# CONFORMANCE-REPORT.json out of it. (Caveat, measured: python/run-s4.sh ignores caller
# args and always writes its tracked report — check before probing a re-exec peer.)
n=1
while [ "$n" -le "$RUNS" ]; do
  sh "$PEER/$SCRIPT" -profile core -category connectivity >/tmp/tp.log 2>&1
  rc=$?
  t0=$(date +%s%N)
  i=0
  while [ "$i" -lt 2000 ]; do
    listening || break
    i=$((i + 1))
  done
  t1=$(date +%s%N)
  ms=$(( (t1 - t0) / 1000000 ))
  if [ "$i" -ge 2000 ]; then
    echo "[$SCRIPT] run $n: rc=$rc STILL LISTENING after ${ms}ms (gave up)"
  else
    echo "[$SCRIPT] run $n: rc=$rc port released ${ms}ms after harness exit (polls=$i)"
  fi
  n=$((n + 1))
done
