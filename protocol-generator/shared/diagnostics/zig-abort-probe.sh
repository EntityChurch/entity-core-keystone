#!/bin/sh
# zig-abort-probe.sh — repeat-run probe for the zig detached-thread abort
# (CONFORMANCE-MATRIX.md §3). "flaky" is not a diagnosis: run N full `--profile core`
# suites and count how many end with the peer aborting.
#
# THIS FILE IS COMMITTED BECAUSE THE PREVIOUS ONE WAS NOT. The abort was measured at
# 5 of 60 runs on the morning of 2026-09-02 with a probe that was never saved; that
# afternoon, on the SAME source, it would not reproduce, and the setup could not be
# recovered — the only trace of how it had been driven was a port number in an old
# log. A rate is a claim about a measurement setup, so the setup ships with it.
#
# CONDITIONS THAT DID **NOT** REPRODUCE IT (2026-09-02 afternoon, unchanged source),
# recorded so the next reader does not re-run them expecting a different answer:
#   0 of 100  sequential, --cpus=4                      (this script, defaults)
#   0 of  30  sequential, no CPU cap (all 32 host cores)
#   0 of  40  sequential, --cpus=4 with 12 CPU burners  (the LOAD arg below)
#   0 of 100  `-category concurrency` only — an isolated category is a different
#             process; that advice is right for COVERAGE and wrong for a RACE
#   0 of  10  a direct connect/close stressor, 24k cycles per round
# What DID reproduce it: a build carrying only the `host.zig` half of the fix — still
# detaching the §4.8 dispatch threads — 1 abort in 100 runs, same `Thread.zig:1377`
# signature. That is what located the abort at the transport site.
#
# AND THE POWERED SIGNAL IN THE SAME DATA IS NOT THE ABORT: `t2_2_connection_churn`
# stalls 20.6s instead of 1.2s in 7 of 100 unfixed runs and 0 of 100 fixed ones, so
# read the `slow` count (elapsed > 5s) as well as the abort count.
#
# EVERYTHING IS COPIED INTO THE CONTAINER FIRST and nothing under /work is touched
# again. Two reasons, both measured:
#   * a 100-run probe reading run-s4.sh off the bind mount died at run 1 with
#     `Permission denied` on its own script, because another project's container
#     relabelled the tree mid-run (`:Z` is an EXCLUSIVE SELinux relabel). A probe
#     that depends on the mount for 6 minutes is a probe that measures the host's
#     container traffic;
#   * the tracked CONFORMANCE-REPORT.json must not be rewritten by a probe.
#
# DETECTION IS SCOPED TO THE PEER'S OWN STDERR: the oracle's `agility_decode_1`
# line contains the word "panic" in its DESCRIPTION, so an unscoped grep reports
# 30 aborts out of 30 clean runs. A detector that fires on every run is the same
# defect as one that fires on none.
#
#   podman run ... entity-core-keystone/zig-toolchain:latest \
#     sh /work/protocol-generator/shared/diagnostics/zig-abort-probe.sh <N> <peer-dir-under-/work>
set -u
N="${1:-20}"
SRC="${2:-/work/protocol-generator/zig}"
# Optional CPU burners. The abort is a scheduling race: it fired 7 times in 90 runs
# on 2026-09-02 morning and 0 times in 130 runs the same afternoon, with the same
# source. The variable that is not in the source is PREEMPTION, so oversubscribe the
# container's cores deliberately rather than wait for the host to be busy.
LOAD="${3:-0}"

rm -rf /tmp/peer && cp -a "$SRC" /tmp/peer || exit 1
cp /work/output/s4-oracles/validate-peer /tmp/validate-peer || exit 1
chmod +x /tmp/validate-peer

# Same identity provisioning as run-s4.sh, so the multisig accept-path probe runs.
KPDIR="${HOME:-/root}/.entity/peers/conformance"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

cd /tmp/peer || exit 1
rm -rf zig-out .zig-cache
zig build -Doptimize=ReleaseSafe || exit 1

burners=""
if [ "$LOAD" -gt 0 ]; then
  b=0
  while [ "$b" -lt "$LOAD" ]; do
    sh -c 'while :; do :; done' & burners="$burners $!"
    b=$((b + 1))
  done
  echo "probe: $LOAD CPU burners running"
fi
cleanup() { [ -n "$burners" ] && kill $burners 2>/dev/null; }
trap cleanup EXIT INT TERM

i=1; aborts=0; red=0; slow=0
while [ "$i" -le "$N" ]; do
  ./zig-out/bin/host --port 7801 --name conformance --debug-open-grants --validate \
    >/tmp/h.out 2>/tmp/h.err &
  hp=$!
  w=0
  while [ "$w" -lt 100 ]; do
    grep -q '^LISTENING' /tmp/h.out 2>/dev/null && break
    w=$((w + 1)); sleep 0.1
  done
  sum=$(/tmp/validate-peer -addr 127.0.0.1:7801 -profile core -json-out /tmp/p.json 2>&1 |
        grep -m1 '^Summary:')
  kill "$hp" 2>/dev/null
  wait "$hp" 2>/dev/null

  verdict=ok
  case "$sum" in *" 0 failed,"*) ;; *) verdict=RED; red=$((red + 1)) ;; esac
  # The churn stall: a normal suite is ~2.1s, a stalled one ~22s (one t2_2 cycle
  # waiting out the oracle's request deadline). Counted separately because it is the
  # signal with actual statistical power — see the header.
  el=$(printf '%s' "$sum" | sed -n 's/.*elapsed \([0-9ms.]*\).*/\1/p')
  case "$el" in
    *m*) verdict="$verdict/slow"; slow=$((slow + 1)) ;;
    *)   if awk -v e="${el%s}" 'BEGIN { exit !(e + 0 > 5) }'; then
           verdict="$verdict/slow"; slow=$((slow + 1))
         fi ;;
  esac
  if grep -qE '^thread [0-9]+ panic:|Segmentation fault|reached unreachable' /tmp/h.err; then
    verdict=ABORT; aborts=$((aborts + 1))
    head -4 /tmp/h.err
  fi
  echo "run $i $verdict | ${sum:-NO SUMMARY}"
  i=$((i + 1))
done
echo "TOTAL aborts=$aborts red=$red slow=$slow of $N  [src: $SRC, load=$LOAD]"
