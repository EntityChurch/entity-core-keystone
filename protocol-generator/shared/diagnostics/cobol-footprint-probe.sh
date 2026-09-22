#!/bin/sh
# cobol-footprint-probe.sh — resident + virtual footprint of the cobol peer at
# idle and after each of N full --profile core suites, plus fd count.
#
# TWO QUESTIONS, AND THE SECOND IS THE ONE A SINGLE SAMPLE CANNOT ANSWER:
#   (1) what does the peer COST — the 2026-09-04 frame-capacity raise put 320
#       admission slots at 512 KiB each into static storage, and an estimate is
#       not a measurement. Answer: idle virt 79 MB -> 229 MB; RSS after one
#       suite ~100 MB, after five ~240 MB, against a 4 GB container cap.
#   (2) is anything LEAKING — a leak is a CURVE where a high-water mark is a
#       plateau (AGENTS.md, the cpp fd retention entry). Answer: yes, VmSize
#       grows dead-linearly at ~23 MB per suite. BISECTED against HEAD: 23.3 MB
#       before the capacity change, 22.3 MB after, so it is pre-existing.
#       cobol-ffi-encode-leak-probe.sh narrows it to ~1 KB per request and the
#       codec FFI's never-freed ec_value tree.
#
# SUITES=N controls the number of suites (default 4). Run it with N>=3: two
# points make a line no matter what the truth is.
#
# HOW TO RUN IT (needs the peer built: make host)
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     -e LD_LIBRARY_PATH=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build \
#     -e SUITES=5 localhost/entity-core-keystone/cobol-toolchain:latest \
#     sh /work/protocol-generator/shared/diagnostics/cobol-footprint-probe.sh
# Peak-footprint probe for the cobol peer: read VmHWM/VmRSS at idle and after a
# full --profile core suite. Kept as a file rather than inlined because the
# quoting of an inline `podman run sh -c` mangles the /proc reads (measured).
set -eu
cd /work/protocol-generator/cobol
mkdir -p "$HOME/.entity/peers/conformance"
printf -- '-----BEGIN ENTITY PRIVATE KEY-----\nERERERERERERERERERERERERERERERERERERERERERE=\n-----END ENTITY PRIVATE KEY-----\n' \
  > "$HOME/.entity/peers/conformance/keypair"

timeout 300 build/host --port 7799 --name conformance --debug-open-grants --validate \
  >/tmp/h.out 2>/tmp/h.err &
sleep 1
# Match the peer, NOT its `timeout` parent: timeout's own cmdline contains the
# string "build/host" too, and being the parent it sorts first -- the obvious
# `head -1` reported timeout's 2.5 MB as the peer's footprint. Require argv[0]
# to BE the binary.
P=""
for d in /proc/[0-9]*; do
  [ -r "$d/cmdline" ] || continue
  a0=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -1)
  case "$a0" in build/host) P=$(basename "$d") ;; esac
done
[ -n "$P" ] || { echo "probe: could not find the peer process" >&2; exit 1; }
i=0; while [ "$i" -lt 100 ]; do grep -q LISTENING /tmp/h.out 2>/dev/null && break; i=$((i+1)); sleep 0.1; done

echo "pid=$P"
echo "IDLE"
grep -E 'VmSize|VmRSS|VmHWM' "/proc/$P/status"
echo "fds=$(ls /proc/$P/fd | wc -l)"

i=1
while [ "$i" -le "${SUITES:-4}" ]; do
  /work/output/s4-oracles/validate-peer -addr 127.0.0.1:7799 -profile core >/tmp/v$i.log 2>&1 || true
  echo "AFTER SUITE $i: $(grep VmRSS /proc/$P/status | awk '{print $2}') kB RSS, $(grep VmSize /proc/$P/status | awk '{print $2}') kB virt, fds=$(ls /proc/$P/fd | wc -l)  $(grep -E '^Summary' /tmp/v$i.log)"
  i=$((i+1))
done
echo "--- peer stderr (empty is the expected result) ---"
cat /tmp/h.err
