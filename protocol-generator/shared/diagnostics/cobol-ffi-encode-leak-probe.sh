#!/bin/sh
# cobol-ffi-encode-leak-probe.sh — does the peer's address space grow with
# CONNECTIONS or with REQUESTS?
#
# WHY THIS FILE EXISTS RATHER THAN A SENTENCE IN A FINDING
#   A rate is a claim about a SETUP; without the setup it is an anecdote with a
#   denominator (AGENTS.md, the zig 5-in-60 probe that was not kept and could
#   not be re-measured the same afternoon). This is the setup.
#
# WHAT IT MEASURED, 2026-09-04, entity-core-protocol-cobol
#   ~1 KB of VmSize per DISPATCHED REQUEST. connectivity (few requests, many
#   short connections): 80 kB per run. type_system (~449 requests, one reused
#   connection): 419 kB per run. Growth follows requests; connections are noise.
#   Whole-suite figure, from cobol-footprint-probe.sh: 23.3 MB per
#   --profile core suite at HEAD, 22.3 MB after the 2026-09-04 capacity work —
#   BISECTED, so the leak is neither new nor worsened by that change.
#
# WHAT IT POINTS AT
#   ffi-generator/c-abi/entity-core-codec-ffi-c/src/ecf.c: "we malloc value
#   nodes and never free the tree (process exits)". ec_encode_ecf and
#   cc_content_hash build an ec_value tree per call and free only the output
#   ecbuf. True of a short-lived harness; false of every peer that links it.
#
# HOW TO RUN IT (needs the peer built: make host)
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     -e LD_LIBRARY_PATH=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build \
#     localhost/entity-core-keystone/cobol-toolchain:latest \
#     sh /work/protocol-generator/shared/diagnostics/cobol-ffi-encode-leak-probe.sh
#
# NOT PEER-SPECIFIC IN PRINCIPLE: any peer linking libentitycore_codec should
# show the same shape. Only cobol has been measured.
# Does the cobol peer's address space grow with CONNECTIONS or with REQUESTS?
#
# Discriminator: `connectivity` is 25 checks that open many short connections and
# dispatch almost nothing; `type_system` is ~350 checks that reuse one connection
# and dispatch a request each. Run each in isolation against a fresh peer and
# report kB of VmSize growth per check, and per run.
set -eu
cd /work/protocol-generator/cobol
mkdir -p "$HOME/.entity/peers/conformance"
printf -- '-----BEGIN ENTITY PRIVATE KEY-----\nERERERERERERERERERERERERERERERERERERERERERE=\n-----END ENTITY PRIVATE KEY-----\n' \
  > "$HOME/.entity/peers/conformance/keypair"

run_cat() {
  cat_name="$1"; reps="$2"; port="$3"
  timeout 600 build/host --port "$port" --name conformance --debug-open-grants --validate \
    >/tmp/h-$cat_name.out 2>/tmp/h-$cat_name.err &
  sleep 1
  P=""
  for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    a0=$(tr '\0' '\n' < "$d/cmdline" 2>/dev/null | head -1)
    cl=$(tr '\0' ' ' < "$d/cmdline" 2>/dev/null)
    case "$a0" in build/host) case "$cl" in *"--port $port"*) P=$(basename "$d") ;; esac ;; esac
  done
  i=0; while [ "$i" -lt 100 ]; do grep -q LISTENING /tmp/h-$cat_name.out 2>/dev/null && break; i=$((i+1)); sleep 0.1; done
  v0=$(awk '/VmSize/{print $2}' "/proc/$P/status")
  n=0
  i=1
  while [ "$i" -le "$reps" ]; do
    /work/output/s4-oracles/validate-peer -addr 127.0.0.1:$port -profile core \
      -category "$cat_name" >/tmp/c-$cat_name.log 2>&1 || true
    i=$((i+1))
  done
  n=$(grep -cE '^(PASS|FAIL|WARN|SKIP) ' /tmp/c-$cat_name.log || echo 0)
  v1=$(awk '/VmSize/{print $2}' "/proc/$P/status")
  total=$((n * reps))
  echo "$cat_name: $reps runs x $n checks = $total checks; virt ${v0} -> ${v1} kB (+$((v1-v0)) kB)"
  [ "$total" -gt 0 ] && echo "   => $(( (v1-v0) * 1024 / total )) bytes per check"
}

run_cat connectivity 10 7801
run_cat type_system  10 7802
