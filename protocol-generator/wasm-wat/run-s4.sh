#!/bin/sh
# S4 conformance harness — entity-core-protocol-wasm-wat (hand-authored WAT peer).
#
# Runs inside the wasm-wat-toolchain container (the Go validate-peer oracle is a fedora:43
# ELF that runs there too, sharing one loopback; --network=none keeps it sealed). Builds the
# merged peer.wasm (make peer), launches it under WasmEdge, waits for LISTENING, points
# validate-peer at it, tears it down.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none \
#     -v "$PWD":/work:Z entity-core-keystone/wasm-wat-toolchain:latest \
#     sh /work/protocol-generator/wasm-wat/run-s4.sh [validate-peer-args...]
#
# Identity is the hardcoded cohort conformance seed (0x11×32 → the same peer_id --name
# conformance yields), so extra launch args (--name) are tolerated/ignored. --port is 7777.
set -eu
PORT="${PORT:-7777}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
PROJ=/work/protocol-generator/wasm-wat
# --debug-open-grants is the cohort gate: the degenerate default→* seed policy so the grant-gated
# categories (capability, handlers, tree, authz, concurrency, universal_address_space) actually
# RUN instead of honest-SKIPping under the discovery-only floor identity.
# --validate arms the §7a conformance scaffold (system/validate/{echo,dispatch-outbound}) so the
# reentrant-dispatch checks (validate_echo_dispatch, t1_2_concurrent_reentry) RUN and PASS — the
# dialer is a real same-connection §6.11 reentrant outbound seam (dispatch.wat serve_dispatch_
# outbound + serve_resume). The scaffold stays OFF in the peer's production default (opt-in).
PEERFLAGS="${PEERFLAGS:---debug-open-grants --validate}"
cd "$PROJ"

[ "${NOBUILD:-0}" = "1" ] || make peer >/dev/null

# --enable-jit is load-bearing: WasmEdge's default interpreter runs the codec's Ed25519 verify at
# ~9 ms/op, so §5.2's two per-request signature verifies (~18 ms) cannot sustain the §6.11
# 10k-request t2_1/t2_2 robustness probes within the window. JIT drops verify to ~84 µs (~107×),
# making full per-request verification fast enough — no auth-caching shortcut needed (which
# tampered_signature proves would be non-conformant). See status/PHASE-S3.md.
wasmedge --enable-jit out/peer.wasm $PEERFLAGS >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

i=0
while [ "$i" -lt 100 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "peer exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1
  fi
  i=$((i + 1)); sleep 0.1
done
head -1 /tmp/host.out

# The peer IS launched with --validate (see PEERFLAGS), so the §7a conformance-handler scaffold
# is present and the two reentrant-dispatch checks (validate_echo_dispatch, t1_2_concurrent_
# reentry) RUN and PASS — no allow-skip needed. This is true cohort parity: the dialer is a real
# same-connection §6.11 reentrant outbound seam, not a declined opt-in. (See status/PHASE-S3.md.)
if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
