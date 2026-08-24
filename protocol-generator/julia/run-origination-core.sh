#!/bin/sh
# §10.2 origination-core probe — Julia target (A-role) against the Go entity-peer
# reference (B-role). Both run inside the julia-toolchain container (Go ELFs run there);
# shared loopback, sealed-offline with --network=none. runOriginationCore is the
# dispatch_outbound_reentry probe — the validator mints a reentry capability, EXECUTEs
# system/validate/dispatch-outbound on the target, and the target originates an outbound
# EXECUTE back to the validator-as-B over the SAME inbound connection (§6.11 reentry; NOT a
# fresh dial to the reference). The reference is connected only to keep the gate's input
# shape (`-reference-peer required`) consistent with --profile full; otherwise unused under
# core. The target MUST run with --validate (dispatch-outbound live); absent it, the probe
# honest-SKIPs.
#
# Julia note: the §6.11 reentry seam is the transport.jl reader-demux (per-request Channel)
# + the conn.outbound closure bound per connection — a plain Task handoff on the single-
# threaded cooperative scheduler (no cross-thread demux). This gate is the cross-impl wire
# proof of that seam from the coroutine/event-loop idiom.
#
# Invoke from the repo root (capped, offline):
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none -v "$PWD":/work:Z \
#     entity-core-keystone/julia-toolchain:latest sh /work/protocol-generator/julia/run-origination-core.sh
set -eu
TPORT="${TPORT:-7777}"   # target (Julia)
RPORT="${RPORT:-7778}"   # reference (Go)
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
PROJ=/work/protocol-generator/julia
cd "$PROJ"

if [ "${NOBUILD:-0}" != "1" ]; then
  julia --project=. -e 'include("src/EntityCore.jl"); using .EntityCore; println("ok")' >/tmp/julia-build.log 2>&1 \
    || { cat /tmp/julia-build.log; exit 1; }
fi

# Provision the standard on-disk identity so the target can co-sign as the peer.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# Reference Go peer (B-role), open-access.
"$REFPEER" --addr "127.0.0.1:$RPORT" --open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!
# Target Julia host (A-role) — --validate makes system/validate/dispatch-outbound live.
julia --project=. bin/peer.jl --port "$TPORT" --name "$NAME" --debug-open-grants --validate \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
trap 'kill "$HOST_PID" "$REF_PID" 2>/dev/null || true' EXIT INT TERM

i=0; while [ "$i" -lt 300 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Julia host exited:"; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.2
done
sleep 1   # give the Go reference a moment to bind
echo "target(Julia)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination "$@" || true
echo "=== Go reference stderr (tail) ===" ; tail -5 /tmp/ref.err 2>/dev/null || true
