#!/bin/sh
# §10.2 origination-core probe — Oz target (A-role) against the Go entity-peer
# reference (B-role). Both run inside the mozart-toolchain container (the Go ELFs
# run there too); shared loopback, sealed-offline (--network=none).
#
# Under --profile core the origination category's substantive leg is
# dispatch_outbound_reentry — the validator mints a reentry capability, EXECUTEs
# system/validate/dispatch-outbound on the target, and the target originates an
# outbound EXECUTE back to the validator-as-B over the SAME inbound connection
# (§6.11 reentry — a dataflow send+wait on that connection's writer, correlated by
# the reader's dataflow-var demux; NOT a fresh dial). The Go reference is connected
# only to satisfy the gate's `-reference-peer required` input shape. The target MUST
# run with --validate so system/validate/dispatch-outbound is live.
#
# Oracle pin: entity-core-go @cc1970f (output/s4-oracles/{validate-peer,entity-peer}).
#
# Invoke from the repo root (./run-origination-core.sh drives podman for you).
set -eu

if [ ! -d /work/protocol-generator/oz ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/mozart-toolchain:latest"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/oz "$IMAGE" sh /work/protocol-generator/oz/run-origination-core.sh "$@"
fi

PROJ=/work/protocol-generator/oz
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
DAEMON="$PROJ/build/eccodecd"
TPORT="${TPORT:-47961}"   # target (Oz)
RPORT="${RPORT:-47962}"   # reference (Go)
NAME="${PEERNAME:-conformance}"

cd "$PROJ"
make host >/tmp/ozbuild.out 2>&1 || { echo "oz peer build failed:" >&2; cat /tmp/ozbuild.out >&2; exit 1; }

KPDIR="${HOME:-/root}/.entity/peers/$NAME"; mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# Reference Go peer (B-role), open-access.
"$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!

# Target Oz host (A-role) — --validate makes system/validate/dispatch-outbound live.
ozengine "$PROJ/build/host.ozf" \
  --port "$TPORT" --name "$NAME" --daemon "$DAEMON" --debug-open-grants --validate \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
cleanup() { kill "$HOST_PID" "$REF_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

i=0; while [ "$i" -lt 300 ]; do
  grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Oz host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
grep -q "^LISTENING" /tmp/host.out 2>/dev/null || { echo "Oz host never reached LISTENING" >&2; cat /tmp/host.err >&2; exit 1; }
sleep 1   # give the Go reference a moment to bind
echo "target(Oz)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination || true
echo "=== Go reference stderr (tail) ==="; tail -5 /tmp/ref.err 2>/dev/null || true
