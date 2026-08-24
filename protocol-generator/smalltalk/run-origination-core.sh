#!/bin/sh
# §10.2 origination-core probe — Smalltalk target (A-role) against the Go entity-peer reference
# (B-role). Both run inside the pharo-toolchain container (the Go ELFs run there too); shared
# loopback, sealed-offline (--network=none).
#
# Under --profile core the origination category''s substantive leg is dispatch_outbound_reentry:
# the validator mints a reentry capability, EXECUTEs system/validate/dispatch-outbound on the
# target, and the target originates ONE outbound EXECUTE back to the validator-as-B over the
# SAME inbound connection (§6.11 reentry; NOT a fresh dial). The Smalltalk peer builds this at S3
# (EcPeer>>dispatchOutbound:... + the EcPending request_id demux) and WIRES it to the validator at
# S4 via the system/validate/dispatch-outbound handler (EcValidate, live under --validate). The Go
# reference is connected only to satisfy the gate''s `-reference-peer required` input shape. Absent
# --validate the probe honest-SKIPs (which is why the single-peer run-s4.sh SKIPs origination).
#
# Oracle pin: entity-core-go @cc1970f (output/s4-oracles/{validate-peer,entity-peer}). Invoke from
# the repo root (drives podman for you), or in-container.
set -eu

if [ ! -d /work/protocol-generator/smalltalk ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/pharo-toolchain:latest"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/smalltalk "$IMAGE" sh /work/protocol-generator/smalltalk/run-origination-core.sh "$@"
fi

PROJ=/work/protocol-generator/smalltalk
CODEC_SRC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD="$CODEC_SRC/build"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"
REFPEER="${REFPEER:-/work/output/s4-oracles/entity-peer}"
NAME="${PEERNAME:-conformance}"
TPORT="${TPORT:-7777}"   # target (Smalltalk)
RPORT="${RPORT:-7778}"   # reference (Go)
PEERIMG="$PROJ/entity-core.image"

if [ ! -x "$ORACLE" ] || [ ! -x "$REFPEER" ]; then
  echo "SKIP origination-core: oracle/reference not built (run tools/oracle-bootstrap.sh)." >&2
  exit 0
fi

cd "$PROJ"
[ -f "$CODEC_BUILD/libentitycore_codec.so" ] || \
  ( cd "$CODEC_SRC" && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null )
export LD_LIBRARY_PATH="$CODEC_BUILD:${LD_LIBRARY_PATH:-}"

make image >/tmp/img.out 2>&1 || { echo "make image failed:" >&2; tail -20 /tmp/img.out >&2; exit 1; }

KPDIR="${HOME:-/root}/.entity/peers/$NAME"; mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# Reference Go peer (B-role), open-access.
"$REFPEER" -addr "127.0.0.1:$RPORT" -open-access >/tmp/ref.out 2>/tmp/ref.err &
REF_PID=$!

# Target Smalltalk host (A-role) — --validate makes system/validate/dispatch-outbound live.
EC_PEER_PORT="$TPORT" EC_PEER_NAME="$NAME" EC_PEER_VALIDATE=1 EC_PEER_OPEN_GRANTS=1 \
  pharo --headless "$PEERIMG" bin/peer.st >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
cleanup() { kill "$HOST_PID" "$REF_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

i=0; while [ "$i" -lt 300 ]; do
  grep -q "^LISTENING" /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "Smalltalk host exited before LISTENING:" >&2; grep -vi 'warning' /tmp/host.err | tail >&2; exit 1; }
  i=$((i+1)); sleep 0.1
done
grep -q "^LISTENING" /tmp/host.out 2>/dev/null || { echo "Smalltalk host never reached LISTENING" >&2; grep -vi 'warning' /tmp/host.err | tail >&2; exit 1; }
sleep 1   # give the Go reference a moment to bind
echo "target(Smalltalk)=$(head -1 /tmp/host.out)  reference(Go) on :$RPORT"

"$ORACLE" -addr "127.0.0.1:$TPORT" -reference-peer "127.0.0.1:$RPORT" \
  -profile core -category origination || true
echo "=== Go reference stderr (tail) ==="; tail -5 /tmp/ref.err 2>/dev/null || true
