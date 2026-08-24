#!/bin/sh
# S4 conformance harness — entity-core-protocol-forth (#25).
#
# Runs entirely inside the forth-toolchain container (fedora:43): the Go validate-peer
# oracle is a static CGO_ENABLED=0 ELF that runs there too, so oracle + peer share one
# loopback and the whole run stays sealed-offline (--network=none — intra-container
# 127.0.0.1 works under it). Unlike the Rexx precedent there is NO co-process daemon:
# gforth owns the sockets + select loop + crypto in-process (A-FT-008), so the peer is a
# single `gforth bin/peer.fs` process. Launches it with --name conformance
# --debug-open-grants --validate, waits for its LISTENING line, points validate-peer at
# it, tears down.
#
# Invoke from the repo root (the oracle binary is a gitignored local tool — build it first
# with tools/oracle-bootstrap.sh):
#   ./run-s4.sh                    # the full --profile core gate (drives podman for you)
#   ./run-s4.sh -category multisig # a single category
#
# Default validate-peer args: -profile core. ORACLE / PORT / PEERNAME / ORACLE_TIMEOUT are
# env overrides. When NOT already inside the container (no /work), re-exec self under podman.
set -eu

if [ ! -d /work/protocol-generator/forth ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/forth-toolchain:latest"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/forth "$IMAGE" sh /work/protocol-generator/forth/run-s4.sh "$@"
fi

PORT="${PORT:-7777}"
CODEC_SRC=/work/ffi-generator/c-abi/entity-core-codec-ffi-c
CODEC_BUILD="$CODEC_SRC/build"
SPEC=/work/ffi-generator/c-abi/spec
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness — but that also swallowed a MISSING
# binary, and the script exited 0 having validated nothing. Measured 2026-08-23: a
# fresh clone with no sibling entity-core-go printed one "No such file or directory"
# line and exited 0, i.e. the documented Quick-start command appeared to succeed.
[ -x "$ORACLE" ] || { echo "run-s4: ERROR conformance oracle not found at $ORACLE" >&2
  echo "  The oracle is a gitignored local tool built from the sibling entity-core-go" >&2
  echo "  repo. Clone it NEXT TO this one, then run tools/oracle-bootstrap.sh." >&2
  echo "  See the Quick start in README.md." >&2
  exit 3; }
PROJ=/work/protocol-generator/forth
NAME="${PEERNAME:-conformance}"

cd "$PROJ"

# Build libentitycore_codec if absent (offline; libsodium is in the toolchain image). GOTCHA
# A-FT-005: clear the libcc wrapper cache so a stale .so never binds old symbols.
[ -f "$CODEC_BUILD/libentitycore_codec.so" ] || \
  ( cd "$CODEC_SRC" && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release >/dev/null && cmake --build build >/dev/null )
rm -rf "${HOME:-/root}/.gforth/libcc-named" "${HOME:-/root}/.gforth/libcc-tmp"

export LIBRARY_PATH="$CODEC_BUILD" LD_LIBRARY_PATH="$CODEC_BUILD" \
       C_INCLUDE_PATH="$SPEC" CPATH="$SPEC"

# Provision the peer's persistent identity at ~/.entity/peers/NAME/keypair so the validator's
# multisig accept-path probe (valid_2of3_peer_signed_accepted) can load the peer's keypair
# (crypto.LookupKeypairByPeerID) and co-sign AS the peer — exercising genuine K-of-N. The seed
# (0x11 x32, PEM base64 "ERER…") matches the launcher default so peer_id is unchanged.
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# --validate enables the §7a conformance handlers (system/validate/{echo,dispatch-outbound}).
# --debug-open-grants seeds the degenerate default→* connection grant (grant-gated categories
# need it). Off in production; on here.
# Enlarged data/return/locals stacks: the §6.11 reentry pump recurses (a handler that originates
# an outbound EXECUTE re-enters the select pump to await its reply), and the recursive canonical
# codec walk (tv-node-len) nests per container level — a concurrent-reentry flood (concurrency
# t1_2/t2_x) drives both deep enough to exhaust gforth's default 64 KiB stacks. A single-thread
# manual-pump substrate legitimately needs headroom here (the correlation-map/reentry tax the
# non-actor peers pay); tv-node-len also carries a hard §4.9 depth+count cap so a MALFORMED frame
# still throws-and-recovers rather than growing without bound.
gforth -d 64M -r 64M -l 16M bin/peer.fs --port "$PORT" --name "$NAME" --debug-open-grants --validate \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
cleanup() { kill "$HOST_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Wait up to 20s for the readiness line.
i=0
while [ "$i" -lt 200 ]; do
  grep -q '^LISTENING' /tmp/host.out 2>/dev/null && break
  kill -0 "$HOST_PID" 2>/dev/null || { echo "host exited before LISTENING:" >&2; grep -v redefined /tmp/host.err | tail >&2; exit 1; }
  i=$((i + 1)); sleep 0.1
done
grep -q '^LISTENING' /tmp/host.out 2>/dev/null || { echo "host never reached LISTENING within 20s:" >&2; grep -v redefined /tmp/host.err | tail >&2; exit 1; }
head -1 /tmp/host.out

# Default args: the full --profile core run, JSON alongside. -timeout is an OPERATOR budget
# (the real gate is the 20s per-request cap, never wall-clock). This peer crosses libffi for
# crypto per op; concurrency.t2_1 streams 10000 tree.gets — widen the overall budget as the
# cohort does (dart 5m, prolog 180s). Override with ORACLE_TIMEOUT.
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout "${ORACLE_TIMEOUT:-10m}" -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi

"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
