#!/bin/sh
# S4 conformance harness — entity-core-protocol-apl (the array/value-model probe).
#
# Runs entirely inside the apl-toolchain container (fedora:43): the Go validate-peer oracle
# is a static fedora:43 ELF that runs there too, so oracle + peer share one loopback and the
# whole run stays sealed-offline (--network=none — intra-container 127.0.0.1 works under it).
#
# APL is INTERPRETED — there is no compiled build/peer binary. This harness: (1) builds
# libentitycore_codec (CMake) + the native-fn shim src/ext/ec_native.so if absent (make shim);
# (2) provisions the persistent identity at ~/.entity/peers/NAME/keypair (entity PEM = base64
# of the 32-byte seed 0x11 × 32 = "ERER…ERE="); (3) launches the peer as
#   apl --script <S3 modules> -f bin/peer.apl -- --name conformance --port 7777 \
#       --debug-open-grants --validate
# scraping its `LISTENING <port>` readiness line (output FILE-redirected, never piped —
# GNU APL hangs after )OFF on a pipe, A-APL-013); (4) points validate-peer at 127.0.0.1:7777;
# (5) tears down. peer.apl reads its flags from ⎕ARG (everything after `--`).
#
# Invoke from the repo root (the oracle binary is a gitignored local tool — build it first
# with tools/oracle-bootstrap.sh):
#   ./protocol-generator/apl/run-s4.sh  [validate-peer-args...]
# (which re-execs itself under capped podman for you).
#
# Default validate-peer args: -profile core (the oracle auto-allowlists the §9.0 extension-
# carve-out skips). Pass args to override (e.g. a single -category, or -failures-only). ORACLE
# / PORT / VALIDATE / NOBUILD are env overrides; ORACLE_TIMEOUT overrides the run budget.
#
# Perf note: interpreted APL is much slower than compiled Fortran — the `concurrency` category
# floods ~10k requests. The real gate is the per-request cap, not wall-clock, so the run budget
# is generous (default 15m, ORACLE_TIMEOUT overridable).
#
# When NOT already inside the container (no /work), re-exec self under capped podman.
set -eu

if [ ! -d /work/protocol-generator/apl ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/apl-toolchain:latest"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/apl "$IMAGE" sh /work/protocol-generator/apl/run-s4.sh "$@"
fi

PORT="${PORT:-7777}"
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
PROJ=/work/protocol-generator/apl
CODEC_BUILD="${CODEC_BUILD:-/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build}"
export LD_LIBRARY_PATH="$CODEC_BUILD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$PROJ"

# The S3 peer-machinery module load order (Makefile S3MODS): the S2 codec (status/varint/
# cbor/ffi/entity) then value helpers -> L1 identity/keystore -> foundation store -> L2 wire
# -> L3 capability -> L4 net/transport -> §9.5 core types -> the peer brain.
MODS="src/status.apl src/varint.apl src/cbor.apl src/ffi.apl src/entity.apl src/val.apl \
src/ent.apl src/identity.apl src/keystore.apl src/store.apl src/wire.apl src/capability.apl \
src/net.apl src/transport.apl src/coretypes.apl src/peer.apl"
LOAD=""; for m in $MODS; do LOAD="$LOAD -f $m"; done

# Build the only compiled artifact (libentitycore_codec via CMake if absent + the native-fn
# shim). Offline. The .apl source is interpreted — nothing to compile there.
if [ "${NOBUILD:-0}" != "1" ]; then
  make shim >/tmp/s4build.out 2>&1 || { echo "s4 shim build failed:" >&2; cat /tmp/s4build.out >&2; exit 1; }
fi

# --validate enables the §7a conformance handlers (system/validate/{echo,dispatch-outbound})
# so the validate_echo_dispatch + dispatch_outbound_reentry probes run live instead of
# honest-SKIP. Off in production; on here. (VALIDATE=0 → SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the peer's persistent identity at the standard on-disk location so the validator's
# multisig accept-path probe (valid_2of3_peer_signed_accepted) can find the peer's keypair
# (crypto.LookupKeypairByPeerID) and co-sign AS the peer — exercising genuine K-of-N instead
# of env-skipping. The seed (0x11 × 32, base64 "ERER…") matches the launcher default (seed
# 0x11 → peer_id 2KHoAk7A5Jmh…), so peer_id is unchanged. NAME follows the Go entity-peer /
# peer-manager convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# Launch the peer. Output FILE-redirected, never piped (GNU APL hangs after )OFF on a pipe —
# A-APL-013). peer.apl parses --name/--port/--validate/--debug-open-grants from ⎕ARG.
# shellcheck disable=SC2086
apl --script $LOAD -f bin/peer.apl -- \
  --name "$NAME" --port "$PORT" --debug-open-grants $VALIDATE_FLAG \
  </dev/null >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
cleanup() { kill "$HOST_PID" 2>/dev/null || true; }
trap cleanup EXIT INT TERM

# Wait up to 40s for the readiness line (apl startup + module load + ⎕FIO listen bind is
# slower than a compiled peer).
i=0
while [ "$i" -lt 400 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2
    cat /tmp/host.err >&2; cat /tmp/host.out >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.1
done
if ! grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then
  echo "host never reached LISTENING within 40s:" >&2
  cat /tmp/host.err >&2; cat /tmp/host.out >&2
  exit 1
fi
head -1 /tmp/host.out

# Default args: the full --profile core run, JSON report emitted alongside. -timeout is the
# overall run budget (an OPERATOR knob; the real gate is the 20s per-request cap, never
# wall-clock). Interpreted APL is much slower than compiled Fortran, so a generous 15m budget
# covers concurrency.t2_1's ~10k-request flood. Override with ORACLE_TIMEOUT.
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout "${ORACLE_TIMEOUT:-15m}" -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi

"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true

# SURFACE THE STDERR OF THE PEER ITSELF. /tmp/host.err is a path INSIDE a --rm
# container, so without this the dying words of the peer are discarded with the
# container and a mid-run abort leaves a log reading only "connection refused".
# That is not hypothetical: the zig intermittent survived four investigations
# reported as "no crash, empty stderr" until this line existed on that harness,
# and then produced a stack trace on the first reproduction. Emitted on stderr so
# it cannot be mistaken for oracle output, and only when non-empty so a clean run
# stays quiet.
if [ -s /tmp/host.err ]; then
  echo "--- peer stderr (/tmp/host.err) ---" >&2
  cat /tmp/host.err >&2
fi
