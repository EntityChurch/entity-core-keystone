#!/bin/sh
# S4 conformance harness — entity-core-protocol-fortran.
#
# Runs entirely inside the fortran-toolchain container (fedora:43): the Go validate-peer
# oracle is a static fedora:43 ELF that runs there too, so oracle + peer share one loopback
# and the whole run stays sealed-offline (--network=none — intra-container 127.0.0.1 works
# under it). Fortran is SIMPLER than the Rexx precedent: the net-shim is linked into the
# single bin/peer binary (no FIFO co-process) and crypto binds libentitycore_codec directly
# (no separate helper). Builds the peer (make peer), provisions the persistent identity at
# ~/.entity/peers/NAME/keypair, launches build/peer --name conformance --port 7777
# --debug-open-grants --validate, waits for its LISTENING line, points validate-peer at it,
# tears down.
#
# Invoke from the repo root (the oracle binary is a gitignored local tool — build it first
# with tools/oracle-bootstrap.sh):
#   ./protocol-generator/fortran/run-s4.sh  [validate-peer-args...]
# (which re-execs itself under capped podman for you).
#
# Default validate-peer args: -profile core (all core-profile categories; the oracle
# auto-allowlists the §9.0 extension-carve-out skips). Pass args to override (e.g. a single
# -category, or -failures-only). ORACLE / PORT / VALIDATE / NOBUILD are env overrides;
# ORACLE_TIMEOUT overrides the run budget.
#
# When NOT already inside the container (no /work), re-exec self under capped podman.
set -eu

if [ ! -d /work/protocol-generator/fortran ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/fortran-toolchain:latest"
  # Forward this script's OWN documented env overrides across the container
  # boundary. Without this an ORACLE= set by the caller is silently DROPPED and
  # the inner run falls back to the real validator -- the run then SUCCEEDS and
  # writes a perfectly good conformance report where a probe report was expected.
  # Measured 2026-09-06: 5 of these 8 harnesses did exactly that during the §6.3
  # put-admission sweep. `${VAR:+...}` so an unset var adds no flag and the inner
  # default still decides -- forwarding, never policy.
  exec podman run ${ORACLE:+-e ORACLE="$ORACLE"} ${JSON_OUT:+-e JSON_OUT="$JSON_OUT"} ${NOBUILD:+-e NOBUILD="$NOBUILD"} ${VALIDATE:+-e VALIDATE="$VALIDATE"} \
    $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/fortran "$IMAGE" sh /work/protocol-generator/fortran/run-s4.sh "$@"
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
PROJ=/work/protocol-generator/fortran
CODEC_BUILD="${CODEC_BUILD:-/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build}"
export LD_LIBRARY_PATH="$CODEC_BUILD${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
cd "$PROJ"

# Build the single host binary (peer + net-shim + codec, all linked). Offline.
if [ "${NOBUILD:-0}" != "1" ]; then
  make peer >/tmp/s4build.out 2>&1 || { echo "s4 peer build failed:" >&2; cat /tmp/s4build.out >&2; exit 1; }
fi

# --validate enables the §7a conformance handlers (system/validate/{echo,dispatch-outbound})
# so the validate_echo_dispatch + dispatch_outbound_reentry probes run live instead of
# honest-SKIP. Off in production; on here. (VALIDATE=0 → SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find the
# peer's keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer — exercising genuine
# K-of-N instead of env-skipping. The seed (0x11 × 32, base64 "ERER…") matches the launcher
# default, so peer_id is unchanged. NAME follows the Go entity-peer / peer-manager
# convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

build/peer --port "$PORT" --name "$NAME" --debug-open-grants $VALIDATE_FLAG \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
cleanup() {
  if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
  [ -n "${HOST_PID:-}" ] || return 0
  kill -0 "$HOST_PID" 2>/dev/null || return 0
  kill -TERM "$HOST_PID" 2>/dev/null || true
  # Poll rather than a bare wait: a peer that ignores TERM is bounded at ~5s and then
  # killed, instead of hanging the run forever.
  j=0
  while [ "$j" -lt 50 ]; do
    kill -0 "$HOST_PID" 2>/dev/null || return 0
    j=$((j + 1))
    sleep 0.1
  done
  kill -KILL "$HOST_PID" 2>/dev/null || true
  wait "$HOST_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait up to 20s for the readiness line (gfortran startup + net-shim listen bind).
i=0
while [ "$i" -lt 200 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then
    echo "host exited before LISTENING:" >&2
    cat /tmp/host.err >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.1
done
if ! grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then
  echo "host never reached LISTENING within 20s:" >&2
  cat /tmp/host.err >&2
  exit 1
fi
head -1 /tmp/host.out

# Default args: the full --profile core run, JSON report emitted alongside. -timeout is the
# overall run budget (an OPERATOR knob; the real gate is the 20s per-request cap, never
# wall-clock). Fortran is compiled and sub-ms/op, so a modest 5m budget is ample even for
# concurrency.t2_1's ~10k-request flood. Override with ORACLE_TIMEOUT.
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout "${ORACLE_TIMEOUT:-5m}" -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
fi

. /work/protocol-generator/shared/tools/refpeer.sh
refpeer_up
"$ORACLE" -addr "127.0.0.1:$PORT" $REFPEER_FLAG "$@" || true

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
