#!/bin/sh
# S4 conformance harness — entity-core-protocol-rexx.
#
# Runs entirely inside the rexx-toolchain container (fedora:43): the Go validate-peer
# oracle is a static CGO_ENABLED=0 ELF that runs there too, so oracle + peer share one
# loopback and the whole run stays sealed-offline (--network=none — intra-container
# 127.0.0.1 works under it). Builds the peer's C prerequisites (the ecnet co-process
# daemon + the eccrypto helper, both over libentitycore_codec) and the concatenated
# host binary, launches bin/peer.rex with --name conformance --debug-open-grants
# --validate, waits for its LISTENING line, points validate-peer at it, tears down.
#
# Invoke from the repo root (the oracle binary is a gitignored local tool — build it
# first with tools/oracle-bootstrap.sh):
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none \
#     -v "$PWD":/work:Z entity-core-keystone/rexx-toolchain:latest sh /work/protocol-generator/rexx/run-s4.sh [validate-peer-args...]
#
# Or via the run wrapper: ./run-s4.sh  (which drives podman for you).
#
# Default validate-peer args: -profile core (all core-profile categories; the oracle
# auto-allowlists the §9.0 extension-carve-out skips). Pass args to override (e.g. a
# single -category, or -failures-only). ORACLE / PORT / VALIDATE are env overrides.
#
# When NOT already inside the container (no /work), re-exec self under podman.
set -eu

if [ ! -d /work/protocol-generator/rexx ]; then
  REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$REPO_ROOT/tools/podman-caps.sh"
  IMAGE="entity-core-keystone/rexx-toolchain:latest"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none -v "$REPO_ROOT":/work:Z \
    -w /work/protocol-generator/rexx "$IMAGE" sh /work/protocol-generator/rexx/run-s4.sh "$@"
fi

PORT="${PORT:-7777}"
CODEC_BUILD=/work/ffi-generator/c-abi/entity-core-codec-ffi-c/build
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
PROJ=/work/protocol-generator/rexx
PEERBIN=/tmp/rexx-peer.rex
NET="$PROJ/src/ext/ecnet"

cd "$PROJ"

# Build the ecnet daemon + eccrypto helper (+ libentitycore_codec if absent) and the
# concatenated host binary (bin/peer.rex + the routine library).
make s4peer >/tmp/s4build.out 2>&1 || { echo "s4 peer build failed:" >&2; cat /tmp/s4build.out >&2; exit 1; }

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}) so the validate_echo_dispatch + dispatch_outbound_reentry probes
# run live instead of honest-SKIP. Off in production; on here. (VALIDATE=0 → SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

# Provision the peer's persistent identity at the standard on-disk location so the
# validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can find the
# peer's keypair (crypto.LookupKeypairByPeerID) and co-sign AS the peer — exercising
# genuine K-of-N instead of env-skipping. The seed (0x11 × 32, base64 "ERER…") matches
# the launcher default, so peer_id is unchanged. NAME follows the Go entity-peer /
# peer-manager convention: ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# The FIFO base is per-run; EC_DBG (optional) redirects the daemon's stderr to a log.
BASE="/tmp/ecnet-s4.$$"
LD_LIBRARY_PATH="$CODEC_BUILD" rexx "$PEERBIN" \
  --port "$PORT" --name "$NAME" --net "$NET" --base "$BASE" \
  --debug-open-grants $VALIDATE_FLAG >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
#
# This peer is the one case where the listening socket is NOT owned by $HOST_PID: the
# Regina interpreter spawns a separate $NET (ecnet) co-process daemon that holds it,
# and the daemon reparents when the interpreter goes, so `wait` cannot see it.
#
# The previous teardown reached for `pkill -f "$NET $BASE"`. THAT COMMAND IS NOT
# INSTALLED IN THIS IMAGE (nor are pgrep or ps), so the line had been a silent no-op
# for as long as it existed: `2>/dev/null || true` swallows the command-not-found and
# the cleanup reports success having reaped nothing. Measured 2026-09-02, at HEAD and
# unchanged by the rest of this sweep -- the daemon survived every run and kept 127.0.0.1
# bound, so the SECOND invocation in a container exited 1 and every one after it.
# That is the "a guard that was never executed is not a guard" shape with the guard
# missing rather than misrouted. Scan /proc, which needs no tooling at all.
ecnet_pids() {
  for d in /proc/[0-9]*; do
    [ -r "$d/cmdline" ] || continue
    case "$(tr '\0' ' ' < "$d/cmdline")" in
      "$NET $BASE"*) echo "${d#/proc/}" ;;
    esac
  done
}
cleanup() {
  if [ -n "${HOST_PID:-}" ] && kill -0 "$HOST_PID" 2>/dev/null; then
    kill -TERM "$HOST_PID" 2>/dev/null || true
    j=0
    while [ "$j" -lt 50 ] && kill -0 "$HOST_PID" 2>/dev/null; do
      j=$((j + 1)); sleep 0.1
    done
    kill -KILL "$HOST_PID" 2>/dev/null || true
    wait "$HOST_PID" 2>/dev/null || true
  fi
  for p in $(ecnet_pids); do kill -TERM "$p" 2>/dev/null || true; done
  j=0
  while [ "$j" -lt 50 ] && [ -n "$(ecnet_pids)" ]; do
    j=$((j + 1)); sleep 0.1
  done
  for p in $(ecnet_pids); do kill -KILL "$p" 2>/dev/null || true; done
  rm -f "$BASE.cmd" "$BASE.evt" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait up to 20s for the readiness line (Regina startup + daemon spawn + FIFO open).
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

# Default args: the full --profile core run, with the JSON report emitted alongside.
# -timeout: the overall run budget (an OPERATOR knob — the test's own design doctrine
# is "a slow language passes by being correct, not by being fast"; the real gate is the
# 20s per-request cap, never wall-clock). This peer is the cohort's slowest: its §9.1
# crypto crosses a FIFO to the ecnet co-process PER OP (A-RX-011 forbids an in-process
# shim), so each request is several IPC round-trips (~17ms) where a compiled peer is
# sub-ms. concurrency.t2_1 alone streams 10000 tree.gets (~170s single-threaded). The
# default 60s budget is consumed long before the later categories surface (the
# budget-exhaustion cascade), so widen it — as dart (5m) and prolog (180s) already do
# for the same reason. Override with ORACLE_TIMEOUT.
if [ "$#" -eq 0 ]; then
  set -- -profile core -timeout "${ORACLE_TIMEOUT:-10m}" -json-out "$PROJ/status/CONFORMANCE-REPORT.json"
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
