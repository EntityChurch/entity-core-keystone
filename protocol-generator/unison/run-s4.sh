#!/bin/sh
# S4 conformance harness — entity-core-protocol-unison.
#
# Runs inside the unison-toolchain container (the Go validate-peer oracle is a
# fedora:43 ELF that runs there too, so oracle + peer share one loopback; stays
# sealed-offline with --network=none — the peer is builtins-only bytecode). Two
# steps, both offline:
#   1. `ucm transcript transcripts/peer-compile.md` loads src/*.u (incl. Host.u)
#      into a fresh codebase and compiles `main` to output/peer.uc.
#   2. `ucm run.compiled output/peer.uc -- <args>` launches the host; wait for its
#      LISTENING line; point validate-peer at it; tear it down.
#
# Invoke from the repo root:
#   . tools/podman-caps.sh
#   podman run $PODMAN_RUN_CAPS --rm --network=none \
#     -v "$PWD":/work:Z -w /work/protocol-generator/unison \
#     localhost/entity-core-keystone/unison-toolchain:latest \
#     sh /work/protocol-generator/unison/run-s4.sh [validate-peer-args...]
#
# Or from the repo root directly (bare `./run-s4.sh`) — the wrapper below re-execs
# itself inside the container automatically.
#
# Default args: -profile core (the single-flag gate). ORACLE/PORT/NOBUILD/VALIDATE
# /PEERNAME env overrides.

set -eu

REPO_ROOT="${REPO_ROOT:-/work}"
PROJ="$REPO_ROOT/protocol-generator/unison"
PORT="${PORT:-7777}"
# If we're not already in the container, re-exec inside it under caps, offline.
# Default INCONTAINER=0: a bare host invocation must self-relaunch, not assume it
# is already sandboxed (the previous default of 1 meant a host run skipped the
# re-exec entirely and died on `cd /work/...`, since /work is never mounted there).
if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  # Forward this script's OWN documented env overrides across the container
  # boundary. Without this an ORACLE= set by the caller is silently DROPPED and
  # the inner run falls back to the real validator -- the run then SUCCEEDS and
  # writes a perfectly good conformance report where a probe report was expected.
  # Measured 2026-09-06: 5 of these 8 harnesses did exactly that during the §6.3
  # put-admission sweep. `${VAR:+...}` so an unset var adds no flag and the inner
  # default still decides -- forwarding, never policy.
  exec podman run ${ORACLE:+-e ORACLE="$ORACLE"} ${JSON_OUT:+-e JSON_OUT="$JSON_OUT"} ${NOBUILD:+-e NOBUILD="$NOBUILD"} ${VALIDATE:+-e VALIDATE="$VALIDATE"} \
    $PODMAN_RUN_CAPS --rm --network=none \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z -w /work/protocol-generator/unison \
    localhost/entity-core-keystone/unison-toolchain:latest \
    sh /work/protocol-generator/unison/run-s4.sh "$@"
fi

# ORACLE is defaulted AFTER the re-exec, and that ordering is the whole point: it
# used to be resolved above, against $REPO_ROOT, and $REPO_ROOT is EXPORTED BY THE
# CENSUS to the host repo root. The forward below then handed the container a HOST
# path, the inner preflight could not find it, and the peer exited 3 on every plain
# census run — a defect the ORACLE-forwarding fix INTRODUCED, and the only one of the
# eight harnesses it touched that had its default ahead of the boundary. `${VAR:+…}`
# is only "forwarding, never policy" while the var is genuinely unset unless a caller
# set it; a default placed before it turns the forward into policy.
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness — but that also swallowed a MISSING
# binary, and the script exited 0 having validated nothing. Measured 2026-08-23: a
# fresh clone with no sibling entity-core-go printed one "No such file or directory"
# line and exited 0, i.e. the documented Quick-start command appeared to succeed.
case "$ORACLE" in
  /work/*) HOST_ORACLE="$(cd "$(dirname "$0")/../.." && pwd)/${ORACLE#/work/}" ;;
  *)       HOST_ORACLE="$ORACLE" ;;
esac
[ -x "$ORACLE" ] || [ -x "$HOST_ORACLE" ] || {
  echo "run-s4: ERROR conformance oracle not found at $ORACLE" >&2
  echo "  The oracle is a gitignored local tool built from the sibling entity-core-go" >&2
  echo "  repo. Clone it NEXT TO this one, then run tools/oracle-bootstrap.sh." >&2
  echo "  See the Quick start in README.md." >&2
  exit 3; }

cd "$PROJ"

# 1. Compile the peer host to bytecode (offline; fresh codebase per transcript).
if [ "${NOBUILD:-0}" != "1" ]; then
  ucm transcript transcripts/peer-compile.md >/tmp/compile.out 2>&1 || {
    echo "peer-compile transcript failed:" >&2; tail -40 /tmp/compile.out >&2; exit 1; }
fi
[ -f output/peer.uc ] || { echo "output/peer.uc not produced" >&2; exit 1; }

# 2. Provision the peer's persistent identity at the standard on-disk location so
# the validator's multisig accept-path probe (valid_2of3_peer_signed_accepted) can
# find the peer's keypair and co-sign AS the peer — genuine K-of-N, not env-skip.
# The seed (0x11 x 32, base64 "ERER...") matches the host default, so peer_id is
# unchanged. NAME follows the Go entity-peer / peer-manager convention:
# ~/.entity/peers/NAME/keypair.
NAME="${PEERNAME:-conformance}"
KPDIR="${HOME:-/root}/.entity/peers/$NAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# --validate enables the §7a conformance handlers (system/validate/{echo,
# dispatch-outbound}); --debug-open-grants is the degenerate open seed the
# grant-gated categories need. (VALIDATE=0 to exercise the SKIP path.)
VALIDATE_FLAG=""; [ "${VALIDATE:-1}" = "1" ] && VALIDATE_FLAG="--validate"

ucm run.compiled output/peer.uc -- \
  --port "$PORT" --name "$NAME" --debug-open-grants $VALIDATE_FLAG \
  >/tmp/host.out 2>/tmp/host.err &
HOST_PID=$!
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
reap_host() {
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
trap reap_host EXIT INT TERM

i=0
while [ "$i" -lt 300 ]; do
  if grep -q '^LISTENING' /tmp/host.out 2>/dev/null; then break; fi
  if ! kill -0 "$HOST_PID" 2>/dev/null; then echo "host exited before LISTENING:" >&2; cat /tmp/host.err >&2; exit 1; fi
  i=$((i + 1)); sleep 0.1
done
grep '^LISTENING' /tmp/host.out || { echo "no LISTENING line after 30s" >&2; cat /tmp/host.err >&2; exit 1; }

if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "${JSON_OUT:-$PROJ/status/CONFORMANCE-REPORT.json}"
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
