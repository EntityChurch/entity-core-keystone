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
ORACLE="${ORACLE:-$REPO_ROOT/output/s4-oracles/validate-peer}"

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

# If we're not already in the container, re-exec inside it under caps, offline.
# Default INCONTAINER=0: a bare host invocation must self-relaunch, not assume it
# is already sandboxed (the previous default of 1 meant a host run skipped the
# re-exec entirely and died on `cd /work/...`, since /work is never mounted there).
if [ "${INCONTAINER:-0}" != "1" ]; then
  HOSTREPO="$(cd "$(dirname "$0")/../.." && pwd)"
  . "$HOSTREPO/tools/podman-caps.sh"
  exec podman run $PODMAN_RUN_CAPS --rm --network=none \
    -e INCONTAINER=1 \
    -v "$HOSTREPO":/work:Z -w /work/protocol-generator/unison \
    localhost/entity-core-keystone/unison-toolchain:latest \
    sh /work/protocol-generator/unison/run-s4.sh "$@"
fi

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
trap 'kill "$HOST_PID" 2>/dev/null || true' EXIT INT TERM

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
"$ORACLE" -addr "127.0.0.1:$PORT" "$@" || true
