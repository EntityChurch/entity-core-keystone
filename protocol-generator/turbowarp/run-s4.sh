#!/bin/sh
# S4 harness — entity-core-protocol-turbowarp (peer #32) via the WS↔TCP bridge.
#
# Proves the SANDBOXED-peer-via-bridge architecture against the real Go oracle,
# headless: the peer harness (ec-peer-node — the stand-in for the Scratch extension,
# using the SAME browser-bundle core) connects OUT over WebSocket to the bridge, which
# listens on TCP for the oracle. This is the optional oracle-gate path from PHASE-S1
# (default scope is visualization-first).
#
# Run from repo root — sealed offline, loopback only. There is no first-run
# network step and no kc-npm volume: the npm closure is baked into the node24
# image from the committed lockfiles (containers/node24/Containerfile).
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm \
#     --network=none -v "$PWD":/work:Z entity-core-keystone/node24:latest \
#     sh /work/protocol-generator/turbowarp/run-s4.sh [validate-peer-args...]
#
# JSON_OUT — WHERE A BARE RUN WRITES ITS REPORT (changed 2026-09-08)
# A bare `./run-s4.sh` used to default `-json-out` to this peer's TRACKED
# status/CONFORMANCE-REPORT.json — the signed-off record the matrix publishes — so a
# human diagnostic run silently republished a number nobody had reviewed. The default is
# now a scratch path. To refresh the tracked report, MEASURE it deliberately:
#     tools/run-cohort-census.sh --to-status <peer>       (preferred)
#     JSON_OUT=<path> ./run-s4.sh                          (explicit)

set -eu

EC_PORT="${EC_PORT:-7801}"
WS_PORT="${WS_PORT:-7802}"
ORACLE="${ORACLE:-/work/output/s4-oracles/validate-peer}"

# Preflight: the oracle must actually be there. The run below ends in `|| true` so a
# conformance FAIL does not abort the harness — but that also swallowed a MISSING
# binary, and the script exited 0 having validated nothing. Measured 2026-08-23: a
# fresh clone with no sibling entity-core-go printed one "No such file or directory"
# line and exited 0, i.e. the documented Quick-start command appeared to succeed.
# $ORACLE is a CONTAINER path -- the repo root is mounted at /work -- so the existence
# test has to be made against the HOST path, or it can never pass. Measured 2026-08-27:
# in this form the guard rejected all 33 peers carrying it. It had never been executed.
ORACLE_HOST="$ORACLE"
case "$ORACLE_HOST" in
  /work/*) ORACLE_HOST="$(cd "$(dirname "$0")/../.." && pwd)/${ORACLE_HOST#/work/}" ;;
esac
[ -x "$ORACLE_HOST" ] || { echo "run-s4: ERROR conformance oracle not found at $ORACLE_HOST" >&2
  echo "  The oracle is a gitignored local tool built from the sibling entity-core-go" >&2
  echo "  repo. Clone it NEXT TO this one, then run tools/oracle-bootstrap.sh." >&2
  echo "  See the Quick start in README.md." >&2
  exit 3; }
PEERNAME="${PEERNAME:-conformance}"
TW="/work/protocol-generator/turbowarp/src"
TS="/work/protocol-generator/typescript"

if [ "${NOBUILD:-0}" != "1" ]; then
  # `npm ci --offline`, never `npm install`: the committed package-lock.json is
  # authoritative and the closure is baked into the node24 image, so this needs no
  # network and no host-local kc-npm volume. It used to be `npm install` behind a
  # network namespace, which made this peer's conformance result depend on the
  # registry being reachable and on whatever `install` resolved that day — the
  # csharp/kc-nuget defect, closed cohort-wide 2026-09-02.
  #
  # Installs are guarded on the LOCKFILE's mtime, not merely on node_modules being
  # missing. The COMPILE and BUNDLE steps are unconditional: "build only if the
  # output is MISSING" is the standing stale-build-artifact defect, and it has
  # already cost this repo three peers measured against week-old binaries.
  npm_sync() { # <dir> — reinstall when the lockfile is newer than the tree
    _d=$1
    if [ ! -d "$_d/node_modules" ] || [ "$_d/package-lock.json" -nt "$_d/node_modules" ]; then
      (cd "$_d" && npm ci --offline --no-audit --no-fund >/dev/null 2>&1) \
        || { echo "ERROR: npm ci --offline failed in $_d (is the node24 image current?)" >&2; return 1; }
    fi
  }
  npm_sync "$TS" || exit 1
  (cd "$TS" && ./node_modules/.bin/tsc -p tsconfig.json) \
    || { echo "ERROR: TS codec build failed" >&2; exit 1; }
  npm_sync "$TW" || exit 1
  (cd "$TW" && npm run bundle >/dev/null 2>&1) || { echo "ERROR: bundle build failed" >&2; exit 1; }
fi

# Peer identity for the multisig accept-path (seed 0x11×32 = the harness kernel default).
KPDIR="${HOME:-/root}/.entity/peers/$PEERNAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

cd "$TW"
# 1. Bridge (TCP for the oracle + WS for the peer).
EC_PORT="$EC_PORT" WS_PORT="$WS_PORT" node bridge/ws-tcp-bridge.js >/tmp/bridge.out 2>&1 &
BR=$!
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
#
# Two processes here, and the one that owns the oracle-facing TCP port is the BRIDGE,
# not the peer -- so reaping only $PEER would leave the port bound. $PEER is not set
# until step 2, hence the :- default rather than a second trap.
reap_host() {
  if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
  for p in "${BR:-}" "${PEER:-}"; do
    [ -n "$p" ] || continue
    kill -0 "$p" 2>/dev/null || continue
    kill -TERM "$p" 2>/dev/null || true
  done
  # Poll rather than a bare wait: a process that ignores TERM is bounded at ~5s and
  # then killed, instead of hanging the run forever.
  for p in "${BR:-}" "${PEER:-}"; do
    [ -n "$p" ] || continue
    j=0
    while [ "$j" -lt 50 ] && kill -0 "$p" 2>/dev/null; do
      j=$((j + 1)); sleep 0.1
    done
    kill -KILL "$p" 2>/dev/null || true
    wait "$p" 2>/dev/null || true
  done
}
trap reap_host EXIT INT TERM
i=0; while [ "$i" -lt 100 ]; do grep -q "^BRIDGE-LISTENING" /tmp/bridge.out 2>/dev/null && break; kill -0 "$BR" 2>/dev/null || { echo "bridge died:"; cat /tmp/bridge.out; exit 1; }; i=$((i+1)); sleep 0.1; done

# 2. Peer harness (connects OUT to the bridge over WS; the Scratch-extension stand-in).
WS_URL="ws://127.0.0.1:$WS_PORT" node harness/ec-peer-node.js >/tmp/peer.out 2>/tmp/peer.err &
PEER=$!
i=0; while [ "$i" -lt 100 ]; do grep -q "^PEER-CONNECTED" /tmp/bridge.out 2>/dev/null && break; kill -0 "$PEER" 2>/dev/null || { echo "peer died:"; cat /tmp/peer.out /tmp/peer.err; exit 1; }; i=$((i+1)); sleep 0.1; done
echo "BRIDGE + PEER up (tcp:$EC_PORT ws:$WS_PORT)"

# 3. Oracle.
if [ "$#" -eq 0 ]; then set -- -profile core -json-out "${JSON_OUT:-/tmp/ec-s4-turbowarp.json}"; fi
. /work/protocol-generator/shared/tools/refpeer.sh
refpeer_up
"$ORACLE" -addr "127.0.0.1:$EC_PORT" $REFPEER_FLAG "$@" || true

# SURFACE THE STDERR OF THE PEER ITSELF. /tmp/peer.err is a path INSIDE a --rm
# container, so without this the dying words of the peer are discarded with the
# container and a mid-run abort leaves a log reading only "connection refused".
# That is not hypothetical: the zig intermittent survived four investigations
# reported as "no crash, empty stderr" until this line existed on that harness,
# and then produced a stack trace on the first reproduction. Emitted on stderr so
# it cannot be mistaken for oracle output, and only when non-empty so a clean run
# stays quiet.
if [ -s /tmp/peer.err ]; then
  echo "--- peer stderr (/tmp/peer.err) ---" >&2
  cat /tmp/peer.err >&2
fi
