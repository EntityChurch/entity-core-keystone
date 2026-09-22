#!/bin/sh
# S4 conformance harness — entity-core-protocol-node-red (peer #31, visual/dataflow).
#
# Runs entirely inside the node24 container (the Go validate-peer oracle is a
# fedora:43 ELF binary that runs there too). Builds the DELEGATED TS codec, boots
# the Node-RED flow headless (the AUTHORED peer), waits for its LISTENING line,
# points validate-peer at it, tears it down.
#
# Invoke from the repo root:
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm --network=none \
#     -v "$PWD":/work:Z entity-core-keystone/node24:latest \
#     sh /work/protocol-generator/node-red/run-s4.sh [validate-peer-args...]
#
# Default: -profile core. Pass args to override (e.g. -category connectivity).
# Env: ORACLE / EC_PORT / NR_ADMIN_PORT / PEERNAME / EC_VALIDATE / NOBUILD.
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
NR_ADMIN_PORT="${NR_ADMIN_PORT:-1880}"
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
NR="/work/protocol-generator/node-red/src"
TS="/work/protocol-generator/typescript"

# 1. Build the DELEGATED TS codec (dist/) — the interop dependency.
if [ "${NOBUILD:-0}" != "1" ]; then
  # `npm ci --offline`, never `npm install`. The comment this replaces called
  # --offline a "foot-gun (it wipes node_modules then fails on an incomplete
  # cache)" — true of a cache that lives in a host-local kc-npm volume somebody
  # warmed once, and no longer true: the closure is baked into the node24 image
  # from these peers' OWN committed lockfiles, so an incomplete cache fails the
  # IMAGE build instead. Failing loudly here is the point, not the foot-gun.
  #
  # Installs are guarded on the LOCKFILE's mtime, not merely on node_modules being
  # missing, and the COMPILE is unconditional. "Rebuild dist/ only when index.js is
  # MISSING, never when it is merely stale" is precisely how this peer was measured
  # against a week-old bundle on 2026-08-28 and reported as failing a fix it
  # already had.
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
  npm_sync "$NR" || exit 1
fi

# 2. Provision the peer's persistent identity at the standard on-disk location so the
# multisig accept-path probe can co-sign AS the peer. Seed 0x11×32 (base64 "ERER…")
# matches the kernel default → peer_id unchanged whether or not --name is used.
KPDIR="${HOME:-/root}/.entity/peers/$PEERNAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

# 3. Boot the Node-RED flow headless (the AUTHORED peer).
cd "$NR"
# --debug-open-grants parity with the TS conformance host (default→* seed policy),
# so capability checks don't 403 before handlers run. Production peers omit this.
EC_VALIDATE="${EC_VALIDATE:-1}" EC_DEBUG_OPEN_GRANTS="${EC_DEBUG_OPEN_GRANTS:-1}" \
  EC_PORT="$EC_PORT" NR_ADMIN_PORT="$NR_ADMIN_PORT" \
  PEERNAME="$PEERNAME" NR_HEADLESS=1 NR_LOG="${NR_LOG:-warn}" \
  node_modules/.bin/node-red --userDir "$NR" --settings "$NR/settings.js" flows.json \
  >/tmp/nr.out 2>/tmp/nr.err &
NR_PID=$!
# Deterministic teardown. kill(1) only DELIVERS the signal, so a fire-and-forget
# trap returns while the peer still owns the listening socket and a second invocation
# in the same container fails to bind. Measured 2026-09-02 -- how long the port kept
# accepting connections AFTER the harness had exited: elixir >400ms (and the next run
# did fail, rc=1), julia ~88ms, smalltalk ~4ms, zig and go 0ms. The window is a
# property of the peer runtime, not of the harness, which is why every peer carries
# this and not only the ones that were seen to fail.
reap_host() {
  if command -v refpeer_reap >/dev/null 2>&1; then refpeer_reap; fi
  [ -n "${NR_PID:-}" ] || return 0
  kill -0 "$NR_PID" 2>/dev/null || return 0
  kill -TERM "$NR_PID" 2>/dev/null || true
  # Poll rather than a bare wait: a peer that ignores TERM is bounded at ~5s and then
  # killed, instead of hanging the run forever.
  j=0
  while [ "$j" -lt 50 ]; do
    kill -0 "$NR_PID" 2>/dev/null || return 0
    j=$((j + 1))
    sleep 0.1
  done
  kill -KILL "$NR_PID" 2>/dev/null || true
  wait "$NR_PID" 2>/dev/null || true
}
trap reap_host EXIT INT TERM

# 4. Wait up to 15s for the readiness line.
i=0
while [ "$i" -lt 150 ]; do
  if grep -q "^LISTENING $EC_PORT" /tmp/nr.out 2>/dev/null; then break; fi
  if ! kill -0 "$NR_PID" 2>/dev/null; then
    echo "node-red exited before LISTENING:" >&2; cat /tmp/nr.err >&2; cat /tmp/nr.out >&2; exit 1
  fi
  i=$((i + 1)); sleep 0.1
done
grep "^LISTENING $EC_PORT" /tmp/nr.out | head -1

# 5. Run the oracle.
if [ "$#" -eq 0 ]; then
  set -- -profile core -json-out "${JSON_OUT:-/tmp/ec-s4-node-red.json}"
fi
. /work/protocol-generator/shared/tools/refpeer.sh
refpeer_up
"$ORACLE" -addr "127.0.0.1:$EC_PORT" $REFPEER_FLAG "$@" || true

# SURFACE THE STDERR OF THE PEER ITSELF. /tmp/nr.err is a path INSIDE a --rm
# container, so without this the dying words of the peer are discarded with the
# container and a mid-run abort leaves a log reading only "connection refused".
# That is not hypothetical: the zig intermittent survived four investigations
# reported as "no crash, empty stderr" until this line existed on that harness,
# and then produced a stack trace on the first reproduction. Emitted on stderr so
# it cannot be mistaken for oracle output, and only when non-empty so a clean run
# stays quiet.
if [ -s /tmp/nr.err ]; then
  echo "--- peer stderr (/tmp/nr.err) ---" >&2
  cat /tmp/nr.err >&2
fi
