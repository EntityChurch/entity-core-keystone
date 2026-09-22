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
  # Build/install only if MISSING (online; needs network on first run). Avoids the
  # `npm ci --offline` foot-gun (it wipes node_modules then fails on an incomplete cache).
  if [ ! -f "$TS/dist/src/index.js" ] || [ ! -d "$TS/node_modules/@noble" ]; then
    (cd "$TS" && npm install --no-audit --no-fund >/dev/null 2>&1 && ./node_modules/.bin/tsc -p tsconfig.json) \
      || { echo "ERROR: TS codec build failed (network needed on first run)" >&2; exit 1; }
  fi
  if [ ! -x "$NR/node_modules/.bin/node-red" ]; then
    (cd "$NR" && npm install --no-audit --no-fund >/dev/null 2>&1) \
      || { echo "ERROR: Node-RED install failed (network needed on first run)" >&2; exit 1; }
  fi
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
trap 'kill "$NR_PID" 2>/dev/null || true' EXIT INT TERM

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
  set -- -profile core -json-out "$NR/../status/CONFORMANCE-REPORT.json"
fi
"$ORACLE" -addr "127.0.0.1:$EC_PORT" "$@" || true
