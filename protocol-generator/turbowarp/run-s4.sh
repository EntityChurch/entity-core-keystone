#!/bin/sh
# S4 harness — entity-core-protocol-turbowarp (peer #32) via the WS↔TCP bridge.
#
# Proves the SANDBOXED-peer-via-bridge architecture against the real Go oracle,
# headless: the peer harness (ec-peer-node — the stand-in for the Scratch extension,
# using the SAME browser-bundle core) connects OUT over WebSocket to the bridge, which
# listens on TCP for the oracle. This is the optional oracle-gate path from PHASE-S1
# (default scope is visualization-first).
#
# Run from repo root (network for the one-time bundle install; then loopback only):
#   podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm \
#     -v "$PWD":/work:Z -v kc-npm:/root/.npm entity-core-keystone/node24:latest \
#     sh /work/protocol-generator/turbowarp/run-s4.sh [validate-peer-args...]

set -eu

EC_PORT="${EC_PORT:-7801}"
WS_PORT="${WS_PORT:-7802}"
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
PEERNAME="${PEERNAME:-conformance}"
TW="/work/protocol-generator/turbowarp/src"
TS="/work/protocol-generator/typescript"

if [ "${NOBUILD:-0}" != "1" ]; then
  # Build/install only if MISSING (online; network needed on first run). Not `npm ci
  # --offline` (wipes node_modules then fails on an incomplete cache).
  if [ ! -f "$TS/dist/src/index.js" ] || [ ! -d "$TS/node_modules/@noble" ]; then
    (cd "$TS" && npm install --no-audit --no-fund >/dev/null 2>&1 && ./node_modules/.bin/tsc -p tsconfig.json) \
      || { echo "ERROR: TS codec build failed (network needed on first run)" >&2; exit 1; }
  fi
  if [ ! -d "$TW/node_modules/esbuild" ]; then
    (cd "$TW" && npm install --no-audit --no-fund >/dev/null 2>&1) \
      || { echo "ERROR: turbowarp deps install failed (network needed on first run)" >&2; exit 1; }
  fi
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
trap 'kill "$BR" "${PEER:-0}" 2>/dev/null || true' EXIT INT TERM
i=0; while [ "$i" -lt 100 ]; do grep -q "^BRIDGE-LISTENING" /tmp/bridge.out 2>/dev/null && break; kill -0 "$BR" 2>/dev/null || { echo "bridge died:"; cat /tmp/bridge.out; exit 1; }; i=$((i+1)); sleep 0.1; done

# 2. Peer harness (connects OUT to the bridge over WS; the Scratch-extension stand-in).
WS_URL="ws://127.0.0.1:$WS_PORT" node harness/ec-peer-node.js >/tmp/peer.out 2>&1 &
PEER=$!
i=0; while [ "$i" -lt 100 ]; do grep -q "^PEER-CONNECTED" /tmp/bridge.out 2>/dev/null && break; kill -0 "$PEER" 2>/dev/null || { echo "peer died:"; cat /tmp/peer.out; exit 1; }; i=$((i+1)); sleep 0.1; done
echo "BRIDGE + PEER up (tcp:$EC_PORT ws:$WS_PORT)"

# 3. Oracle.
if [ "$#" -eq 0 ]; then set -- -profile core -json-out "$TW/../status/CONFORMANCE-REPORT.json"; fi
"$ORACLE" -addr "127.0.0.1:$EC_PORT" "$@" || true
