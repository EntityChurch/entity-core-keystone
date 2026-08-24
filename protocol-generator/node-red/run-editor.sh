#!/bin/sh
# run-editor.sh — launch the Node-RED peer WITH the browser editor, so you can SEE
# and interact with the flow-graph (the visual "pass-through" the operator asked for).
#
# Unlike run-s4.sh (headless conformance host), this enables the editor and binds the
# admin UI to 0.0.0.0 so a host browser reaches the published port. The peer's protocol
# port (EC_PORT) also listens — you can point a client / the oracle at it while watching
# the flow in the browser.
#
# Run from the repo root (note: NOT --network=none, and publish the admin port):
#   podman run --rm --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 \
#     -p 1880:1880 -p 7801:7801 -v "$PWD":/work:Z \
#     entity-core-keystone/node24:latest sh /work/protocol-generator/node-red/run-editor.sh
#
# Then open http://localhost:1880 in your browser:
#   • the "entity-core peer" tab shows the graph (transport → classify demux → dispatch/
#     reentry). Double-click any function node to read/edit its code.
#   • drag a Debug node onto a wire + Deploy to watch live msgs (each carries CBOR bytes).
#   • the peer is live on :7801 — run `run-s4.sh -category connectivity` against it (or the
#     TS peer as a client) and watch frames flow through the nodes in real time.

set -eu

EC_PORT="${EC_PORT:-7801}"
NR_ADMIN_PORT="${NR_ADMIN_PORT:-1880}"
NR="/work/protocol-generator/node-red/src"
TS="/work/protocol-generator/typescript"
PEERNAME="${PEERNAME:-conformance}"

# Build the delegated TS codec + install Node-RED only if MISSING. Uses `npm install`
# (online — needs network on the FIRST run; the kc-npm volume caches it thereafter).
# NOT `npm ci --offline`, which wipes node_modules then fails on an incomplete cache.
if [ ! -f "$TS/dist/src/index.js" ] || [ ! -d "$TS/node_modules/@noble" ]; then
  echo "building the delegated TypeScript codec (first run; needs network) …"
  (cd "$TS" && npm install --no-audit --no-fund && ./node_modules/.bin/tsc -p tsconfig.json) \
    || { echo "ERROR: TypeScript codec build failed — is network available on this first run?" >&2; exit 1; }
fi
if [ ! -x "$NR/node_modules/.bin/node-red" ]; then
  echo "installing Node-RED (first run; needs network) …"
  (cd "$NR" && npm install --no-audit --no-fund) \
    || { echo "ERROR: Node-RED install failed — is network available on this first run?" >&2; exit 1; }
fi

# Provision a peer identity (so a client can complete a real handshake while you watch).
KPDIR="${HOME:-/root}/.entity/peers/$PEERNAME"
mkdir -p "$KPDIR"
printf '%s\n%s\n%s\n' \
  '-----BEGIN ENTITY PRIVATE KEY-----' \
  'ERERERERERERERERERERERERERERERERERERERERERE=' \
  '-----END ENTITY PRIVATE KEY-----' > "$KPDIR/keypair"

cd "$NR"
echo "Node-RED editor → http://localhost:${NR_ADMIN_PORT}   (peer protocol port ${EC_PORT})"
# Editor ENABLED (NR_HEADLESS unset), admin UI on 0.0.0.0, debug-open-grants for a live demo.
EC_VALIDATE=1 EC_DEBUG_OPEN_GRANTS="${EC_DEBUG_OPEN_GRANTS:-1}" \
  EC_PORT="$EC_PORT" NR_ADMIN_PORT="$NR_ADMIN_PORT" NR_ADMIN_HOST=0.0.0.0 \
  PEERNAME="$PEERNAME" NR_LOG="${NR_LOG:-info}" \
  exec node_modules/.bin/node-red --userDir "$NR" --settings "$NR/settings.js" flows.json
