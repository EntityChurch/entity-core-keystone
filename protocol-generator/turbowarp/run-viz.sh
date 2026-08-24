#!/bin/sh
# run-viz.sh — the visualization "pass-through": serve the custom extension + run the
# WS↔TCP bridge, so you can load the peer into the TurboWarp editor and WATCH the
# protocol run on the stage. Optionally loops the oracle to generate live traffic.
#
# Run from the repo root (network for the one-time build; publish the ports):
#   podman run --rm --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 \
#     -p 8601:8601 -p 7802:7802 -p 7801:7801 -v "$PWD":/work:Z -v kc-npm:/root/.npm \
#     entity-core-keystone/node24:latest sh /work/protocol-generator/turbowarp/run-viz.sh
#
# ⚠ BROWSER LOCAL-NETWORK-ACCESS (LNA) BLOCK — read this first:
#   A public HTTPS site (https://turbowarp.org) reaching http/ws on localhost is now
#   blocked by default (Firefox LNA "auto_deny"; Chrome PNA). This gates BOTH the
#   extension fetch (:8601) AND the bridge WebSocket (:7802), so loading the extension
#   from a local FILE does not help — the ws://localhost:7802 connect is still denied.
#   Two ways through (pick one):
#
#   (A) RECOMMENDED — TurboWarp Desktop app (https://desktop.turbowarp.org): it is not a
#       public origin, so LNA never applies; localhost + unsandboxed extensions just work.
#       Same steps below, no browser toggle. Best for repeat use.
#   (B) QUICK — allow localhost in Firefox: about:config → set  network.lna.blocking = false
#       (keeps LNA enabled but stops the auto-deny; or network.lna.enabled = false to turn
#       it off). This relaxes a security feature for ALL sites — flip it back when done.
#       (Chrome: enable "Insecure private network requests" for the site, or use the desktop app.)
#
# Then, in the TurboWarp editor (desktop app OR browser after the toggle):
#   1. open the editor (desktop app, or https://turbowarp.org)
#   2. Add Extension (bottom-left) → "Custom Extension" → "URL" →
#        http://localhost:8601/ecutils.js   (choose "unsandboxed" — it needs WebSocket)
#      (must be the literal host "localhost" — 127.0.0.1 / 0.0.0.0 are rejected by TurboWarp)
#   3. build a tiny script (see BLOCK-DESIGN.md), e.g.:
#        when green flag clicked → [start peer, connect to bridge ws://localhost:7802]
#        forever → set stage text to (peer id) / (open connections) / (last dispatched path)
#   4. with TRAFFIC=1 the oracle hits the peer in a loop → watch the reporters move.

set -eu

EC_PORT="${EC_PORT:-7801}"; WS_PORT="${WS_PORT:-7802}"; HTTP_PORT="${HTTP_PORT:-8601}"
TW="/work/protocol-generator/turbowarp/src"; TS="/work/protocol-generator/typescript"

# Build/install only if MISSING (online; needs network on the FIRST run — the kc-npm
# volume caches it after). NOT `npm ci --offline` (it wipes node_modules then fails).
if [ ! -f "$TS/dist/src/index.js" ] || [ ! -d "$TS/node_modules/@noble" ]; then
  echo "building the delegated TypeScript codec (first run; needs network) …"
  (cd "$TS" && npm install --no-audit --no-fund && ./node_modules/.bin/tsc -p tsconfig.json) \
    || { echo "ERROR: TS codec build failed (network needed on first run)" >&2; exit 1; }
fi
if [ ! -d "$TW/node_modules/esbuild" ]; then
  echo "installing esbuild + ws (first run; needs network) …"
  (cd "$TW" && npm install --no-audit --no-fund) \
    || { echo "ERROR: turbowarp deps install failed (network needed on first run)" >&2; exit 1; }
fi
# (Re)build the browser core, the `ecutils` utility-seam extension, and the .sb3 (whose
# blocks ARE the §6.5 dispatch) — fast, offline, deterministic.
(cd "$TW" && npm run bundle >/dev/null 2>&1 && npm run bundle:utils >/dev/null 2>&1 && npm run bundle:sb3 >/dev/null 2>&1) \
  || { echo "ERROR: bundle/utils/sb3 build failed" >&2; exit 1; }

cd "$TW"
# Static server for the extension (CORS-open so turbowarp.org can fetch it).
node -e '
  const http=require("http"), fs=require("fs"), path=require("path");
  const port='"$HTTP_PORT"';
  http.createServer((req,res)=>{
    res.setHeader("Access-Control-Allow-Origin","*");
    const f=path.join("dist", path.basename(req.url.split("?")[0]||"ecutils.js"));
    fs.readFile(f,(e,b)=>{ if(e){res.statusCode=404;res.end("not found");} else {res.setHeader("Content-Type","text/javascript");res.end(b);} });
  }).listen(port,"0.0.0.0",()=>console.log("EXTENSION served at http://localhost:"+port+"/ecutils.js"));
' &
HTTP=$!

# Bridge.
EC_PORT="$EC_PORT" WS_PORT="$WS_PORT" node bridge/ws-tcp-bridge.js &
BR=$!
trap 'kill "$HTTP" "$BR" "${TR:-0}" 2>/dev/null || true' EXIT INT TERM

echo ""
echo "  ⚠ localhost from a public HTTPS site is blocked by default (Firefox LNA / Chrome PNA)."
echo "    This blocks the ws://localhost:$WS_PORT bridge too — loading from a file won't help."
echo "    → EASIEST: use the TurboWarp DESKTOP app (desktop.turbowarp.org) — no browser policy."
echo "    → OR in Firefox about:config set  network.lna.blocking = false  (revert when done)."
echo ""
echo "  → in the editor: Add Extension → Custom → URL:"
echo "       http://localhost:$HTTP_PORT/ecutils.js   (unsandboxed; host must be 'localhost')"
echo "  → then File → Load from your computer → protocol-generator/turbowarp/src/project/"
echo "       entity-core-peer.sb3   (the ready-made stage; green flag → it connects + shows)"
echo "     (or build the blocks yourself per BLOCK-DESIGN.md; connect to ws://localhost:$WS_PORT)"
echo ""

# Optional live traffic so the stage moves.
if [ "${TRAFFIC:-0}" = "1" ]; then
  ( while true; do /work/output/s4-oracles/validate-peer -addr "127.0.0.1:$EC_PORT" -category connectivity >/dev/null 2>&1 || true; sleep 3; done ) &
  TR=$!
  echo "  (TRAFFIC=1: oracle connectivity looping every 3s — the stage reporters will move)"
fi

# Keep the servers up.
wait "$BR"
