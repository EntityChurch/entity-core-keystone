/**
 * Node-RED settings for the entity-core peer (headless conformance host + editor).
 *
 * The codec-bridge (the DELEGATED half — the compiled TS peer's codec/crypto/model)
 * is loaded once here into functionGlobalContext, so every authored node reaches it
 * as `global.get("ec")`. This is the single interop seam; everything else is graph.
 */
const path = require("node:path");

let ec;
try {
  ec = require(path.join(__dirname, "lib", "codec-bridge.js"));
  // Share the per-connection session registry with the flow (nodes look sessions
  // up by msg.conn — a string — since Node-RED clones msg and would break a
  // session object carried on it).
  ec.sessions = require(path.join(__dirname, "lib", "session.js")).sessions;
} catch (e) {
  // Surface a clear message if the TS peer isn't built (run-s4.sh builds it first).
  console.error("[entity-core] codec-bridge failed to load — is the TS peer built (dist/)?", e && e.message);
  throw e;
}

module.exports = {
  // Headless: no periodic flow file writes fighting the read-only mounted tree,
  // admin API on a loopback port distinct from the PEER's protocol port.
  uiPort: process.env.NR_ADMIN_PORT ? Number(process.env.NR_ADMIN_PORT) : 1880,
  // 127.0.0.1 by default (headless conformance host); 0.0.0.0 for the editor
  // launcher so a host browser can reach the published admin port.
  uiHost: process.env.NR_ADMIN_HOST || "127.0.0.1",
  flowFile: "flows.json",
  flowFilePretty: true,
  // The authored custom nodes (ec-listener, ec-decode, ec-dispatch, handlers, …).
  nodesDir: [path.join(__dirname, "nodes")],
  // Do not require editor auth in the headless conformance host (loopback only).
  disableEditor: process.env.NR_HEADLESS === "1",
  logging: {
    console: { level: process.env.NR_LOG || "info", metrics: false, audit: false },
  },
  // THE interop seam: the delegated codec/crypto/model, reachable from any node.
  functionGlobalContext: {
    ec,
  },
  // The peer's protocol TCP port (authored transport reads this).
  entityCore: {
    port: process.env.EC_PORT ? Number(process.env.EC_PORT) : 7801,
    peerName: process.env.PEERNAME || "conformance",
    validate: process.env.EC_VALIDATE !== "0",
    // Conformance-host parity with the TS run-s4 (`host … --debug-open-grants`):
    // the degenerate default→* seed policy so capability checks don't 403 before
    // handlers run. Off in a production peer (standard §4.4 discovery-floor policy).
    debugOpenGrants: process.env.EC_DEBUG_OPEN_GRANTS === "1",
  },
  exportGlobalContextKeys: false,
  externalModules: {},
};
