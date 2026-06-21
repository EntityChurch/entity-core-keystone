/**
 * L2/L4 transport — TCP framing, the §6.11 reentrant connection demux (N6/N7), the
 * §4.1 handshake, and the authenticated session surface. The one Node-coupled
 * corner (`node:net`); the codec/crypto layers below stay browser-portable.
 */

export * from "./frame-codec.js";
export * from "./reentrant-sender.js";
export * from "./peer-connection.js";
export * from "./peer-session.js";
export * from "./handshake.js";
