/**
 * Foundation — the handler interface contract (`HandlerContext`, registration,
 * dispatch index) plus the three bootstrap handlers: connect (§4), tree (§6.3),
 * and capability (§6.2). Concrete domain handlers are community-installed above
 * this boundary.
 */

export * from "./handler-abstractions.js";
export * from "./connection-state.js";
export * from "./errors.js";
export * from "./handler-registry.js";
export * from "./connect-handler.js";
export * from "./handlers-handler.js";
export * from "./tree-handler.js";
export * from "./capability-handler.js";
export * from "./conformance-handlers.js";
