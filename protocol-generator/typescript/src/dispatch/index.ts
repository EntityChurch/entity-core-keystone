/**
 * The §6.5 dispatch chain — the protocol heart that composes integrity
 * verification, the deterministic Layer-1 capability verdict, and handler
 * execution into an EXECUTE_RESPONSE.
 */

export * from "./dispatcher.js";
export * from "./outbound-dispatch.js";
// Explicit, not `export *`: `claimDispatchContextFactory` and `DispatchContextState` stay
// off the package surface — the factory is the only way to build a context, and the
// dispatcher claims it as it loads (keystone peer contract `context.unforgeable`).
export {
  ContextForgeryError,
  DispatchContext,
  type LocalExecute,
  MAX_LOCAL_DISPATCH_DEPTH,
} from "./dispatch-context.js";
