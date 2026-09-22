import { Status } from "../model/index.js";
import { type Handler, type HandlerContext, type HandlerOperations, type HandlerResult } from "./handler-abstractions.js";
import { errorResult } from "./errors.js";
import { type HandlerBody, type HandlerSpec } from "./handler-install.js";

/**
 * The dispatch-index entry for a handler installed by `Peer.registerHandler(spec, body)`.
 *
 * Deliberately NOT re-exported from the package: it is how the dispatcher recognises a
 * body that must receive a dispatcher-built `DispatchContext` rather than the legacy
 * `HandlerContext`. It implements {@link Handler} only so the registry's existing
 * `native` slot and every reader of it (resolution, a `res.native !== null` check) keep
 * working unchanged.
 */
export class SpecRegistration implements Handler {
  readonly pattern: string;
  readonly name: string;
  readonly operations: HandlerOperations;

  constructor(
    spec: HandlerSpec,
    readonly body: HandlerBody,
    readonly generation: number,
  ) {
    this.pattern = spec.pattern;
    this.name = spec.name;
    this.operations = spec.operations;
  }

  /**
   * Reached only by code that runs a registered body outside the dispatcher with a
   * hand-built legacy context. That is not an execution this body accepts.
   */
  handle(_ctx: HandlerContext): Promise<HandlerResult> {
    return Promise.resolve(
      errorResult(Status.InternalError, "internal_error", "a registerHandler(spec, body) body runs only under the dispatcher"),
    );
  }
}
