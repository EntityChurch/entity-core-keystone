import { Entity, Ecf, Status, TypeNames, ResourceTarget } from "../model/index.js";
import { ecfPreEncoded } from "../codec/ecf-value.js";
import { CapabilityToken } from "../capability/index.js";
import {
  type Handler,
  type HandlerContext,
  type OutboundAuthority,
  HandlerResult,
} from "./handler-abstractions.js";
import { errorResult } from "./errors.js";

/**
 * The `system/validate/*` conformance test-handlers (GUIDE-CONFORMANCE §7a).
 *
 * These are **not core protocol** — they are conformance scaffolding, present only in a
 * peer's conformance build (opt-in via the `conformanceHandlers` peer option, surfaced as
 * the host `--validate` switch), off by default. They give a black-box validator a native,
 * compute-free way to drive the two extensibility hooks that have no other wire-reachable
 * trigger in a core-only peer: `echo` (the §6.13(a) resolve→dispatch half, closing A-011)
 * and `dispatch-outbound` (the §6.13(b)/§6.11 outbound seam via reentry, closing A-013).
 */

export const ConformancePatterns = {
  echo: "system/validate/echo",
  dispatchOutbound: "system/validate/dispatch-outbound",
} as const;

/**
 * §7a `system/validate/echo`. EXECUTE returns the params entity verbatim (the literal value
 * carried in params round-trips out). Native body, no compute — the portable replacement
 * for the A-011 `compute/literal` dispatch step.
 */
export class ValidateEchoHandler implements Handler {
  readonly pattern = ConformancePatterns.echo;
  readonly name = "validate-echo";
  readonly operations: readonly string[] = ["echo"];

  handle(ctx: HandlerContext): Promise<HandlerResult> {
    return Promise.resolve(HandlerResult.ok(ctx.params));
  }
}

/**
 * §7a `system/validate/dispatch-outbound`. EXECUTE originates exactly one outbound EXECUTE —
 * via the §6.13(b) handler-reachable outbound closure (`ctx.outbound`, the §6.11 reentry
 * sender) — back to the calling peer, invoking `operation` on the `target` pattern with the
 * carried `value`, and returns that downstream response. Proves the target can *originate*,
 * not just respond.
 *
 * The reentry direction (this peer → caller) can only be authorized by the caller, so the
 * caller carries the capability it minted for this peer in the params (the three authority
 * entities, each embedded as a nested entity).
 */
export class ValidateDispatchOutboundHandler implements Handler {
  readonly pattern = ConformancePatterns.dispatchOutbound;
  readonly name = "validate-dispatch-outbound";
  readonly operations: readonly string[] = ["dispatch"];

  async handle(ctx: HandlerContext): Promise<HandlerResult> {
    if (ctx.outbound === null) {
      return errorResult(
        Status.ServiceUnavailable,
        "no_outbound_seam",
        "dispatch-outbound requires a live §6.11 reentry connection (handler was not dispatched over a connection)",
      );
    }

    const p = ctx.params.data;
    const target = Ecf.requireText(p, "target"); // handler pattern at the caller, e.g. system/validate/echo
    const operation = Ecf.requireText(p, "operation"); // operation there, e.g. echo
    const value = Ecf.require(p, "value"); // value to round-trip

    // The caller-minted reentry authority (this peer is the grantee), carried in-band.
    const cap = new CapabilityToken(Entity.fromDecoded(Ecf.require(p, "reentry_capability")));
    const granter = Entity.fromDecoded(Ecf.require(p, "reentry_granter"));
    const capSig = Entity.fromDecoded(Ecf.require(p, "reentry_cap_signature"));
    const authority: OutboundAuthority = { capability: cap, granterPeer: granter, capabilitySignature: capSig };

    // §7a.1: the `value` field IS the outbound params entity data — pass it through
    // (the reference uses it directly). Re-wrapping as {"value": value} double-wraps,
    // so the echo's result.value returns a map (keystone §7b t1_2).
    const inner = Entity.create(TypeNames.PrimitiveAny, value);
    const resource = new ResourceTarget(["system/handler/" + target], null);

    const downstream = await ctx.outbound.execute(target, operation, inner, resource, authority, 10000);

    const result = Entity.create(
      TypeNames.PrimitiveAny,
      Ecf.map(["status", Ecf.uint(BigInt(downstream.statusCode))], ["result", ecfPreEncoded(downstream.result.wireBytes)]),
    );
    return HandlerResult.ok(result);
  }
}
