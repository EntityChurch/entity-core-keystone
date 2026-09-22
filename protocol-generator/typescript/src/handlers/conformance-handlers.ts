import { Entity, Ecf, Status, TypeNames, ResourceTarget } from "../model/index.js";
import { ecfPreEncoded } from "../codec/ecf-value.js";
import { CapabilityToken } from "../capability/index.js";
import * as Capability from "../capability/permissions.js";
import * as Paths from "../capability/paths.js";
import { verifyCapabilityChain } from "../capability/chain-verifier.js";
import { Envelope } from "../model/index.js";
import { peerEntityId } from "../identity/index.js";
import { Scope } from "../capability/scope.js";
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
        "dispatch-outbound requires a live section 6.11 reentry connection (handler was not dispatched over a connection)",
      );
    }

    const p = ctx.params.data;
    const target = Ecf.requireText(p, "target"); // handler pattern at the caller, e.g. system/validate/echo
    const operation = Ecf.requireText(p, "operation"); // operation there, e.g. echo
    const value = Ecf.require(p, "value"); // value to round-trip

    // GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
    // single-granter case is an array of ONE. They were singular, which made §1.4's
    // multi-signature-root rule ungateable on the wire: driving it needs two granter
    // identities and two signatures, and a single-credential carrier cannot express
    // that input.
    //
    // TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
    // because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle is
    // what all 46 tracked reports are measured against and it sends the SINGULAR
    // names; a plural-only peer reads the triple as absent there, takes the ambient
    // arm and refuses — measured on the `go` vanguard as 2 of 778 severities moving
    // PASS -> FAIL. Accepting both keeps the cohort 0-FAIL at BOTH check sets.
    // REMOVE THIS FALLBACK AT THE ORACLE RE-PIN, and not before: the exit condition is
    // that `tools/oracle-pin.env`'s `ref` names an oracle whose dispatch-outbound probe
    // sends the plural carriers.
    const entityList = (key: string, singular: string): Entity[] | null => {
      const arr = Ecf.field(p, key);
      if (arr !== null) {
        // An array whose members do not all decode is a MALFORMED carrier and is null,
        // never a silently shorter list — the all-or-none test below would otherwise
        // read a partial credential as a complete one.
        try {
          return Ecf.asArray(arr).map((v) => Entity.fromDecoded(v));
        } catch {
          return null;
        }
      }
      const one = Ecf.field(p, singular);
      if (one === null) return null;
      try {
        return [Entity.fromDecoded(one)];
      } catch {
        return null;
      }
    };
    const capField = Ecf.field(p, "reentry_capability");
    const capEnt = capField === null ? null : Entity.fromDecoded(capField);
    const granters = entityList("reentry_granters", "reentry_granter");
    const capSigs = entityList("reentry_cap_signatures", "reentry_cap_signature");
    // The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED arm,
    // all three absent selects the AMBIENT arm, and a PARTIAL set is 400 invalid_params
    // — a partial credential is malformed, not ambient. An empty array is partial, not
    // present: it carries no credential.
    const nPresent = [capEnt !== null, (granters?.length ?? 0) > 0, (capSigs?.length ?? 0) > 0].filter(Boolean).length;
    if (nPresent !== 0 && nPresent !== 3) {
      return errorResult(Status.BadRequest, "invalid_params", "dispatch-outbound reentry authority is all-or-none");
    }
    const hasCred = nPresent === 3;
    const cred = hasCred && capEnt !== null ? new CapabilityToken(capEnt) : null;
    const authority: OutboundAuthority | null =
      cred === null
        ? null
        : { capability: cred, granterPeers: granters ?? [], capabilitySignatures: capSigs ?? [] };

    // §7a.1: the `value` field IS the outbound params entity data — pass it through
    // (the reference uses it directly). Re-wrapping as {"value": value} double-wraps,
    // so the echo's result.value returns a map (keystone §7b t1_2).
    const inner = Entity.create(TypeNames.PrimitiveAny, value);
    // `target` arrives as any of §1.4's three spellings and the validator sends the
    // SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the resource target
    // want the PEER-RELATIVE path — §1.4's PD-2 block says so for Dimension 1, and a
    // resource target carrying a scheme is not a path at all.
    const relTarget = Capability.peerRelativeOf(target);
    const resource = new ResourceTarget(["system/handler/" + relTarget], null);

    // §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer, all four
    // dimensions, on THIS handler's own grant — with a target-minted credential relaxing
    // Dimension 4 and nothing else. Consulting only the presented credential here is the
    // §6.8 confused-deputy bypass.
    if (!authorizeOutboundSubDispatch(ctx, relTarget, operation, resource, cred, granters ?? [], capSigs ?? [])) {
      // §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
      // transport- or gateway-class code would launder an authorization verdict into a
      // route fault, and the ambient and presented branches would then disagree about
      // what the same gate decided.
      return errorResult(
        Status.Forbidden,
        "capability_denied",
        "outbound sub-dispatch not authorized by the handler grant",
      );
    }

    const downstream = await ctx.outbound.execute(target, operation, inner, resource, authority, 10000);

    const result = Entity.create(
      TypeNames.PrimitiveAny,
      Ecf.map(["status", Ecf.uint(BigInt(downstream.statusCode))], ["result", ecfPreEncoded(downstream.result.wireBytes)]),
    );
    return HandlerResult.ok(result);
  }
}

/**
 * §1.4's PD-2 gate, wired to this peer's store: resolve the executing handler's OWN
 * grant, verify a presented credential in the TARGET's frame, and run the four-dimension
 * check.
 *
 * §7a.2a: the credential, its granters and its signatures arrive NESTED IN PARAMS
 * (ratified shape (a), in-band), so they are NOT in `ctx.envelope.included` and a
 * verifier handed that alone cannot resolve a single link — every credential then reads
 * as invalid and the legitimate reentry is refused. The bundle merges them in.
 *
 * ⚠ `Envelope` keys `included` by content-hash HEX. Building the merged bundle through
 * the constructor is what keeps that true: a hand-built map keyed by anything else puts
 * entries in that `find()` cannot see, and the credential then reads as unresolvable —
 * which the WIRE CANNOT DETECT, because the validator also carries the credential in the
 * parent envelope and the gate would be working off a copy we did not put there. That is
 * exactly how the python vanguard passed with a mis-keyed bundle.
 */
function authorizeOutboundSubDispatch(
  ctx: HandlerContext,
  relTarget: string,
  operation: string,
  resource: ResourceTarget,
  cred: CapabilityToken | null,
  granters: readonly Entity[],
  capSigs: readonly Entity[],
): boolean {
  const local = ctx.peer.localPeerId;
  // §6.8: a handler with no valid grant does not run. Fail closed rather than falling
  // back to the credential, which is the substitution §6.8 forbids. `ctx.handlerGrant`
  // is the grant §6.5 already resolved for this dispatch — used rather than a fresh
  // store read, so the handler-level check runs against the SAME authority the dispatch
  // check resolved.
  const ownGrant =
    ctx.handlerGrant ??
    (() => {
      const e = ctx.peer.tree.get(Capability.grantPathFor(local, ctx.pattern));
      return e === undefined ? null : new CapabilityToken(e);
    })();
  if (ownGrant === null) return false;

  // §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the
  // absolute form, so the URI names the target. Where the uri is PEER-RELATIVE there is
  // no peer in it and the §6.11 seam's destination is the connection's remote, so that
  // is the fallback — without it Dimension 4 passes vacuously on the default
  // {include: [local]} and the exemption is never exercised.
  const uriPeer = Paths.extractPeer(ctx.execute.uri, local);
  const targetPeer = uriPeer === local ? (ctx.connection?.remotePeerId ?? uriPeer) : uriPeer;

  let relaxTo: Scope | null = null;
  if (cred !== null && targetPeer !== local) {
    const bundle = new Envelope(ctx.envelope.root, [
      ...ctx.envelope.included.values(),
      cred.entity,
      ...granters,
      ...capSigs,
    ]);
    // Every clause is required and failing any relaxes NOTHING: the chain ROOT granter
    // resolves to the TARGET peer and is NOT a multi-signature root; the LEAF grantee is
    // this peer; the chain is valid and not revoked.
    if (verifyCapabilityChain(cred, bundle, local, BigInt(Date.now()), targetPeer)) {
      const grantee = bundle.find(cred.grantee);
      const revokedPath =
        "/" + local + "/system/capability/revocations/" + cred.contentHashHex;
      const revoked = ctx.peer.tree.get(revokedPath) !== undefined;
      if (!revoked && grantee !== undefined && peerEntityId(grantee) === local) {
        // The credential's own `peers` scope is what Dimension 4 relaxes TO. Absent
        // means the granter — the target peer — which is the ordinary reentry shape:
        // "you may dispatch back to me."
        const first = cred.grants[0];
        if (first !== undefined) relaxTo = first.peers ?? new Scope([targetPeer], null);
      }
    }
  }

  return Capability.checkOutboundSubDispatch(
    ownGrant,
    local,
    targetPeer,
    relTarget,
    operation,
    resource,
    relaxTo,
  );
}
