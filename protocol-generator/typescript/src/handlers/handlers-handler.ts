import { type EcfValue } from "../codec/ecf-value.js";
import { Entity, Ecf, Status, TypeNames } from "../model/index.js";
import { CapabilityToken, GrantEntry } from "../capability/index.js";
import { type Handler, type HandlerContext, HandlerResult } from "./handler-abstractions.js";
import { errorResult } from "./errors.js";

/**
 * The handlers handler at `system/handler` (V7 §6.2). Manages handler lifecycle over
 * the wire: `register` installs a handler (the five normative writes), `unregister`
 * removes it (reversing all five). Behavioral presence is a v7.74 §6.13(a) MUST — a
 * `501` on either op from a `--profile core` peer is non-conformant.
 *
 * Authorization rides the standard dispatch boundary (B1 / V2.0/L1): the caller's
 * capability is cap-checked against the `EXECUTE.resource` install path before the body
 * runs — no separate cap-check path. The peer-owner cap (§6.9a) satisfies it vacuously.
 */
export class HandlersHandler implements Handler {
  readonly pattern = "system/handler";
  readonly name = "handler";
  readonly operations: readonly string[] = ["register", "unregister"];

  async handle(ctx: HandlerContext): Promise<HandlerResult> {
    switch (ctx.operation) {
      case "register":
        return this.#register(ctx);
      case "unregister":
        return this.#unregister(ctx);
      default:
        return errorResult(Status.NotSupported, "unsupported_operation", `unknown handlers-handler operation '${ctx.operation}'`);
    }
  }

  /**
   * `register` (§6.2 / §6.13(a)): execute the five normative writes for the handler
   * whose install path is `EXECUTE.resource.targets[0]` (`system/handler/{pattern}`).
   */
  #register(ctx: HandlerContext): HandlerResult {
    const patternOrErr = patternFromResource(ctx);
    if (typeof patternOrErr !== "string") {
      return patternOrErr;
    }
    const pattern = patternOrErr;
    if (ctx.params.type !== TypeNames.HandlerRegisterRequest) {
      return errorResult(Status.BadRequest, "invalid_params", `register expects a ${TypeNames.HandlerRegisterRequest} (got '${ctx.params.type}')`);
    }

    const req = ctx.params.data;
    const manifest = Ecf.require(req, "manifest");
    const name = Ecf.optText(manifest, "name") ?? pattern;
    const operations = Ecf.field(manifest, "operations") ?? Ecf.emptyMap();
    const expressionPath = Ecf.optText(manifest, "expression_path");
    const maxScope = Ecf.field(manifest, "max_scope");
    const internalScope = Ecf.field(manifest, "internal_scope");

    // Grant scope = requested_scope ?? internal_scope ?? [] (§6.2 grant issuance).
    const grantScopeEcf = Ecf.field(req, "requested_scope") ?? internalScope;
    const grantScope = grantScopeEcf === null ? [] : Ecf.asArray(grantScopeEcf).map((g) => GrantEntry.fromEcf(g));

    const interfaceRelPath = "system/handler/" + pattern;

    // (1) Handler manifest (dispatch target) at the pattern path {pattern}.
    const handlerEntity = Entity.create(
      TypeNames.Handler,
      Ecf.map(
        ["interface", Ecf.text(interfaceRelPath)],
        ["max_scope", maxScope],
        ["internal_scope", internalScope],
        ["expression_path", expressionPath === null ? null : Ecf.text(expressionPath)],
      ),
    );

    // (3) Self-issued, signed handler grant at system/capability/grants/{pattern}.
    const local = ctx.peer.localIdentity;
    const { token: grant, signature: grantSig } = CapabilityToken.createRoot(local, local.identityHash, grantScope, ctx.peer.nowMs);

    // (5) Handler interface entity (discovery index) at system/handler/{pattern}.
    const ifaceEntity = Entity.create(
      TypeNames.HandlerInterface,
      Ecf.map(["pattern", Ecf.text(pattern)], ["name", Ecf.text(name)], ["operations", operations]),
    );

    // The five writes (§6.2 / §6.13(a)). Order per the §6.2 inventory.
    ctx.peer.tree.put(abs(ctx, pattern), handlerEntity); // 1. manifest
    installTypes(ctx, req); // 2. types
    ctx.peer.tree.put(abs(ctx, "system/capability/grants/" + pattern), grant.entity); // 3. grant
    ctx.peer.tree.put(abs(ctx, "system/signature/" + grant.contentHashHex), grantSig); // 4. grant-signature
    ctx.peer.tree.put(abs(ctx, interfaceRelPath), ifaceEntity); // 5. interface

    const result = Entity.create(
      TypeNames.HandlerRegisterResult,
      Ecf.map(["pattern", Ecf.text(pattern)], ["grant", grant.entity.data]),
    );
    return HandlerResult.ok(result);
  }

  /**
   * `unregister` (§6.2): reverse all five register writes for the pattern in
   * `EXECUTE.resource.targets[0]`. The grant-signature at `system/signature/{grant_hash}`
   * is removed alongside the grant (writer/unregister symmetry). Installed types are left
   * in place (they may be shared; see A-012).
   */
  #unregister(ctx: HandlerContext): HandlerResult {
    const patternOrErr = patternFromResource(ctx);
    if (typeof patternOrErr !== "string") {
      return patternOrErr;
    }
    const pattern = patternOrErr;

    // Recover the grant hash before removing the grant so the signature path resolves.
    const grant = ctx.peer.tree.get(abs(ctx, "system/capability/grants/" + pattern));
    if (grant !== undefined) {
      const grantHashHex = new CapabilityToken(grant).contentHashHex;
      ctx.peer.tree.remove(abs(ctx, "system/signature/" + grantHashHex));
      ctx.peer.tree.remove(abs(ctx, "system/capability/grants/" + pattern));
    }
    ctx.peer.tree.remove(abs(ctx, pattern));
    ctx.peer.tree.remove(abs(ctx, "system/handler/" + pattern));

    return HandlerResult.ok(Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap()));
  }
}

/**
 * (2) Install associated types at `system/type/{type_name}` per `register-request.types`
 * (a `map[type_name]TypeDefinition`). Each value is a type-definition data map stored as
 * a `system/type` entity.
 */
function installTypes(ctx: HandlerContext, req: EcfValue): void {
  const types = Ecf.field(req, "types");
  if (types === null) {
    return;
  }
  for (const [typeName, typeDef] of Ecf.entries(types)) {
    ctx.peer.tree.put(abs(ctx, "system/type/" + typeName), Entity.create(TypeNames.Type, typeDef));
  }
}

/**
 * Derive the install pattern from `EXECUTE.resource.targets[0]` (`system/handler/{pattern}`).
 * Exactly one target is required — anything else is `400 ambiguous_resource` (§6.2).
 * Returns the pattern, or a HandlerResult error.
 */
function patternFromResource(ctx: HandlerContext): string | HandlerResult {
  const resource = ctx.resource;
  if (resource === null || resource.targets.length !== 1) {
    return errorResult(Status.BadRequest, "ambiguous_resource", "register/unregister require exactly one resource target (system/handler/{pattern}) (§6.2)");
  }
  const prefix = "system/handler/";
  const target = resource.targets[0] ?? "";
  if (!target.startsWith(prefix) || target.length === prefix.length) {
    return errorResult(Status.BadRequest, "invalid_resource", "register/unregister resource target MUST be system/handler/{pattern} (§6.2)");
  }
  return target.slice(prefix.length);
}

function abs(ctx: HandlerContext, peerRelative: string): string {
  return "/" + ctx.localPeerId + "/" + peerRelative;
}
