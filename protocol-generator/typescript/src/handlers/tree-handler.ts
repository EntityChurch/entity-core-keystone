import { type EcfValue, ecfMap, ecfText } from "../codec/ecf-value.js";
import { EntityProtocolError } from "../errors.js";
import { Entity, Ecf, Status, TypeNames, hashEqual, isZeroHash } from "../model/index.js";
import { Paths, Permissions } from "../capability/index.js";
import { type Handler, type HandlerContext, HandlerResult } from "./handler-abstractions.js";
import { errorResult } from "./errors.js";

/**
 * The tree handler at `system/tree` (V7 §6.3) — direct access to the location
 * index and content store via `get` and `put`. Enforces two-level authorization:
 * the dispatcher's `check_permission` ran first; this handler re-checks each path
 * with `check_path_permission` (defense-in-depth, and sole enforcement when
 * `resource` is absent).
 */
export class TreeHandler implements Handler {
  readonly pattern = "system/tree";
  readonly name = "tree";
  readonly operations: readonly string[] = ["get", "put"];

  async handle(ctx: HandlerContext): Promise<HandlerResult> {
    switch (ctx.operation) {
      case "get":
        return this.#get(ctx);
      case "put":
        return this.#put(ctx);
      default:
        return errorResult(Status.NotSupported, "operation_not_supported", `tree handler has no '${ctx.operation}'`);
    }
  }

  #get(ctx: HandlerContext): HandlerResult {
    const target = requireSingleTarget(ctx);
    const tree = ctx.peer.tree;
    const localPeerId = ctx.localPeerId;

    try {
      Paths.validateCallerTarget(target);
    } catch (e) {
      if (e instanceof EntityProtocolError) {
        return errorResult(Status.BadRequest, "invalid_path", e.message);
      }
      throw e;
    }

    // Listing request — trailing slash or empty (§6.3).
    if (target.length === 0 || target.endsWith("/")) {
      const prefix = Paths.canonicalize(target.replace(/\/+$/, ""), localPeerId);
      const raw = tree.list(prefix);
      const entries: [string, EcfValue][] = [];
      for (const [name, entry] of raw) {
        // Filter each entry against the caller's capability (§6.3 listing filter).
        const entryPath = (prefix.endsWith("/") ? prefix : prefix + "/") + name;
        if (!authorizePath(ctx, "get", entryPath)) {
          continue;
        }
        // §6.3 / v7.72 §9.5a CORE-TREE-DELETE-1: a direct child bound to a
        // system/deletion-marker is omitted (a marked leaf reads as absent); a
        // marker that still prefixes deeper live paths survives as a pure prefix.
        if (entry.hash !== null && tree.get(entryPath)?.type === TypeNames.DeletionMarker) {
          if (!entry.hasChildren) {
            continue;
          }
          entries.push([name, Ecf.map(["hash", null], ["has_children", Ecf.bool(true)])]);
          continue;
        }
        entries.push([
          name,
          Ecf.map(["hash", entry.hash === null ? null : Ecf.bytes(entry.hash)], ["has_children", Ecf.bool(entry.hasChildren)]),
        ]);
      }
      const listing = Entity.create(
        "system/tree/listing",
        Ecf.map(
          ["path", Ecf.text(prefix)],
          ["entries", ecfMap(entries.map(([name, value]) => [ecfText(name), value] as const))],
          ["count", Ecf.uint(BigInt(entries.length))],
          ["offset", Ecf.uint(0n)],
        ),
      );
      return HandlerResult.ok(listing);
    }

    const path = Paths.canonicalize(target, localPeerId);
    if (!authorizePath(ctx, "get", path)) {
      return errorResult(Status.Forbidden, "capability_denied", "capability does not cover path");
    }

    const mode = Ecf.optText(ctx.params.data, "mode") ?? "entity";
    const hash = tree.getHash(path);
    if (hash === undefined) {
      return errorResult(Status.NotFound, "not_found", `no entity bound at ${path}`);
    }
    if (mode === "hash") {
      return HandlerResult.ok(Entity.create(TypeNames.PrimitiveAny, Ecf.bytes(hash)));
    }
    return HandlerResult.ok(tree.get(path)!);
  }

  #put(ctx: HandlerContext): HandlerResult {
    const target = requireSingleTarget(ctx);
    let path: string;
    try {
      // §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1: reject control bytes + malformed
      // leading-slash forms (400 invalid_path) before the write reaches the store.
      Paths.validateCallerTarget(target);
      path = Paths.canonicalize(target, ctx.localPeerId);
    } catch (e) {
      if (e instanceof EntityProtocolError) {
        return errorResult(Status.BadRequest, "invalid_path", e.message);
      }
      throw e;
    }

    // Caller-specified path: the caller's capability MUST cover it (§6.8).
    if (!authorizePath(ctx, "put", path)) {
      return errorResult(Status.Forbidden, "capability_denied", "capability does not cover path");
    }

    const entityField = Ecf.field(ctx.params.data, "entity");
    const expectedHash = Ecf.optBytes(ctx.params.data, "expected_hash");

    if (entityField === null) {
      // Remove binding (§6.3). CAS-checked when expected_hash present.
      if (expectedHash !== null && !isZeroHash(expectedHash)) {
        const current = ctx.peer.tree.getHash(path);
        if (current === undefined || !hashEqual(current, expectedHash)) {
          return errorResult(Status.Conflict, "hash_mismatch", "expected_hash does not match current binding");
        }
      }
      ctx.peer.tree.remove(path);
      return HandlerResult.ok(emptyAck());
    }

    const entity = Entity.fromDecoded(entityField);
    if (!ctx.peer.tree.compareAndPut(path, entity, expectedHash)) {
      return errorResult(Status.Conflict, "hash_mismatch", "conditional write failed");
    }
    return HandlerResult.ok(emptyAck());
  }
}

function authorizePath(ctx: HandlerContext, operation: string, path: string): boolean {
  return (
    ctx.callerCapability !== null &&
    Permissions.checkPathPermission(operation, path, ctx.callerCapability, ctx.pattern, ctx.localPeerId)
  );
}

function requireSingleTarget(ctx: HandlerContext): string {
  const resource = ctx.resource;
  if (resource === null || resource.targets.length !== 1) {
    throw new EntityProtocolError("tree operation requires exactly one resource target (§6.3)");
  }
  return resource.targets[0]!;
}

function emptyAck(): Entity {
  return Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap());
}
