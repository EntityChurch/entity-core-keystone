import { type EcfValue, ecfMap, ecfText } from "../codec/ecf-value.js";
import { decodeLeb128 } from "../codec/leb128.js";
import { SHA256_FORMAT, SHA384_FORMAT } from "../codec/hash-formats.js";
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
      ctx.peer.tree.remove(path, ctx.emitContext());
      return HandlerResult.ok(emptyAck());
    }

    const admitted = admitPut(entityField);
    if (admitted instanceof HandlerResult) {
      return admitted;
    }
    if (!ctx.peer.tree.compareAndPut(path, admitted, expectedHash, ctx.emitContext())) {
      return errorResult(Status.Conflict, "hash_mismatch", "conditional write failed");
    }
    return HandlerResult.ok(emptyAck());
  }
}

/**
 * Digest byte length for a `content_hash_format` code per the §1.2 seed table, or
 * `null` when this peer cannot VERIFY that code. The total wire length is this
 * plus the LEB128 prefix, which is not a constant of the code (§7.3): codes
 * >= 0x80 occupy more than one byte.
 */
function hashDigestLen(formatCode: bigint): number | null {
  if (formatCode === SHA256_FORMAT) return 32;
  if (formatCode === SHA384_FORMAT) return 48;
  return null;
}

/** Presence, not truthiness: `Ecf.field` collapses a CBOR null into `null`, and
 *  §6.3 makes a null `data` a legal payload. */
function hasKey(value: EcfValue, key: string): boolean {
  if (value.kind !== "map") return false;
  return value.pairs.some(([k]) => k.kind === "text" && k.value === key);
}

/**
 * §6.3's `put` admission ladder (normative, 0.8.2.11).
 *
 * `put` is a RECEIPT path: the submitter authors the entity, the peer validates
 * what it received (§1.8 item 1) and MUST NOT author a submitted entity's
 * `content_hash` on the submitter's behalf. Two ordered steps:
 *
 * 1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any
 *    CBOR value; null is a legal payload), and a `content_hash` that is a
 *    well-formed `system/hash` whose total byte length matches its format code
 *    (§1.2). Any failure → 400 `invalid_request`. A well-formed hash naming a
 *    format code this peer cannot verify is the separate §1.2 ingest-dispatch
 *    case → 400 `unsupported_content_hash_format`.
 * 2. HASH — carried `content_hash` vs `content_hash({type, data})`. Disagreement
 *    → 400 `hash_mismatch`.
 *
 * Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
 * inputs are exactly what step 1 establishes, so a submission that is both
 * malformed and mis-hashed is step 1's and answers `invalid_request`.
 *
 * Structural admission is not semantic validation: `data` is never checked
 * against the type named by `type`.
 */
function admitPut(v: EcfValue): Entity | HandlerResult {
  const refuse = (code: string, message: string): HandlerResult =>
    errorResult(Status.BadRequest, code, message);

  if (v.kind !== "map") {
    return refuse("invalid_request", "put: entity is not a map");
  }
  const typeV = Ecf.field(v, "type");
  if (typeV === null || typeV.kind !== "text" || typeV.value === "") {
    return refuse("invalid_request", "put: entity.type absent, empty or not a text string");
  }
  if (!hasKey(v, "data")) {
    return refuse("invalid_request", "put: entity.data absent");
  }
  const chV = Ecf.field(v, "content_hash");
  if (chV === null || chV.kind !== "bytes" || chV.value.length === 0) {
    return refuse("invalid_request", "put: entity.content_hash absent or not a byte string");
  }
  const carried = chV.value;
  let decoded: { value: bigint; nextOffset: number };
  try {
    decoded = decodeLeb128(carried, 0);
  } catch {
    return refuse("invalid_request", "put: entity.content_hash is not a well-formed system/hash");
  }
  const digestLen = hashDigestLen(decoded.value);
  if (digestLen === null) {
    // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
    // invalid_request: the shape is fine, the algorithm is what we lack.
    return refuse("unsupported_content_hash_format", "put: unsupported content_hash_format");
  }
  if (carried.length !== decoded.nextOffset + digestLen) {
    return refuse("invalid_request", "put: content_hash length does not match its format code");
  }
  try {
    // fromDecoded VERIFIES the carried hash and stores it — it does not author
    // one, which is what §6.3 forbids here. A mismatch throws, and that throw is
    // step 2's row rather than a codec fault.
    return Entity.fromDecoded(v);
  } catch {
    return refuse("hash_mismatch", "put: content_hash does not match content_hash({type, data})");
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
