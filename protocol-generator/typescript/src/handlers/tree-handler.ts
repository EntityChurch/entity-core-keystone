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

  /**
   * RESOLVE THE OPERATION FIRST; only then run the §3.3 resource ladder. This switch is
   * what makes that true: a handler that validates the resource first answers a RESOURCE
   * fault for an unknown-OPERATION request, so `system/tree:bogusop` with no `resource`
   * reports `ambiguous_resource` where §3.3 pins `501 unsupported_operation`.
   */
  async handle(ctx: HandlerContext): Promise<HandlerResult> {
    switch (ctx.operation) {
      case "get":
        return this.#get(ctx);
      case "put":
        return this.#put(ctx);
      default:
        // §3.3's 501 slot is spelled `unsupported_operation` — the same code every
        // other handler in this peer already used; `operation_not_supported` is a
        // minted synonym, and §3.3's (code, status) pair is a MUST-emit contract.
        return errorResult(Status.NotSupported, "unsupported_operation", `tree handler has no '${ctx.operation}'`);
    }
  }

  #get(ctx: HandlerContext): HandlerResult {
    const tree = ctx.peer.tree;
    const localPeerId = ctx.localPeerId;

    // §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on `resource.targets`: a
    // handler that counts the effective list and then indexes `targets[0]` has implemented
    // the arithmetic completely and is still reading a path no authorization covered.
    //
    // This replaces a `targets.length !== 1` THROW, which answered `400 handler_error` for
    // every row of the ladder at once: an absent resource, two targets and a single-entry
    // effective set all landed on the generic handler-fault frame. 0.8.2.20 pins each to
    // its own code because the code is what selects the caller's remedy, and a peer that
    // refuses correctly for a reason §6.3 does not name has not implemented the selection.
    const { survivors, hasResource } = Permissions.effectiveTargets(ctx.execute, localPeerId);
    if (!hasResource) {
      // THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION IS WHAT
      // SAYS SO. §3.3's "an empty effective list IS the absent case" is scoped "for an
      // operation that REQUIRES a resource" (0.8.2.24, N7); `get` does not. For a
      // resource-OPTIONAL operation 0.8.2.25 (N10) decides the present-but-empty case by
      // whether the absent case is WIDER than the request — BROAD-RESULT refuses it,
      // OPTIONAL-FILTER answers it empty — and requires the operation to declare which.
      //
      // EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is resource-OPTIONAL and
      // BROAD-RESULT, absent-case answer "the root listing", self-excluded case
      // "400 path_required". Both arms are pinned by text and neither is this peer's choice.
      return this.#listing(ctx, "/" + localPeerId + "/");
    }
    if (survivors.length === 0) {
      // The self-excluded request: `resource` PRESENT, every target carved out by the
      // caller's own exclude. Serving it the absent case "answers a request for one
      // excluded path with a listing of the tree" (EXTENSION-TREE §2.2a) — the root
      // listing is wider than what was asked for, which is what BROAD-RESULT means.
      return errorResult(Status.BadRequest, "path_required", "tree: effective target list is empty");
    }
    if (survivors.length > 1) {
      return errorResult(Status.BadRequest, "ambiguous_resource", "tree: more than one effective target");
    }
    const target = survivors[0]!;

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
      return this.#listing(ctx, Paths.canonicalize(target.replace(/\/+$/, ""), localPeerId));
    }

    // A resource-requiring operation takes a CONCRETE path (0.8.2.20). Without this the
    // pattern is looked up as a literal and answers `404 not_found`, which names the wrong
    // fault: the request is malformed, the tree is fine.
    if (isPatternPath(target)) {
      return errorResult(Status.BadRequest, "malformed_resource", target);
    }

    const path = Paths.canonicalize(target, localPeerId);
    // §6.3: the handler MUST verify the CALLER's capability covers the path it is about to
    // read. NOT a secondary check — the dispatch-level check never saw this path if the
    // caller excluded it.
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

  /**
   * Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
   *
   * *"When any handler returns a multi-entry result whose entries are tree paths, each
   * entry MUST be individually checked using `check_path_permission`. Entries for which
   * `check_path_permission` returns DENY MUST be omitted. The result's `count` field MUST
   * reflect the filtered entry count, not the source tree's total count."*
   *
   * This is the read path at its highest volume and it is the reason 0.8.2.21 refused to
   * carve reads out of the caller-specified-path rule: an unfiltered listing discloses the
   * EXISTENCE of every binding under a prefix to a caller whose capability covers none of
   * them.
   *
   * The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the subject,
   * and testing the prefix would deny a listing to a caller whose grant covers children but
   * not the node above them, which is the ordinary shape of a narrowed grant.
   */
  #listing(ctx: HandlerContext, prefix: string): HandlerResult {
    const tree = ctx.peer.tree;
    const raw = tree.list(prefix);
    const entries: [string, EcfValue][] = [];
    for (const [name, entry] of raw) {
      // §6.3's per-entry check (0.8.2.21/.22).
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
        // `count` follows the FILTERED total. A count that still reports the source total
        // is the disclosure the rule exists to prevent.
        ["count", Ecf.uint(BigInt(entries.length))],
        ["offset", Ecf.uint(0n)],
      ),
    );
    return HandlerResult.ok(listing);
  }

  #put(ctx: HandlerContext): HandlerResult {
    // Same ladder as `#get`, with the two empties COLLAPSED rather than split:
    // EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's "an empty
    // effective list IS the absent case" applies in its unscoped form and both empties
    // answer `path_required`. That is the same table `#get`'s branch cites, one row down.
    //
    // Note the code 0.8.2.20 forces: a MISSING target is `path_required`, never
    // `ambiguous_resource` — 0.8.2.20 names that inversion outright, because *supply a
    // resource* is not *disambiguate your request* and the code is what selects the remedy.
    // This peer answered `400 handler_error` for both.
    const { survivors, hasResource } = Permissions.effectiveTargets(ctx.execute, ctx.localPeerId);
    if (!hasResource || survivors.length === 0) {
      return errorResult(Status.BadRequest, "path_required", "tree: put requires a resource target");
    }
    if (survivors.length > 1) {
      return errorResult(Status.BadRequest, "ambiguous_resource", "tree: more than one effective target");
    }
    const target = survivors[0]!;

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
    if (isPatternPath(target)) {
      return errorResult(Status.BadRequest, "malformed_resource", target);
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

/**
 * §6.3's per-path authorization, against the CALLER's verified capability and the OWNING
 * handler's pattern — both carried on the context by the dispatcher, which already
 * computed them. Carried rather than recomputed: recomputing invites the two to drift, and
 * §6.8 is explicit that the authority is selected by who named the path.
 *
 * An UNAUTHENTICATED context (no capability) is NOT filtered: the filter's subject is "the
 * caller's verified capability", and where there is none there is no caller to narrow.
 * That is the bootstrap/internal path, and it matches both vanguard peers. On this peer
 * every reachable tree dispatch carries a capability — `#route` only reaches a handler
 * after `verifyRequest` produced one, and the connect handler is the sole `null` case —
 * so the branch is unreachable today and is written for the rule rather than for a caller.
 */
function authorizePath(ctx: HandlerContext, operation: string, path: string): boolean {
  if (ctx.callerCapability === null) {
    return true;
  }
  return Permissions.checkPathPermission(operation, path, ctx.callerCapability, ctx.pattern, ctx.localPeerId);
}

/**
 * A §5.4 PATTERN rather than a concrete path. A resource-requiring operation takes a
 * CONCRETE path (0.8.2.20), and a trailing `/` is a listing request rather than a pattern —
 * only a `*` makes it one.
 */
function isPatternPath(target: string): boolean {
  return target.includes("*");
}

function emptyAck(): Entity {
  return Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap());
}
