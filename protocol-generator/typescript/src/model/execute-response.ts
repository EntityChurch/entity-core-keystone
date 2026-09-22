import { ecfPreEncoded } from "../codec/ecf-value.js";
import { EntityProtocolError } from "../errors.js";
import * as Ecf from "./ecf.js";
import { Entity } from "./entity.js";
import { hashHex } from "./hashes.js";
import { TypeNames } from "./protocol-constants.js";

/**
 * A typed view over a `system/protocol/execute/response` entity (V7 §3.3). The
 * second and final wire message type. Correlates to its EXECUTE by `request_id`
 * (§6.11 demux key).
 */
export class ExecuteResponse {
  readonly entity: Entity;

  /**
   * The response envelope's `included` map (§3.1), keyed by content-hash hex.
   *
   * A response carries supporting entities the same way a request does — a minted
   * capability and its granter identity on the handshake, and, for an extension like
   * CONTENT, the blob and chunk entities the result entity only *references*. This
   * view used to be constructed from `envelope.root` alone, so every caller reaching a
   * peer through its own client surface received the reference and not the referent:
   * the server side was correct and nothing was conformance-visible, because the
   * oracle reads the envelope directly rather than through this class.
   *
   * Empty when the view was built from a bare entity, which is what
   * {@link ExecuteResponse.build} does — a response under construction has no envelope
   * yet, and its included entities are carried by {@link HandlerResult}.
   */
  readonly included: ReadonlyMap<string, Entity>;

  constructor(entity: Entity, included: ReadonlyMap<string, Entity> = new Map()) {
    if (entity.type !== TypeNames.ExecuteResponse) {
      throw new EntityProtocolError(`expected ${TypeNames.ExecuteResponse}, got '${entity.type}'`);
    }
    this.entity = entity;
    this.included = included;
  }

  /** Look an included entity up by its content hash (§3.1 map key). */
  includedByHash(contentHash: Uint8Array): Entity | undefined {
    return this.included.get(hashHex(contentHash));
  }

  get requestId(): string {
    return Ecf.requireText(this.entity.data, "request_id");
  }

  get statusCode(): number {
    return Number(Ecf.requireUint(this.entity.data, "status"));
  }

  /** The result entity (materialized; §3.4). */
  get result(): Entity {
    return Entity.fromDecoded(Ecf.require(this.entity.data, "result"));
  }

  get budgetConsumed(): bigint | null {
    return Ecf.optUint(this.entity.data, "budget_consumed");
  }

  /** Build an EXECUTE_RESPONSE carrying a result entity. */
  static build(requestId: string, status: number, result: Entity, budgetConsumed: bigint | null = null): ExecuteResponse {
    const data = Ecf.map(
      ["request_id", Ecf.text(requestId)],
      ["status", Ecf.uint(BigInt(status))],
      ["result", ecfPreEncoded(result.wireBytes)],
      ["budget_consumed", budgetConsumed === null ? null : Ecf.uint(budgetConsumed)],
    );
    return new ExecuteResponse(Entity.create(TypeNames.ExecuteResponse, data));
  }

  /**
   * Build an error EXECUTE_RESPONSE with a `system/protocol/error` result (§3.3):
   * `{code, message?}`. The `code` field is required on error responses (§6.12 —
   * its absence is itself a protocol violation).
   */
  static error(requestId: string, status: number, code: string, message: string | null = null): ExecuteResponse {
    const error = Entity.create(
      TypeNames.Error,
      Ecf.map(["code", Ecf.text(code)], ["message", message === null ? null : Ecf.text(message)]),
    );
    return ExecuteResponse.build(requestId, status, error);
  }
}
