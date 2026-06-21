import { ecfPreEncoded } from "../codec/ecf-value.js";
import { EntityProtocolError } from "../errors.js";
import * as Ecf from "./ecf.js";
import { Entity } from "./entity.js";
import { TypeNames } from "./protocol-constants.js";

/**
 * A typed view over a `system/protocol/execute/response` entity (V7 §3.3). The
 * second and final wire message type. Correlates to its EXECUTE by `request_id`
 * (§6.11 demux key).
 */
export class ExecuteResponse {
  readonly entity: Entity;

  constructor(entity: Entity) {
    if (entity.type !== TypeNames.ExecuteResponse) {
      throw new EntityProtocolError(`expected ${TypeNames.ExecuteResponse}, got '${entity.type}'`);
    }
    this.entity = entity;
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
