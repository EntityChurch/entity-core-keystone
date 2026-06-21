import { type EcfValue, ecfPreEncoded } from "../codec/ecf-value.js";
import { EntityProtocolError } from "../errors.js";
import * as Ecf from "./ecf.js";
import { Entity } from "./entity.js";
import { ResourceTarget } from "./resource-target.js";
import { TypeNames } from "./protocol-constants.js";

/**
 * A typed view over a `system/protocol/execute` entity (V7 §3.2). One of the two
 * wire message types. Carries a request id, target uri, operation, an entity
 * `params`, and — for authenticated requests — `author` and `capability`
 * reference hashes. The signature is a separate `system/signature` entity found
 * by target-matching in the envelope.
 */
export class Execute {
  /** The underlying materialized entity (its content hash is the signature target). */
  readonly entity: Entity;

  constructor(entity: Entity) {
    if (entity.type !== TypeNames.Execute) {
      throw new EntityProtocolError(`expected ${TypeNames.Execute}, got '${entity.type}'`);
    }
    this.entity = entity;
  }

  get requestId(): string {
    return Ecf.requireText(this.entity.data, "request_id");
  }

  get uri(): string {
    return Ecf.requireText(this.entity.data, "uri");
  }

  get operation(): string {
    return Ecf.requireText(this.entity.data, "operation");
  }

  /** The `params` entity (materialized; §3.4). */
  get params(): Entity {
    return Entity.fromDecoded(Ecf.require(this.entity.data, "params"));
  }

  /** Author identity hash, or null on a pre-auth connect request (§3.2, §4.2). */
  get author(): Uint8Array | null {
    return Ecf.optBytes(this.entity.data, "author");
  }

  /** Capability token hash, or null on a pre-auth connect request. */
  get capability(): Uint8Array | null {
    return Ecf.optBytes(this.entity.data, "capability");
  }

  /** The optional resource target (§3.2), or null when absent. */
  get resource(): ResourceTarget | null {
    const r = Ecf.field(this.entity.data, "resource");
    return r === null ? null : ResourceTarget.fromEcf(r);
  }

  /**
   * Build a `system/protocol/execute` entity. `paramsEntity` is spliced verbatim
   * (fidelity). `author` / `capability` are omitted for connect-path requests
   * (§4.2).
   */
  static build(args: {
    requestId: string;
    uri: string;
    operation: string;
    params: Entity;
    author?: Uint8Array | null;
    capability?: Uint8Array | null;
    resource?: ResourceTarget | null;
    bounds?: EcfValue | null;
  }): Execute {
    const data = Ecf.map(
      ["request_id", Ecf.text(args.requestId)],
      ["uri", Ecf.text(args.uri)],
      ["operation", Ecf.text(args.operation)],
      ["resource", args.resource ? args.resource.toEcf() : null],
      ["params", ecfPreEncoded(args.params.wireBytes)],
      ["bounds", args.bounds ?? null],
      ["author", args.author ? Ecf.bytes(args.author) : null],
      ["capability", args.capability ? Ecf.bytes(args.capability) : null],
    );
    return new Execute(Entity.create(TypeNames.Execute, data));
  }
}
