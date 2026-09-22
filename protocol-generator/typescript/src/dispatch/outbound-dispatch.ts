import { Entity, Envelope, Execute, ExecuteResponse, type ResourceTarget } from "../model/index.js";
import { type PeerIdentity, signEntity } from "../identity/index.js";
import { type OutboundAuthority, type OutboundDispatch } from "../handlers/index.js";
import { type ReentrantSender } from "../transport/reentrant-sender.js";

/**
 * The production {@link OutboundDispatch} (V7 §6.13(b)): builds, signs, and sends an
 * outbound EXECUTE as the local peer and awaits the correlated EXECUTE_RESPONSE via the
 * §6.11 reentry seam ({@link ReentrantSender}) — typically the very connection the
 * handler is servicing (§4.8). Mirrors {@link PeerSession}'s send path, factored to
 * reuse the reentrant sender so a handler can originate without owning a session object.
 */
export class OutboundDispatchImpl implements OutboundDispatch {
  constructor(
    private readonly local: PeerIdentity,
    private readonly sender: ReentrantSender,
  ) {}

  async execute(
    uri: string,
    operation: string,
    paramsEntity: Entity,
    resource: ResourceTarget | null,
    authority: OutboundAuthority | null,
    timeoutMs: number,
  ): Promise<ExecuteResponse> {
    const execute = Execute.build({
      requestId: this.sender.nextRequestId(),
      uri,
      operation,
      params: paramsEntity,
      author: this.local.identityHash,
      // §1.4 PD-2 AMBIENT arm: no credential, so no `capability` field at all.
      capability: authority === null ? null : authority.capability.contentHash,
      resource,
    });

    const executeSignature = signEntity(execute.entity, this.local);

    const included = [
      ...(authority === null
        ? []
        : [
            authority.capability.entity,
            // Every granter and every signature: §5.5's chain walk resolves them BY
            // HASH out of this map.
            ...authority.granterPeers, // capability granters (the target peer's identity)
            ...authority.capabilitySignatures,
          ]),
      this.local.peerEntity, // grantee + author (this peer's identity)
      executeSignature,
    ];

    const response = await this.sender.sendRequest(new Envelope(execute.entity, included), timeoutMs);
    // Carry the response envelope's `included` through (§3.1). A handler that
    // originates an EXECUTE and gets back a result REFERENCING entities — CONTENT's
    // blob and chunk shapes are the motivating case — needs the referents, and
    // dropping the map here made them unreachable from the only surface a body has.
    return new ExecuteResponse(response.root, response.included);
  }
}
