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
    authority: OutboundAuthority,
    timeoutMs: number,
  ): Promise<ExecuteResponse> {
    const execute = Execute.build({
      requestId: this.sender.nextRequestId(),
      uri,
      operation,
      params: paramsEntity,
      author: this.local.identityHash,
      capability: authority.capability.contentHash,
      resource,
    });

    const executeSignature = signEntity(execute.entity, this.local);

    const included = [
      authority.capability.entity,
      authority.granterPeer, // capability granter (the target peer's identity)
      this.local.peerEntity, // grantee + author (this peer's identity)
      authority.capabilitySignature,
      executeSignature,
    ];

    const response = await this.sender.sendRequest(new Envelope(execute.entity, included), timeoutMs);
    return new ExecuteResponse(response.root);
  }
}
