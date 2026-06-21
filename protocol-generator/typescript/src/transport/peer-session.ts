import { Entity, Ecf, Envelope, Execute, ExecuteResponse, type ResourceTarget, TypeNames } from "../model/index.js";
import { type PeerIdentity, signEntity } from "../identity/index.js";
import { type CapabilityToken } from "../capability/index.js";
import { type PeerConnection } from "./peer-connection.js";

const DEFAULT_TIMEOUT_MS = 10_000;

/**
 * An authenticated session over an established connection: the capability the
 * remote peer issued at connect (§4.4) plus the entities needed to re-present its
 * authority chain on every request (§5.8 chain inclusion). Builds, signs, and sends
 * authenticated EXECUTEs and returns the correlated response.
 */
export class PeerSession {
  constructor(
    private readonly connection: PeerConnection,
    private readonly local: PeerIdentity,
    /** The peer id of the remote endpoint this session authenticates against. */
    readonly remotePeerId: string,
    /** The capability this session wields (granted by the remote peer at connect). */
    readonly capability: CapabilityToken,
    private readonly granterPeer: Entity,
    private readonly capabilitySignature: Entity,
  ) {}

  /**
   * Build, sign, and send an authenticated EXECUTE; await the correlated
   * EXECUTE_RESPONSE. The full authority chain travels in `included` (§5.8): the
   * capability token, the granter and grantee identities, the capability signature,
   * and the EXECUTE signature.
   */
  async execute(
    uri: string,
    operation: string,
    params: Entity,
    resource: ResourceTarget | null = null,
    timeoutMs = DEFAULT_TIMEOUT_MS,
  ): Promise<ExecuteResponse> {
    const execute = Execute.build({
      requestId: this.connection.nextRequestId(),
      uri,
      operation,
      params,
      author: this.local.identityHash,
      capability: this.capability.contentHash,
      resource,
    });

    const executeSignature = signEntity(execute.entity, this.local);

    const included = [
      this.capability.entity,
      this.granterPeer, // capability granter (remote peer identity)
      this.local.peerEntity, // grantee + author (this peer's identity)
      this.capabilitySignature,
      executeSignature,
    ];

    const request = new Envelope(execute.entity, included);
    const response = await this.connection.sendRequest(request, timeoutMs);
    return new ExecuteResponse(response.root);
  }

  /** Empty-params entity for operations that take no params (§3.2): `0xA0`. */
  static emptyParams(): Entity {
    return Entity.create(TypeNames.PrimitiveAny, Ecf.emptyMap());
  }
}
