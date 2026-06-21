import { EntityProtocolError, HelloFailedError, RecvTimeoutError } from "../errors.js";
import { Entity, Ecf, Envelope, Execute, ExecuteResponse, Protocols, Status } from "../model/index.js";
import { type PeerIdentity, signEntity } from "../identity/index.js";
import { CapabilityToken, ChainVerifier } from "../capability/index.js";
import { type ConnectionState, buildHello } from "../handlers/index.js";
import { type PeerConnection } from "./peer-connection.js";
import { PeerSession } from "./peer-session.js";

/**
 * Drives connection establishment (V7 §4.1). The initiator sends `hello` then
 * `authenticate`; the responder, having returned its hello data in the hello
 * response, sends its own `authenticate` in the reverse direction. Each
 * authenticate response carries that side's initial capability (§4.4). Total: 3
 * EXECUTE + 3 EXECUTE_RESPONSE.
 */

/** Initiator side: `hello` → `authenticate`, returning this peer's session on the remote. */
export async function initiate(
  conn: PeerConnection,
  local: PeerIdentity,
  state: ConnectionState,
  timeoutMs: number,
): Promise<PeerSession> {
  // We have sent hello, so an inbound reverse-authenticate is in order (§4.2).
  state.helloReceived = true;

  const helloEntity = buildHello(local, nowMs());
  // Retain our challenge nonce so the responder's reverse authenticate (leg 3) can
  // be verified to echo it (§4.6 PoP step 1, symmetric).
  state.sentNonce = Ecf.requireBytes(helloEntity.data, "nonce");
  const r1 = await sendConnect(conn, "hello", helloEntity, [], timeoutMs);
  const resp1 = requireOk(r1, "hello");

  const remoteHello = resp1.result;
  const remotePeerId = Ecf.requireText(remoteHello.data, "peer_id");
  const remoteNonce = Ecf.requireBytes(remoteHello.data, "nonce");
  state.remotePeerId = remotePeerId;

  return authenticate(conn, local, remoteNonce, remotePeerId, timeoutMs);
}

/** Responder side: await the inbound hello, then send the reverse `authenticate` (§4.1 E3). */
export async function respond(
  conn: PeerConnection,
  local: PeerIdentity,
  state: ConnectionState,
  timeoutMs: number,
): Promise<PeerSession> {
  const info = await withTimeout(state.inboundHello.promise, timeoutMs);
  // §4.1 leg-3 ordering: hold the reverse authenticate until the leg-2 response
  // (to the initiator's authenticate) has been written. A sequential initiator
  // reads exactly one frame for its authenticate response; sending leg 3 before
  // that frame makes it read our EXECUTE where it expects its EXECUTE_RESPONSE.
  await withTimeout(state.authResponseSent.promise, timeoutMs);
  return authenticate(conn, local, info.nonce, info.peerId, timeoutMs);
}

async function authenticate(
  conn: PeerConnection,
  local: PeerIdentity,
  remoteNonce: Uint8Array,
  remotePeerId: string,
  timeoutMs: number,
): Promise<PeerSession> {
  const authEntity = Entity.create(
    "system/protocol/connect/authenticate",
    Ecf.map(
      ["peer_id", Ecf.text(local.peerId)],
      ["public_key", Ecf.bytes(local.publicKey)],
      ["key_type", Ecf.text(local.keyTypeName)],
      ["nonce", Ecf.bytes(remoteNonce)],
    ),
  );
  const authSignature = signEntity(authEntity, local);

  const response = await sendConnect(conn, "authenticate", authEntity, [local.peerEntity, authSignature], timeoutMs);
  const resp = requireOk(response, "authenticate");

  // Parse the initial capability grant (§4.4): token + granter + signature in included.
  const grant = resp.result;
  const tokenHash = Ecf.requireBytes(grant.data, "token");
  const tokenEntity = response.find(tokenHash);
  if (tokenEntity === undefined) {
    throw new EntityProtocolError("authenticate grant omits the capability token");
  }
  const capability = new CapabilityToken(tokenEntity);
  if (capability.granter === null) {
    throw new EntityProtocolError("authenticate grant token has no single-sig granter");
  }
  const granterPeer = response.find(capability.granter);
  if (granterPeer === undefined) {
    throw new EntityProtocolError("authenticate grant omits the granter identity");
  }
  const capSignature = ChainVerifier.findSignature(response, capability.contentHash);
  if (capSignature === null) {
    throw new EntityProtocolError("authenticate grant omits the capability signature");
  }

  return new PeerSession(conn, local, remotePeerId, capability, granterPeer, capSignature);
}

function sendConnect(
  conn: PeerConnection,
  operation: string,
  params: Entity,
  included: readonly Entity[],
  timeoutMs: number,
): Promise<Envelope> {
  // Connect-path EXECUTEs carry no author/capability (§4.2 pre-authorization).
  const execute = Execute.build({ requestId: conn.nextRequestId(), uri: Protocols.ConnectPath, operation, params });
  return conn.sendRequest(new Envelope(execute.entity, included), timeoutMs);
}

function requireOk(response: Envelope, step: string): ExecuteResponse {
  const resp = new ExecuteResponse(response.root);
  if (resp.statusCode !== Status.Ok) {
    const code = Ecf.optText(resp.result.data, "code") ?? "unknown";
    const message = Ecf.optText(resp.result.data, "message") ?? "";
    throw new HelloFailedError(`${step} failed: ${resp.statusCode} ${code} ${message}`, resp.statusCode);
  }
  return resp;
}

/** Reject a deferred handshake step after `ms` (the .NET `WaitAsync(timeout)` analogue). */
function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new RecvTimeoutError(`handshake step timed out after ${ms}ms`)), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error: unknown) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}

function nowMs(): bigint {
  return BigInt(Date.now());
}
