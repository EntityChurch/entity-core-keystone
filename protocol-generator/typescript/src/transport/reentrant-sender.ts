import { type Envelope } from "../model/index.js";

/**
 * The §6.11 transport-reentry seam: send an EXECUTE envelope and await its correlated
 * EXECUTE_RESPONSE over a connection, concurrently with that connection's inbound
 * dispatch (§4.8). {@link PeerConnection} is the production implementation (its reader
 * loop demuxes responses by `request_id`); tests supply a fake.
 *
 * This is the seam a handler's outbound dispatch (v7.74 §6.13(b)) routes through: a
 * handler servicing an inbound EXECUTE can originate an outbound EXECUTE back over the
 * same connection and await the response, without the reader blocking on it.
 */
export interface ReentrantSender {
  /** A connection-scoped unique request id (§6.11 informative). */
  nextRequestId(): string;
  /** Send an EXECUTE envelope and await its correlated EXECUTE_RESPONSE (§6.11). */
  sendRequest(request: Envelope, timeoutMs: number): Promise<Envelope>;
}
