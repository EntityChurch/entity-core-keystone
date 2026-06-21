package org.entitycore.protocol.peer

/**
 * Dispatch-layer value types: the handler [Outcome], the [Handler] interface, the
 * [HandlerContext], and per-connection [Conn] state.
 *
 * **The idiom axis (sealed-class verdicts + single-dispatch operation `when`).** A core
 * system handler (§6.2) is a [Handler] whose [Handler.handle] switches over the
 * operation string with an exhaustive `when` — the mainstream `match op` ladder, with
 * the "unknown operation → 501" arm as the `else` branch. The §5.2/§5.10 verdicts are
 * Kotlin `enum class`es matched exhaustively at the dispatch site (the static-rigor seam
 * the profile's `exhaustive_when` calls for). Distinct from the Java peer's
 * checked-exception ladder: here failures are VALUES ([Outcome] with a status) on the
 * recoverable path.
 */

/**
 * A handler outcome: a status, a result entity, and any protocol entities to carry in
 * the response envelope's `included` (§3.1) — caps, peer identities, signatures.
 */
data class Outcome(
    val status: Int,
    val result: Entity,
    val included: List<Envelope.Included> = emptyList(),
) {
    companion object {
        fun ok(result: Entity, included: List<Envelope.Included> = emptyList()): Outcome =
            Outcome(200, result, included)

        fun err(status: Int, code: String, message: String? = null): Outcome =
            Outcome(status, Wire.errorResult(code, message))
    }
}

/**
 * A core system handler (§6.2). The §6.6 backward tree-walk resolves a request URI to a
 * bootstrapped handler instance; [handle] then dispatches the operation. `suspend` so a
 * handler that originates an outbound EXECUTE (§6.13(b)/§6.11 reentry) can `await` the
 * response without blocking a thread — the Kotlin coroutine idiom (profile [async]).
 */
fun interface Handler {
    suspend fun handle(operation: String, ctx: HandlerContext): Outcome
}

/**
 * The §6.6 HandlerContext: everything a handler needs to service one operation — the
 * EXECUTE entity, the per-connection state, the envelope's `included`, the resolved
 * caller capability (null for the unauthenticated connect path), and the envelope.
 */
data class HandlerContext(
    val exec: Entity,
    val conn: Conn,
    val included: List<Envelope.Included>,
    val callerCap: Entity?,
    val env: Envelope,
) {
    /** The EXECUTE's params entity, or null. */
    fun params(): Entity? = exec.entityField("params")
}

/**
 * Per-connection state (§4.2 connection state is per-connection). Holds the §4.1
 * handshake progress (issued nonce, the initiator's claimed peer_id, established flag)
 * and the §6.13(b) handler-facing outbound seam.
 *
 * The [outbound] seam sends an EXECUTE envelope over THIS connection and awaits its
 * correlated EXECUTE_RESPONSE (§6.11 reentry); the transport sets it. It is null when
 * the request did not arrive over a reentrant connection (e.g. an in-process call). It
 * is a `suspend` function (the coroutine reentry primitive).
 */
class Conn {
    @Volatile var established: Boolean = false
    @Volatile var issuedNonce: ByteArray? = null   // nonce we issued in our hello response
    @Volatile var helloPeerId: String? = null      // initiator's claimed peer_id from hello

    /** §6.13(b) reentry seam: send-and-await over this connection; null if unavailable. */
    @Volatile var outbound: (suspend (Envelope) -> Envelope?)? = null

    private var outCounter = 0

    @Synchronized
    fun nextOutCounter(): Int = ++outCounter
}
