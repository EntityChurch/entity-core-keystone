package org.entitycore.protocol.peer

import org.entitycore.protocol.EcfResult
import org.entitycore.protocol.codec.CanonicalCbor
import org.entitycore.protocol.codec.EcfValue
import java.io.DataInputStream
import java.io.EOFException
import java.io.IOException
import java.io.OutputStream

/**
 * §1.6 / §6.12 transport-layer failure: a malformed frame, a frame exceeding the §1.6
 * bound, or a closed connection during a framed read/write. Distinct from a
 * protocol-status [Outcome] — a transport fault ends the connection. Kotlin keeps
 * exceptions for the unrecoverable I/O boundary (the recoverable protocol path is the
 * sealed-result/[Outcome] seam — profile [error_model]).
 */
open class EntityTransportException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

/**
 * A length prefix over the connection's bound (§4.10(a)).
 *
 * Distinguished from [TruncatedFrameException] because §4.11 gives the two DIFFERENT
 * codes: this one is `413 payload_too_large`, and since 0.8.2.25 (N14) emitting it is a
 * MUST rather than a SHOULD — the condition is detected at the length prefix with the
 * connection intact and nothing spent, so the permissive mood had nothing to license.
 */
class FrameTooLargeException(message: String) : EntityTransportException(message)

/**
 * A frame that never completed: a prefix declaring `n` bytes followed by fewer, or a
 * partial length prefix. §4.11's framing arm names this input outright — *"un-parseable,
 * truncated or non-canonical CBOR, or a length prefix that never completes"* →
 * `400 invalid_request`.
 *
 * A SEPARATE TYPE FROM A CLEAN EOF because the two are different events and the stream
 * collapses them. A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing;
 * a stream that ends MID-FRAME is a REFUSAL and is owed a coded frame. This reader
 * previously reported both as a bare [EntityTransportException] that ended the loop in
 * silence, which is §4.11's other named non-conformant behaviour.
 */
class TruncatedFrameException(message: String, cause: Throwable? = null) :
    EntityTransportException(message, cause)

/**
 * A §1.8 / §3.1 RESOLUTION-INTEGRITY failure: an entity whose carried `content_hash` is
 * not `content_hash({type, data})`, or an `included` entry whose MAP KEY does not bind to
 * the entity filed under it.
 *
 * §5.2a pins this arm: *"A peer that refuses at the decode boundary MUST answer
 * `400 hash_mismatch` `[MUST]`"* (mood corrected 0.8.2.24), and in the same breath
 * *"`400 non_canonical_ecf` is NOT conformant here `[MUST]`"*. That code is
 * `ENTITY-CBOR-ENCODING` §5.4's, for a CBOR TAG-POLICY violation, and a mis-keyed included
 * entry carries no tag. Its encoding is canonical; what is false is the claim the KEY
 * makes, so the remedy `non_canonical_ecf` selects (*re-encode*) sends an honest caller to
 * the wrong layer. This peer answered `non_canonical_ecf` for every decode-boundary refusal
 * until 0.8.2.24 (measured on the wire: arc-probe B1/B2).
 *
 * A TYPE RATHER THAN A MESSAGE, because a classifier that has to recognise the cause by
 * matching on `message` is one string edit away from silently re-collapsing the two codes.
 * It extends [IllegalArgumentException] so every existing `catch` on the decode path keeps
 * catching it unchanged — the shape those sites were already written against.
 */
class HashMismatchException(message: String) : IllegalArgumentException(message)

/**
 * A codec refusal carried with its CAUSE intact.
 *
 * [Wire.envelopeOfFrame] used to flatten every [org.entitycore.protocol.EntityError] into
 * an [EntityTransportException] carrying only a message, which destroys exactly the
 * distinction §4.11 makes normative: the TAG arm keeps `non_canonical_ecf` and every other
 * codec fault takes `invalid_request`. Keeping the sealed error value is what lets
 * `preAdmissionRefusal` decide by cause instead of by matching a string.
 */
class CodecRefusalException(val error: org.entitycore.protocol.EntityError) :
    EntityTransportException(error.message)

/**
 * Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3 EXECUTE_RESPONSE).
 * Frame := `[4-byte BE length][CBOR payload]`; the payload is a CBOR-encoded
 * system/protocol/envelope (§3.1).
 *
 * Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello / authenticate
 * are OPERATIONS on system/protocol/connect, not message types — any other root type is
 * ignored on the server side (the dispatcher returns no response).
 */
internal object Wire {

    /** §1.6 / §4.10(a) bound — 16 MiB max inbound payload. */
    const val MAX_FRAME = 16 * 1024 * 1024

    // ── frame read/write ────────────────────────────────────────────────────────

    /** Read one length-prefixed frame; return its CBOR payload bytes. Returns null on a
     *  clean EOF at a frame boundary (the connection closed). §4.10(a): a length prefix
     *  over [MAX_FRAME] is rejected BEFORE the body is buffered (a transport fault that
     *  ends the connection — the caller maps the over-limit case to 413). */
    fun readFrame(input: DataInputStream): ByteArray? {
        // READ THE PREFIX BYTE BY BYTE, because §4.11 makes "no bytes" and "some bytes"
        // DIFFERENT EVENTS and `DataInputStream.readInt` collapses them into one
        // EOFException. A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed
        // nothing; a stream that ends inside the length prefix is a framing REFUSAL —
        // §4.11 names "a length prefix that never completes" outright — and is owed a coded
        // frame. The distinction can only be made here, where the boundary is known.
        val hdr = ByteArray(4)
        var got = 0
        try {
            while (got < 4) {
                val n = input.read(hdr, got, 4 - got)
                if (n < 0) break
                got += n
            }
        } catch (e: IOException) {
            return null                         // the socket went away mid-read
        }
        if (got == 0) return null               // clean EOF at a frame boundary
        if (got < 4) throw TruncatedFrameException("stream ended inside a frame length prefix")
        val len = ((hdr[0].toInt() and 0xff) shl 24) or ((hdr[1].toInt() and 0xff) shl 16) or
            ((hdr[2].toInt() and 0xff) shl 8) or (hdr[3].toInt() and 0xff)
        if (len < 0 || len > MAX_FRAME) {
            // §4.10(a), mood raised to MUST at 0.8.2.25 (N14): the condition is detected at
            // the length prefix with the connection intact and nothing spent, so the
            // permissive mood had nothing to license. The read loop answers `413
            // payload_too_large` and THEN closes.
            throw FrameTooLargeException("frame length out of bounds: $len")
        }
        val payload = ByteArray(len)
        try {
            input.readFully(payload)
        } catch (e: IOException) {
            // A prefix declaring `n` bytes followed by fewer. The CLEAN-EOF case is the arm
            // above and is owed nothing; this one is a §4.11 REFUSAL and is owed a coded
            // frame.
            throw TruncatedFrameException("truncated frame", e)
        }
        return payload
    }

    /** Write [payload] as a length-prefixed frame and flush. Caller serializes concurrent
     *  writers on the same stream (a per-connection write mutex). */
    fun writeFrame(out: OutputStream, payload: ByteArray) {
        val len = payload.size
        val hdr = byteArrayOf(
            (len ushr 24).toByte(), (len ushr 16).toByte(),
            (len ushr 8).toByte(), len.toByte(),
        )
        try {
            out.write(hdr)
            out.write(payload)
            out.flush()
        } catch (e: IOException) {
            throw EntityTransportException("frame write failed", e)
        }
    }

    // ── envelope <-> frame ────────────────────────────────────────────────────────

    fun envelopeOfFrame(payload: ByteArray): Envelope {
        // KEEP THE CAUSE. Flattening the sealed error into a message here destroys the one
        // distinction §4.11 makes normative on this path: the TAG arm keeps
        // `non_canonical_ecf` and every other codec fault takes `invalid_request`.
        val v = when (val r = CanonicalCbor.decode(payload)) {
            is EcfResult.Ok -> r.value
            is EcfResult.Err -> throw CodecRefusalException(r.error)
        }
        if (v !is EcfValue.MapVal) {
            throw EntityTransportException("frame: not a map")
        }
        return Envelope.ofCbor(v)
    }

    fun frameOfEnvelope(env: Envelope): ByteArray = CanonicalCbor.encodeOrThrow(env.toCbor())

    // ── EXECUTE builder (§3.2) ─────────────────────────────────────────────────────

    /** Build an EXECUTE entity. [author]/[capability] are 33-byte hashes; [resource] is a
     *  cbor-map (`{targets:[...]}`) or null. */
    fun makeExecute(
        requestId: String,
        uri: String,
        operation: String,
        params: Entity,
        author: ByteArray? = null,
        capability: ByteArray? = null,
        resource: EcfValue.MapVal? = null,
    ): Entity {
        val pairs = ArrayList<EcfValue.Entry>()
        pairs.add(entry("request_id", EcfValue.Text(requestId)))
        pairs.add(entry("uri", EcfValue.Text(uri)))
        pairs.add(entry("operation", EcfValue.Text(operation)))
        pairs.add(entry("params", params.toCbor()))
        if (author != null) pairs.add(entry("author", EcfValue.Bytes(author)))
        if (capability != null) pairs.add(entry("capability", EcfValue.Bytes(capability)))
        if (resource != null) pairs.add(entry("resource", resource))
        return Entity.make("system/protocol/execute", EcfValue.MapVal(pairs))
    }

    // ── EXECUTE_RESPONSE builder (§3.3) ─────────────────────────────────────────────

    fun makeResponse(requestId: String, status: Int, result: Entity): Entity =
        Entity.make(
            "system/protocol/execute/response",
            EcfValue.MapVal.of(
                "request_id", EcfValue.Text(requestId),
                "status", EcfValue.IntVal.of(status.toLong()),
                "result", result.toCbor(),
            ),
        )

    // ── error result + empty params + resource target ───────────────────────────────

    fun errorResult(code: String, message: String?): Entity {
        val data = if (message != null) {
            EcfValue.MapVal.of("code", EcfValue.Text(code), "message", EcfValue.Text(message))
        } else {
            EcfValue.MapVal.of("code", EcfValue.Text(code))
        }
        return Entity.make("system/protocol/error", data)
    }

    /** Empty-params (§3.2): a primitive/any whose data is the canonical empty map. */
    fun emptyParams(): Entity = Entity.make("primitive/any", Cbor.emptyMap())

    /** Build a resource cbor-map `{targets: [...]}`. */
    fun resourceTarget(vararg targets: String): EcfValue.MapVal =
        EcfValue.MapVal.of("targets", Cbor.textArray(*targets))

    // ── response decode helpers (initiator side) ─────────────────────────────────────

    fun responseStatus(env: Envelope): Int = env.root.uint("status")?.toInt() ?: 0

    fun responseResult(env: Envelope): Entity? =
        env.root.mapField("result")?.let { Entity.ofCbor(it) }

    private fun entry(key: String, value: EcfValue): EcfValue.Entry =
        EcfValue.Entry(EcfValue.Text(key), value)
}
