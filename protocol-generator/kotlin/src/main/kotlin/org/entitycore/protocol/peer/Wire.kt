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
class EntityTransportException(message: String, cause: Throwable? = null) :
    RuntimeException(message, cause)

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
        val len = try {
            input.readInt()
        } catch (eof: EOFException) {
            return null
        } catch (e: IOException) {
            return null
        }
        if (len < 0 || len > MAX_FRAME) {
            throw EntityTransportException("frame length out of bounds: $len")
        }
        val payload = ByteArray(len)
        try {
            input.readFully(payload)
        } catch (e: IOException) {
            throw EntityTransportException("truncated frame", e)
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
        val v = when (val r = CanonicalCbor.decode(payload)) {
            is EcfResult.Ok -> r.value
            is EcfResult.Err -> throw EntityTransportException("frame decode: ${r.error.message}")
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
