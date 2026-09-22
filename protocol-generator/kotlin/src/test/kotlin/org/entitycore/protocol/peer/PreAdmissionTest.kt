package org.entitycore.protocol.peer

import org.entitycore.protocol.EcfResult
import org.entitycore.protocol.EntityError
import org.entitycore.protocol.codec.CanonicalCbor
import org.entitycore.protocol.codec.EcfValue
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * §4.11 pre-admission refusals (0.8.2.25).
 *
 * §4.11's rule has two parts and they fail differently. *"The frame obligation belongs to
 * the class"* is wire-visible and is driven over a socket below; *"the CODE belongs to the
 * cause `[MUST]`"* is a mapping, and a mapping is exactly the thing that regresses silently
 * when a new failure joins an existing branch, so it is pinned at the unit level.
 *
 * The pinned check set (778) has NO vector on this surface, which is why the coverage is
 * authored here rather than inherited. Both of §4.11's separately-named non-conformant
 * behaviours were present on this peer at HEAD: DROPPING the frame (the non-EXECUTE root,
 * which produced no response at all) and CLOSING with no coded frame (the oversize and
 * truncated arms).
 */
class PreAdmissionTest {

    private fun seed(b: Int): ByteArray = ByteArray(32) { b.toByte() }

    // ── the CODE belongs to the CAUSE (§4.11's table) ──────────────────────────────

    @Test
    fun preAdmissionRefusalCodeIsTheCauses() {
        // §4.10(a), mood raised to MUST at 0.8.2.25 (N14).
        assertEquals(
            Triple(413, "payload_too_large", "inbound frame exceeds the configured maximum size"),
            Transport.preAdmissionRefusal(FrameTooLargeException("x")),
        )
        // §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
        // `non_canonical_ecf` NON-CONFORMANT here.
        assertEquals("hash_mismatch", Transport.preAdmissionRefusal(HashMismatchException("x")).second)
        // ENTITY-CBOR-ENCODING §5.4 — the tag-policy arm keeps its own code.
        assertEquals(
            "non_canonical_ecf",
            Transport.preAdmissionRefusal(CodecRefusalException(EntityError.CodecError.TagRejected("x"))).second,
        )
        // §4.7 / §4.11 framing arm: bytes that never become an Envelope.
        assertEquals("invalid_request", Transport.preAdmissionRefusal(TruncatedFrameException("x")).second)
        assertEquals(
            "invalid_request",
            Transport.preAdmissionRefusal(CodecRefusalException(EntityError.CodecError.TruncatedInput("x"))).second,
        )
        assertEquals("invalid_request", Transport.preAdmissionRefusal(IllegalArgumentException("x")).second)
        assertEquals(400, Transport.preAdmissionRefusal(IllegalArgumentException("x")).first)
    }

    // ── a clean close is not a refusal; a truncation is ────────────────────────────

    /**
     * A clean EOF at a frame boundary is an ordinary close and is owed nothing; a stream
     * that ends MID-FRAME is a §4.11 framing refusal and is owed a coded frame. The stream
     * collapses the two, so the distinction has to be made where the frame boundary is
     * known — and getting it wrong in the other direction answers a 400 to every peer that
     * simply hangs up.
     */
    @Test
    fun readFrameDistinguishesCloseFromTruncation() {
        assertNull(readFrom(ByteArray(0)), "a clean close at a frame boundary")
        assertFailsWith<TruncatedFrameException> { readFrom(byteArrayOf(0, 0)) }
        assertFailsWith<TruncatedFrameException> {
            readFrom(byteArrayOf(0x00, 0x00, 0x10, 0x00, 0xa1.toByte()))
        }
        assertFailsWith<FrameTooLargeException> { readFrom(byteArrayOf(0x02, 0x00, 0x00, 0x00)) }

        // A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
        // refused there as bytes that never become an Envelope.
        val empty = readFrom(byteArrayOf(0, 0, 0, 0))
        assertNotNull(empty)
        assertEquals(0, empty.size)
    }

    private fun readFrom(bytes: ByteArray): ByteArray? =
        Wire.readFrame(DataInputStream(ByteArrayInputStream(bytes)))

    // ── the two decode-boundary causes must arrive as DIFFERENT exceptions ─────────

    /**
     * Before 0.8.2.24 this peer answered `400 non_canonical_ecf` for every decode-boundary
     * cause, which is the code-under-the-wrong-reason defect §5.2a names: a mis-keyed
     * `included` entry carries no tag, its encoding is canonical, and *re-encode* is not the
     * caller's remedy.
     */
    @Test
    fun decodeBoundarySplitsResolutionIntegrityFromStructure() {
        val good = Entity.make("primitive/any", Cbor.map("x", EcfValue.IntVal.of(1L)))
        val root = Wire.makeExecute("t1", "system/tree", "get", Wire.emptyParams())

        // A key that does not bind to the entity filed under it (§3.1 / §1.8).
        assertFailsWith<HashMismatchException> {
            Envelope.ofCbor(envelopeCbor(root, ByteArray(33) { 0x11 }, good))
        }

        // A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same
        // class (§1.8 item 1) and takes the same code. The digest is garbage under a VALID
        // format prefix (0x00 = ecfv1-sha256): a garbage FORMAT byte is a different refusal
        // (§1.2's `unsupported_content_hash_format`) and would let this case pass for a
        // reason that is not the one under test.
        val wrongDigest = ByteArray(33) { 0x22 }.also { it[0] = 0x00 }
        assertFailsWith<HashMismatchException> {
            Entity.ofCbor(
                Cbor.map(
                    "type", "primitive/any",
                    "data", Cbor.map("x", EcfValue.IntVal.of(1L)),
                    "content_hash", Cbor.bytes(wrongDigest),
                ),
            )
        }

        // STRUCTURAL faults stay a plain IllegalArgumentException -> invalid_request. THIS
        // IS THE DISCRIMINATOR: if both causes collapsed into one exception the split above
        // would pass vacuously.
        val structural = assertFailsWith<IllegalArgumentException> {
            Entity.ofCbor(Cbor.map("data", EcfValue.IntVal.of(1L)))
        }
        assertFalse(structural is HashMismatchException)
        assertEquals("invalid_request", Transport.preAdmissionRefusal(structural).second)

        // A CBOR tag keeps `non_canonical_ecf`, and the sealed ERROR VALUE is what says so —
        // not the message. 0xc1 is a major-type-6 tag.
        val tag = CanonicalCbor.decode(byteArrayOf(0xc1.toByte(), 0x00))
        assertTrue(tag is EcfResult.Err && tag.error is EntityError.CodecError.TagRejected)

        // A NON-tag codec fault must NOT be a TagRejected, or the arm above is vacuous.
        // 0x41 declares a 1-byte byte string and supplies none.
        val truncated = CanonicalCbor.decode(byteArrayOf(0x41))
        assertTrue(truncated is EcfResult.Err)
        assertFalse(truncated.error is EntityError.CodecError.TagRejected)

        // The envelope decoder must CARRY those values rather than flatten them, or the
        // classification above is about the codec and not about the wire.
        assertEquals(
            "non_canonical_ecf",
            Transport.preAdmissionRefusal(
                assertFailsWith<CodecRefusalException> {
                    Wire.envelopeOfFrame(byteArrayOf(0xc1.toByte(), 0x00))
                },
            ).second,
        )
        assertEquals(
            "invalid_request",
            Transport.preAdmissionRefusal(
                assertFailsWith<CodecRefusalException> { Wire.envelopeOfFrame(byteArrayOf(0x41)) },
            ).second,
        )

        // And the WELL-FORMED envelope must still decode, or every case above is satisfied
        // by a decoder that refuses everything.
        val ok = Envelope.ofCbor(envelopeCbor(root, good.hash(), good))
        assertNotNull(ok.includedGet(good.hash()))
    }

    private fun envelopeCbor(root: Entity, key: ByteArray, included: Entity): EcfValue.MapVal =
        Cbor.map(
            "root", root.toCbor(),
            "included", EcfValue.MapVal(listOf(EcfValue.Entry(EcfValue.Bytes(key), included.toCbor()))),
        )

    // ── the FRAME obligation, over a real socket ───────────────────────────────────

    /**
     * §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): *"400 invalid_request,
     * coded frame; MAY then close. NOT a bare close — that is indistinguishable from a
     * network fault."* §3.3 previously read "the connection MUST be closed", assigning no
     * code and requiring no frame; this peer did something weaker still and wrote NOTHING at
     * all, which is §4.11's silent-drop failure. §9.1's floor row that MANDATED the bare
     * close was REPLACED at the same revision (N18).
     */
    @Test
    fun nonExecuteRootIsAnsweredAndTheConnectionSurvives() {
        val responder = Peer.create(seed(0x61), openGrants = true)
        Transport.startListener(responder, 0).use { listener ->
            Socket("127.0.0.1", listener.port).use { sock ->
                sock.soTimeout = 10_000
                val root = Entity.make("primitive/any", Cbor.map("request_id", "x-1"))

                writeFrame(sock.getOutputStream(), Envelope(root))
                val r1 = readEnvelope(sock.getInputStream())
                assertEquals("system/protocol/execute/response", r1.root.type)
                assertEquals(400, Wire.responseStatus(r1))
                assertEquals("invalid_request", Wire.responseResult(r1)?.text("code"))
                // Correlated where the id is recoverable; §4.11's best-effort uncorrelated
                // frame is the fallback, not the default.
                assertEquals("x-1", r1.root.text("request_id"))

                // THE CONNECTION SURVIVES. §4.11 leaves the close to the peer, and closing
                // here would cost every ADMITTED in-flight request on a multiplexed
                // connection its response. A second bad root answered is what proves the
                // reader did not break out.
                writeFrame(sock.getOutputStream(), Envelope(root))
                assertEquals("x-1", readEnvelope(sock.getInputStream()).root.text("request_id"))
            }
        }
    }

    /**
     * The two framing arms, each with its own code. Both used to close with NO coded frame,
     * which is §4.11's second named non-conformant behaviour — indistinguishable from a
     * network fault.
     */
    @Test
    fun framingRefusalsPutACodedFrameOnTheWire() {
        val arms = listOf(
            // A length prefix of 0x02000000 = 32 MiB, over the 16 MiB bound.
            Triple(byteArrayOf(0x02, 0x00, 0x00, 0x00), 413, "payload_too_large"),
            // A prefix declaring 16 bytes followed by 2, then FIN.
            Triple(byteArrayOf(0x00, 0x00, 0x00, 0x10, 0xa1.toByte(), 0x00), 400, "invalid_request"),
        )
        for ((bytes, status, code) in arms) {
            val responder = Peer.create(seed(0x62), openGrants = true)
            Transport.startListener(responder, 0).use { listener ->
                Socket("127.0.0.1", listener.port).use { sock ->
                    sock.soTimeout = 10_000
                    sock.getOutputStream().write(bytes)
                    sock.getOutputStream().flush()
                    // Half-close so the truncated arm becomes knowable at end-of-stream while
                    // the peer can still write its answer.
                    sock.shutdownOutput()

                    val r = readEnvelope(sock.getInputStream())
                    assertEquals(status, Wire.responseStatus(r))
                    assertEquals(code, Wire.responseResult(r)?.text("code"))
                    // §4.11's best-effort UNCORRELATED form: no request_id can be recovered
                    // from a frame whose body never arrived, and guessing one would correlate
                    // the refusal to somebody else's in-flight request.
                    assertEquals("", r.root.text("request_id"))
                }
            }
        }
    }

    private fun writeFrame(out: OutputStream, env: Envelope) {
        val payload = Wire.frameOfEnvelope(env)
        val d = DataOutputStream(out)
        d.writeInt(payload.size)
        d.write(payload)
        d.flush()
    }

    private fun readEnvelope(input: InputStream): Envelope {
        val d = DataInputStream(input)
        val payload = ByteArray(d.readInt())
        d.readFully(payload)
        return Wire.envelopeOfFrame(payload)
    }
}
