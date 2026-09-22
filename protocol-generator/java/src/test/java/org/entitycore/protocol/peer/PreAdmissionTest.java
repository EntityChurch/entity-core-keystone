package org.entitycore.protocol.peer;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.Arrays;
import java.util.List;

import org.entitycore.protocol.codec.CanonicalCbor;
import org.entitycore.protocol.codec.EcfValue;
import org.entitycore.protocol.codec.TagRejectedException;
import org.junit.jupiter.api.Test;

/**
 * §4.11 pre-admission refusals (0.8.2.25).
 *
 * <p>§4.11's rule has two parts and they fail differently. <em>"The frame obligation belongs
 * to the class"</em> is wire-visible and is driven over a socket below;
 * <em>"the CODE belongs to the cause {@code [MUST]}"</em> is a mapping, and a mapping is
 * exactly the thing that regresses silently when a new failure joins an existing branch, so
 * it is pinned at the unit level.
 *
 * <p>The pinned check set (778) has NO vector on this surface, which is why the coverage is
 * authored here rather than inherited. Both of §4.11's separately-named non-conformant
 * behaviours were present on this peer at HEAD: DROPPING the frame (the non-EXECUTE root,
 * which produced no response at all) and CLOSING with no coded frame (the oversize and
 * truncated arms).
 */
final class PreAdmissionTest {

    private static byte[] seed(int b) {
        byte[] s = new byte[32];
        Arrays.fill(s, (byte) b);
        return s;
    }

    // ── the CODE belongs to the CAUSE (§4.11's table) ──────────────────────────────

    @Test
    void preAdmissionRefusalCodeIsTheCauses() {
        // §4.10(a), mood raised to MUST at 0.8.2.25 (N14).
        assertArrayEquals(new String[] { "413", "payload_too_large",
                "inbound frame exceeds the configured maximum size" },
                Transport.preAdmissionRefusal(new FrameTooLargeException("x")));
        // §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
        // `non_canonical_ecf` NON-CONFORMANT here.
        assertEquals("hash_mismatch", Transport.preAdmissionRefusal(new HashMismatchException("x"))[1]);
        // ENTITY-CBOR-ENCODING §5.4 — the tag-policy arm keeps its own code.
        assertEquals("non_canonical_ecf",
                Transport.preAdmissionRefusal(new TagRejectedException("x"))[1]);
        // §4.7 / §4.11 framing arm: bytes that never become an Envelope.
        assertEquals("invalid_request",
                Transport.preAdmissionRefusal(new TruncatedFrameException("x", null))[1]);
        assertEquals("invalid_request",
                Transport.preAdmissionRefusal(new IllegalArgumentException("not an envelope"))[1]);
        assertEquals("400", Transport.preAdmissionRefusal(new IllegalArgumentException("x"))[0]);
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
    void readFrameDistinguishesCloseFromTruncation() throws Exception {
        assertNull(readFrom(new byte[0]), "a clean close at a frame boundary");
        assertThrows(TruncatedFrameException.class, () -> readFrom(new byte[] { 0, 0 }));
        assertThrows(TruncatedFrameException.class,
                () -> readFrom(new byte[] { 0x00, 0x00, 0x10, 0x00, (byte) 0xa1 }));
        assertThrows(FrameTooLargeException.class,
                () -> readFrom(new byte[] { 0x02, 0x00, 0x00, 0x00 }));   // 32 MiB > 16 MiB

        // A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
        // refused there as bytes that never become an Envelope.
        byte[] empty = readFrom(new byte[] { 0, 0, 0, 0 });
        assertNotNull(empty);
        assertEquals(0, empty.length);
    }

    private static byte[] readFrom(byte[] bytes) throws EntityTransportException {
        return Wire.readFrame(new DataInputStream(new ByteArrayInputStream(bytes)));
    }

    // ── the two decode-boundary causes must arrive as DIFFERENT exceptions ─────────

    /**
     * Before 0.8.2.24 this peer answered {@code 400 non_canonical_ecf} for every
     * decode-boundary cause, which is the code-under-the-wrong-reason defect §5.2a names: a
     * mis-keyed {@code included} entry carries no tag, its encoding is canonical, and
     * <em>re-encode</em> is not the caller's remedy.
     */
    @Test
    void decodeBoundarySplitsResolutionIntegrityFromStructure() {
        Entity good = Entity.make("primitive/any", Cbor.map("x", EcfValue.Int.of(1)));
        Entity root = Wire.makeExecute("t1", "system/tree", "get", Wire.emptyParams());

        // A key that does not bind to the entity filed under it (§3.1 / §1.8).
        byte[] bogusKey = new byte[33];
        Arrays.fill(bogusKey, (byte) 0x11);
        assertThrows(HashMismatchException.class,
                () -> Envelope.ofCbor(envelopeCbor(root, bogusKey, good)));

        // A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same
        // class (§1.8 item 1) and takes the same code.
        byte[] wrongDigest = new byte[33];
        Arrays.fill(wrongDigest, (byte) 0x22);
        wrongDigest[0] = 0x00;                 // a VALID format prefix, a garbage digest
        assertThrows(HashMismatchException.class, () -> Entity.ofCbor(Cbor.map(
                "type", "primitive/any",
                "data", Cbor.map("x", EcfValue.Int.of(1)),
                "content_hash", Cbor.bytes(wrongDigest))));

        // STRUCTURAL faults stay a plain IllegalArgumentException -> invalid_request. THIS
        // IS THE DISCRIMINATOR: if both causes collapsed into one exception the split above
        // would pass vacuously.
        IllegalArgumentException structural = assertThrows(IllegalArgumentException.class,
                () -> Entity.ofCbor(Cbor.map("data", EcfValue.Int.of(1))));
        assertFalse(structural instanceof HashMismatchException);
        assertEquals("invalid_request", Transport.preAdmissionRefusal(structural)[1]);

        // A CBOR tag keeps `non_canonical_ecf`, and the TYPE is what says so — not the
        // message. 0xc1 is a major-type-6 tag.
        Throwable tag = assertThrows(Throwable.class,
                () -> CanonicalCbor.decode(new byte[] { (byte) 0xc1, 0x00 }));
        assertInstanceOf(TagRejectedException.class, tag);
        assertEquals("non_canonical_ecf", Transport.preAdmissionRefusal(tag)[1]);

        // A NON-tag codec fault must NOT be a TagRejectedException, or the arm above is
        // vacuous. 0x41 declares a 1-byte byte string and supplies none.
        Throwable nonCanonical = assertThrows(Throwable.class,
                () -> CanonicalCbor.decode(new byte[] { 0x41 }));
        assertFalse(nonCanonical instanceof TagRejectedException);
        assertEquals("invalid_request", Transport.preAdmissionRefusal(nonCanonical)[1]);

        // And the WELL-FORMED envelope must still decode, or every case above is satisfied
        // by a decoder that refuses everything.
        Envelope ok = Envelope.ofCbor(envelopeCbor(root, good.hash(), good));
        assertNotNull(ok.includedGet(good.hash()));
    }

    private static EcfValue.Map envelopeCbor(Entity root, byte[] key, Entity included) {
        return EcfValue.Map.of(
                "root", root.toCbor(),
                "included", new EcfValue.Map(List.of(
                        new EcfValue.Map.Entry(new EcfValue.Bytes(key), included.toCbor()))));
    }

    // ── the FRAME obligation, over a real socket ───────────────────────────────────

    /**
     * §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): <em>"400
     * invalid_request, coded frame; MAY then close. NOT a bare close — that is
     * indistinguishable from a network fault."</em> §3.3 previously read "the connection
     * MUST be closed", assigning no code and requiring no frame; this peer did something
     * weaker still and wrote NOTHING at all, which is §4.11's silent-drop failure. §9.1's
     * floor row that MANDATED the bare close was REPLACED at the same revision (N18).
     */
    @Test
    void nonExecuteRootIsAnsweredAndTheConnectionSurvives() throws Exception {
        Peer responder = Peer.create(seed(0x61), true, false);
        try (Transport.Listener listener = Transport.startListener(responder, 0);
             Socket sock = new Socket("127.0.0.1", listener.port())) {
            sock.setSoTimeout(10_000);
            Entity root = Entity.make("primitive/any", Cbor.map("request_id", "x-1"));

            writeFrame(sock.getOutputStream(), new Envelope(root));
            Envelope r1 = readEnvelope(sock.getInputStream());
            assertEquals("system/protocol/execute/response", r1.root().type());
            assertEquals(400, Wire.responseStatus(r1));
            assertEquals("invalid_request", Wire.responseResult(r1).text("code"));
            // Correlated where the id is recoverable; §4.11's best-effort uncorrelated frame
            // is the fallback, not the default.
            assertEquals("x-1", r1.root().text("request_id"));

            // THE CONNECTION SURVIVES. §4.11 leaves the close to the peer, and closing here
            // would cost every ADMITTED in-flight request on a multiplexed connection its
            // response. A second bad root answered is what proves the reader did not break.
            writeFrame(sock.getOutputStream(), new Envelope(root));
            assertEquals("x-1", readEnvelope(sock.getInputStream()).root().text("request_id"));
        }
    }

    /**
     * The two framing arms, each with its own code. Both used to close with NO coded frame,
     * which is §4.11's second named non-conformant behaviour — indistinguishable from a
     * network fault.
     */
    @Test
    void framingRefusalsPutACodedFrameOnTheWire() throws Exception {
        Object[][] arms = {
            // A length prefix of 0x02000000 = 32 MiB, over the 16 MiB bound.
            { new byte[] { 0x02, 0x00, 0x00, 0x00 }, 413, "payload_too_large" },
            // A prefix declaring 16 bytes followed by 2, then FIN.
            { new byte[] { 0x00, 0x00, 0x00, 0x10, (byte) 0xa1, 0x00 }, 400, "invalid_request" },
        };
        for (Object[] arm : arms) {
            Peer responder = Peer.create(seed(0x62), true, false);
            try (Transport.Listener listener = Transport.startListener(responder, 0);
                 Socket sock = new Socket("127.0.0.1", listener.port())) {
                sock.setSoTimeout(10_000);
                sock.getOutputStream().write((byte[]) arm[0]);
                sock.getOutputStream().flush();
                // Half-close so the truncated arm becomes knowable at end-of-stream while
                // the peer can still write its answer.
                sock.shutdownOutput();

                Envelope r = readEnvelope(sock.getInputStream());
                assertEquals(arm[1], Wire.responseStatus(r));
                assertEquals(arm[2], Wire.responseResult(r).text("code"));
                // §4.11's best-effort UNCORRELATED form: no request_id can be recovered from
                // a frame whose body never arrived, and guessing one would correlate the
                // refusal to somebody else's in-flight request.
                assertEquals("", r.root().text("request_id"));
            }
        }
    }

    private static void writeFrame(OutputStream out, Envelope env) throws Exception {
        byte[] payload = Wire.frameOfEnvelope(env);
        DataOutputStream d = new DataOutputStream(out);
        d.writeInt(payload.length);
        d.write(payload);
        d.flush();
    }

    private static Envelope readEnvelope(InputStream in) throws Exception {
        DataInputStream d = new DataInputStream(in);
        byte[] payload = new byte[d.readInt()];
        d.readFully(payload);
        return Wire.envelopeOfFrame(payload);
    }

}
