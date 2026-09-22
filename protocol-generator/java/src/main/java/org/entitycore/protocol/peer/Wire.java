package org.entitycore.protocol.peer;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import org.entitycore.protocol.codec.CanonicalCbor;
import org.entitycore.protocol.codec.EcfValue;
import org.entitycore.protocol.codec.EntityCodecException;

/**
 * Wire framing (§1.6) + the two message builders (§3.2 EXECUTE, §3.3
 * EXECUTE_RESPONSE). Frame := {@code [4-byte BE length][CBOR payload]}; the payload is
 * a CBOR-encoded system/protocol/envelope (§3.1).
 *
 * <p>Only EXECUTE and EXECUTE_RESPONSE are wire message types (§3.3). hello /
 * authenticate are OPERATIONS on system/protocol/connect, not message types — any
 * other root type is ignored on the server side (the dispatcher returns no response).
 */
public final class Wire {
    private Wire() { }

    /** §1.6 SHOULD bound — 16 MiB. */
    public static final int MAX_FRAME = 16 * 1024 * 1024;

    // ── frame read/write ────────────────────────────────────────────────────────

    /** Read one length-prefixed frame; return its CBOR payload bytes. Returns null on
     *  a clean EOF at a frame boundary (the connection closed). */
    public static byte[] readFrame(DataInputStream in) throws EntityTransportException {
        // READ THE PREFIX BYTE BY BYTE, because §4.11 makes "no bytes" and "some bytes"
        // DIFFERENT EVENTS and `DataInputStream.readInt` collapses them into one
        // EOFException. A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed
        // nothing; a stream that ends inside the length prefix is a framing REFUSAL —
        // §4.11 names "a length prefix that never completes" outright — and is owed a
        // coded frame. The distinction can only be made here, where the boundary is known.
        byte[] hdr = new byte[4];
        int got = 0;
        try {
            while (got < 4) {
                int n = in.read(hdr, got, 4 - got);
                if (n < 0) {
                    break;
                }
                got += n;
            }
        } catch (IOException e) {
            return null;                        // the socket went away mid-read
        }
        if (got == 0) {
            return null;                        // clean EOF at a frame boundary
        }
        if (got < 4) {
            throw new TruncatedFrameException("stream ended inside a frame length prefix", null);
        }
        int len = ((hdr[0] & 0xff) << 24) | ((hdr[1] & 0xff) << 16)
                | ((hdr[2] & 0xff) << 8) | (hdr[3] & 0xff);
        if (len < 0 || len > MAX_FRAME) {
            // §4.10(a), mood raised to MUST at 0.8.2.25 (N14): the condition is detected
            // at the length prefix with the connection intact and nothing spent, so the
            // permissive mood had nothing to license. The read loop answers `413
            // payload_too_large` and THEN closes.
            throw new FrameTooLargeException("frame length out of bounds: " + len);
        }
        byte[] payload = new byte[len];
        try {
            in.readFully(payload);
        } catch (IOException e) {
            // A prefix declaring `n` bytes followed by fewer. The CLEAN-EOF case is the
            // `readInt` arm above and is owed nothing; this one is a §4.11 REFUSAL and is
            // owed a coded frame. Both look like "the socket ended" to the stream, so the
            // distinction can only be made here, where the frame boundary is known — and
            // getting it wrong in the other direction would answer a 400 to every peer
            // that simply hangs up.
            throw new TruncatedFrameException("truncated frame", e);
        }
        return payload;
    }

    /** Write {@code payload} as a length-prefixed frame and flush. Caller serializes
     *  concurrent writers on the same stream. */
    public static void writeFrame(OutputStream out, byte[] payload) throws EntityTransportException {
        int len = payload.length;
        byte[] hdr = new byte[] {
                (byte) (len >>> 24), (byte) (len >>> 16), (byte) (len >>> 8), (byte) len
        };
        try {
            out.write(hdr);
            out.write(payload);
            out.flush();
        } catch (IOException e) {
            throw new EntityTransportException("frame write failed", e);
        }
    }

    // ── envelope <-> frame ────────────────────────────────────────────────────────

    public static Envelope envelopeOfFrame(byte[] payload) throws EntityCodecException {
        EcfValue v = CanonicalCbor.decode(payload);
        if (!(v instanceof EcfValue.Map m)) {
            throw new org.entitycore.protocol.codec.NonCanonicalEcfException("frame: not a map");
        }
        return Envelope.ofCbor(m);
    }

    public static byte[] frameOfEnvelope(Envelope env) throws EntityCodecException {
        return CanonicalCbor.encode(env.toCbor());
    }

    // ── EXECUTE builder (§3.2) ─────────────────────────────────────────────────────

    /** Build an EXECUTE entity. {@code author}/{@code capability} are 33-byte hashes;
     *  {@code resource} is a cbor-map ({@code {targets:[...]}}) or null. */
    public static Entity makeExecute(String requestId, String uri, String operation, Entity params,
                                     byte[] author, byte[] capability, EcfValue.Map resource) {
        List<EcfValue.Map.Entry> pairs = new ArrayList<>();
        pairs.add(entry("request_id", new EcfValue.Text(requestId)));
        pairs.add(entry("uri", new EcfValue.Text(uri)));
        pairs.add(entry("operation", new EcfValue.Text(operation)));
        pairs.add(entry("params", params.toCbor()));
        if (author != null) {
            pairs.add(entry("author", new EcfValue.Bytes(author)));
        }
        if (capability != null) {
            pairs.add(entry("capability", new EcfValue.Bytes(capability)));
        }
        if (resource != null) {
            pairs.add(entry("resource", resource));
        }
        return Entity.make("system/protocol/execute", new EcfValue.Map(pairs));
    }

    /** Build an EXECUTE with no author/capability/resource (the handshake legs). */
    public static Entity makeExecute(String requestId, String uri, String operation, Entity params) {
        return makeExecute(requestId, uri, operation, params, null, null, null);
    }

    // ── EXECUTE_RESPONSE builder (§3.3) ─────────────────────────────────────────────

    public static Entity makeResponse(String requestId, int status, Entity result) {
        return Entity.make("system/protocol/execute/response",
                EcfValue.Map.of(
                        "request_id", new EcfValue.Text(requestId),
                        "status", EcfValue.Int.of(status),
                        "result", result.toCbor()));
    }

    // ── error result + empty params + resource target ───────────────────────────────

    public static Entity errorResult(String code, String message) {
        EcfValue.Map data = (message != null)
                ? EcfValue.Map.of("code", new EcfValue.Text(code), "message", new EcfValue.Text(message))
                : EcfValue.Map.of("code", new EcfValue.Text(code));
        return Entity.make("system/protocol/error", data);
    }

    /** Empty-params (§3.2): a primitive/any whose data is the canonical empty map. */
    public static Entity emptyParams() {
        return Entity.make("primitive/any", Cbor.emptyMap());
    }

    /** Build a resource cbor-map {@code {targets: [...]}}. */
    public static EcfValue.Map resourceTarget(String... targets) {
        return EcfValue.Map.of("targets", Cbor.textArray(targets));
    }

    // ── response decode helpers (initiator side) ─────────────────────────────────────

    public static int responseStatus(Envelope env) {
        BigInteger s = env.root().uint("status");
        return (s != null) ? s.intValue() : 0;
    }

    public static Entity responseResult(Envelope env) {
        EcfValue.Map rc = env.root().mapField("result");
        return (rc != null) ? Entity.ofCbor(rc) : null;
    }

    private static EcfValue.Map.Entry entry(String key, EcfValue value) {
        return new EcfValue.Map.Entry(new EcfValue.Text(key), value);
    }
}
