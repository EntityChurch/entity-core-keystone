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
        int len;
        try {
            len = in.readInt();
        } catch (EOFException eof) {
            return null;
        } catch (IOException e) {
            return null;
        }
        if (len < 0 || len > MAX_FRAME) {
            throw new EntityTransportException("frame length out of bounds: " + len);
        }
        byte[] payload = new byte[len];
        try {
            in.readFully(payload);
        } catch (IOException e) {
            throw new EntityTransportException("truncated frame", e);
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
