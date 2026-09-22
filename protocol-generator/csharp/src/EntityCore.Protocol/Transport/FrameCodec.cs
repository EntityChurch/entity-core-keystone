using System.Buffers.Binary;

namespace EntityCore.Protocol.Transport;

/// <summary>
/// TCP wire framing (V7 §1.6): a 4-byte big-endian length prefix followed by that
/// many bytes of CBOR payload. A default 16 MiB frame limit bounds inbound
/// allocation (§1.6 SHOULD).
/// </summary>
internal static class FrameCodec
{
    /// <summary>Default maximum frame payload size (§1.6) — bounds inbound allocation.</summary>
    public const int DefaultMaxFrameBytes = 16 * 1024 * 1024;

    /// <summary>
    /// The <c>(status, code, message)</c> §4.11 (0.8.2.25) assigns a pre-admission
    /// failure's CAUSE.
    /// <para>
    /// <em>"The frame obligation belongs to the class; the CODE belongs to the cause
    /// <c>[MUST]</c>"</em> — a single code for the class would answer an honest caller
    /// under the wrong reason and send them to the wrong layer.
    /// </para>
    /// <list type="table">
    /// <item><term>connect-auth proof-of-possession</term><description><c>401 authentication_failed</c> — the connect handler's, not this function's</description></item>
    /// <item><term>envelope over the configured max</term><description><c>413 payload_too_large</c> (§4.10(a), N14)</description></item>
    /// <item><term>resolution integrity (mis-keyed <c>included</c>)</term><description><c>400 hash_mismatch</c> (§5.2a, §1.8)</description></item>
    /// <item><term>framing / never becomes an Envelope</term><description><c>400 invalid_request</c> (§4.7, §4.11)</description></item>
    /// <item><term>root is neither EXECUTE nor EXECUTE_RESPONSE</term><description><c>400 invalid_request</c> — in the reader, not here</description></item>
    /// </list>
    /// <para>
    /// THE TAG ARM KEEPS <c>non_canonical_ecf</c> AND THAT IS DELIBERATE. §4.11 rules that
    /// code non-conformant <em>"on the framing arm"</em> and gives its reason in the same
    /// sentence: <c>ENTITY-CBOR-ENCODING</c> <em>"defines that code for CBOR tag-policy
    /// violations specifically"</em>, which that document still MUSTs at decode time (§6.3).
    /// The two rows are disjoint by CAUSE rather than in conflict: a tag in a DATA-FIELD
    /// position is the policy violation with its own code, while a tag in the fixed envelope
    /// or entity-wrapper maps is a structurally invalid frame — i.e. the framing arm.
    /// Everything else this decoder calls non-canonical (a non-minimal head, an indefinite
    /// length, mis-ordered keys) is genuinely "non-canonical CBOR that never becomes an
    /// Envelope" and takes <c>invalid_request</c>.
    /// </para>
    /// <para>
    /// ORDER IS LOAD-BEARING: <see cref="HashMismatchException"/> is a subclass of
    /// <see cref="EntityProtocolException"/>, so the specific arm must be tested first or
    /// it can never be reached.
    /// </para>
    /// <para>
    /// The messages are a FIXED TABLE, never the internal exception text: a wire-visible
    /// string must stay ASCII (two peers in this cohort have been killed at runtime by a
    /// non-ASCII byte in an encoded string, on two unrelated compilers), and nothing here
    /// echoes attacker-supplied bytes back.
    /// </para>
    /// </summary>
    public static (int Status, string Code, string Message) PreAdmissionRefusal(Exception e) => e switch
    {
        FrameTooLargeException => (Model.Status.PayloadTooLarge, "payload_too_large",
            "inbound frame exceeds the configured maximum size"),
        HashMismatchException => (Model.Status.BadRequest, "hash_mismatch",
            "an entity was addressed by a hash that does not bind to it"),
        EntityCodecException { TagRejected: true } => (Model.Status.BadRequest, "non_canonical_ecf",
            "CBOR tags are forbidden anywhere in an entity data field"),
        _ => (Model.Status.BadRequest, "invalid_request", "frame did not decode into an envelope"),
    };

    /// <summary>
    /// Whether a <see cref="ReadFrameAsync"/> failure is a §4.11 REFUSAL owed a coded frame
    /// rather than an ordinary end of connection. A closed or reset socket is not a refusal
    /// of anything and there is nobody left to answer.
    /// </summary>
    public static bool FramingRefusal(Exception e) =>
        e is FrameTooLargeException or TruncatedFrameException;

    /// <summary>Write a single length-prefixed frame.</summary>
    public static async Task WriteFrameAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        byte[] prefix = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(prefix, (uint)payload.Length);
        await stream.WriteAsync(prefix, ct).ConfigureAwait(false);
        await stream.WriteAsync(payload, ct).ConfigureAwait(false);
        await stream.FlushAsync(ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Read a single length-prefixed frame.
    /// <para>
    /// Returns null ONLY on a clean EOF at a frame boundary (the peer closed and owes
    /// nothing). A stream that ends MID-FRAME throws <see cref="TruncatedFrameException"/>,
    /// and an over-limit length prefix throws <see cref="FrameTooLargeException"/> — both
    /// are §4.11 REFUSALS owed a coded response, and the read loop emits it.
    /// </para>
    /// </summary>
    public static async Task<byte[]?> ReadFrameAsync(Stream stream, int maxFrameBytes, CancellationToken ct)
    {
        byte[] prefix = new byte[4];
        int read = await ReadAtMostAsync(stream, prefix, ct).ConfigureAwait(false);
        if (read == 0)
        {
            return null; // clean EOF at boundary
        }
        if (read < 4)
        {
            // §4.11's framing arm names this input outright — "a length prefix that never
            // completes". A partial prefix is a REFUSAL, not a hangup: the caller began a
            // frame and did not finish it.
            throw new TruncatedFrameException("stream ended inside a frame length prefix");
        }

        uint length = BinaryPrimitives.ReadUInt32BigEndian(prefix);
        if (length > (uint)maxFrameBytes)
        {
            throw new FrameTooLargeException($"frame length {length} exceeds limit {maxFrameBytes}");
        }

        byte[] payload = new byte[length];
        try
        {
            await stream.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
        }
        catch (EndOfStreamException e)
        {
            // A prefix declaring `n` bytes followed by fewer. The CLEAN-EOF case is the one
            // above and is owed nothing; this one is a refusal and is owed a coded frame.
            // Both look like "the socket ended" to the stream, so the distinction can only
            // be made here, where the frame boundary is known — and getting it wrong in the
            // other direction would answer a 400 to every peer that simply hangs up.
            throw new TruncatedFrameException($"stream ended mid-frame, {length} byte(s) declared", e);
        }
        return payload;
    }

    /// <summary>Read up to <paramref name="buffer"/>.Length bytes; returns count (0 = immediate EOF).</summary>
    private static async Task<int> ReadAtMostAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        int total = 0;
        while (total < buffer.Length)
        {
            int n = await stream.ReadAsync(buffer[total..], ct).ConfigureAwait(false);
            if (n == 0)
            {
                break;
            }
            total += n;
        }
        return total;
    }
}

/// <summary>
/// A length prefix over the connection's bound (§4.10(a)).
/// <para>
/// Distinguished from <see cref="TruncatedFrameException"/> because §4.11 gives the two
/// DIFFERENT codes: this one is <c>413 payload_too_large</c>, and since 0.8.2.25 (N14)
/// emitting it is a MUST rather than a SHOULD — the condition is detected at the length
/// prefix with the connection intact and nothing spent, so the permissive mood had nothing
/// to license.
/// </para>
/// </summary>
internal sealed class FrameTooLargeException : EntityProtocolException
{
    /// <summary>Create an over-limit-frame exception with a message.</summary>
    public FrameTooLargeException(string message)
        : base(message)
    {
    }
}

/// <summary>
/// A frame that never completed: a prefix declaring <c>n</c> bytes followed by fewer, or a
/// partial length prefix. §4.11's framing arm names this input outright — <em>"un-parseable,
/// truncated or non-canonical CBOR, or a length prefix that never completes"</em> →
/// <c>400 invalid_request</c>.
/// <para>
/// A SEPARATE TYPE FROM A CLEAN EOF because the two are different events and the stream
/// collapses them. A clean EOF at a FRAME BOUNDARY is an ordinary close and is owed nothing;
/// a stream that ends MID-FRAME is a REFUSAL and is owed a coded frame. This reader
/// previously reported both as a bare <c>EndOfStreamException</c> that ended the loop in
/// silence, which is §4.11's other named non-conformant behaviour.
/// </para>
/// </summary>
internal sealed class TruncatedFrameException : EntityProtocolException
{
    /// <summary>Create a truncated-frame exception with a message.</summary>
    public TruncatedFrameException(string message)
        : base(message)
    {
    }

    /// <summary>Create a truncated-frame exception with a message and an inner cause.</summary>
    public TruncatedFrameException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}
