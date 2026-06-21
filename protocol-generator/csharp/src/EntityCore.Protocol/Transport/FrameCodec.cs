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
    /// Read a single length-prefixed frame. Returns null on a clean EOF at a frame
    /// boundary (peer closed). Throws on a truncated frame or an over-limit length.
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
            throw new EndOfStreamException("truncated frame length prefix");
        }

        uint length = BinaryPrimitives.ReadUInt32BigEndian(prefix);
        if (length > (uint)maxFrameBytes)
        {
            throw new EntityProtocolException($"frame length {length} exceeds limit {maxFrameBytes}");
        }

        byte[] payload = new byte[length];
        await stream.ReadExactlyAsync(payload, ct).ConfigureAwait(false);
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
