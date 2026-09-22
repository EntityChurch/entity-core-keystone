using System.Buffers.Binary;
using System.Net.Sockets;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// §4.11 pre-admission refusals (0.8.2.25).
/// <para>
/// §4.11's rule has two parts and they fail differently. <em>"The frame obligation belongs
/// to the class"</em> is wire-visible and is driven over a socket below;
/// <em>"the CODE belongs to the cause <c>[MUST]</c>"</em> is a mapping, and a mapping is
/// exactly the thing that regresses silently when a new failure joins an existing branch,
/// so it is pinned at the unit level.
/// </para>
/// <para>
/// The pinned check set (778) has NO vector on this surface, which is why the coverage is
/// authored here rather than inherited. Both of §4.11's separately-named non-conformant
/// behaviours were present on this peer at HEAD: DROPPING the frame (the un-salvageable
/// decode arm) and CLOSING with no coded frame (the oversize and truncated arms, and the
/// non-EXECUTE root's bare <c>break</c>).
/// </para>
/// </summary>
public sealed class PreAdmissionTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    // ── the CODE belongs to the CAUSE (§4.11's table) ──────────────────────────────

    [Fact]
    public void PreAdmissionRefusal_CodeIsTheCauses()
    {
        // §4.10(a), mood raised to MUST at 0.8.2.25 (N14).
        Assert.Equal((413, "payload_too_large"), StatusCode(new FrameTooLargeException("x")));
        // §5.2a / §1.8 resolution integrity. 0.8.2.24 pins this and rules
        // `non_canonical_ecf` NON-CONFORMANT here.
        Assert.Equal((400, "hash_mismatch"), StatusCode(new HashMismatchException("x")));
        // ENTITY-CBOR-ENCODING §5.4 — the tag-policy arm keeps its own code.
        Assert.Equal((400, "non_canonical_ecf"),
            StatusCode(new EntityCodecException("x") { TagRejected = true }));
        // §4.7 / §4.11 framing arm: bytes that never become an Envelope.
        Assert.Equal((400, "invalid_request"), StatusCode(new TruncatedFrameException("x")));
        Assert.Equal((400, "invalid_request"), StatusCode(new EntityCodecException("non-canonical CBOR")));
        Assert.Equal((400, "invalid_request"), StatusCode(new EntityProtocolException("not an envelope")));

        // `FramingRefusal` separates "owed a frame" from "the connection simply ended".
        Assert.True(FrameCodec.FramingRefusal(new FrameTooLargeException("x")));
        Assert.True(FrameCodec.FramingRefusal(new TruncatedFrameException("x")));
        Assert.False(FrameCodec.FramingRefusal(new EndOfStreamException()));
        Assert.False(FrameCodec.FramingRefusal(new IOException("reset")));
    }

    private static (int, string) StatusCode(Exception e)
    {
        (int status, string code, _) = FrameCodec.PreAdmissionRefusal(e);
        return (status, code);
    }

    // ── a clean close is not a refusal; a truncation is ────────────────────────────

    /// <summary>
    /// A clean EOF at a frame boundary is an ordinary close and is owed nothing; a stream
    /// that ends MID-FRAME is a §4.11 framing refusal and is owed a coded frame. The
    /// stream collapses the two, so the distinction has to be made where the frame boundary
    /// is known — and getting it wrong in the other direction answers a 400 to every peer
    /// that simply hangs up.
    /// </summary>
    [Fact]
    public async Task ReadFrame_DistinguishesCloseFromTruncation()
    {
        Assert.Null(await ReadFrom(System.Array.Empty<byte>()));                          // clean close
        await Assert.ThrowsAsync<TruncatedFrameException>(() => ReadFrom(new byte[] { 0, 0 }));
        await Assert.ThrowsAsync<TruncatedFrameException>(
            () => ReadFrom(new byte[] { 0x00, 0x00, 0x10, 0x00, 0xa1 }));                 // prefix > body
        await Assert.ThrowsAsync<FrameTooLargeException>(
            () => ReadFrom(new byte[] { 0x02, 0x00, 0x00, 0x00 }));                       // 32 MiB > 16 MiB

        // A ZERO-LENGTH frame is COMPLETE, not truncated: it reaches the decoder and is
        // refused there as bytes that never become an Envelope.
        byte[]? empty = await ReadFrom(new byte[] { 0, 0, 0, 0 });
        Assert.NotNull(empty);
        Assert.Empty(empty!);
    }

    private static Task<byte[]?> ReadFrom(byte[] bytes) =>
        FrameCodec.ReadFrameAsync(new MemoryStream(bytes), FrameCodec.DefaultMaxFrameBytes, CancellationToken.None);

    // ── the two decode-boundary causes must arrive as DIFFERENT exceptions ─────────

    /// <summary>
    /// Before 0.8.2.24 this peer answered <c>400 non_canonical_ecf</c> for every
    /// decode-boundary cause, which is the code-under-the-wrong-reason defect §5.2a names:
    /// a mis-keyed <c>included</c> entry carries no tag, its encoding is canonical, and
    /// <em>re-encode</em> is not the caller's remedy.
    /// </summary>
    [Fact]
    public void DecodeBoundary_SplitsResolutionIntegrityFromStructure()
    {
        Entity good = Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(("x", Ecf.Uint(1))));
        EcfValue root = Ecf.Map(
            ("type", Ecf.Text(TypeNames.Execute)),
            ("data", Ecf.Map(
                ("request_id", Ecf.Text("t1")),
                ("uri", Ecf.Text("system/tree")),
                ("operation", Ecf.Text("get")),
                ("params", new EcfValue.PreEncoded(good.WireBytes)))));

        EcfValue Envelope1(EcfValue key, EcfValue entity) => new EcfValue.Map(new[]
        {
            new KeyValuePair<EcfValue, EcfValue>(Ecf.Text("root"), RootWrapper(root)),
            new KeyValuePair<EcfValue, EcfValue>(Ecf.Text("included"), new EcfValue.Map(new[]
            {
                new KeyValuePair<EcfValue, EcfValue>(key, entity),
            })),
        });

        // A key that does not bind to the entity filed under it (§3.1 / §1.8).
        Assert.Throws<HashMismatchException>(() => Envelope.Decode(
            CanonicalCbor.Encode(Envelope1(Ecf.Bytes(Filled(0x11)), Decoded(good)))));

        // A CORRECTLY keyed entry whose entity carries a wrong content_hash is the same
        // class (§1.8 item 1) and takes the same code. The digest is garbage under a VALID
        // format prefix (0x00 = ecfv1-sha256): a garbage FORMAT byte is a different
        // refusal (§1.2's `unsupported_content_hash_format`) and would let this case pass
        // for a reason that is not the one under test.
        byte[] wrongDigest = Filled(0x22);
        wrongDigest[0] = 0x00;
        EcfValue tampered = Ecf.Map(
            ("type", Ecf.Text(good.Type)),
            ("data", Ecf.Map(("x", Ecf.Uint(1)))),
            ("content_hash", Ecf.Bytes(wrongDigest)));
        Assert.Throws<HashMismatchException>(() => Entity.FromDecoded(tampered));

        // STRUCTURAL faults stay a plain protocol fault -> invalid_request. THIS IS THE
        // DISCRIMINATOR: if both causes collapsed into one exception the split above would
        // pass vacuously.
        EntityProtocolException structural = Assert.Throws<EntityProtocolException>(
            () => Entity.FromDecoded(Ecf.Map(("data", Ecf.Uint(1)))));
        Assert.IsNotType<HashMismatchException>(structural);
        Assert.Equal((400, "invalid_request"), StatusCode(structural));

        // A CBOR tag keeps `non_canonical_ecf`, and the marker is what says so — not the
        // message. 0xc1 is a major-type-6 tag.
        EntityCodecException tag = Assert.Throws<EntityCodecException>(
            () => CanonicalCbor.Decode(new byte[] { 0xc1, 0x00 }));
        Assert.True(tag.TagRejected);
        Assert.Equal((400, "non_canonical_ecf"), StatusCode(tag));

        // A NON-tag codec fault must NOT carry the marker, or the arm above is vacuous.
        // 0x1801 is a non-minimal integer head.
        EntityCodecException nonCanonical = Assert.Throws<EntityCodecException>(
            () => CanonicalCbor.Decode(new byte[] { 0x18, 0x01 }));
        Assert.False(nonCanonical.TagRejected);

        // And the WELL-FORMED envelope must still decode, or every case above is satisfied
        // by a decoder that refuses everything.
        Envelope ok = Envelope.Decode(
            CanonicalCbor.Encode(Envelope1(Ecf.Bytes(good.ContentHash), Decoded(good))));
        Assert.True(ok.Included.ContainsKey(good.ContentHashHex));
    }

    private static byte[] Filled(byte b) => Enumerable.Repeat(b, 33).ToArray();

    private static EcfValue Decoded(Entity e) => CanonicalCbor.Decode(e.WireBytes);

    /// <summary>Wrap a <c>{type, data}</c> map into a full entity by authoring its hash.</summary>
    private static EcfValue RootWrapper(EcfValue typeAndData) => Decoded(Entity.Create(
        Ecf.RequireText(typeAndData, "type"), Ecf.Require(typeAndData, "data")));

    // ── the FRAME obligation, over a real socket ───────────────────────────────────

    /// <summary>
    /// §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): <em>"400
    /// invalid_request, coded frame; MAY then close. NOT a bare close — that is
    /// indistinguishable from a network fault."</em> §3.3 previously read "the connection
    /// MUST be closed", assigning no code and requiring no frame, and this loop did exactly
    /// that: a bare <c>break</c>. §9.1's floor row that MANDATED the bare close was
    /// REPLACED at the same revision (N18).
    /// </summary>
    [Fact]
    public async Task NonExecuteRoot_IsAnsweredAndTheConnectionSurvives()
    {
        await using var responder = new Peer(seedPolicy: SeedPolicy.DebugOpen());
        responder.ListenAsync(0);
        using var client = new TcpClient();
        await client.ConnectAsync("127.0.0.1", responder.Port);
        NetworkStream stream = client.GetStream();

        Entity root = Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(("request_id", Ecf.Text("x-1"))));
        await WriteFrame(stream, new Envelope(root, System.Array.Empty<Entity>()).Encode());

        Envelope response = await ReadEnvelope(stream);
        Assert.Equal(TypeNames.ExecuteResponse, response.Root.Type);
        var er = new ExecuteResponse(response.Root);
        Assert.Equal(Status.BadRequest, er.StatusCode);
        Assert.Equal("invalid_request", Ecf.OptText(er.Result.Data, "code"));
        // Correlated where the id is recoverable; §4.11's best-effort uncorrelated frame is
        // the fallback, not the default.
        Assert.Equal("x-1", er.RequestId);

        // THE CONNECTION SURVIVES. §4.11 leaves the close to the peer, and closing here
        // would cost every ADMITTED in-flight request on a multiplexed connection its
        // response. Sending a second bad root and getting a second answer is what proves
        // the reader did not break out.
        await WriteFrame(stream, new Envelope(root, System.Array.Empty<Entity>()).Encode());
        Assert.Equal("x-1", new ExecuteResponse((await ReadEnvelope(stream)).Root).RequestId);
    }

    /// <summary>
    /// The two framing arms, each with its own code. Both used to close with NO coded
    /// frame, which is §4.11's second named non-conformant behaviour — indistinguishable
    /// from a network fault.
    /// </summary>
    [Fact]
    public async Task FramingRefusals_PutACodedFrameOnTheWire()
    {
        foreach ((byte[] bytes, int status, string code) in new[]
                 {
                     // A length prefix of 0x02000000 = 32 MiB, over the 16 MiB bound.
                     (new byte[] { 0x02, 0x00, 0x00, 0x00 }, 413, "payload_too_large"),
                     // A prefix declaring 16 bytes followed by 2, then FIN.
                     (new byte[] { 0x00, 0x00, 0x00, 0x10, 0xa1, 0x00 }, 400, "invalid_request"),
                 })
        {
            await using var responder = new Peer(seedPolicy: SeedPolicy.DebugOpen());
            responder.ListenAsync(0);
            using var client = new TcpClient();
            await client.ConnectAsync("127.0.0.1", responder.Port);
            NetworkStream stream = client.GetStream();
            await stream.WriteAsync(bytes);
            await stream.FlushAsync();
            // Half-close so the truncated arm becomes knowable at end-of-stream while the
            // peer can still write its answer. The oversize arm does not need it.
            client.Client.Shutdown(SocketShutdown.Send);

            var er = new ExecuteResponse((await ReadEnvelope(stream)).Root);
            Assert.Equal(status, er.StatusCode);
            Assert.Equal(code, Ecf.OptText(er.Result.Data, "code"));
            // §4.11's best-effort UNCORRELATED form: no request_id can be recovered from a
            // frame whose body never arrived, and guessing one would correlate the refusal
            // to somebody else's in-flight request.
            Assert.Equal("", er.RequestId);
        }
    }

    private static async Task WriteFrame(Stream stream, byte[] payload)
    {
        byte[] prefix = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(prefix, (uint)payload.Length);
        await stream.WriteAsync(prefix);
        await stream.WriteAsync(payload);
        await stream.FlushAsync();
    }

    private static async Task<Envelope> ReadEnvelope(Stream stream)
    {
        using var cts = new CancellationTokenSource(Timeout);
        byte[] prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix, cts.Token);
        byte[] payload = new byte[BinaryPrimitives.ReadUInt32BigEndian(prefix)];
        await stream.ReadExactlyAsync(payload, cts.Token);
        return Envelope.Decode(payload);
    }
}
