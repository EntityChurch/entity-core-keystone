using EntityCore.Protocol;
using EntityCore.Protocol.Codec;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// Focused unit tests for the codec primitives. These complement the corpus
/// gate: they pin the hand-rolled pieces (shortest-float, LEB128, Base58,
/// tag-reject) directly and cover beyond-corpus ranges.
/// </summary>
public sealed class CodecUnitTests
{
    [Theory]
    [InlineData(0.0, "f90000")]
    [InlineData(1.0, "f93c00")]
    [InlineData(1.5, "f93e00")]
    [InlineData(double.PositiveInfinity, "f97c00")]
    [InlineData(double.NegativeInfinity, "f9fc00")]
    [InlineData(double.NaN, "f97e00")]
    [InlineData(32768.0, "f97800")]
    [InlineData(65504.0, "f97bff")]
    [InlineData(65503.0, "fa477fdf00")]
    [InlineData(100000.0, "fa47c35000")]
    [InlineData(1.1, "fb3ff199999999999a")]
    public void ShortestFloat(double value, string expectedHex)
    {
        Assert.Equal(expectedHex, Hex(CanonicalCbor.EncodeFloat(value)));
    }

    [Fact]
    public void NegativeZeroFloat()
    {
        Assert.Equal("f98000", Hex(CanonicalCbor.EncodeFloat(-0.0)));
    }

    [Theory]
    [InlineData(0UL, "00")]
    [InlineData(127UL, "7f")]
    [InlineData(128UL, "8001")]
    [InlineData(300UL, "ac02")]
    public void Leb128RoundTrip(ulong value, string expectedHex)
    {
        byte[] encoded = Leb128.Encode(value);
        Assert.Equal(expectedHex, Hex(encoded));
        int offset = 0;
        Assert.Equal(value, Leb128.Decode(encoded, ref offset));
        Assert.Equal(encoded.Length, offset);
    }

    [Fact]
    public void Base58RoundTripWithLeadingZeros()
    {
        byte[] raw = Convert.FromHexString("0000ff10abcdef");
        string encoded = Base58.Encode(raw);
        Assert.StartsWith("11", encoded); // two leading zero bytes -> two '1's
        Assert.Equal(raw, Base58.Decode(encoded));
    }

    [Fact]
    public void PeerIdRoundTrip()
    {
        byte[] digest = Convert.FromHexString("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        string id = EntityCodec.FormatPeerId(1, 1, digest);
        PeerId parsed = EntityCodec.ParsePeerId(id);
        Assert.Equal(1UL, parsed.KeyType);
        Assert.Equal(1UL, parsed.HashType);
        Assert.Equal(digest, parsed.Digest);
    }

    [Theory]
    [InlineData("d9d9f7a0")] // tag 55799 (self-describe) wrapping empty map
    [InlineData("c074323032362d30362d30365431323a30303a30305a")] // tag 0 datetime
    public void DecodeRejectsTags(string hex)
    {
        Assert.Throws<EntityCodecException>(() => CanonicalCbor.Decode(Convert.FromHexString(hex)));
    }

    [Fact]
    public void DecodeRejectsTrailingBytes()
    {
        // valid empty map (a0) followed by a stray byte
        Assert.Throws<EntityCodecException>(() => CanonicalCbor.Decode(Convert.FromHexString("a000")));
    }

    [Fact]
    public void ContentHashEmptyEntityMatchesFixture()
    {
        // content_hash.1: {type:"system/empty", data:{}} (F5 superseding value)
        byte[] emptyMap = CanonicalCbor.Encode(new EcfValue.Map(System.Array.Empty<KeyValuePair<EcfValue, EcfValue>>()));
        Assert.Equal("a0", Hex(emptyMap));
        byte[] hash = EntityCodec.ContentHash("system/empty", emptyMap);
        Assert.Equal("005f3139e342f5ef35c1e0eb3140c4511c469d604979d20542bc2ab92fd0ca396b", Hex(hash));
    }

    [Fact]
    public void SignVerifyRoundTrip()
    {
        byte[] seed = new byte[32];
        byte[] message = "hello entity"u8.ToArray();
        byte[] sig = EntityCodec.Sign(seed, message);
        Assert.Equal(64, sig.Length);

        byte[] pub = EntityCodec.PublicKeyFromSeed(seed);
        Assert.True(EntityCodec.Verify(pub, message, sig));
        Assert.False(EntityCodec.Verify(pub, "tampered"u8.ToArray(), sig));
    }

    private static string Hex(byte[] b) => Convert.ToHexString(b).ToLowerInvariant();
}
