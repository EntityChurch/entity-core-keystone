using System.Text;
using EntityCore.Protocol;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

// Crypto-agility byte-verification harness (v7.67 corpus, vendored
// test-vectors/v0.8.0/agility-vectors-v1).  Derives every value from the pinned
// seeds through the crypto-agility seam (KeyTypes + HashFormats) and asserts
// byte-equality against the .diag ground truth.  Per S5/S7: byte-identical or the
// generated code is wrong.  Pins are transcribed from agility-vectors-v1.diag /
// agility-SEEDS.md (the spec-derived source of truth).

int pass = 0, fail = 0;

void Check(string name, string expected, string actual)
{
    bool ok = string.Equals(expected, actual, StringComparison.OrdinalIgnoreCase);
    Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}");
    if (ok) { pass++; return; }
    fail++;
    Console.WriteLine($"        expected {expected}");
    Console.WriteLine($"        actual   {actual}");
}

void CheckThrows(string name, Action body)
{
    try { body(); Console.WriteLine($"  [FAIL] {name} (did not throw)"); fail++; }
    catch (EntityCodecException) { Console.WriteLine($"  [PASS] {name}"); pass++; }
}

static byte[] Seed(byte b, int n) { var a = new byte[n]; Array.Fill(a, b); return a; }
static string HexOf(ReadOnlySpan<byte> b) => Convert.ToHexStringLower(b);

// Build a system/peer entity under an explicit home content_hash_format (the agility
// path; the live peer always authors under 0x00 SHA-256).
static Entity BuildPeer(IKeyAlgorithm kt, byte[] pub, ulong home) =>
    Entity.Create("system/peer", Ecf.Map(("key_type", Ecf.Text(kt.Name)), ("public_key", Ecf.Bytes(pub))), home);

IKeyAlgorithm ed25519 = KeyTypes.ByCode(KeyTypes.Ed25519Code);
IKeyAlgorithm ed448 = KeyTypes.ByCode(KeyTypes.Ed448Code);

Console.WriteLine("entity-core-protocol-csharp — crypto-agility byte verification (v7.67 corpus)\n");

// ── Phase 1: KEY-TYPE-ED448-1 ────────────────────────────────────────────────
Console.WriteLine("KEY-TYPE-ED448-1 (Ed448 / SHA-256-form):");
{
    byte[] seed = Seed(0x42, 57);
    byte[] pub = ed448.PublicKeyFromSeed(seed);
    Check("public_key (57B)",
        "2601850dc77aaf141e065b2fe83ecfe08b6c15ba930886e9f111b6f0fd8f9f246b167e0398f957df61c9cead939cdf5bc9fe43c9432f3b0e00",
        HexOf(pub));
    Check("peer_id (SHA-256-form, key_type=0x02 hash_type=0x01)",
        "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4",
        PeerIdentity.DerivePeerId(pub, ed448));
    Check("system/peer content_hash (SHA-256 home)",
        "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748",
        HexOf(BuildPeer(ed448, pub, HashFormats.Sha256).ContentHash));

    byte[] msg = Encoding.ASCII.GetBytes("v7.67 Phase 1 cohort cross-impl Ed448 fixture");
    byte[] sig = ed448.Sign(seed, msg);
    Check("Ed448 signature (114B, RFC 8032 deterministic)",
        "0aff7a36b2b5e7502f9a133bc9ed39316284f0be738e2485546b33fda60966b19ac0e3424ed549072af7ac5caa6d695c3e1e6412207cecaf8085444fbf062cb5271ea6d127c6c87327e1e20793f2b10341d04bd4bed32e220eca1b2255cc8aa4d2a0c8304d67e6f20e814b90411049b33400",
        HexOf(sig));
    Console.WriteLine($"  [{(ed448.Verify(pub, msg, sig) ? "PASS" : "FAIL")}] Ed448 sign→verify round-trip");
    if (ed448.Verify(pub, msg, sig)) pass++; else fail++;
}

// ── Phase 1: HASH-FORMAT-SHA-384-1 (0xFE experimental-test stub) ──────────────
Console.WriteLine("\nHASH-FORMAT-SHA-384-1 (experimental-test 0xFE, 0xAA×64):");
{
    IKeyAlgorithm exp = KeyTypes.ByCode(KeyTypes.ExperimentalTestCode);
    byte[] pub = Seed(0xAA, 64);
    Check("content_hash under SHA-256 (0x00)",
        "003d0c34b508c5bf9eca5f086f09aac10f44bd43fca1a091b6aa55a096ca8fcd45",
        HexOf(BuildPeer(exp, pub, HashFormats.Sha256).ContentHash));
    Check("content_hash under SHA-384 (0x01)",
        "012e64bbde3c494cf7cd4fb53ae3bf6420ec6d9bfa686348729eaa687e421c01c059c1ed5775824bcffc50df0f3eef5a69",
        HexOf(BuildPeer(exp, pub, HashFormats.Sha384).ContentHash));
}

// ── Phase 2: matrix peer identities (M2 / M3 / M6, peers A & B) ───────────────
// peer_id is home-format-independent; content_hash tracks the peer's home format.
(string label, IKeyAlgorithm kt, byte b, int n, ulong home, string peerId, string ch)[] matrix =
[
    ("M2.A ed448/sha256",  ed448,   0x42, 57, HashFormats.Sha256, "3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4", "002785b314436a82503829339cb2519b4efe795712406ea19ac185e31ae8c70748"),
    ("M2.B ed25519/sha256", ed25519, 0x43, 32, HashFormats.Sha256, "2K68ekpdm3sTCUfTs39tpNxowivTsXpRsukodvtqwZmudX", "00f4a5dd5bb2afe38e8c822847832b2ce83616ac5ed86a7f3c668d4d98753be86b"),
    ("M3.A ed25519/sha384", ed25519, 0x44, 32, HashFormats.Sha384, "2KJGifeh6LynPNnmyQqHrugjm7iW8YPQ4VpWSGgYvHp2VM", "0166f421381111d3c861787a6e233c9cbc1a652093a472c177d6e4bdec0ed95e3873f9f482c282b781f7c44b4ff91b2c59"),
    ("M3.B ed25519/sha256", ed25519, 0x45, 32, HashFormats.Sha256, "2KATqnFJZboriNzCpVQ6nx7oCtc2qcTBToin4muxqo3ja5", "00bbc4eb0be2c82159a0fcd8eaf22b420b0ac5f3da6f746e0cddadb9f935e71040"),
    ("M6.A ed448/sha384",  ed448,   0x46, 57, HashFormats.Sha384, "3dWKQXt2foyNFwZ7iyvXxiKLwnLHQZzdsdEpdzdYhP5aZD", "01ef28f9251ac8d26ee0a520b96b19cb93205a1923a238ef903b07b896738396faafc4be2d1d7d77dee0a53c992584f9cd"),
    ("M6.B ed25519/sha256", ed25519, 0x47, 32, HashFormats.Sha256, "2KK2QYVGptXdChBXoNcXWhfaGRik85xSpefSeL4tPzkeye", "0056d326c087087e04f4f5a62b1ef518b20541705c2760283b3f490882f133c335"),
];
Console.WriteLine("\nMATRIX peer identities (peer_id + home-format content_hash):");
foreach (var v in matrix)
{
    byte[] pub = v.kt.PublicKeyFromSeed(Seed(v.b, v.n));
    Check($"{v.label} peer_id", v.peerId, PeerIdentity.DerivePeerId(pub, v.kt));
    Check($"{v.label} content_hash", v.ch, HexOf(BuildPeer(v.kt, pub, v.home).ContentHash));
}

// ── Reject paths (VARINT-MULTIBYTE-1 / VARINT-RESERVED-FF-1 / FORMAT-CODE-INTERP) ─
Console.WriteLine("\nReject paths (agility probes):");
CheckThrows("key_type 255 reserved (VARINT-RESERVED-FF-1.key_type)", () => KeyTypes.ByCode(KeyTypes.Reserved));
CheckThrows("content_hash_format 255 reserved (VARINT-RESERVED-FF-1.format)", () => HashFormats.Digest(HashFormats.Reserved, []));
CheckThrows("unallocated format-code 0x42 (FORMAT-CODE-INTERPRETATION-1)", () => HashFormats.Digest(0x42, []));
CheckThrows("unknown key_type name", () => KeyTypes.ByName("blake-fake"));
{
    // VARINT-MULTIBYTE-1: multi-byte LEB128 0x80 0x01 decodes to 128, which is not a
    // supported format → unsupported_content_hash_format (decoder exists; the error
    // fires from interpretation, not a single-byte short-circuit).
    ulong code = HashFormats.ReadFormatCode([0x80, 0x01]);
    bool ok = code == 128 && !HashFormats.IsSupported(code);
    Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] VARINT-MULTIBYTE-1 (0x80 0x01 → 128, unsupported)");
    if (ok) pass++; else fail++;
}

Console.WriteLine($"\n# RESULT: {(fail == 0 ? "PASS" : "FAIL")} ({pass}/{pass + fail})");
return fail == 0 ? 0 : 1;
