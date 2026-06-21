using System.Text;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Types;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// Diffs every natively-rendered core type definition against the Go-rendered
/// vector set (<c>type-registry-vectors-v1.cbor</c>, the S8 drift target). A green
/// run proves the C# registry's <c>system/type/*</c> entities are byte-identical to
/// the oracle's — the content-hash-first match the <c>type_system</c> category needs.
/// </summary>
public sealed class CoreTypeRegistryTests
{
    private const string VectorsRelativePath =
        "protocol-generator/shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor";

    [Fact]
    public void CoreTypesRenderByteIdenticalToVectorSet()
    {
        IReadOnlyDictionary<string, string> vectors = LoadVectorHashes();

        var mismatches = new List<string>();
        var missingFromVectors = new List<string>();

        foreach (TypeDefinition def in CoreTypeRegistry.All)
        {
            if (!vectors.TryGetValue(def.Name, out string? expected))
            {
                missingFromVectors.Add(def.Name);
                continue;
            }

            Entity rendered = def.ToEntity();
            // content_hash is [format_code(0x00)] + 32-byte SHA-256 digest; the vector
            // string is "ecf-sha256:<digest-hex>".
            string actual = "ecf-sha256:" + Hashes.Hex(rendered.ContentHash.AsSpan(1));
            if (actual != expected)
            {
                mismatches.Add($"  {def.Name}\n    want {expected}\n    got  {actual}");
            }
        }

        Assert.Equal(53, CoreTypeRegistry.All.Count);

        if (missingFromVectors.Count > 0 || mismatches.Count > 0)
        {
            var sb = new StringBuilder();
            sb.AppendLine($"{mismatches.Count} content-hash mismatch(es), "
                + $"{missingFromVectors.Count} core type(s) absent from the vector set:");
            foreach (string m in mismatches) sb.AppendLine(m);
            foreach (string n in missingFromVectors) sb.AppendLine($"  (absent from vectors) {n}");
            Assert.Fail(sb.ToString());
        }
    }

    private static IReadOnlyDictionary<string, string> LoadVectorHashes()
    {
        byte[] bytes = File.ReadAllBytes(LocateVectors());
        EcfValue parsed = CanonicalCbor.Parse(bytes);
        if (parsed is not EcfValue.Array array)
        {
            throw new InvalidOperationException("vector set is not a CBOR array");
        }

        var map = new Dictionary<string, string>(array.Items.Count);
        foreach (EcfValue item in array.Items)
        {
            string name = Ecf.RequireText(item, "name");
            string hash = Ecf.RequireText(item, "content_hash");
            map[name] = hash;
        }
        return map;
    }

    private static string LocateVectors()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, VectorsRelativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }
        throw new FileNotFoundException($"could not locate {VectorsRelativePath} above {AppContext.BaseDirectory}");
    }
}
