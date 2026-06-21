namespace EntityCore.Protocol.Conformance;

/// <summary>Locates the vendored conformance fixture relative to the build output.</summary>
public static class Corpus
{
    private const string RelativePath =
        "protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.cbor";

    /// <summary>
    /// Walk up from the current directory to find the repo's vendored fixture.
    /// Falls back to the <c>ECF_VECTORS</c> environment variable if set.
    /// </summary>
    public static string Locate()
    {
        string? fromEnv = Environment.GetEnvironmentVariable("ECF_VECTORS");
        if (!string.IsNullOrEmpty(fromEnv) && File.Exists(fromEnv))
        {
            return fromEnv;
        }

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir is not null)
        {
            string candidate = Path.Combine(dir.FullName, RelativePath);
            if (File.Exists(candidate))
            {
                return candidate;
            }
            dir = dir.Parent;
        }

        throw new FileNotFoundException(
            $"could not locate {RelativePath} above {AppContext.BaseDirectory}; " +
            "set ECF_VECTORS to the fixture path.");
    }
}
