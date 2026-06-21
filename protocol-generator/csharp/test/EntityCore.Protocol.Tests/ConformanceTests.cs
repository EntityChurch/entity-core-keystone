using EntityCore.Protocol.Conformance;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// The S2 conformance gate: every vector in the vendored, cross-blessed fixture
/// must pass byte-identical (S7 lower bar). This is the same run the console
/// harness performs, asserted under <c>dotnet test</c>.
/// </summary>
public sealed class ConformanceTests
{
    [Fact]
    public void AllVectorsPassByteIdentical()
    {
        string corpus = Corpus.Locate();
        ConformanceReport report = ConformanceRunner.Run(corpus);

        var failures = report.Results.Where(r => !r.Pass)
            .Select(r => $"{r.Id} [{r.Kind}]: {r.Message}")
            .ToList();

        Assert.True(
            report.AllPass,
            $"{failures.Count}/{report.Results.Count} vectors failed:\n" + string.Join("\n", failures));
        Assert.NotEmpty(report.Results);
    }
}
