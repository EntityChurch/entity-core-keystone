using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Conformance;

string corpusPath = args.Length >= 1 ? args[0] : Corpus.Locate();

ConformanceReport report = ConformanceRunner.Run(corpusPath);

Console.WriteLine("# entity-core-protocol-csharp — conformance run");
Console.WriteLine($"# impl: native (System.Formats.Cbor 9.0.0 / NSec 25.4.0 / BouncyCastle 2.4.0) / spec-data v7.71");
Console.WriteLine($"# corpus: {corpusPath} ({report.Results.Count} vectors)");
Console.WriteLine();
Console.WriteLine($"{"category",-14} {"pass",5} {"total",5}");
Console.WriteLine("--------------------------");

int totalPass = 0, totalAll = 0;
foreach ((string category, int pass, int total) in report.ByCategory())
{
    string mark = pass == total ? "ok" : "XX";
    Console.WriteLine($"{category,-14} {pass,5} {total,5}  {mark}");
    totalPass += pass;
    totalAll += total;
}
Console.WriteLine("--------------------------");
Console.WriteLine($"{"TOTAL",-14} {totalPass,5} {totalAll,5}");

var failures = report.Results.Where(r => !r.Pass).ToList();
if (failures.Count > 0)
{
    Console.WriteLine();
    Console.WriteLine($"# {failures.Count} failure(s):");
    foreach (VectorResult f in failures)
    {
        Console.WriteLine($"  FAIL {f.Id,-16} [{f.Kind}] {f.Message}");
    }
    return 1;
}

Console.WriteLine();
Console.WriteLine($"# RESULT: PASS ({totalPass}/{totalAll})");
return 0;
