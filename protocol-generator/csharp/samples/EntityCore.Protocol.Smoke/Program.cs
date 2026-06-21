using EntityCore.Protocol;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;

// ---------------------------------------------------------------------------
// entity-core-protocol-csharp — S3 peer smoke runner.
//
// Boots two C# peers over real loopback TCP and drives the V7 §4.1 handshake
// (3 EXECUTE + 3 EXECUTE_RESPONSE), then exercises authenticated dispatch:
//   - an EXECUTE to an unregistered path → 404 (no handler resolves)
//   - an EXECUTE the initial grant covers → 200
//   - both fired concurrently and interleaved to prove request_id correlation
//     (§6.11 demux) routes each response to its own awaiter (N6 + N7).
//
// Cross-impl validation against the Go reference peer is the S4 step
// (validate-peer); this S3 smoke is self-contained C#↔C#.
// ---------------------------------------------------------------------------

var timeout = TimeSpan.FromSeconds(10);
int failures = 0;

void Check(string name, bool ok, string detail = "")
{
    Console.WriteLine($"  [{(ok ? "PASS" : "FAIL")}] {name}{(detail.Length > 0 ? $" — {detail}" : "")}");
    if (!ok)
    {
        failures++;
    }
}

var responder = new Peer();
var initiator = new Peer();
try
{

Console.WriteLine("entity-core-protocol-csharp — S3 peer smoke");
Console.WriteLine($"  responder peer_id : {responder.LocalPeerId}");
Console.WriteLine($"  initiator peer_id : {initiator.LocalPeerId}");
Console.WriteLine();

responder.ListenAsync(0);
Console.WriteLine($"Responder listening on 127.0.0.1:{responder.Port}");

// --- Handshake (§4.1) ------------------------------------------------------
PeerSession session = await initiator.ConnectAsync("127.0.0.1", responder.Port, timeout);
Console.WriteLine();
Console.WriteLine("Handshake:");
Check("session established", session is not null);
Check("remote peer_id matches responder", session!.RemotePeerId == responder.LocalPeerId,
    session.RemotePeerId);

// --- 404: unregistered path ------------------------------------------------
Console.WriteLine();
Console.WriteLine("Dispatch:");
ExecuteResponse notFound = await session.ExecuteAsync(
    uri: "local/files/readme.md", operation: "get",
    paramsEntity: PeerSession.EmptyParams(), resource: null, timeout: timeout);
Check("unregistered path → 404", notFound.StatusCode == Status.NotFound, $"status {notFound.StatusCode}");

// --- 200: a path the initial grant covers (tree get on system/handler/*) ---
Entity getRequest = Entity.Create("system/tree/get-request", Ecf.EmptyMap);
ExecuteResponse allowed = await session.ExecuteAsync(
    uri: "system/tree", operation: "get",
    paramsEntity: getRequest,
    resource: new ResourceTarget(new[] { "system/handler/system/tree" }, null),
    timeout: timeout);
Check("granted tree get → 200", allowed.StatusCode == Status.Ok, $"status {allowed.StatusCode}");

// --- capability handler: request a token (initial grant authorizes this) ---
var requestedScope = new GrantEntry(
    Handlers: new Scope(new[] { "system/tree" }, null),
    Resources: new Scope(new[] { "system/type/*" }, null),
    Operations: new Scope(new[] { "get" }, null),
    Peers: null, Constraints: null, Allowances: null);
Entity capRequest = Entity.Create("system/capability/request", Ecf.Map(
    ("grants", Ecf.Array(requestedScope.ToEcf()))));
ExecuteResponse capGrant = await session.ExecuteAsync(
    uri: "system/capability", operation: "request",
    paramsEntity: capRequest, resource: null, timeout: timeout);
Check("capability request → 200", capGrant.StatusCode == Status.Ok, $"status {capGrant.StatusCode}");

// --- request_id correlation under concurrency (§6.11, N6/N7) ----------------
Console.WriteLine();
Console.WriteLine("Concurrency (request_id demux):");
const int rounds = 8;
var tasks = new List<Task<(int Expected, int Actual)>>();
for (int i = 0; i < rounds; i++)
{
    if (i % 2 == 0)
    {
        tasks.Add(Task.Run(async () =>
        {
            ExecuteResponse r = await session.ExecuteAsync(
                "local/files/readme.md", "get", PeerSession.EmptyParams(), null, timeout);
            return (Status.NotFound, r.StatusCode);
        }));
    }
    else
    {
        tasks.Add(Task.Run(async () =>
        {
            ExecuteResponse r = await session.ExecuteAsync(
                "system/tree", "get",
                Entity.Create("system/tree/get-request", Ecf.EmptyMap),
                new ResourceTarget(new[] { "system/handler/system/tree" }, null), timeout);
            return (Status.Ok, r.StatusCode);
        }));
    }
}
(int Expected, int Actual)[] results = await Task.WhenAll(tasks);
int correlated = results.Count(r => r.Expected == r.Actual);
Check($"{rounds} interleaved requests each correlated to its own response",
    correlated == rounds, $"{correlated}/{rounds} matched");

}
finally
{
    // --- Teardown ----------------------------------------------------------
    Console.WriteLine();
    await initiator.DisposeAsync();
    await responder.DisposeAsync();
    Console.WriteLine("Teardown clean.");
}

Console.WriteLine();
Console.WriteLine(failures == 0 ? "SMOKE: PASS" : $"SMOKE: FAIL ({failures} failed)");
return failures == 0 ? 0 : 1;
