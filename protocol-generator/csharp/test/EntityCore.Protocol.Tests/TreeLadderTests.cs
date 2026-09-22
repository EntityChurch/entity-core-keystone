using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Handlers;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;
using Xunit;

namespace EntityCore.Protocol.Tests;

/// <summary>
/// §3.3's effective-targets ladder (0.8.2.20, refined at .24/.25) and §6.3's listing
/// filter, driven end-to-end.
/// <para>
/// The ladder runs on the EFFECTIVE list, never on <c>resource.targets</c>: a handler that
/// counts the effective list and then indexes <c>targets[0]</c> has implemented the
/// arithmetic completely and is still reading a path no authorization covered. Before this,
/// every row below answered <c>400 handler_error</c> — a refusal for a reason §6.3 does not
/// name, which is not the selection mechanism and reads as conformance on any check that
/// only asks whether something uncovered was served.
/// </para>
/// </summary>
public sealed class TreeLadderTests
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(10);

    private static Entity EmptyParams() => Entity.Create(TypeNames.PrimitiveAny, Ecf.EmptyMap);

    private static string CodeOf(ExecuteResponse r) => Ecf.OptText(r.Result.Data, "code") ?? "";

    private static Task<ExecuteResponse> Get(PeerSession s, ResourceTarget? r) =>
        s.ExecuteAsync("system/tree", "get", EmptyParams(), r, Timeout);

    private static Task<ExecuteResponse> Put(PeerSession s, ResourceTarget? r) =>
        s.ExecuteAsync("system/tree", "put", EmptyParams(), r, Timeout);

    /// <summary>§3.3's rows, one code each.</summary>
    [Fact]
    public async Task Ladder_AnswersEachRowWithItsOwnCode()
    {
        // The responder runs the degenerate default→* seed policy so the caller's grant
        // covers every path: these rows are about the LADDER's arithmetic, not about
        // authorization, and a narrow grant would answer 403 before the ladder is reached.
        await using var responder = new Peer(seedPolicy: SeedPolicy.DebugOpen());
        await using var initiator = new Peer();
        responder.ListenAsync(0);
        PeerSession s = await initiator.ConnectAsync("127.0.0.1", responder.Port, Timeout);

        // `get`, ABSENT resource -> the root listing. EXTENSION-TREE §2.2a (v4.11) declares
        // `get` resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root listing".
        // This used to be a `Targets.Count != 1` THROW -> 400 handler_error.
        ExecuteResponse absent = await Get(s, null);
        Assert.Equal(Status.Ok, absent.StatusCode);
        Assert.Equal("system/tree/listing", absent.Result.Type);

        // `get`, PRESENT and self-excluded -> 400 path_required. THE TWO EMPTIES ARE
        // DISTINCT for a resource-OPTIONAL operation (0.8.2.24 N7 / 0.8.2.25 N10): serving
        // this the absent case "answers a request for one excluded path with a listing of
        // the tree".
        ExecuteResponse selfExcluded = await Get(s, new ResourceTarget(new[] { "app/a" }, new[] { "app/a" }));
        Assert.Equal(Status.BadRequest, selfExcluded.StatusCode);
        Assert.Equal("path_required", CodeOf(selfExcluded));

        // Two survivors -> 400 ambiguous_resource. A peer indexing targets[0] answers 200
        // and cannot tell the caller it ignored the second.
        ExecuteResponse ambiguous = await Get(s, new ResourceTarget(new[] { "app/a", "app/b" }, null));
        Assert.Equal(Status.BadRequest, ambiguous.StatusCode);
        Assert.Equal("ambiguous_resource", CodeOf(ambiguous));

        // A PATTERN subject -> 400 malformed_resource. A resource-requiring operation takes
        // a CONCRETE path; without this the pattern is looked up as a literal and answers
        // 404, which names the wrong fault: the request is malformed, the tree is fine.
        ExecuteResponse pattern = await Get(s, new ResourceTarget(new[] { "system/type/*" }, null));
        Assert.Equal(Status.BadRequest, pattern.StatusCode);
        Assert.Equal("malformed_resource", CodeOf(pattern));

        // An unmatchable CALLER exclude carves out NOTHING — the fail-OPEN direction of
        // §5.4's sentinel, and the correct one here (§5.4's table rules the caller arm
        // separately from the grant arm). A 400 would mean the peer raised on a path it
        // cannot canonicalize, i.e. the error return 0.8.2.20 removed.
        ExecuteResponse unmatchable = await Get(s, new ResourceTarget(new[] { "system/type/" }, new[] { "../nope" }));
        Assert.Equal(Status.Ok, unmatchable.StatusCode);

        // `put` collapses the two empties: §2.2a declares it resource-REQUIRED, so both
        // answer `path_required`. Note the code 0.8.2.20 forces — a MISSING target is NOT
        // `ambiguous_resource`; *supply a resource* is not *disambiguate your request*.
        foreach (ResourceTarget? r in new ResourceTarget?[]
                 { null, new ResourceTarget(new[] { "app/a" }, new[] { "app/a" }) })
        {
            ExecuteResponse res = await Put(s, r);
            Assert.Equal(Status.BadRequest, res.StatusCode);
            Assert.Equal("path_required", CodeOf(res));
        }
        ExecuteResponse putAmbiguous = await Put(s, new ResourceTarget(new[] { "app/a", "app/b" }, null));
        Assert.Equal("ambiguous_resource", CodeOf(putAmbiguous));

        // RULE G control: the OPERATION resolves FIRST. An unknown op with no resource
        // answers the OPERATION fault, never the resource one — a handler that validates
        // the resource first answers `path_required`/`ambiguous_resource` here and names
        // the wrong fault for every unknown operation.
        ExecuteResponse bogus = await s.ExecuteAsync("system/tree", "bogusop", EmptyParams(), null, Timeout);
        Assert.Equal(Status.NotSupported, bogus.StatusCode);
        Assert.Equal("unsupported_operation", CodeOf(bogus));
    }

    /// <summary>
    /// <c>targets:[a,b] exclude:[a]</c>. The effective set is <c>{b}</c>, size 1, so the
    /// COUNT rule says proceed — and a raw <c>targets[0]</c> selector proceeds on <c>a</c>.
    /// Both are bound, so a 200 naming <c>a</c> is a selection defect and nothing else.
    /// </summary>
    [Fact]
    public async Task Ladder_SubjectIsSelectedFromTheEffectiveSet()
    {
        await using var responder = new Peer(seedPolicy: SeedPolicy.DebugOpen());
        await using var initiator = new Peer();
        responder.ListenAsync(0);
        PeerSession s = await initiator.ConnectAsync("127.0.0.1", responder.Port, Timeout);

        foreach ((string path, string type) in new[] { ("app/sel/a", "test/a"), ("app/sel/b", "test/b") })
        {
            Entity leaf = Entity.Create(type, Ecf.EmptyMap);
            Entity putReq = Entity.Create("system/tree/put-request", Ecf.Map(
                ("entity", new EcfValue.PreEncoded(leaf.WireBytes))));
            ExecuteResponse ok = await s.ExecuteAsync("system/tree", "put", putReq,
                new ResourceTarget(new[] { path }, null), Timeout);
            Assert.Equal(Status.Ok, ok.StatusCode);
        }

        ExecuteResponse res = await Get(s,
            new ResourceTarget(new[] { "app/sel/a", "app/sel/b" }, new[] { "app/sel/a" }));
        Assert.Equal(Status.Ok, res.StatusCode);
        Assert.Equal("test/b", res.Result.Type);        // targets[0] would have answered test/a
    }

    /// <summary>
    /// §6.3's listing filter (0.8.2.21/.22) — <em>"each entry MUST be individually checked
    /// using <c>check_path_permission</c>. Entries for which <c>check_path_permission</c>
    /// returns DENY MUST be omitted. The result's <c>count</c> field MUST reflect the
    /// filtered entry count, not the source tree's total count."</em>
    /// <para>
    /// Driven through a hand-built <see cref="HandlerContext"/> rather than a session,
    /// because the NARROW GRANT is the whole input and minting one over the wire would put
    /// three more moving parts between the assertion and the thing asserted. The wire half
    /// is <c>tools/arc-probe</c> G4.
    /// </para>
    /// </summary>
    [Fact]
    public async Task Listing_OmitsEntriesTheCallersCapabilityExcludes()
    {
        await using var peer = new Peer(seedPolicy: SeedPolicy.DebugOpen());
        string basePath = "/" + peer.LocalPeerId + "/app/list";
        Entity leaf = Entity.Create("test/leaf", Ecf.EmptyMap);
        peer.Tree.Put(basePath + "/a", leaf);
        peer.Tree.Put(basePath + "/b", leaf);

        async Task<(List<string> Names, ulong Count)> ListUnder(CapabilityToken? cap)
        {
            var execute = new Execute(Entity.Create(TypeNames.Execute, Ecf.Map(
                ("request_id", Ecf.Text("l1")),
                ("uri", Ecf.Text("system/tree")),
                ("operation", Ecf.Text("get")),
                ("resource", new ResourceTarget(new[] { "app/list/" }, null).ToEcf()),
                ("params", new EcfValue.PreEncoded(EmptyParams().WireBytes)))));
            var ctx = new HandlerContext
            {
                Peer = peer,
                Execute = execute,
                Envelope = new Envelope(execute.Entity, System.Array.Empty<Entity>()),
                Pattern = "system/tree",
                Suffix = "",
                CallerCapability = cap,
            };
            HandlerResult result = await new TreeHandler().HandleAsync(ctx, CancellationToken.None);
            Assert.Equal(Status.Ok, result.Status);
            var names = new List<string>();
            if (Ecf.Require(result.Result.Data, "entries") is EcfValue.Map entries)
            {
                names.AddRange(entries.Pairs.Select(p => ((EcfValue.Text)p.Key).Value));
            }
            names.Sort(StringComparer.Ordinal);
            return (names, Ecf.RequireUint(result.Result.Data, "count"));
        }

        // THE CONTROL, and it is what makes the assertion below falsifiable: with a grant
        // covering BOTH, the listing names both. "b is absent" under a narrower grant is
        // the trivial truth if the directory read does not work at all.
        (List<string> wideNames, ulong wideCount) = await ListUnder(NarrowToken("app/list/*"));
        Assert.Equal(new[] { "a", "b" }, wideNames);
        Assert.Equal(2ul, wideCount);

        (List<string> narrowNames, ulong narrowCount) = await ListUnder(NarrowToken("app/list/a"));
        Assert.Equal(new[] { "a" }, narrowNames);
        Assert.Equal(1ul, narrowCount);   // `count` follows the FILTERED total

        // An UNAUTHENTICATED context is not filtered — the filter's subject is "the
        // caller's verified capability", and where there is none there is no caller to
        // narrow. This is the bootstrap path, and it matches both vanguard peers.
        (List<string> bootstrapNames, _) = await ListUnder(null);
        Assert.Equal(new[] { "a", "b" }, bootstrapNames);
    }

    /// <summary>
    /// A token whose single grant covers <c>system/tree</c>, <c>get</c>, and exactly
    /// <paramref name="resources"/>. <c>granter</c>/<c>grantee</c>/<c>created_at</c> are
    /// REQUIRED by the §3.6 parser and are not read by <c>check_path_permission</c>, which
    /// answers about the token's GRANTS only — the chain, signature, temporal bounds and
    /// revocation are <c>VerifyRequest</c>'s and must already have held.
    /// </summary>
    private static CapabilityToken NarrowToken(params string[] resources)
    {
        var grant = new GrantEntry(
            new Scope(new[] { "system/tree" }, null),
            new Scope(resources, null),
            new Scope(new[] { "get" }, null),
            null, null, null);
        return new CapabilityToken(Entity.Create(TypeNames.CapabilityToken, Ecf.Map(
            ("grants", Ecf.Array(grant.ToEcf())),
            ("granter", Ecf.Bytes(new byte[33])),
            ("grantee", Ecf.Bytes(new byte[33])),
            ("created_at", Ecf.Uint(1_700_000_000_000)))));
    }
}
