using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Store;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The tree handler at <c>system/tree</c> (V7 §6.3) — direct access to the location
/// index and content store via <c>get</c> and <c>put</c>. Enforces two-level
/// authorization: the dispatcher's <c>check_permission</c> ran first; this handler
/// re-checks each path with <c>check_path_permission</c> (defense-in-depth, and
/// sole enforcement when <c>resource</c> is absent).
/// </summary>
internal sealed class TreeHandler : IHandler
{
    public string Pattern => "system/tree";

    public string Name => "tree";

    public IReadOnlyList<string> Operations { get; } = new[] { "get", "put" };

    public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct) =>
        Task.FromResult(ctx.Operation switch
        {
            "get" => Get(ctx),
            "put" => Put(ctx),
            _ => Errors.Error(Status.NotSupported, "operation_not_supported", $"tree handler has no '{ctx.Operation}'"),
        });

    private static HandlerResult Get(HandlerContext ctx)
    {
        string target = RequireSingleTarget(ctx);
        EntityTree tree = ctx.Peer.Tree;
        string localPeerId = ctx.LocalPeerId;

        try
        {
            Paths.ValidateCallerTarget(target);
        }
        catch (EntityProtocolException ex)
        {
            return Errors.Error(Status.BadRequest, "invalid_path", ex.Message);
        }

        // Listing request — trailing slash or empty (§6.3).
        if (target.Length == 0 || target.EndsWith('/'))
        {
            string prefix = Paths.Canonicalize(target.TrimEnd('/'), localPeerId);
            IReadOnlyDictionary<string, ListingEntry> raw = tree.List(prefix);
            var entries = new List<(string Key, EcfValue Value)>();
            foreach ((string name, ListingEntry entry) in raw)
            {
                // Filter each entry against the caller's capability (§6.3 listing filter).
                // The peer-root prefix canonicalizes to "/{peer}/" (trailing slash); guard
                // against a "//" empty segment when joining the entry name (root listing).
                string entryPath = (prefix.EndsWith('/') ? prefix : prefix + "/") + name;
                if (!AuthorizePath(ctx, "get", entryPath))
                {
                    continue;
                }
                // §6.3 / v7.72 §9.5a CORE-TREE-DELETE-1: a direct child bound to a
                // system/deletion-marker is omitted (deletion is marker-represented; a
                // marked leaf reads as absent). A marker that still prefixes deeper live
                // paths survives as a pure child-prefix with its own binding hidden.
                if (entry.Hash is not null && tree.Get(entryPath)?.Type == TypeNames.DeletionMarker)
                {
                    if (!entry.HasChildren)
                    {
                        continue;
                    }
                    entries.Add((name, Ecf.Map(
                        ("hash", null),
                        ("has_children", Ecf.Bool(true)))));
                    continue;
                }
                entries.Add((name, Ecf.Map(
                    ("hash", entry.Hash is null ? null : Ecf.Bytes(entry.Hash)),
                    ("has_children", Ecf.Bool(entry.HasChildren)))));
            }
            Entity listing = Entity.Create("system/tree/listing", Ecf.Map(
                ("path", Ecf.Text(prefix)),
                ("entries", new EcfValue.Map(entries.Select(e =>
                    new KeyValuePair<EcfValue, EcfValue>(Ecf.Text(e.Key), e.Value)).ToList())),
                ("count", Ecf.Uint((ulong)entries.Count)),
                ("offset", Ecf.Uint(0))));
            return HandlerResult.Ok(listing);
        }

        string path = Paths.Canonicalize(target, localPeerId);
        if (!AuthorizePath(ctx, "get", path))
        {
            return Errors.Error(Status.Forbidden, "capability_denied", "capability does not cover path");
        }

        string mode = Ecf.OptText(ctx.Params.Data, "mode") ?? "entity";
        byte[]? hash = tree.GetHash(path);
        if (hash is null)
        {
            return Errors.Error(Status.NotFound, "not_found", $"no entity bound at {path}");
        }
        if (mode == "hash")
        {
            return HandlerResult.Ok(Entity.Create(TypeNames.PrimitiveAny, Ecf.Bytes(hash)));
        }
        Entity entity = tree.Get(path)!;
        return HandlerResult.Ok(entity);
    }

    private static HandlerResult Put(HandlerContext ctx)
    {
        string target = RequireSingleTarget(ctx);
        string path;
        try
        {
            // §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1: reject control bytes + malformed
            // leading-slash forms (400 invalid_path) before the write reaches the store.
            Paths.ValidateCallerTarget(target);
            path = Paths.Canonicalize(target, ctx.LocalPeerId);
        }
        catch (EntityProtocolException ex)
        {
            return Errors.Error(Status.BadRequest, "invalid_path", ex.Message);
        }

        // Caller-specified path: the caller's capability MUST cover it (§6.8).
        if (!AuthorizePath(ctx, "put", path))
        {
            return Errors.Error(Status.Forbidden, "capability_denied", "capability does not cover path");
        }

        EcfValue? entityField = Ecf.Field(ctx.Params.Data, "entity");
        byte[]? expectedHash = Ecf.OptBytes(ctx.Params.Data, "expected_hash");

        if (entityField is null)
        {
            // Remove binding (§6.3). CAS-checked when expected_hash present.
            if (expectedHash is not null && !Hashes.IsZero(expectedHash))
            {
                byte[]? current = ctx.Peer.Tree.GetHash(path);
                if (current is null || !Hashes.Equal(current, expectedHash))
                {
                    return Errors.Error(Status.Conflict, "hash_mismatch", "expected_hash does not match current binding");
                }
            }
            ctx.Peer.Tree.Remove(path);
            return HandlerResult.Ok(EmptyAck());
        }

        Entity entity = Entity.FromDecoded(entityField);
        if (!ctx.Peer.Tree.CompareAndPut(path, entity, expectedHash))
        {
            return Errors.Error(Status.Conflict, "hash_mismatch", "conditional write failed");
        }
        return HandlerResult.Ok(EmptyAck());
    }

    private static bool AuthorizePath(HandlerContext ctx, string operation, string path) =>
        ctx.CallerCapability is not null
        && Permissions.CheckPathPermission(operation, path, ctx.CallerCapability, ctx.Pattern, ctx.LocalPeerId);

    private static string RequireSingleTarget(HandlerContext ctx)
    {
        ResourceTarget? resource = ctx.Resource;
        if (resource is null || resource.Targets.Count != 1)
        {
            throw new EntityProtocolException("tree operation requires exactly one resource target (§6.3)");
        }
        return resource.Targets[0];
    }

    private static Entity EmptyAck() => Entity.Create(TypeNames.PrimitiveAny, Ecf.EmptyMap);
}
