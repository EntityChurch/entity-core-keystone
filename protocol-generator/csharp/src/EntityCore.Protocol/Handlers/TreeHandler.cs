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

        (Entity? entity, HandlerResult? refusal) = AdmitPut(entityField);
        if (refusal is not null)
        {
            return refusal;
        }
        if (!ctx.Peer.Tree.CompareAndPut(path, entity!, expectedHash))
        {
            return Errors.Error(Status.Conflict, "hash_mismatch", "conditional write failed");
        }
        return HandlerResult.Ok(EmptyAck());
    }

    /// <summary>
    /// Digest byte length for a <c>content_hash_format</c> code per the §1.2 seed
    /// table, or -1 when this peer cannot VERIFY that code. The total wire length is
    /// this plus the LEB128 prefix, which is not a constant of the code (§7.3):
    /// codes &gt;= 0x80 occupy more than one byte.
    /// </summary>
    private static int HashDigestLen(ulong formatCode) => formatCode switch
    {
        HashFormats.Sha256 => 32,
        HashFormats.Sha384 => 48,
        _ => -1,
    };

    /// <summary>
    /// Presence, not truthiness: <c>Ecf.Field</c> collapses a CBOR null into
    /// <c>null</c>, and §6.3 makes a null <c>data</c> a legal payload.
    /// </summary>
    private static bool HasKey(EcfValue value, string key)
    {
        if (value is not EcfValue.Map map)
        {
            return false;
        }
        foreach (KeyValuePair<EcfValue, EcfValue> pair in map.Pairs)
        {
            if (pair.Key is EcfValue.Text t && t.Value == key)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>
    /// §6.3's <c>put</c> admission ladder (normative, 0.8.2.11).
    ///
    /// <para><c>put</c> is a RECEIPT path: the submitter authors the entity, the peer
    /// validates what it received (§1.8 item 1) and MUST NOT author a submitted
    /// entity's <c>content_hash</c> on the submitter's behalf. Two ordered steps:</para>
    ///
    /// <list type="number">
    /// <item>STRUCTURE — a map carrying a non-empty text <c>type</c>, a PRESENT
    /// <c>data</c> (any CBOR value; null is a legal payload), and a
    /// <c>content_hash</c> that is a well-formed <c>system/hash</c> whose total byte
    /// length matches its format code (§1.2). Any failure -&gt; 400
    /// <c>invalid_request</c>. A well-formed hash naming a format code this peer
    /// cannot verify is the separate §1.2 ingest-dispatch case -&gt; 400
    /// <c>unsupported_content_hash_format</c>.</item>
    /// <item>HASH — carried <c>content_hash</c> vs <c>content_hash({type, data})</c>.
    /// Disagreement -&gt; 400 <c>hash_mismatch</c>.</item>
    /// </list>
    ///
    /// <para>Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step
    /// 2's inputs are exactly what step 1 establishes, so a submission that is both
    /// malformed and mis-hashed is step 1's and answers <c>invalid_request</c>.</para>
    ///
    /// <para>Structural admission is not semantic validation: <c>data</c> is never
    /// checked against the type named by <c>type</c>.</para>
    /// </summary>
    private static (Entity?, HandlerResult?) AdmitPut(EcfValue v)
    {
        static (Entity?, HandlerResult?) Refuse(string code, string message) =>
            (null, Errors.Error(Status.BadRequest, code, message));

        if (v is not EcfValue.Map)
        {
            return Refuse("invalid_request", "put: entity is not a map");
        }
        if (Ecf.Field(v, "type") is not EcfValue.Text typeV || typeV.Value.Length == 0)
        {
            return Refuse("invalid_request", "put: entity.type absent, empty or not a text string");
        }
        if (!HasKey(v, "data"))
        {
            return Refuse("invalid_request", "put: entity.data absent");
        }
        if (Ecf.Field(v, "content_hash") is not EcfValue.Bytes chV || chV.Value.Length == 0)
        {
            return Refuse("invalid_request", "put: entity.content_hash absent or not a byte string");
        }
        byte[] carried = chV.Value.ToArray();
        int next = 0;
        ulong formatCode;
        try
        {
            formatCode = Leb128.Decode(carried, ref next);
        }
        catch (EntityCoreException)
        {
            return Refuse("invalid_request", "put: entity.content_hash is not a well-formed system/hash");
        }
        int digestLen = HashDigestLen(formatCode);
        if (digestLen < 0)
        {
            // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it. NOT
            // invalid_request: the shape is fine, the algorithm is what we lack.
            return Refuse("unsupported_content_hash_format", "put: unsupported content_hash_format");
        }
        if (carried.Length != next + digestLen)
        {
            return Refuse("invalid_request", "put: content_hash length does not match its format code");
        }
        try
        {
            // FromDecoded VERIFIES the carried hash and keeps it — it does not author
            // one, which is what §6.3 forbids here. A mismatch throws, and that throw
            // is step 2's row rather than a codec fault.
            return (Entity.FromDecoded(v), null);
        }
        catch (EntityCoreException)
        {
            return Refuse("hash_mismatch", "put: content_hash does not match content_hash({type, data})");
        }
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
