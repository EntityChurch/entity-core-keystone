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

    /// <summary>
    /// RESOLVE THE OPERATION FIRST; only then run the §3.3 resource ladder. This switch is
    /// what makes that true: a handler that validates the resource first answers a RESOURCE
    /// fault for an unknown-OPERATION request, so <c>system/tree:bogusop</c> with no
    /// <c>resource</c> reports <c>ambiguous_resource</c> where §3.3 pins
    /// <c>501 unsupported_operation</c>.
    /// </summary>
    public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct) =>
        Task.FromResult(ctx.Operation switch
        {
            "get" => Get(ctx),
            "put" => Put(ctx),
            // §3.3's 501 slot is spelled `unsupported_operation` — the same code every
            // other handler in this peer already uses; `operation_not_supported` is a
            // minted synonym and §3.3's (code, status) pair is a MUST-emit contract.
            _ => Errors.Error(Status.NotSupported, "unsupported_operation", $"tree handler has no '{ctx.Operation}'"),
        });

    private static HandlerResult Get(HandlerContext ctx)
    {
        EntityTree tree = ctx.Peer.Tree;
        string localPeerId = ctx.LocalPeerId;

        // §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
        // `resource.targets`: a handler that counts the effective list and then indexes
        // `targets[0]` has implemented the arithmetic completely and is still reading a
        // path no authorization covered.
        //
        // This replaces a `Targets.Count != 1` THROW, which answered `400 handler_error`
        // for every row of the ladder at once: an absent resource, two targets and a
        // single-entry effective set all landed on the generic handler-fault frame.
        // 0.8.2.20 pins each to its own code because the code is what selects the caller's
        // remedy, and a peer that refuses correctly for a reason §6.3 does not name has not
        // implemented the selection.
        (IReadOnlyList<string> survivors, bool hasResource) = Permissions.EffectiveTargets(ctx.Execute, localPeerId);
        if (!hasResource)
        {
            // THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN SPECIFICATION IS
            // WHAT SAYS SO. §3.3's "an empty effective list IS the absent case" is scoped
            // "for an operation that REQUIRES a resource" (0.8.2.24, N7); `get` does not.
            // For a resource-OPTIONAL operation 0.8.2.25 (N10) decides the
            // present-but-empty case by whether the absent case is WIDER than the request —
            // BROAD-RESULT refuses it, OPTIONAL-FILTER answers it empty — and requires the
            // operation to declare which.
            //
            // EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is resource-OPTIONAL
            // and BROAD-RESULT, absent-case answer "the root listing", self-excluded case
            // "400 path_required". Both arms are pinned by text and neither is this peer's
            // choice.
            return Listing(ctx, "/" + localPeerId + "/");
        }
        if (survivors.Count == 0)
        {
            // The self-excluded request: `resource` PRESENT, every target carved out by the
            // caller's own exclude. Serving it the absent case "answers a request for one
            // excluded path with a listing of the tree" (EXTENSION-TREE §2.2a) — the root
            // listing is wider than what was asked for, which is what BROAD-RESULT means.
            return Errors.Error(Status.BadRequest, "path_required", "tree: effective target list is empty");
        }
        if (survivors.Count > 1)
        {
            return Errors.Error(Status.BadRequest, "ambiguous_resource", "tree: more than one effective target");
        }
        string target = survivors[0];

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
            return Listing(ctx, Paths.Canonicalize(target.TrimEnd('/'), localPeerId));
        }

        // A resource-requiring operation takes a CONCRETE path (0.8.2.20). Without this
        // the pattern is looked up as a literal and answers `404 not_found`, which names
        // the wrong fault: the request is malformed, the tree is fine.
        if (IsPatternPath(target))
        {
            return Errors.Error(Status.BadRequest, "malformed_resource", target);
        }

        string path = Paths.Canonicalize(target, localPeerId);
        // §6.3: the handler MUST verify the CALLER's capability covers the path it is
        // about to read. NOT a secondary check — the dispatch-level check never saw this
        // path if the caller excluded it.
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

    /// <summary>
    /// Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
    /// <para>
    /// <em>"When any handler returns a multi-entry result whose entries are tree paths,
    /// each entry MUST be individually checked using <c>check_path_permission</c>. Entries
    /// for which <c>check_path_permission</c> returns DENY MUST be omitted. The result's
    /// <c>count</c> field MUST reflect the filtered entry count, not the source tree's
    /// total count."</em>
    /// </para>
    /// <para>
    /// The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the
    /// subject, and testing the prefix would deny a listing to a caller whose grant covers
    /// children but not the node above them, which is the ordinary shape of a narrowed
    /// grant.
    /// </para>
    /// </summary>
    private static HandlerResult Listing(HandlerContext ctx, string prefix)
    {
        EntityTree tree = ctx.Peer.Tree;
        IReadOnlyDictionary<string, ListingEntry> raw = tree.List(prefix);
        var entries = new List<(string Key, EcfValue Value)>();
        foreach ((string name, ListingEntry entry) in raw)
        {
            // §6.3's per-entry check (0.8.2.21/.22). The peer-root prefix canonicalizes to
            // "/{peer}/" (trailing slash); guard against a "//" empty segment when joining
            // the entry name (root listing).
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
            // `count` follows the FILTERED total. A count that still reports the source
            // total is the disclosure the rule exists to prevent.
            ("count", Ecf.Uint((ulong)entries.Count)),
            ("offset", Ecf.Uint(0))));
        return HandlerResult.Ok(listing);
    }

    private static HandlerResult Put(HandlerContext ctx)
    {
        // Same ladder as <see cref="Get"/>, with the two empties COLLAPSED rather than
        // split: EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's
        // "an empty effective list IS the absent case" applies in its unscoped form and
        // both empties answer `path_required`. That is the same table `Get`'s branch
        // cites, one row down.
        //
        // Note the code 0.8.2.20 forces: a MISSING target is `path_required`, never
        // `ambiguous_resource` — 0.8.2.20 names that inversion outright, because *supply a
        // resource* is not *disambiguate your request* and the code is what selects the
        // remedy. This peer answered `400 handler_error` for both.
        (IReadOnlyList<string> survivors, bool hasResource) = Permissions.EffectiveTargets(ctx.Execute, ctx.LocalPeerId);
        if (!hasResource || survivors.Count == 0)
        {
            return Errors.Error(Status.BadRequest, "path_required", "tree: put requires a resource target");
        }
        if (survivors.Count > 1)
        {
            return Errors.Error(Status.BadRequest, "ambiguous_resource", "tree: more than one effective target");
        }
        string target = survivors[0];

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
        if (IsPatternPath(target))
        {
            return Errors.Error(Status.BadRequest, "malformed_resource", target);
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

    /// <summary>
    /// §6.3's per-path authorization, against the CALLER's verified capability and the
    /// OWNING handler's pattern — both carried on the context by the dispatcher, which
    /// already computed them. Carried rather than recomputed: recomputing invites the two
    /// to drift, and §6.8 is explicit that the authority is selected by who named the path.
    /// <para>
    /// An UNAUTHENTICATED context (no capability) is NOT filtered: the filter's subject is
    /// "the caller's verified capability", and where there is none there is no caller to
    /// narrow. That is the bootstrap/internal path, and it matches both vanguard peers. On
    /// this peer every reachable tree dispatch carries a capability — the dispatcher only
    /// reaches a handler after <c>VerifyRequest</c> produced one, and the connect handler
    /// is the sole <c>null</c> case — so the branch is unreachable today and is written for
    /// the rule rather than for a caller.
    /// </para>
    /// </summary>
    private static bool AuthorizePath(HandlerContext ctx, string operation, string path) =>
        ctx.CallerCapability is null
        || Permissions.CheckPathPermission(operation, path, ctx.CallerCapability, ctx.Pattern, ctx.LocalPeerId);

    /// <summary>
    /// A §5.4 PATTERN rather than a concrete path. A resource-requiring operation takes a
    /// CONCRETE path (0.8.2.20), and a trailing <c>/</c> is a listing request rather than a
    /// pattern — only a <c>*</c> makes it one.
    /// </summary>
    private static bool IsPatternPath(string target) => target.Contains('*');

    private static Entity EmptyAck() => Entity.Create(TypeNames.PrimitiveAny, Ecf.EmptyMap);
}
