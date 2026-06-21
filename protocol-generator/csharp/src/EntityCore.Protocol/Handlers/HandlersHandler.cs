using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The handlers handler at <c>system/handler</c> (V7 §6.2). Manages handler
/// lifecycle over the wire: <c>register</c> installs a handler (the five normative
/// writes), <c>unregister</c> removes it (reversing all five). Behavioral presence
/// is a v7.74 §6.13(a) MUST — a <c>501</c> on either op from a <c>--profile core</c>
/// peer is non-conformant; this handler executes the writes.
/// <para>
/// Authorization rides the standard dispatch boundary (B1 / V2.0/L1): the caller's
/// capability is cap-checked against the <c>EXECUTE.resource</c> install path before
/// the body runs — no separate cap-check path. The peer-owner cap (§6.9a) satisfies
/// it vacuously for the owner. The handler's own writes are authorized by the
/// handlers handler's own grant (self-namespace authorization, §6.2).
/// </para>
/// </summary>
internal sealed class HandlersHandler : IHandler
{
    public string Pattern => "system/handler";

    public string Name => "handler";

    public IReadOnlyList<string> Operations { get; } = new[] { "register", "unregister" };

    public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct) =>
        Task.FromResult(ctx.Operation switch
        {
            "register" => Register(ctx),
            "unregister" => Unregister(ctx),
            _ => Errors.Error(Status.NotSupported, "unsupported_operation",
                $"unknown handlers-handler operation '{ctx.Operation}'"),
        });

    /// <summary>
    /// <c>register</c> (§6.2 / §6.13(a)): execute the five normative writes for the
    /// handler whose install path is carried in <c>EXECUTE.resource.targets[0]</c>
    /// (<c>system/handler/{pattern}</c>). The caller's authority over that path was
    /// already validated at the dispatch boundary (§3.2 path-as-resource).
    /// </summary>
    private static HandlerResult Register(HandlerContext ctx)
    {
        if (!TryPattern(ctx, out string pattern, out HandlerResult err))
        {
            return err;
        }
        if (ctx.Params.Type != TypeNames.HandlerRegisterRequest)
        {
            return Errors.Error(Status.BadRequest, "invalid_params",
                $"register expects a {TypeNames.HandlerRegisterRequest} (got '{ctx.Params.Type}')");
        }

        EcfValue req = ctx.Params.Data;
        EcfValue manifest = Ecf.Require(req, "manifest");
        string name = Ecf.OptText(manifest, "name") ?? pattern;
        EcfValue operations = Ecf.Field(manifest, "operations") ?? Ecf.EmptyMap;
        string? expressionPath = Ecf.OptText(manifest, "expression_path");
        EcfValue? maxScope = Ecf.Field(manifest, "max_scope");
        EcfValue? internalScope = Ecf.Field(manifest, "internal_scope");

        // Grant scope = requested_scope ?? internal_scope ?? [] (§6.2 grant issuance).
        EcfValue? grantScopeEcf = Ecf.Field(req, "requested_scope") ?? internalScope;
        IReadOnlyList<GrantEntry> grantScope = grantScopeEcf is null
            ? System.Array.Empty<GrantEntry>()
            : Ecf.AsArray(grantScopeEcf).Select(GrantEntry.FromEcf).ToList();

        string interfaceRelPath = "system/handler/" + pattern;

        // (1) Handler manifest (dispatch target) at the pattern path {pattern}.
        Entity handlerEntity = Entity.Create(TypeNames.Handler, Ecf.Map(
            ("interface", Ecf.Text(interfaceRelPath)),
            ("max_scope", maxScope),
            ("internal_scope", internalScope),
            ("expression_path", expressionPath is null ? null : Ecf.Text(expressionPath))));

        // (3) Self-issued, signed handler grant at system/capability/grants/{pattern}.
        PeerIdentity local = ctx.Peer.LocalIdentity;
        (CapabilityToken grant, Entity grantSig) = CapabilityToken.CreateRoot(
            local, local.IdentityHash, grantScope, ctx.Peer.NowMs);

        // (5) Handler interface entity (discovery index) at system/handler/{pattern}.
        Entity ifaceEntity = Entity.Create(TypeNames.HandlerInterface, Ecf.Map(
            ("pattern", Ecf.Text(pattern)),
            ("name", Ecf.Text(name)),
            ("operations", operations)));

        // The five writes (§6.2 / §6.13(a)). Order per the §6.2 inventory.
        ctx.Peer.Tree.Put(Abs(ctx, pattern), handlerEntity);                                  // 1. manifest
        InstallTypes(ctx, req);                                                                // 2. types
        ctx.Peer.Tree.Put(Abs(ctx, "system/capability/grants/" + pattern), grant.Entity);     // 3. grant
        ctx.Peer.Tree.Put(Abs(ctx, "system/signature/" + grant.ContentHashHex), grantSig);    // 4. grant-signature
        ctx.Peer.Tree.Put(Abs(ctx, interfaceRelPath), ifaceEntity);                           // 5. interface

        Entity result = Entity.Create(TypeNames.HandlerRegisterResult, Ecf.Map(
            ("pattern", Ecf.Text(pattern)),
            ("grant", grant.Entity.Data)));
        return HandlerResult.Ok(result);
    }

    /// <summary>
    /// <c>unregister</c> (§6.2): reverse all five register writes for the pattern in
    /// <c>EXECUTE.resource.targets[0]</c>. The grant-signature at
    /// <c>system/signature/{grant_hash}</c> is removed alongside the grant (writer /
    /// unregister symmetry — a half-removed state is the hazard the symmetry prevents).
    /// Installed types are left in place (they may be shared; see A-012).
    /// </summary>
    private static HandlerResult Unregister(HandlerContext ctx)
    {
        if (!TryPattern(ctx, out string pattern, out HandlerResult err))
        {
            return err;
        }

        // Recover the grant hash before removing the grant so the signature path resolves.
        Entity? grant = ctx.Peer.Tree.Get(Abs(ctx, "system/capability/grants/" + pattern));
        if (grant is not null)
        {
            ctx.Peer.Tree.Remove(Abs(ctx, "system/signature/" + grant.ContentHashHex));
            ctx.Peer.Tree.Remove(Abs(ctx, "system/capability/grants/" + pattern));
        }
        ctx.Peer.Tree.Remove(Abs(ctx, pattern));
        ctx.Peer.Tree.Remove(Abs(ctx, "system/handler/" + pattern));

        return HandlerResult.Ok(Entity.Create(TypeNames.PrimitiveAny, Ecf.EmptyMap));
    }

    /// <summary>
    /// (2) Install associated types at <c>system/type/{type_name}</c> per
    /// <c>register-request.types</c> (a <c>map[type_name]TypeDefinition</c>). Each value
    /// is a type-definition data map stored as a <c>system/type</c> entity.
    /// </summary>
    private static void InstallTypes(HandlerContext ctx, EcfValue req)
    {
        EcfValue? types = Ecf.Field(req, "types");
        if (types is null)
        {
            return;
        }
        foreach ((string typeName, EcfValue typeDef) in Ecf.Entries(types))
        {
            ctx.Peer.Tree.Put(Abs(ctx, "system/type/" + typeName), Entity.Create(TypeNames.Type, typeDef));
        }
    }

    /// <summary>
    /// Derive the install pattern from <c>EXECUTE.resource.targets[0]</c>
    /// (<c>system/handler/{pattern}</c>). Exactly one target is required — anything else
    /// is <c>400 ambiguous_resource</c> (§6.2). <c>unregister</c> carries the pattern
    /// entirely in resource (empty params).
    /// </summary>
    private static bool TryPattern(HandlerContext ctx, out string pattern, out HandlerResult error)
    {
        pattern = string.Empty;
        error = default!;
        ResourceTarget? resource = ctx.Resource;
        if (resource is null || resource.Targets.Count != 1)
        {
            error = Errors.Error(Status.BadRequest, "ambiguous_resource",
                "register/unregister require exactly one resource target (system/handler/{pattern}) (§6.2)");
            return false;
        }

        const string prefix = "system/handler/";
        string target = resource.Targets[0];
        if (!target.StartsWith(prefix, StringComparison.Ordinal) || target.Length == prefix.Length)
        {
            error = Errors.Error(Status.BadRequest, "invalid_resource",
                "register/unregister resource target MUST be system/handler/{pattern} (§6.2)");
            return false;
        }
        pattern = target[prefix.Length..];
        return true;
    }

    private static string Abs(HandlerContext ctx, string peerRelative) => "/" + ctx.LocalPeerId + "/" + peerRelative;
}
