using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The capability handler at <c>system/capability</c> (V7 §6.2). Runtime capability
/// management:
/// <list type="bullet">
/// <item><c>request</c> — issues a token from the peer's own authority, bounded by the
///   caller's presented authority (§6.2 / §5.6: an issued grant MUST NOT exceed the
///   caller's scope → <c>scope_exceeds_authority</c>). Returns inline with the token in
///   <c>included</c>.</item>
/// <item><c>configure</c> — binds a <c>system/capability/policy-entry</c> at
///   <c>system/capability/policy/{peer_pattern}</c> (v7.62 §4). <c>peer_pattern</c> is
///   exactly <c>"default"</c> or a 66-char hex content hash; partial prefixes reject.</item>
/// <item><c>revoke</c> — writes a <c>system/capability/revocation</c> marker at
///   <c>system/capability/revocations/{cap_hash_hex}</c> with a handler-set
///   <c>revoked_at</c> (v7.62 §5/§6). The dispatcher's §5.2 <c>is_revoked</c> step
///   enforces it on subsequent use.</item>
/// <item><c>delegate</c> — same-peer-only in v1 (closeout F1 / F13); a remote caller
///   receives 501 <c>unsupported_operation</c>.</item>
/// </list>
/// </summary>
internal sealed class CapabilityHandler : IHandler
{
    public string Pattern => "system/capability";

    public string Name => "capability";

    public IReadOnlyList<string> Operations { get; } = new[] { "request", "delegate", "revoke", "configure" };

    public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct) =>
        Task.FromResult(ctx.Operation switch
        {
            "request" => Request(ctx),
            "configure" => Configure(ctx),
            "revoke" => Revoke(ctx),
            // §6.2 closeout F1: delegate is same-peer-only in v1 — a remote caller (every
            // validate-peer client) receives 501 unsupported_operation, not 403. The
            // input shape (where the grantee is named) is still under-specified (F13).
            "delegate" => Errors.Error(Status.NotSupported, "unsupported_operation",
                "delegate is same-peer-only in v1 (closeout F1); input shape under-specified (F13)"),
            _ => Errors.Error(Status.NotSupported, "unsupported_operation",
                $"unknown capability operation '{ctx.Operation}'"),
        });

    private static HandlerResult Request(HandlerContext ctx)
    {
        if (ctx.Author is null)
        {
            return Errors.Error(Status.Forbidden, "missing_authorization", "capability request requires an author");
        }
        Entity? granteePeer = ctx.Envelope.Find(ctx.Author);
        if (granteePeer is null)
        {
            return Errors.Error(Status.BadRequest, "unresolvable_grantee", "author identity not in included");
        }

        // Parse the requested scope (§3.6 system/capability/request).
        IReadOnlyList<GrantEntry> requested = Ecf.AsArray(Ecf.Require(ctx.Params.Data, "grants"))
            .Select(GrantEntry.FromEcf).ToList();

        // §6.2 / §5.6 attenuation-on-issue: the issued grant MUST NOT exceed the caller's
        // presented authority. A narrow presented cap asking for a wider grant is refused
        // with 403 scope_exceeds_authority — the cap-handler analogue of delegation
        // attenuation, enforced regardless of how broad the connection identity is.
        if (ctx.CallerCapability is not null
            && !Attenuation.GrantsWithinAuthority(requested, ctx.CallerCapability.Grants, ctx.LocalPeerId))
        {
            return Errors.Error(Status.Forbidden, "scope_exceeds_authority",
                "requested grant exceeds the caller's presented authority (§6.2 / §5.6)");
        }

        ulong? ttlMs = Ecf.OptUint(ctx.Params.Data, "ttl_ms");
        ulong? expiresAt = ttlMs is null ? null : ctx.Peer.NowMs + ttlMs.Value;

        // The core peer grants the requested (now-bounded) scope from its own root
        // authority (the peer is the sole root for caps it issues, §5.5).
        (CapabilityToken token, Entity signature) = CapabilityToken.CreateRoot(
            ctx.Peer.LocalIdentity, granteePeer.ContentHash, requested, ctx.Peer.NowMs, expiresAt);

        Entity grant = Entity.Create(TypeNames.CapabilityGrant, Ecf.Map(
            ("token", Ecf.Bytes(token.ContentHash))));

        var included = new List<Entity> { token.Entity, ctx.Peer.LocalIdentity.PeerEntity, granteePeer, signature };
        return HandlerResult.Ok(grant, included);
    }

    /// <summary>
    /// <c>configure</c> (v7.62 §4): bind a policy-entry at the canonical policy path. The
    /// <c>peer_pattern</c> MUST be exactly <c>"default"</c> or a 66-hex-char content hash;
    /// a partial prefix (e.g. <c>00abc*</c>) is a typo-attack surface and rejects 400.
    /// </summary>
    private static HandlerResult Configure(HandlerContext ctx)
    {
        if (ctx.Params.Type != TypeNames.CapabilityPolicyEntry)
        {
            return Errors.Error(Status.BadRequest, "invalid_params",
                $"configure expects a {TypeNames.CapabilityPolicyEntry} (got '{ctx.Params.Type}')");
        }
        string peerPattern = Ecf.RequireText(ctx.Params.Data, "peer_pattern");
        if (!IsValidPolicyPattern(peerPattern))
        {
            return Errors.Error(Status.BadRequest, "invalid_params",
                "peer_pattern MUST be \"default\", a 66/98-char hex content hash, or a Base58 peer_id; partial prefixes are rejected (v7.62 §4)");
        }
        // v7.62 §4: a policy entry MUST carry at least one grant — an empty policy is meaningless.
        if (Ecf.AsArray(Ecf.Require(ctx.Params.Data, "grants")).Count == 0)
        {
            return Errors.Error(Status.BadRequest, "invalid_params", "policy-entry MUST specify at least one grant (v7.62 §4)");
        }

        string path = Paths.Canonicalize("system/capability/policy/" + peerPattern, ctx.LocalPeerId);
        ctx.Peer.Tree.Put(path, ctx.Params);
        return HandlerResult.Ok(Ack());
    }

    /// <summary>
    /// <c>revoke</c> (v7.62 §5/§6): write a revocation marker keyed by the token's content
    /// hash, with a handler-set wall-clock <c>revoked_at</c>. A zero token is rejected.
    /// </summary>
    private static HandlerResult Revoke(HandlerContext ctx)
    {
        byte[]? token = Ecf.OptBytes(ctx.Params.Data, "token");
        if (token is null || Hashes.IsZero(token))
        {
            return Errors.Error(Status.BadRequest, "invalid_params", "revoke-request.token must be non-zero (v7.62 §10)");
        }
        string? reason = Ecf.OptText(ctx.Params.Data, "reason");

        Entity marker = Entity.Create(TypeNames.CapabilityRevocation, Ecf.Map(
            ("token", Ecf.Bytes(token)),
            ("reason", reason is null ? null : Ecf.Text(reason)),
            ("revoked_at", Ecf.Uint(ctx.Peer.NowMs))));

        string path = Paths.Canonicalize("system/capability/revocations/" + Hashes.Hex(token), ctx.LocalPeerId);
        ctx.Peer.Tree.Put(path, marker);
        return HandlerResult.Ok(Ack());
    }

    /// <summary>
    /// A valid policy <c>peer_pattern</c> is one of three shapes (v7.62 §4 + v7.65 §3.6
    /// rule 3): the literal <c>"default"</c> fallback; a canonical hex content hash (66
    /// chars SHA-256 / 98 chars SHA-384, format-relative per v7.70 §1.2); or a decodable
    /// Base58 wire-form peer_id (the lazy-canonicalization pending state — canonicalized to
    /// hex on first contact). Glob/partial-prefix patterns (e.g. <c>00abc*</c>) are rejected
    /// — <c>*</c> is V7's match glyph everywhere else and has no policy-key meaning.
    /// </summary>
    private static bool IsValidPolicyPattern(string pattern)
    {
        if (pattern == "default")
        {
            return true;
        }
        // Reject obvious glob attempts before the length / decode checks (v7.62 §4).
        if (pattern.Contains('*'))
        {
            return false;
        }
        // Hex form: §3.5 invariant-pointer width — 66 (SHA-256) or 98 (SHA-384) hex chars.
        if (pattern.Length is 66 or 98)
        {
            foreach (char c in pattern)
            {
                bool hex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
                if (!hex)
                {
                    return false;
                }
            }
            return true;
        }
        // Base58 form (v7.65 §3.6 rule 3): must decode to a valid peer_id of a known family.
        try
        {
            PeerId pid = EntityCodec.ParsePeerId(pattern);
            return KeyTypes.IsSupported(pid.KeyType) && pid.Digest.Length > 0;
        }
        catch (Exception ex) when (ex is EntityCodecException or FormatException or ArgumentException)
        {
            return false;
        }
    }

    private static Entity Ack() => Entity.Create(TypeNames.PrimitiveAny, Ecf.EmptyMap);
}
