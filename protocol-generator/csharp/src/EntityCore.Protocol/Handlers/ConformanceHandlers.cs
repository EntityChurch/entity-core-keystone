using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Identity;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The <c>system/validate/*</c> conformance test-handlers (GUIDE-CONFORMANCE §7a).
/// These are <b>not core protocol</b> — they are conformance scaffolding, present only
/// in a peer's conformance build (opt-in via the <c>conformanceHandlers</c> peer flag,
/// surfaced as the host <c>--validate</c> switch), off by default. They give a black-box
/// validator a native, compute-free way to drive the two extensibility hooks that have no
/// other wire-reachable trigger in a core-only peer:
/// <list type="bullet">
///   <item><see cref="EchoHandler"/> — proves the §6.13(a) resolve→dispatch half (closes A-011,
///     replacing the compute/literal round-trip).</item>
///   <item><see cref="DispatchOutboundHandler"/> — proves the §6.13(b)/§6.11 outbound seam by
///     originating one outbound EXECUTE back over the inbound connection (the §6.11 reentry
///     surface — the only origination path reachable in core; closes A-013).</item>
/// </list>
/// </summary>
internal static class ConformancePatterns
{
    public const string Echo = "system/validate/echo";
    public const string DispatchOutbound = "system/validate/dispatch-outbound";
}

/// <summary>
/// §7a <c>system/validate/echo</c>. EXECUTE returns, verbatim, the params entity it was
/// given (the literal value carried in params round-trips out). Native body, no compute —
/// this is the portable replacement for the A-011 <c>compute/literal</c> dispatch step.
/// </summary>
internal sealed class EchoHandler : IHandler
{
    public string Pattern => ConformancePatterns.Echo;
    public string Name => "validate-echo";
    public IReadOnlyList<string> Operations { get; } = new[] { "echo" };

    public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct) =>
        Task.FromResult(HandlerResult.Ok(ctx.Params));
}

/// <summary>
/// §7a <c>system/validate/dispatch-outbound</c>. EXECUTE originates exactly one outbound
/// EXECUTE — via the §6.13(b) handler-reachable outbound closure (<c>ctx.Outbound</c>,
/// the §6.11 reentry sender) — back to the calling peer, invoking <c>operation</c> on the
/// <c>target</c> pattern with the carried <c>value</c>, and returns that downstream
/// response. This proves the target can <em>originate</em>, not just respond.
///
/// <para>Authority: the reentry direction (this peer → caller) can only be authorized by
/// the caller, so the caller supplies the capability it minted for this peer in the params
/// (the three authority entities, each embedded as a nested entity). This mirrors the
/// B-rooted dispatch capability the wire harness already constructs for cross-peer
/// remote-execute — here carried in-band rather than via a continuation wrapper.</para>
/// </summary>
internal sealed class DispatchOutboundHandler : IHandler
{
    private static readonly TimeSpan OutboundTimeout = TimeSpan.FromSeconds(10);

    public string Pattern => ConformancePatterns.DispatchOutbound;
    public string Name => "validate-dispatch-outbound";
    public IReadOnlyList<string> Operations { get; } = new[] { "dispatch" };

    public async Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct)
    {
        if (ctx.Outbound is null)
        {
            return Errors.Error(Status.ServiceUnavailable, "no_outbound_seam",
                "dispatch-outbound requires a live section 6.11 reentry connection (handler was not dispatched over a connection)");
        }

        EcfValue p = ctx.Params.Data;
        string target = Ecf.RequireText(p, "target");        // handler pattern at the caller, e.g. system/validate/echo
        string operation = Ecf.RequireText(p, "operation");  // operation to invoke there, e.g. echo
        EcfValue value = Ecf.Require(p, "value");            // value to round-trip, so the loop is verifiable

        // GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
        // single-granter case is an array of ONE. They were singular, which made §1.4's
        // multi-signature-root rule ungateable on the wire: driving it needs two granter
        // identities and two signatures, and a single-credential carrier cannot express
        // that input.
        //
        // TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
        // because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle is
        // what all 46 tracked reports are measured against and it sends the SINGULAR
        // names; a plural-only peer reads the triple as absent there, takes the ambient arm
        // and refuses — measured on the `go` vanguard as 2 of 778 severities moving
        // PASS -> FAIL. Accepting both keeps the cohort 0-FAIL at BOTH check sets. REMOVE
        // THIS FALLBACK AT THE ORACLE RE-PIN, and not before: the exit condition is that
        // `tools/oracle-pin.env`'s `ref` names an oracle whose dispatch-outbound probe
        // sends the plural carriers.
        EcfValue? capField = Ecf.Field(p, "reentry_capability");
        Entity? capEnt = capField is null ? null : Entity.FromDecoded(capField);
        List<Entity>? granters = EntityList(p, "reentry_granters", "reentry_granter");
        List<Entity>? capSigs = EntityList(p, "reentry_cap_signatures", "reentry_cap_signature");
        // The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED arm,
        // all three absent selects the AMBIENT arm, and a PARTIAL set is 400
        // invalid_params — a partial credential is malformed, not ambient. An empty array
        // is partial, not present: it carries no credential.
        int nPresent = (capEnt is not null ? 1 : 0)
            + (granters is { Count: > 0 } ? 1 : 0)
            + (capSigs is { Count: > 0 } ? 1 : 0);
        if (nPresent is not (0 or 3))
        {
            return Errors.Error(Status.BadRequest, "invalid_params",
                "dispatch-outbound reentry authority is all-or-none");
        }
        bool hasCred = nPresent == 3;
        CapabilityToken? cred = hasCred && capEnt is not null ? new CapabilityToken(capEnt) : null;
        OutboundAuthority? authority = cred is null
            ? null
            : new OutboundAuthority(cred, granters ?? new List<Entity>(), capSigs ?? new List<Entity>());

        // §7a.1: the `value` field IS the outbound params entity data — pass it
        // through (the reference uses it directly). Re-wrapping as {"value": value}
        // double-wraps, so the echo's result.value returns a map (keystone §7b t1_2).
        Entity inner = Entity.Create(TypeNames.PrimitiveAny, value);
        // `target` arrives as any of §1.4's three spellings and the validator sends the
        // SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the resource target
        // want the PEER-RELATIVE path — §1.4's PD-2 block says so for Dimension 1, and a
        // resource target carrying a scheme is not a path at all.
        string relTarget = Permissions.PeerRelativeOf(target);
        var resource = new ResourceTarget(new[] { "system/handler/" + relTarget }, null);

        // §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer, all
        // four dimensions, on THIS handler's own grant — with a target-minted credential
        // relaxing Dimension 4 and nothing else. Consulting only the presented credential
        // here is the §6.8 confused-deputy bypass.
        if (!AuthorizeOutboundSubDispatch(ctx, relTarget, operation, resource, cred,
                granters ?? new List<Entity>(), capSigs ?? new List<Entity>()))
        {
            // §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
            // transport- or gateway-class code would launder an authorization verdict into
            // a route fault, and the ambient and presented branches would then disagree
            // about what the same gate decided.
            return Errors.Error(Status.Forbidden, "capability_denied",
                "outbound sub-dispatch not authorized by the handler grant");
        }

        ExecuteResponse downstream = await ctx.Outbound.ExecuteAsync(
            target, operation, inner, resource, authority, OutboundTimeout, ct).ConfigureAwait(false);

        // Return the downstream response so the validator sees the full round-trip.
        Entity result = Entity.Create(TypeNames.PrimitiveAny, Ecf.Map(
            ("status", Ecf.Uint((ulong)downstream.StatusCode)),
            ("result", new EcfValue.PreEncoded(downstream.Result.WireBytes))));
        return HandlerResult.Ok(result);
    }

    /// <summary>
    /// Decode an ARRAY of nested entities at <paramref name="key"/>, falling back to the
    /// SINGULAR spelling as a list of one (the §7a.1 transitional carriers).
    /// <para>
    /// <c>null</c> means absent or not a list; an array whose members do not all decode is
    /// a MALFORMED carrier and is also <c>null</c>, never a silently shorter list, because
    /// the caller's all-or-none test would then read a partial credential as a complete
    /// one.
    /// </para>
    /// </summary>
    private static List<Entity>? EntityList(EcfValue p, string key, string singular)
    {
        EcfValue? arr = Ecf.Field(p, key);
        if (arr is not null)
        {
            try
            {
                var outp = new List<Entity>();
                foreach (EcfValue v in Ecf.AsArray(arr)) outp.Add(Entity.FromDecoded(v));
                return outp;
            }
            catch
            {
                return null;
            }
        }
        EcfValue? one = Ecf.Field(p, singular);
        if (one is null) return null;
        try { return new List<Entity> { Entity.FromDecoded(one) }; }
        catch { return null; }
    }

    /// <summary>
    /// §1.4's PD-2 gate, wired to this peer's store: resolve the executing handler's OWN
    /// grant, verify a presented credential in the TARGET's frame, and run the
    /// four-dimension check.
    /// <para>
    /// §7a.2a: the credential, its granters and its signatures arrive NESTED IN PARAMS
    /// (ratified shape (a), in-band), so they are NOT in <c>ctx.Envelope</c> and a verifier
    /// handed that alone cannot resolve a single link — every credential then reads as
    /// invalid and the legitimate reentry is refused. The bundle merges them in, through
    /// the <c>Envelope</c> constructor so the content-hash keying cannot drift.
    /// </para>
    /// </summary>
    private static bool AuthorizeOutboundSubDispatch(
        HandlerContext ctx, string relTarget, string operation, ResourceTarget resource,
        CapabilityToken? cred, IReadOnlyList<Entity> granters, IReadOnlyList<Entity> capSigs)
    {
        string local = ctx.Peer.LocalPeerId;
        // §6.8: a handler with no valid grant does not run. Fail closed rather than falling
        // back to the credential, which is the substitution §6.8 forbids. `ctx.HandlerGrant`
        // is the grant §6.5 already resolved — used rather than a fresh store read, so the
        // handler-level check runs against the SAME authority the dispatch check resolved.
        CapabilityToken? ownGrant = ctx.HandlerGrant;
        if (ownGrant is null)
        {
            Entity? e = ctx.Peer.Tree.Get(Permissions.GrantPathFor(local, ctx.Pattern));
            if (e is null) return false;
            ownGrant = new CapabilityToken(e);
        }

        // §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the
        // absolute form, so the URI names the target. Where the uri is PEER-RELATIVE there
        // is no peer in it and the §6.11 seam's destination is the connection's remote, so
        // that is the fallback — without it Dimension 4 passes vacuously on the default
        // {include: [local]} and the exemption is never exercised.
        string uriPeer = Paths.ExtractPeer(ctx.Execute.Uri, local);
        string targetPeer = uriPeer == local ? (ctx.Connection?.RemotePeerId ?? uriPeer) : uriPeer;

        Scope? relaxTo = null;
        if (cred is not null && targetPeer != local)
        {
            var merged = new List<Entity>(ctx.Envelope.Included.Values) { cred.Entity };
            merged.AddRange(granters);
            merged.AddRange(capSigs);
            var bundle = new Envelope(ctx.Envelope.Root, merged);
            // Every clause is required and failing any relaxes NOTHING: the chain ROOT
            // granter resolves to the TARGET peer and is NOT a multi-signature root; the
            // LEAF grantee is this peer; the chain is valid and not revoked.
            if (ChainVerifier.VerifyCapabilityChain(cred, bundle, local, ctx.Peer.NowMs, targetPeer))
            {
                Entity? grantee = bundle.Find(cred.Grantee);
                bool revoked = ctx.Peer.Tree.Get(
                    "/" + local + "/system/capability/revocations/" + cred.ContentHashHex) is not null;
                if (!revoked && grantee is not null && PeerEntities.PeerId(grantee) == local)
                {
                    // The credential's own `peers` scope is what Dimension 4 relaxes TO.
                    // Absent means the granter — the target peer — which is the ordinary
                    // reentry shape: "you may dispatch back to me."
                    GrantEntry? first = cred.Grants.Count > 0 ? cred.Grants[0] : null;
                    if (first is not null) relaxTo = first.Peers ?? new Scope(new[] { targetPeer }, null);
                }
            }
        }

        return Permissions.CheckOutboundSubDispatch(
            ownGrant, local, targetPeer, relTarget, operation, resource, relaxTo);
    }
}
