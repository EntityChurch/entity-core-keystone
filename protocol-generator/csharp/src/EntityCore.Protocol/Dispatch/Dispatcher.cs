using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Handlers;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;
using EntityCore.Protocol.Transport;

namespace EntityCore.Protocol.Dispatch;

/// <summary>
/// The dispatch chain (V7 §6.5): decode → integrity verify → handler resolution →
/// permission check → handler execution, producing an EXECUTE_RESPONSE envelope.
/// Connection pre-authorization (§4.2) is the sole special case. Composes the
/// deterministic Layer-1 capability verdict (<see cref="ChainVerifier"/>) with the
/// local checks here; no Layer-1 hook reads local policy (§5.10 / N8).
/// </summary>
internal sealed class Dispatcher
{
    private readonly IPeerServices _peer;
    private readonly HandlerRegistry _registry;

    public Dispatcher(IPeerServices peer, HandlerRegistry registry)
    {
        _peer = peer;
        _registry = registry;
    }

    /// <summary>
    /// Dispatch an inbound EXECUTE envelope and return the response envelope. The
    /// caller (connection reader) has already routed EXECUTE_RESPONSE roots to their
    /// awaiting callers; only EXECUTE roots reach here.
    /// </summary>
    public async Task<Envelope> DispatchAsync(
        Envelope request, ConnectionState conn, IReentrantSender? sender, CancellationToken ct)
    {
        Execute execute;
        try
        {
            execute = new Execute(request.Root);
        }
        catch (EntityProtocolException ex)
        {
            // No request_id available — respond with a best-effort error.
            return ErrorEnvelope("", Status.BadRequest, "invalid_request", ex.Message);
        }

        string requestId;
        try
        {
            requestId = execute.RequestId;
        }
        catch (EntityProtocolException ex)
        {
            return ErrorEnvelope("", Status.BadRequest, "invalid_request", ex.Message);
        }

        // §6.5 robustness (Finding 1): verification/dispatch faults become an error
        // response — an inbound EXECUTE MUST never hang the peer. An unsupported or
        // malformed shape (e.g. a multi-sig granter) rejects cleanly, never throws past.
        try
        {
            return await DispatchCoreAsync(execute, request, requestId, conn, sender, ct).ConfigureAwait(false);
        }
        catch (EntityProtocolException ex)
        {
            return ErrorEnvelope(requestId, ex.Status, "request_error", ex.Message);
        }
        catch (Exception ex)
        {
            return ErrorEnvelope(requestId, Status.InternalError, "internal_error", ex.Message);
        }
    }

    private async Task<Envelope> DispatchCoreAsync(
        Execute execute, Envelope request, string requestId, ConnectionState conn, IReentrantSender? sender, CancellationToken ct)
    {
        string path;
        try
        {
            path = Paths.DispatchPath(execute.Uri, _peer.LocalPeerId);
        }
        catch (EntityProtocolException ex)
        {
            return ErrorEnvelope(requestId, Status.BadRequest, "invalid_request", ex.Message);
        }

        // Inbound dispatch MUST target the local peer (§1.4).
        if (Paths.ExtractPeer(path, _peer.LocalPeerId) != _peer.LocalPeerId)
        {
            return ErrorEnvelope(requestId, Status.BadRequest, "invalid_request", "request does not target local peer");
        }

        // Connection pre-authorization (§4.2, §6.5) — the sole no-auth special case.
        string connectPath = "/" + _peer.LocalPeerId + "/" + Protocols.ConnectPath;
        if (path == connectPath && !conn.Established)
        {
            IHandler? connect = _registry.Get(Protocols.ConnectPath);
            if (connect is null)
            {
                return ErrorEnvelope(requestId, Status.InternalError, "no_connect_handler", "connect handler missing");
            }
            return await RunHandlerAsync(connect, execute, request, conn, callerCapability: null, handlerGrant: null,
                pattern: Protocols.ConnectPath, suffix: string.Empty, sender, ct).ConfigureAwait(false);
        }

        // Authenticated path. Every EXECUTE MUST carry author + capability (§5.1). The
        // §3.3 two-level model splits the two: a missing author is an authentication-class
        // failure (can't establish who is asking) → 401; a missing capability is an
        // authorization-class failure (no authority presented) → 403.
        if (execute.Author is null)
        {
            return ErrorEnvelope(requestId, Status.Unauthorized, "missing_author", "author required");
        }
        if (execute.Capability is null)
        {
            return ErrorEnvelope(requestId, Status.Forbidden, "missing_authorization", "capability required");
        }

        // Ingest envelope signatures to their invariant pointer paths (§6.5).
        IngestSignatures(request);

        // Integrity + capability verification (§5.2 verify_request).
        VerifyResult verify = VerifyRequest(execute, request);
        if (verify.Status != Status.Ok)
        {
            return ErrorEnvelope(requestId, verify.Status, verify.Code!, verify.Message);
        }

        // Resolve handler by tree walk (§6.6). No match → 404.
        HandlerRegistry.Resolution? resolved = _registry.Resolve(path);
        if (resolved is null)
        {
            return ErrorEnvelope(requestId, Status.NotFound, "not_found", $"no handler resolves {path}");
        }
        HandlerRegistry.Resolution res = resolved.Value;

        // Dispatch permission check (§5.2 check_permission). §PR-8: resolve the cap's
        // granter once here; its grant resource patterns canonicalize against that
        // frame, not the verifier's. Register/unregister ride this same boundary
        // (B1 / V2.0/L1) — the EXECUTE.resource install path is the authorization target.
        CapabilityToken capability = verify.Capability!;
        string granterPeerId = Permissions.ResolveGranterPeerId(capability, request, _peer.LocalPeerId);
        if (!Permissions.CheckPermission(execute, capability, res.Pattern, _peer.LocalPeerId, granterPeerId))
        {
            return ErrorEnvelope(requestId, Status.Forbidden, "capability_denied", "capability does not grant the operation");
        }

        // Resolve + validate the handler grant (§6.8 dispatch-time grant validation). A
        // dynamically-registered handler's grant was written by register at
        // system/capability/grants/{pattern} with its signature at the §3.5 pointer.
        CapabilityToken? handlerGrant = _registry.ResolveGrant(res.Pattern);
        if (handlerGrant is null || !ValidateHandlerGrant(handlerGrant))
        {
            return ErrorEnvelope(requestId, Status.Forbidden, "permission_denied", "handler grant missing or invalid");
        }

        // Bootstrap handler (in-process body) vs dynamically-registered handler
        // (entity-native body at expression_path, v7.74 §6.13(a)).
        if (res.Native is not null)
        {
            return await RunHandlerAsync(res.Native, execute, request, conn, capability, handlerGrant, res.Pattern, res.Suffix, sender, ct)
                .ConfigureAwait(false);
        }
        return RunEntityNative(res.HandlerEntity, execute);
    }

    /// <summary>
    /// Dispatch a dynamically-registered (entity-native) handler by evaluating the body
    /// at its <c>expression_path</c> (v7.74 §6.13(a)). The core peer's body-binding seam
    /// (impl-private per §9.4) evaluates the minimal <c>compute/literal</c> shape and
    /// returns a <c>compute/result</c>, which is what the §10.1 register round-trip
    /// exercises. Fuller expression bodies need the compute extension (501). See A-011.
    /// </summary>
    private Envelope RunEntityNative(Entity handlerEntity, Execute execute)
    {
        string? exprPath = Ecf.OptText(handlerEntity.Data, "expression_path");
        if (exprPath is null)
        {
            return ErrorEnvelope(execute.RequestId, Status.NotSupported, "no_handler_body",
                "registered handler has neither a native body nor an expression_path");
        }

        string absExpr = Paths.Canonicalize(exprPath, _peer.LocalPeerId);
        Entity? expr = _peer.Tree.Get(absExpr);
        if (expr is null)
        {
            return ErrorEnvelope(execute.RequestId, Status.NotFound, "expression_not_found",
                $"no entity bound at the handler's expression_path {absExpr}");
        }

        if (expr.Type == TypeNames.ComputeLiteral)
        {
            EcfValue value = Ecf.Require(expr.Data, "value");
            Entity result = Entity.Create(TypeNames.ComputeResult, Ecf.Map(
                ("value", value),
                ("expression", Ecf.Bytes(expr.ContentHash))));
            ExecuteResponse response = ExecuteResponse.Build(execute.RequestId, Status.Ok, result);
            return new Envelope(response.Entity, System.Array.Empty<Entity>());
        }

        return ErrorEnvelope(execute.RequestId, Status.NotSupported, "unsupported_expression",
            "core peer evaluates only compute/literal bodies (the entity-native seam); richer bodies need the compute extension");
    }

    private async Task<Envelope> RunHandlerAsync(
        IHandler handler, Execute execute, Envelope request, ConnectionState conn,
        CapabilityToken? callerCapability, CapabilityToken? handlerGrant, string pattern, string suffix,
        IReentrantSender? sender, CancellationToken ct)
    {
        var context = new HandlerContext
        {
            Peer = _peer,
            Execute = execute,
            Envelope = request,
            Pattern = pattern,
            Suffix = suffix,
            CallerCapability = callerCapability,
            HandlerGrant = handlerGrant,
            Author = execute.Author,
            Connection = conn,
            // §6.13(b) handler-facing outbound seam — routes through §6.11 reentry on the
            // serving connection. Present whenever a reentrant sender is available.
            Outbound = sender is null ? null : new OutboundDispatch(_peer.LocalIdentity, sender),
        };

        try
        {
            HandlerResult result = await handler.HandleAsync(context, ct).ConfigureAwait(false);
            ExecuteResponse response = ExecuteResponse.Build(execute.RequestId, result.Status, result.Result);
            return new Envelope(response.Entity, result.Included);
        }
        catch (EntityProtocolException ex)
        {
            return ErrorEnvelope(execute.RequestId, ex.Status, "handler_error", ex.Message);
        }
        catch (Exception ex)
        {
            return ErrorEnvelope(execute.RequestId, Status.InternalError, "internal_error", ex.Message);
        }
    }

    private readonly record struct VerifyResult(int Status, string? Code, string? Message, CapabilityToken? Capability)
    {
        public static VerifyResult Ok(CapabilityToken capability) => new(Model.Status.Ok, null, null, capability);

        public static VerifyResult Deny(int status, string code, string message) => new(status, code, message, null);
    }

    /// <summary>Request integrity + capability verification (§5.2). Revocation skipped (supports_revocation=false).</summary>
    private VerifyResult VerifyRequest(Execute execute, Envelope envelope)
    {
        byte[] authorHash = execute.Author!;
        byte[] capabilityHash = execute.Capability!;

        // Signature (target-matching) over the EXECUTE.
        Entity? signature = ChainVerifier.FindSignature(envelope, execute.Entity.ContentHash);
        if (signature is null)
        {
            return VerifyResult.Deny(Status.Unauthorized, "invalid_signature", "no signature for EXECUTE");
        }
        if (!Hashes.Equal(Signatures.Signer(signature), authorHash))
        {
            return VerifyResult.Deny(Status.Unauthorized, "invalid_signature", "signature signer is not the author");
        }
        Entity? author = envelope.Find(authorHash);
        if (author is null)
        {
            return VerifyResult.Deny(Status.Unauthorized, "unresolvable_author", "author identity not in included");
        }
        if (!Signatures.Verify(signature, author))
        {
            return VerifyResult.Deny(Status.Unauthorized, "invalid_signature", "EXECUTE signature does not verify");
        }

        // Capability integrity.
        Entity? capabilityEntity = envelope.Find(capabilityHash);
        if (capabilityEntity is null)
        {
            return VerifyResult.Deny(Status.Forbidden, "capability_denied", "capability not in included");
        }
        var capability = new CapabilityToken(capabilityEntity);

        // §5.2 / §3.6 PR-3 single-401 carve-out: the leaf cap's grantee MUST resolve to a
        // present system/peer entity. An unresolvable grantee (zero-hash or any hash absent
        // from included) is an *authentication*-class failure — 401 unresolvable_grantee —
        // and is pinned to fire BEFORE the structural grantee==author check (which keeps its
        // 403). This closes the bearer-cap class (a cap whose grantee names nobody resolvable).
        Entity? granteeEntity = envelope.Find(capability.Grantee);
        if (granteeEntity is null || granteeEntity.Type != TypeNames.Peer)
        {
            return VerifyResult.Deny(Status.Unauthorized, "unresolvable_grantee",
                "leaf cap grantee does not resolve to a system/peer entity");
        }
        if (!Hashes.Equal(capability.Grantee, authorHash))
        {
            return VerifyResult.Deny(Status.Forbidden, "capability_denied", "capability grantee is not the author");
        }
        // §4.10(b) resource bound: a chain exceeding the peer's max depth is rejected
        // as 400 chain_depth_exceeded (structural excess) BEFORE the per-link authz
        // walk — distinct from 403 capability_denied. Arch v7.75 ruling: 400 lets the
        // caller distinguish "shorten your chain" from "you lack the capability".
        if (ChainVerifier.ExceedsMaxDepth(capability, envelope))
        {
            return VerifyResult.Deny(Status.BadRequest, "chain_depth_exceeded",
                "capability chain exceeds max depth (§4.10b)");
        }
        if (!ChainVerifier.VerifyCapabilityChain(capability, envelope, _peer.LocalPeerId, _peer.NowMs))
        {
            return VerifyResult.Deny(Status.Forbidden, "capability_denied", "capability chain verification failed");
        }

        // §5.2 step 4: revocation. A revoked link anywhere in the authority chain denies.
        // The verifier KNOWS this is a revocation (is_revoked returned true against the
        // §6.2 marker), so it emits the specific code: 403 capability_revoked — a V7 core
        // code per §3.3 line 900, preferred over the generic capability_denied catch-all
        // when the revocation semantic is known (Class C ruling 2026-06-11). The status
        // stays 403; the 401 carve-out for capability_revoked is ROLE-only (§5.5 in-flight
        // cascade race), out of core scope. The chain already verified, so every parent
        // resolves in included.
        if (IsChainRevoked(capability, envelope))
        {
            return VerifyResult.Deny(Status.Forbidden, "capability_revoked", "capability is revoked (§5.1)");
        }

        return VerifyResult.Ok(capability);
    }

    /// <summary>
    /// §5.1 <c>is_revoked</c> over the full authority chain: true if any link's content
    /// hash has a revocation marker bound at
    /// <c>/{local}/system/capability/revocations/{hash_hex}</c> (written by the cap
    /// handler's <c>revoke</c> op). Walks leaf → root via parent pointers in
    /// <c>included</c>; the chain has already verified, so every parent resolves.
    /// </summary>
    private bool IsChainRevoked(CapabilityToken leaf, Envelope envelope)
    {
        CapabilityToken? current = leaf;
        int depth = 0;
        while (current is not null && depth <= 64)
        {
            string path = "/" + _peer.LocalPeerId + "/system/capability/revocations/" + current.ContentHashHex;
            if (_peer.Tree.Get(path) is not null)
            {
                return true;
            }
            if (current.Parent is null)
            {
                break;
            }
            Entity? parent = envelope.Find(current.Parent);
            if (parent is null)
            {
                break;
            }
            current = new CapabilityToken(parent);
            depth++;
        }
        return false;
    }

    /// <summary>Dispatch-time handler-grant validation (§6.8): self-issued by the local peer, signed, temporal.</summary>
    private bool ValidateHandlerGrant(CapabilityToken grant)
    {
        if (grant.Granter is null || !Hashes.Equal(grant.Granter, _peer.LocalIdentity.IdentityHash))
        {
            return false; // handler grants are self-issued single-sig; multi-sig/cross-peer is a category error
        }
        // Signature at the §3.5 invariant pointer path.
        Entity? sig = _peer.Tree.Get("/" + _peer.LocalPeerId + "/system/signature/" + grant.ContentHashHex);
        if (sig is null || !Signatures.Verify(sig, _peer.LocalIdentity.PeerEntity))
        {
            return false;
        }
        if (grant.NotBefore is { } nb && _peer.NowMs < nb)
        {
            return false;
        }
        if (grant.ExpiresAt is { } exp && exp < _peer.NowMs)
        {
            return false;
        }
        return true;
    }

    /// <summary>
    /// Bind <c>system/signature</c> entities from <c>included</c> at their invariant
    /// pointer paths (§6.5 ingest_envelope_signatures), so handler validation can
    /// find them by tree lookup. Idempotent on content hash.
    /// </summary>
    private void IngestSignatures(Envelope envelope)
    {
        foreach (Entity entity in envelope.Included.Values)
        {
            if (entity.Type != TypeNames.Signature)
            {
                continue;
            }
            _peer.ContentStore.Put(entity);

            byte[] signerHash = Signatures.Signer(entity);
            Entity? signerPeer = envelope.Find(signerHash) ?? _peer.ContentStore.Get(signerHash);
            if (signerPeer is null)
            {
                continue; // cannot recover signer peer id; skip binding
            }
            _peer.ContentStore.Put(signerPeer);

            string path = "/" + PeerEntities.PeerId(signerPeer) + "/system/signature/" + Hashes.Hex(Signatures.Target(entity));
            Entity? existing = _peer.Tree.Get(path);
            if (existing is null)
            {
                _peer.Tree.Put(path, entity);
            }
        }
    }

    private static Envelope ErrorEnvelope(string requestId, int status, string code, string? message)
    {
        ExecuteResponse response = ExecuteResponse.Error(requestId, status, code, message);
        return new Envelope(response.Entity, System.Array.Empty<Entity>());
    }
}
