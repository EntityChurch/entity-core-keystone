using System.Collections.Concurrent;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The in-memory dispatch index (V7 §6.1, §6.6): maps a handler pattern to its
/// executable <see cref="IHandler"/>, and keeps the tree the source of truth by
/// installing the matching <c>system/handler</c> (dispatch target),
/// <c>system/handler/interface</c> (discovery), and
/// <c>system/capability/grants/{pattern}</c> (authorization) entities. The tree
/// walk in <see cref="Resolve"/> produces results equivalent to a pure §6.6 walk.
/// </summary>
internal sealed class HandlerRegistry
{
    private readonly ConcurrentDictionary<string, IHandler> _handlers = new();
    private readonly IPeerServices _peer;

    public HandlerRegistry(IPeerServices peer) => _peer = peer;

    /// <summary>
    /// Register a handler: index it by pattern and install its three tree entities.
    /// Bootstrap handlers (§6.9) are installed this way during peer initialization.
    /// </summary>
    public void Register(IHandler handler)
    {
        _handlers[handler.Pattern] = handler;

        // Peer-relative interface path (§6.2 N5): the `interface` field is a
        // system/tree/path, published peer-relative (no {peer_id} segment) — that is
        // what a remote resolves and what validate-peer's interface_ref check expects.
        // The tree *binding* below is still absolute.
        string interfaceRelPath = "system/handler/" + handler.Pattern;
        string interfacePath = AbsolutePath(interfaceRelPath);

        Entity ifaceEntity = Entity.Create(TypeNames.HandlerInterface, Ecf.Map(
            ("pattern", Ecf.Text(handler.Pattern)),
            ("name", Ecf.Text(handler.Name)),
            ("operations", OperationsMap(handler.Operations))));

        Entity handlerEntity = Entity.Create(TypeNames.Handler, Ecf.Map(
            ("interface", Ecf.Text(interfaceRelPath))));

        // Self-issued, signed, empty-scope grant (§6.8: empty grants are valid for
        // pure-functional handlers; bootstrap handlers authorize caller-specified
        // tree writes via the caller capability, not their own grant).
        (CapabilityToken grant, Entity grantSig) = CapabilityToken.CreateRoot(
            _peer.LocalIdentity, _peer.LocalIdentity.IdentityHash,
            System.Array.Empty<GrantEntry>(), _peer.NowMs);

        _peer.Tree.Put(AbsolutePath(handler.Pattern), handlerEntity);
        _peer.Tree.Put(interfacePath, ifaceEntity);
        _peer.Tree.Put(AbsolutePath("system/capability/grants/" + handler.Pattern), grant.Entity);
        // Bind the grant's signature at the §3.5 invariant pointer so dispatch-time
        // grant validation (§6.8 step 3) can find and verify it by tree lookup.
        _peer.Tree.Put(
            AbsolutePath("system/signature/" + grant.ContentHashHex),
            grantSig);
    }

    public IHandler? Get(string pattern) => _handlers.TryGetValue(pattern, out IHandler? h) ? h : null;

    /// <summary>
    /// A resolved dispatch target (§6.6): the peer-relative pattern, the URI suffix, and
    /// the <c>system/handler</c> tree entity. <see cref="Native"/> is the in-process
    /// executable for a bootstrap handler, or <c>null</c> for a dynamically-registered
    /// (entity-native) handler whose body lives at the entity's <c>expression_path</c>.
    /// </summary>
    public readonly record struct Resolution(string Pattern, string Suffix, Entity HandlerEntity, IHandler? Native);

    /// <summary>
    /// Resolve a handler by walking backward from <paramref name="canonicalPath"/> for
    /// the longest <c>system/handler</c>-typed prefix (§6.6). A registered handler with
    /// no in-process executable still resolves — its body is entity-native (the v7.74
    /// §6.13(a) dynamic-register surface), dispatched via its <c>expression_path</c>.
    /// </summary>
    public Resolution? Resolve(string canonicalPath)
    {
        string[] segments = canonicalPath.TrimStart('/').Split('/');
        for (int i = segments.Length; i >= 1; i--)
        {
            string absPrefix = "/" + string.Join('/', segments[..i]);
            Entity? entity = _peer.Tree.Get(absPrefix);
            if (entity is not null && entity.Type == TypeNames.Handler)
            {
                string pattern = StripPeer(absPrefix);
                string suffix = canonicalPath[absPrefix.Length..];
                return new Resolution(pattern, suffix, entity, Get(pattern));
            }
        }
        return null;
    }

    /// <summary>Resolve a handler's grant from <c>system/capability/grants/{pattern}</c> (§6.8).</summary>
    public CapabilityToken? ResolveGrant(string pattern)
    {
        Entity? grant = _peer.Tree.Get(AbsolutePath("system/capability/grants/" + pattern));
        return grant is null ? null : new CapabilityToken(grant);
    }

    private string AbsolutePath(string peerRelative) => "/" + _peer.LocalPeerId + "/" + peerRelative;

    private string StripPeer(string absolutePath)
    {
        string prefix = "/" + _peer.LocalPeerId + "/";
        return absolutePath.StartsWith(prefix, StringComparison.Ordinal) ? absolutePath[prefix.Length..] : absolutePath;
    }

    private static EcfValue OperationsMap(IReadOnlyList<string> operations) =>
        new EcfValue.Map(operations.Select(op =>
            new KeyValuePair<EcfValue, EcfValue>(Ecf.Text(op), Ecf.EmptyMap)).ToList());
}
