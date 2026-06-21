using System.Security.Cryptography;
using EntityCore.Protocol.Capability;
using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Handlers;

/// <summary>
/// The connection handler at <c>system/protocol/connect</c> (V7 §4, §6.2) — the
/// sole pre-authorized path. Services the <c>hello</c> and <c>authenticate</c>
/// operations of connection establishment. Note these are <em>operations</em>, not
/// wire message types (F3): the only wire messages are EXECUTE / EXECUTE_RESPONSE.
/// </summary>
internal sealed class ConnectHandler : IHandler
{
    public string Pattern => Protocols.ConnectPath;

    public string Name => "connect";

    public IReadOnlyList<string> Operations { get; } = new[] { "hello", "authenticate" };

    public Task<HandlerResult> HandleAsync(HandlerContext ctx, CancellationToken ct)
    {
        ConnectionState conn = ctx.Connection
            ?? throw new EntityProtocolException("connection handler requires connection state");

        return Task.FromResult(ctx.Operation switch
        {
            "hello" => Hello(ctx, conn),
            "authenticate" => Authenticate(ctx, conn),
            _ => Error(ctx, Status.BadRequest, "connection_sequence_error", $"unknown connect operation '{ctx.Operation}'"),
        });
    }

    private static HandlerResult Hello(HandlerContext ctx, ConnectionState conn)
    {
        Entity hello = ctx.Params;
        if (hello.Type != TypeNames.Hello)
        {
            return Error(ctx, Status.BadRequest, "connection_sequence_error", "expected a hello entity");
        }

        // v7.66 §4.4 surface 6 / V7 §4.7: reject an unsupported peer_id key_type at the
        // earliest handshake boundary — before protocol/format negotiation. The peer_id
        // wire prefix carries the initiator's key_type (§1.5); a family this peer cannot
        // sign/verify with (anything but Ed25519/Ed448 — incl. the 0xFE stub and the
        // experimental/reserved ranges) is unnegotiable → 400 unsupported_key_type.
        // A malformed peer_id falls through (its shape is caught downstream).
        string? helloPeerId = Ecf.OptText(hello.Data, "peer_id");
        if (helloPeerId is not null)
        {
            try
            {
                PeerId decoded = EntityCodec.ParsePeerId(helloPeerId);
                if (!KeyTypes.IsHandshakeSupported(decoded.KeyType))
                {
                    return Error(ctx, Status.BadRequest, "unsupported_key_type",
                        $"unsupported peer_id key_type 0x{decoded.KeyType:x2}; this peer signs/verifies Ed25519 (0x01) and Ed448 (0x02) only");
                }
            }
            catch (Exception ex) when (ex is EntityCodecException or FormatException or ArgumentException)
            {
                // Undecodable peer_id — not a key_type rejection; let the §3.8 shape
                // validation below surface it.
            }
        }

        // Negotiation (§4.5): protocols intersection must be non-empty.
        IReadOnlyList<EcfValue> protocols = Ecf.AsArray(Ecf.Require(hello.Data, "protocols"));
        if (!protocols.Select(Ecf.AsText).Contains(Protocols.Version))
        {
            return Error(ctx, Status.BadRequest, "incompatible_protocol", "no common protocol version");
        }

        // §4.5: a non-empty hash_formats advertisement with no overlap against our
        // accepted families is unnegotiable → 400 incompatible_hash_format.
        EcfValue? helloFormats = Ecf.Field(hello.Data, "hash_formats");
        if (helloFormats is not null)
        {
            var theirFormats = Ecf.AsArray(helloFormats).Select(Ecf.AsText).ToHashSet();
            if (theirFormats.Count > 0 && !HashFormats.SupportedNames.Any(theirFormats.Contains))
            {
                return Error(ctx, Status.BadRequest, "incompatible_hash_format", "no common content_hash_format");
            }
        }

        // §4.5: a key_types accept-set that excludes our own signing key_type means the
        // remote will not accept our reverse authenticate → 400 unsupported_key_type.
        EcfValue? helloKeyTypes = Ecf.Field(hello.Data, "key_types");
        if (helloKeyTypes is not null)
        {
            var theirKeyTypes = Ecf.AsArray(helloKeyTypes).Select(Ecf.AsText).ToHashSet();
            if (theirKeyTypes.Count > 0 && !theirKeyTypes.Contains(ctx.Peer.LocalIdentity.KeyTypeName))
            {
                return Error(ctx, Status.BadRequest, "unsupported_key_type", "key_types accept-set excludes responder key_type");
            }
        }

        string remotePeerId = Ecf.RequireText(hello.Data, "peer_id");
        byte[] remoteNonce = Ecf.RequireBytes(hello.Data, "nonce");
        conn.RemotePeerId = remotePeerId;
        conn.HelloReceived = true;
        conn.InboundHello.TrySetResult(new RemoteHelloInfo(remotePeerId, remoteNonce));

        // Respond with the local peer's own hello data (§4.4 hello response). Retain
        // the challenge nonce so the inbound authenticate's echo can be verified (§4.6).
        Entity response = BuildHello(ctx.Peer.LocalIdentity, ctx.Peer.NowMs);
        conn.SentNonce = Ecf.RequireBytes(response.Data, "nonce");
        return HandlerResult.Ok(response);
    }

    private HandlerResult Authenticate(HandlerContext ctx, ConnectionState conn)
    {
        if (conn.Established)
        {
            return Error(ctx, Status.Conflict, "connection_already_established", "connection already established");
        }
        if (!conn.HelloReceived)
        {
            return Error(ctx, Status.BadRequest, "connection_sequence_error", "authenticate before hello");
        }

        Entity authenticate = ctx.Params;
        if (authenticate.Type != TypeNames.Authenticate)
        {
            return Error(ctx, Status.BadRequest, "connection_sequence_error", "expected an authenticate entity");
        }

        byte[] publicKey = Ecf.RequireBytes(authenticate.Data, "public_key");
        string claimedPeerId = Ecf.RequireText(authenticate.Data, "peer_id");

        // PoP step 1 (§4.6 / §3.8): the authenticate MUST echo the nonce this peer
        // issued in its own hello on this connection. A captured authenticate replayed
        // on a different connection carries a stale nonce and fails here (F12).
        byte[] echoedNonce = Ecf.OptBytes(authenticate.Data, "nonce") ?? [];
        if (conn.SentNonce is null || !Hashes.Equal(echoedNonce, conn.SentNonce))
        {
            return Error(ctx, Status.Unauthorized, "invalid_nonce", "authenticate nonce does not echo the challenge");
        }

        // Resolve the remote's announced key family (§1.5); default to the §9.1 floor.
        string keyTypeName = Ecf.OptText(authenticate.Data, "key_type") ?? PeerEntities.Ed25519;
        IKeyAlgorithm remoteKeyType;
        try
        {
            remoteKeyType = KeyTypes.ByName(keyTypeName);
        }
        catch (EntityCodecException)
        {
            return Error(ctx, Status.BadRequest, "unsupported_key_type", $"unsupported key_type '{keyTypeName}'");
        }

        // Public key must match the claimed peer id under its key family (§4.7 identity_mismatch).
        if (PeerIdentity.DerivePeerId(publicKey, remoteKeyType) != claimedPeerId)
        {
            return Error(ctx, Status.Unauthorized, "identity_mismatch", "public key does not match peer_id");
        }

        // Verify the authenticate signature via target-matching (§4.6).
        Entity remotePeer = PeerEntities.Build(remoteKeyType, publicKey);
        Entity? signature = ChainVerifier.FindSignature(ctx.Envelope, authenticate.ContentHash);
        if (signature is null
            || !Hashes.Equal(Signatures.Signer(signature), remotePeer.ContentHash)
            || !Signatures.Verify(signature, remotePeer))
        {
            return Error(ctx, Status.Unauthorized, "invalid_signature", "authenticate signature invalid");
        }

        conn.RemotePeerEntity = remotePeer;
        conn.RemotePeerId = claimedPeerId;

        // Mint the initial capability for the authenticating peer (§4.4 / §6.9a). The
        // scope is derived from the declared seed policy read from the tree — NOT a
        // hardcoded initialGrants()/openGrants() fork (§6.9a declares that non-conformant).
        // The matched policy scope is UNION'd with the §4.4 discovery floor (v7.62 §8).
        PeerIdentity local = ctx.Peer.LocalIdentity;
        IReadOnlyList<GrantEntry> grants = DeriveSeedGrants(ctx, remotePeer, claimedPeerId);
        (CapabilityToken token, Entity capSignature) = CapabilityToken.CreateRoot(
            local, remotePeer.ContentHash, grants, ctx.Peer.NowMs);

        conn.Established = true;

        Entity grant = Entity.Create(TypeNames.CapabilityGrant, Ecf.Map(
            ("token", Ecf.Bytes(token.ContentHash))));

        var included = new List<Entity> { token.Entity, local.PeerEntity, remotePeer, capSignature };
        return HandlerResult.Ok(grant, included);
    }

    /// <summary>Build the local peer's <c>hello</c> entity with a fresh nonce (§3.8).</summary>
    public static Entity BuildHello(PeerIdentity local, ulong nowMs) =>
        Entity.Create(TypeNames.Hello, Ecf.Map(
            ("peer_id", Ecf.Text(local.PeerId)),
            ("nonce", Ecf.Bytes(RandomNumberGenerator.GetBytes(32))),
            ("protocols", Ecf.Array(Ecf.Text(Protocols.Version))),
            // §4.5 negotiation advertisement: the accepted content_hash_format and
            // key_type families. Without these the peer offers an empty accept-set and
            // a remote cannot negotiate the agility families it shares with us.
            ("hash_formats", Ecf.Array(HashFormats.SupportedNames.Select(Ecf.Text))),
            ("key_types", Ecf.Array(KeyTypes.SupportedNames.Select(Ecf.Text))),
            ("timestamp", Ecf.Uint(nowMs))));

    /// <summary>
    /// §6.9a authenticate-time derivation: resolve the seed-policy scope for the
    /// authenticating identity via the v7.64 dual-form lookup
    /// (<c>hex → Base58 → default</c>), then UNION it with the §4.4 discovery floor
    /// (v7.62 §8). The matched policy entry may be a <c>system/capability/token</c>
    /// (the §6.9a.0 detached-signature shape — e.g. the <c>self</c>-owner cap, whose
    /// detached signature is verified at the §3.5 invariant pointer before its grants
    /// are trusted) or a <c>system/capability/policy-entry</c> (the scope-template
    /// shape — e.g. the <c>default</c> entry). When nothing matches (no policy at all),
    /// the floor alone is minted.
    /// </summary>
    private static IReadOnlyList<GrantEntry> DeriveSeedGrants(HandlerContext ctx, Entity remotePeer, string remotePeerId)
    {
        string policyBase = "/" + ctx.LocalPeerId + "/system/capability/policy/";
        string hexKey = Hashes.Hex(remotePeer.ContentHash);

        // v7.64 dual-form lookup: hex (canonical) → Base58 (pre-contact) → default sentinel.
        Entity? entry = ctx.Peer.Tree.Get(policyBase + hexKey)
                        ?? ctx.Peer.Tree.Get(policyBase + remotePeerId)
                        ?? ctx.Peer.Tree.Get(policyBase + "default");

        IReadOnlyList<GrantEntry> floor = SeedPolicy.DiscoveryFloor();
        IReadOnlyList<GrantEntry> policyGrants = entry is null ? System.Array.Empty<GrantEntry>() : SeedEntryGrants(ctx, entry);

        // v7.62 §8 UNION: grant entries are independent — dispatch matches if ANY entry
        // covers, so the union is the concatenation of the floor and the policy scope.
        if (policyGrants.Count == 0)
        {
            return floor;
        }
        var union = new List<GrantEntry>(floor);
        union.AddRange(policyGrants);
        return union;
    }

    /// <summary>
    /// Extract the grant scope from a matched seed-policy entry, handling both §6.9a.0
    /// artifact shapes. A capability token (detached-signature shape) is trusted only
    /// after its self-signature verifies at <c>system/signature/{cap_hash}</c>; a
    /// policy-entry (tree-as-trust-root / scope-template shape) yields its grants directly.
    /// </summary>
    private static IReadOnlyList<GrantEntry> SeedEntryGrants(HandlerContext ctx, Entity entry)
    {
        if (entry.Type == TypeNames.CapabilityToken)
        {
            var token = new CapabilityToken(entry);
            Entity? sig = ctx.Peer.Tree.Get("/" + ctx.LocalPeerId + "/system/signature/" + token.ContentHashHex);
            if (sig is null || !Signatures.Verify(sig, ctx.Peer.LocalIdentity.PeerEntity))
            {
                return System.Array.Empty<GrantEntry>(); // unverifiable seed cap → no authority
            }
            return token.Grants;
        }
        if (entry.Type == TypeNames.CapabilityPolicyEntry)
        {
            return Ecf.AsArray(Ecf.Require(entry.Data, "grants")).Select(GrantEntry.FromEcf).ToList();
        }
        return System.Array.Empty<GrantEntry>();
    }

    private static HandlerResult Error(HandlerContext ctx, int status, string code, string message)
    {
        Entity error = Entity.Create(TypeNames.Error, Ecf.Map(
            ("code", Ecf.Text(code)),
            ("message", Ecf.Text(message))));
        return HandlerResult.Of(status, error);
    }
}
