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
            // §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
            // 400 invalid_request — not the 501 every other handler answers, and NOT
            // the connection_sequence_error this arm used to carry. The table separates
            // a STATE conflict from an UNKNOWN operation because they select different
            // remedies: "an unknown connect operation is not out of order at all; it
            // exists in no state", so connection_sequence_error points the caller at
            // its ORDERING when the defect is its OPERATION NAME. Row 10 is scoped "in
            // any state", so this arm covers pre-handshake AND established.
            //
            // SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
            // (§3.3's 501 row, §6.2) is a different contract and is separately gated.
            _ => Error(ctx, Status.BadRequest, "invalid_request", $"unknown connect operation '{ctx.Operation}'"),
        });
    }

    private static HandlerResult Hello(HandlerContext ctx, ConnectionState conn)
    {
        // §4.2 / §4.7 rows 3-4: "After connection is established, subsequent connection
        // requests on the same connection MUST be rejected with status 409."
        if (conn.Established)
        {
            return Error(ctx, Status.Conflict, "connection_already_established", "connection already established");
        }
        // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
        // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
        // implement arriving in a state that forbids it — the same class as the row
        // above, taking the same 409. A half-open connection is NOT established, so
        // the guard above cannot reach it; §4.7 names this gap explicitly because two
        // adjacent rules each look like they cover it and neither does.
        if (conn.HelloReceived)
        {
            return Error(ctx, Status.Conflict, "connection_sequence_error", "hello already received on this connection");
        }

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

        // Negotiation (§4.5). `protocols` is the one negotiated field Required with NO
        // default, so there is no floor to fall back to, and its two failure modes carry
        // different codes on purpose (§4.5 table row / §4.7 row 1):
        //
        //   absent or empty     -> 400 invalid_request       (a malformed hello)
        //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
        //
        // "a caller that named no version cannot be told the comparison failed" — the
        // remedies differ (send the field vs change the version) and §4.7 exists so the
        // code selects the remedy. This peer had the comparison and not the distinction,
        // so an EMPTY set was answered incompatible_protocol: the right status reached by
        // a check that was never asked.
        EcfValue? protocolsField = Ecf.Field(hello.Data, "protocols");
        IReadOnlyList<string> protocols = protocolsField is null
            ? []
            : Ecf.AsArray(protocolsField).Select(Ecf.AsText).ToList();
        if (protocols.Count == 0)
        {
            return Error(ctx, Status.BadRequest, "invalid_request", "hello: protocols absent or empty");
        }
        if (!protocols.Contains(Protocols.Version))
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
            // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
            // single-use nonce. The anti-replay property is the MUST and the mechanism
            // (established-state tracking) is impl-defined, but the STATUS is pinned to
            // 401 invalid_nonce — a 409 state-conflict under-signals the replay.
            return Error(ctx, Status.Unauthorized, "invalid_nonce", "authenticate replayed on an already-established connection");
        }
        if (!conn.HelloReceived)
        {
            // FM-1 (§4.2, §4.7 row 6, 0.8.2.1): an authenticate arriving before any
            // hello nonce was issued is the SAME input as the replay handled directly
            // above — a captured authenticate replayed onto a fresh connection is
            // exactly this — so it is an authentication failure, not a malformed
            // request. §4.7's out-of-order row no longer names it.
            return Error(ctx, Status.Unauthorized, "invalid_nonce", "authenticate before hello");
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
            // §4.7 row 7: a non-verifying authenticate signature is
            // 401 authentication_failed. `invalid_signature` is a minted spelling and
            // the (code, status) pair is a normative MUST-emit contract.
            return Error(ctx, Status.Unauthorized, "authentication_failed", "authenticate signature invalid");
        }

        // §4.7 row 8, the OTHER input on the same row: the derivation above proves the
        // claimed peer_id is self-consistent with its public_key and says nothing about
        // whether it is the identity this connection GREETED as. Without this a caller
        // may greet as one peer and authenticate as another, and every seed-policy
        // lookup after it resolves against the second. Hello sets conn.RemotePeerId, so
        // it holds the greeted identity at this point.
        if (conn.RemotePeerId is not null && conn.RemotePeerId != claimedPeerId)
        {
            return Error(ctx, Status.Unauthorized, "identity_mismatch", "authenticate peer_id differs from the hello's peer_id");
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
