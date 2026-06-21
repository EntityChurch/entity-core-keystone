using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Capability;

/// <summary>
/// Layer-1 capability-chain verdict (V7 §5.5, §5.10). Collects the full authority
/// chain to its root, then validates each level: signatures, structural linkage,
/// grantee resolution, temporal validity, attenuation, and delegation caveats.
/// <para>
/// This is the deterministic Layer-1 entry point (§5.10 / N8): it consults only the
/// chain and the envelope's <c>included</c> map — no local policy, no extension
/// state — so the verdict is identical across conformant peers given the same
/// inputs. Layer-2 local policy gates live above this, in the dispatcher.
/// </para>
/// </summary>
internal static class ChainVerifier
{
    private const int MaxDepth = 64; // §5.5 collect_authority_chain default

    /// <summary>
    /// §4.10(b) structural-bound pre-check: true if the authority chain rooted at
    /// <paramref name="cap"/> exceeds <see cref="MaxDepth"/> links. Walks parent
    /// pointers in <c>included</c> without verifying signatures — depth is a purely
    /// structural property, gated BEFORE the per-link authz walk so an over-deep
    /// chain is reported as 400 <c>chain_depth_exceeded</c> (structural excess),
    /// distinct from a 403 <c>capability_denied</c> authz failure (arch ruling,
    /// v7.75 §4.10(b): a too-deep chain is structural excess, not authz denial).
    /// An unreachable parent is NOT a depth problem — it returns false here and is
    /// left for <see cref="VerifyCapabilityChain"/> to deny (403).
    /// </summary>
    public static bool ExceedsMaxDepth(CapabilityToken cap, Envelope envelope)
    {
        CapabilityToken? current = cap;
        int depth = 0;
        while (current is not null)
        {
            if (depth > MaxDepth)
            {
                return true;
            }
            if (current.Parent is null)
            {
                return false; // root reached within bound
            }
            Entity? parent = envelope.Find(current.Parent);
            if (parent is null)
            {
                return false; // unreachable — not a depth problem
            }
            current = new CapabilityToken(parent);
            depth++;
        }
        return false;
    }

    /// <summary>Find the signature targeting <paramref name="targetHash"/> in <c>included</c> (§5.2).</summary>
    public static Entity? FindSignature(Envelope envelope, ReadOnlySpan<byte> targetHash)
    {
        foreach (Entity entity in envelope.Included.Values)
        {
            if (entity.Type == TypeNames.Signature && Hashes.Equal(Signatures.Target(entity), targetHash))
            {
                return entity;
            }
        }
        return null;
    }

    /// <summary>
    /// Verify a capability chain at dispatch time (§5.5). Returns true (ALLOW) only
    /// if the chain roots at the local peer, every link's signature verifies, every
    /// grantee resolves, all links are temporally valid, and each delegation is a
    /// valid attenuation of its parent.
    /// </summary>
    public static bool VerifyCapabilityChain(CapabilityToken capability, Envelope envelope, string localPeerId, ulong nowMs)
    {
        List<CapabilityToken>? chain = CollectAuthorityChain(capability, envelope);
        if (chain is null)
        {
            return false; // ChainUnreachable / ChainTooDeep — fail closed
        }

        // Root authority: a single-sig root must root at the local peer; a multi-sig
        // root (§3.6 M3, root-only) must pass k-of-n quorum validation.
        CapabilityToken root = chain[^1];
        if (root.IsMultiSig)
        {
            if (!VerifyMultiSigRoot(root, envelope, localPeerId, nowMs))
            {
                return false;
            }
        }
        else
        {
            Entity? rootGranter = envelope.Find(root.Granter!);
            if (rootGranter is null || PeerEntities.PeerId(rootGranter) != localPeerId)
            {
                return false;
            }
        }

        for (int i = 0; i < chain.Count; i++)
        {
            CapabilityToken current = chain[i];

            // A multi-sig token is root-only and is fully verified above (signatures,
            // temporal, grantee all covered by VerifyMultiSigRoot).
            if (current.IsMultiSig)
            {
                if (i != chain.Count - 1)
                {
                    return false; // multi-sig must be the chain root (§3.6 M3)
                }
                continue;
            }

            // Signature.
            Entity? sig = FindSignature(envelope, current.ContentHash);
            if (sig is null)
            {
                return false;
            }
            Entity? granter = envelope.Find(current.Granter);
            if (granter is null)
            {
                return false;
            }
            if (!Hashes.Equal(Signatures.Signer(sig), current.Granter))
            {
                return false;
            }
            if (!Signatures.Verify(sig, granter))
            {
                return false;
            }

            // Grantee resolution — per-link (§5.5 PR-3). Unresolvable → 401.
            if (envelope.Find(current.Grantee) is null)
            {
                return false;
            }

            // Temporal validity.
            if (current.NotBefore is { } nb && nowMs < nb)
            {
                return false;
            }
            if (current.ExpiresAt is { } exp && exp < nowMs)
            {
                return false;
            }

            // Delegation (not for root — root has no parent).
            if (i < chain.Count - 1)
            {
                CapabilityToken parent = chain[i + 1];
                if (!Hashes.Equal(parent.Grantee, current.Granter))
                {
                    return false;
                }
                // §5.5a: resolve each link's granter peer_id as the per-link frame for
                // its resource patterns. Hard-fail (deny) on an unresolvable granter
                // rather than fall back to the local frame (Amendment-1 §4 scrutiny).
                string? childPeerId = LinkGranterPeerId(current, envelope, localPeerId);
                string? parentPeerId = LinkGranterPeerId(parent, envelope, localPeerId);
                if (childPeerId is null || parentPeerId is null)
                {
                    return false;
                }
                if (!Attenuation.IsAttenuated(current, parent, localPeerId, childPeerId, parentPeerId))
                {
                    return false;
                }
                if (!Attenuation.CheckDelegationCaveats(parent, current, i))
                {
                    return false;
                }
            }
        }

        return true;
    }

    /// <summary>
    /// §5.5a per-link granter frame: the peer_id a chain link's resource patterns
    /// canonicalize against. Single-sig granter → derive from its identity public_key;
    /// multi-sig granter (root-only M3) → the local peer. Returns null when the granter
    /// identity is unresolvable or keyless → the caller denies the chain walk (hard-fail
    /// per Amendment-1 §4, never a silent fallback to the local frame).
    /// </summary>
    private static string? LinkGranterPeerId(CapabilityToken cap, Envelope envelope, string localPeerId)
    {
        if (cap.Granter is null)
        {
            return localPeerId; // multi-sig root (M3) → local frame
        }
        Entity? granter = envelope.Find(cap.Granter);
        if (granter is null)
        {
            return null; // unresolvable granter → deny
        }
        try
        {
            return PeerEntities.PeerId(granter);
        }
        catch
        {
            return null; // present identity, no usable key → deny
        }
    }

    /// <summary>
    /// Validate a multi-signature root capability (V7 §3.6 M3 / §5.5 M4/M6). Returns
    /// true (ALLOW) only if the structure is well-formed <em>and</em> a quorum signs.
    /// Structural validation precedes signature counting (§3.6 precedence 25): a
    /// malformed quorum is rejected on its structure, not on missing/invalid sigs.
    /// Every failure path returns false → the dispatcher maps it to 403
    /// <c>capability_denied</c> (never a throw, never a hang).
    /// </summary>
    private static bool VerifyMultiSigRoot(CapabilityToken cap, Envelope envelope, string localPeerId, ulong nowMs)
    {
        MultiSigGranter mg = cap.MultiGranter!;

        // §3.6 M3 structure — root-only; a real quorum (n ≥ 2); a usable threshold
        // (2 ≤ threshold ≤ n, so neither degenerate-single nor unsatisfiable); distinct
        // signers.
        if (cap.Parent is not null)
        {
            return false;
        }
        int n = mg.Signers.Count;
        if (n < 2)
        {
            return false;
        }
        if (mg.Threshold < 2 || mg.Threshold > (ulong)n)
        {
            return false;
        }
        if (HasDuplicateSigners(mg.Signers))
        {
            return false;
        }

        // §5.5 M6 root-at-local: the local peer MUST be one of the quorum signers.
        bool localInSigners = mg.Signers.Any(s =>
        {
            Entity? p = envelope.Find(s);
            return p is not null && PeerEntities.PeerId(p) == localPeerId;
        });
        if (!localInSigners)
        {
            return false;
        }

        // Temporal validity + grantee resolution (as for any root).
        if (cap.NotBefore is { } nb && nowMs < nb)
        {
            return false;
        }
        if (cap.ExpiresAt is { } exp && exp < nowMs)
        {
            return false;
        }
        if (envelope.Find(cap.Grantee) is null)
        {
            return false;
        }

        // §5.5 M4 k-of-n: at least `threshold` distinct quorum members produced a valid
        // signature over the cap's content hash.
        var validSigners = new HashSet<string>();
        foreach (byte[] signerHash in mg.Signers)
        {
            Entity? signerPeer = envelope.Find(signerHash);
            if (signerPeer is null)
            {
                continue;
            }
            foreach (Entity sig in SignaturesTargeting(envelope, cap.ContentHash))
            {
                if (Hashes.Equal(Signatures.Signer(sig), signerHash) && Signatures.Verify(sig, signerPeer))
                {
                    validSigners.Add(Hashes.Hex(signerHash));
                    break;
                }
            }
        }
        return (ulong)validSigners.Count >= mg.Threshold;
    }

    private static bool HasDuplicateSigners(IReadOnlyList<byte[]> signers)
    {
        var seen = new HashSet<string>();
        foreach (byte[] s in signers)
        {
            if (!seen.Add(Hashes.Hex(s)))
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>All signature entities in <c>included</c> that target <paramref name="targetHash"/>.</summary>
    private static IEnumerable<Entity> SignaturesTargeting(Envelope envelope, byte[] targetHash)
    {
        foreach (Entity entity in envelope.Included.Values)
        {
            if (entity.Type == TypeNames.Signature && Hashes.Equal(Signatures.Target(entity), targetHash))
            {
                yield return entity;
            }
        }
    }

    /// <summary>
    /// Walk the authority chain from <paramref name="cap"/> to root, resolving
    /// parents from the envelope (§5.5 shared walker). Returns null on an
    /// unreachable parent or a chain exceeding <see cref="MaxDepth"/>.
    /// </summary>
    private static List<CapabilityToken>? CollectAuthorityChain(CapabilityToken cap, Envelope envelope)
    {
        var chain = new List<CapabilityToken>();
        CapabilityToken? current = cap;
        int depth = 0;

        while (current is not null)
        {
            if (depth > MaxDepth)
            {
                return null; // ChainTooDeep
            }
            chain.Add(current);
            if (current.Parent is null)
            {
                return chain; // root reached
            }
            Entity? parent = envelope.Find(current.Parent);
            if (parent is null)
            {
                return null; // ChainUnreachable
            }
            current = new CapabilityToken(parent);
            depth++;
        }
        return chain;
    }
}
