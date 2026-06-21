using EntityCore.Protocol.Codec;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Capability;

/// <summary>
/// Attenuation rules (V7 §5.6): a child capability MUST be ≤ its parent. All four
/// scope dimensions narrow; constraint keys are retained with byte-equal values;
/// allowance keys are only ever removed, never added. CONFORMANCE-class — the
/// ALLOW/DENY outcome is what must match across impls.
/// </summary>
internal static class Attenuation
{
    /// <summary>
    /// True if every grant in <paramref name="requested"/> is covered by some grant in
    /// <paramref name="authority"/> (V7 §6.2 / §5.6): a peer issuing a capability MUST NOT
    /// grant scope exceeding the caller's presented authority. The per-grant subset rule
    /// is the same one delegation uses (<see cref="IsAttenuated"/>); this surfaces it for
    /// the <c>request</c> op, where the "parent" is the caller's presented capability and
    /// the "child" is the requested grant. A failure is the §6.2 <c>scope_exceeds_authority</c>
    /// rejection.
    /// </summary>
    public static bool GrantsWithinAuthority(
        IReadOnlyList<GrantEntry> requested, IReadOnlyList<GrantEntry> authority, string localPeerId)
    {
        // §6.2 mint-time subset check — the capability-handler surface, not the
        // dispatch chain walk. No V1'-family vector gates it; kept on the local frame
        // (child = parent = local) to preserve current behavior.
        foreach (GrantEntry req in requested)
        {
            if (!GrantCoveredBy(req, authority, localPeerId, localPeerId, localPeerId))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>
    /// §5.5a (Amendment 1): <paramref name="childPeerId"/> / <paramref name="parentPeerId"/>
    /// are the per-link granter frames for canonicalizing each side's RESOURCE patterns
    /// in the subset-check. Handlers/operations/peers stay on <paramref name="localPeerId"/>.
    /// When child = parent = local (same-peer chain) this is byte-identical to the
    /// pre-Amendment behavior.
    /// </summary>
    public static bool IsAttenuated(
        CapabilityToken child, CapabilityToken parent, string localPeerId, string childPeerId, string parentPeerId)
    {
        // 1. Every child grant must be covered by some parent grant.
        foreach (GrantEntry childGrant in child.Grants)
        {
            if (!GrantCoveredBy(childGrant, parent.Grants, localPeerId, childPeerId, parentPeerId))
            {
                return false;
            }
        }

        // 2. Child expiration must not exceed parent's (null = infinite).
        if (parent.ExpiresAt is not null)
        {
            if (child.ExpiresAt is null)
            {
                return false; // child infinite, parent finite (§5.6 nil-vs-finite)
            }
            if (child.ExpiresAt > parent.ExpiresAt)
            {
                return false;
            }
        }

        return true;
    }

    private static bool GrantCoveredBy(
        GrantEntry childGrant, IReadOnlyList<GrantEntry> parentGrants, string localPeerId, string childPeerId, string parentPeerId)
    {
        foreach (GrantEntry parentGrant in parentGrants)
        {
            if (GrantSubset(childGrant, parentGrant, localPeerId, childPeerId, parentPeerId))
            {
                return true;
            }
        }
        return false;
    }

    private static bool GrantSubset(GrantEntry child, GrantEntry parent, string localPeerId, string childPeerId, string parentPeerId)
    {
        // §5.5a: only the RESOURCE dimension uses the per-link granter frames; the
        // other dimensions stay on the local frame.
        if (!ScopeSubset(child.Handlers, parent.Handlers, localPeerId, localPeerId)) return false;
        if (!ScopeSubset(child.Operations, parent.Operations, localPeerId, localPeerId)) return false;
        if (!ScopeSubset(child.Resources, parent.Resources, childPeerId, parentPeerId)) return false;
        if (!ScopeSubset(child.EffectivePeers(localPeerId), parent.EffectivePeers(localPeerId), localPeerId, localPeerId)) return false;

        // Constraint attenuation: parent keys retained + byte-equal values.
        if (!ConstraintsRetained(parent.Constraints, child.Constraints)) return false;

        // Allowance attenuation: child keys ⊆ parent keys + byte-equal values.
        if (!AllowancesContained(child.Allowances, parent.Allowances)) return false;

        return true;
    }

    private static bool ScopeSubset(Scope child, Scope parent, string childPeerId, string parentPeerId)
    {
        // Every child include pattern (child granter frame) must be covered by some
        // parent include (parent granter frame).
        foreach (string childPattern in child.Include)
        {
            string cc = Paths.Canonicalize(childPattern, childPeerId);
            bool covered = parent.Include.Any(pp => Paths.MatchesPattern(cc, Paths.Canonicalize(pp, parentPeerId)));
            if (!covered)
            {
                return false;
            }
        }

        // Child must inherit all parent excludes (parent frame vs child frame).
        if (parent.Exclude is not null)
        {
            foreach (string parentEx in parent.Exclude)
            {
                string cp = Paths.Canonicalize(parentEx, parentPeerId);
                bool childHas = child.Exclude is not null
                    && child.Exclude.Any(ce => Paths.MatchesPattern(cp, Paths.Canonicalize(ce, childPeerId)));
                if (!childHas)
                {
                    return false;
                }
            }
        }
        return true;
    }

    private static bool ConstraintsRetained(EcfValue? parentConstraints, EcfValue? childConstraints)
    {
        var parent = AsMap(parentConstraints);
        var child = AsMap(childConstraints);
        if (parent is null || child is null)
        {
            return false; // defensive: reject non-map values
        }
        foreach ((string key, EcfValue parentValue) in parent)
        {
            if (!child.TryGetValue(key, out EcfValue? childValue))
            {
                return false; // key dropped — escalation
            }
            if (!BytesEqual(parentValue, childValue))
            {
                return false; // value changed
            }
        }
        return true;
    }

    private static bool AllowancesContained(EcfValue? childAllowances, EcfValue? parentAllowances)
    {
        var child = AsMap(childAllowances);
        var parent = AsMap(parentAllowances);
        if (child is null || parent is null)
        {
            return false;
        }
        foreach ((string key, EcfValue childValue) in child)
        {
            if (!parent.TryGetValue(key, out EcfValue? parentValue))
            {
                return false; // key added — escalation
            }
            if (!BytesEqual(childValue, parentValue))
            {
                return false;
            }
        }
        return true;
    }

    /// <summary>A null map is the unconstrained empty map (§3.6 absent-field defaults).</summary>
    private static Dictionary<string, EcfValue>? AsMap(EcfValue? value)
    {
        if (value is null)
        {
            return new Dictionary<string, EcfValue>();
        }
        if (value is not EcfValue.Map)
        {
            return null;
        }
        var dict = new Dictionary<string, EcfValue>();
        foreach ((string key, EcfValue v) in Ecf.Entries(value))
        {
            dict[key] = v;
        }
        return dict;
    }

    /// <summary>Byte equality over the canonical CBOR encoding of two values (§5.6).</summary>
    private static bool BytesEqual(EcfValue a, EcfValue b) =>
        CanonicalCbor.Encode(a).AsSpan().SequenceEqual(CanonicalCbor.Encode(b));

    /// <summary>Per-link delegation caveat enforcement (§5.7).</summary>
    public static bool CheckDelegationCaveats(CapabilityToken parent, CapabilityToken child, int depth)
    {
        DelegationCaveats? caveats = parent.Caveats;
        if (caveats is null)
        {
            return true;
        }
        if (caveats.NoDelegation == true)
        {
            return false;
        }
        if (caveats.MaxDelegationDepth is { } maxDepth && (ulong)depth >= maxDepth)
        {
            return false;
        }
        if (caveats.MaxDelegationTtl is { } maxTtl)
        {
            if (child.ExpiresAt is null)
            {
                return false; // infinite lifetime exceeds any finite limit
            }
            ulong childTtl = child.ExpiresAt.Value - child.CreatedAt;
            if (childTtl > maxTtl)
            {
                return false;
            }
        }
        return true;
    }
}
