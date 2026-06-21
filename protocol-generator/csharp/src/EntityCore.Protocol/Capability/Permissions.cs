using EntityCore.Protocol.Identity;
using EntityCore.Protocol.Model;

namespace EntityCore.Protocol.Capability;

/// <summary>
/// Permission checks (V7 §5.2, §6.3): the dispatch-level <see cref="CheckPermission"/>
/// (handler + operation + peer + resource), the tree handler's defense-in-depth
/// <see cref="CheckPathPermission"/>, and the full resource-scope check. Both
/// levels must pass for any data access (§5.4 two-level authorization).
/// </summary>
internal static class Permissions
{
    /// <summary>
    /// §PR-8 (v7.73): the canonicalization frame for a cap's grant RESOURCE patterns
    /// is the GRANTER's peer_id, not the verifier's. Single-sig granter → derive the
    /// peer_id from its identity public_key; multi-sig granter (no single key) or an
    /// unresolvable granter → the local peer (M3 root-only fallback). A bare "*" on a
    /// foreign-granted cap thus means "/{granter}/*", which does NOT reach the local
    /// peer's namespace — closing the V2(a) cross-peer under-enforcement.
    /// </summary>
    public static string ResolveGranterPeerId(CapabilityToken capability, Envelope envelope, string localPeerId)
    {
        if (capability.Granter is null) return localPeerId;            // multi-sig → local
        Entity? granter = envelope.Find(capability.Granter);
        if (granter is null) return localPeerId;                       // unresolvable → local
        try { return PeerEntities.PeerId(granter); }
        catch { return localPeerId; }                                  // not a single-key identity → local
    }

    /// <summary>
    /// Dispatch-time permission check (§5.2). All matched dimensions must come from
    /// a single grant entry. When <c>resource</c> is absent, the resource dimension
    /// is unchecked here (the handler may still check internally).
    /// <paramref name="granterPeerId"/> is the §PR-8 frame for grant resource patterns
    /// only; operation/handler/peer dimensions stay on the local frame. Per proposal
    /// §3.2.3 the v7.73 gate is this dispatch boundary only.
    /// </summary>
    public static bool CheckPermission(Execute execute, CapabilityToken capability, string handlerPattern, string localPeerId, string granterPeerId)
    {
        string operation = execute.Operation;
        string targetPeer = Paths.ExtractPeer(execute.Uri, localPeerId);
        ResourceTarget? resourceTarget = execute.Resource;

        foreach (GrantEntry grant in capability.Grants)
        {
            if (!grant.Operations.Matches(operation, localPeerId)) continue;
            if (!grant.Handlers.Matches(handlerPattern, localPeerId)) continue;
            if (!grant.EffectivePeers(localPeerId).Matches(targetPeer, localPeerId)) continue;
            if (resourceTarget is not null && !CheckResourceScope(resourceTarget, grant.Resources, localPeerId, granterPeerId)) continue;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Defense-in-depth path check used by the tree handler after dispatch (§6.3).
    /// Sole resource enforcement when <c>resource</c> is absent.
    /// </summary>
    public static bool CheckPathPermission(string operation, string path, CapabilityToken capability, string handlerPattern, string localPeerId)
    {
        string canonicalPath = Paths.Canonicalize(path, localPeerId);
        foreach (GrantEntry grant in capability.Grants)
        {
            if (!grant.Handlers.Matches(handlerPattern, localPeerId)) continue;
            if (!grant.Operations.Matches(operation, localPeerId)) continue;
            if (!grant.Resources.Matches(canonicalPath, localPeerId)) continue;
            return true;
        }
        return false;
    }

    /// <summary>
    /// Full resource-scope check (§5.2): the effective target scope (targets minus
    /// caller excludes) must lie within the effective grant scope (includes minus
    /// grant excludes).
    /// </summary>
    public static bool CheckResourceScope(ResourceTarget resourceTarget, Scope grantResources, string localPeerId, string granterPeerId)
    {
        IReadOnlyList<string> callerExclude = resourceTarget.Exclude ?? System.Array.Empty<string>();
        IReadOnlyList<string> grantInclude = grantResources.Include;
        IReadOnlyList<string> grantExclude = grantResources.Exclude ?? System.Array.Empty<string>();

        foreach (string target in resourceTarget.Targets)
        {
            // Request target canonicalizes on the local/request frame (§5.4).
            string ct = Paths.Canonicalize(target, localPeerId);
            if (!Paths.IsPattern(ct))
            {
                Paths.ValidateAbsolutePath(ct);
            }

            // Caller-supplied excludes stay on the local/request frame.
            if (IsCoveredBy(ct, callerExclude, localPeerId))
            {
                continue;
            }

            // §PR-8: the grant's own resource patterns canonicalize on the GRANTER frame.
            if (!IsCoveredBy(ct, grantInclude, granterPeerId))
            {
                return false;
            }

            if (Paths.IsPattern(ct))
            {
                // Every overlapping grant exclude (granter frame) must be covered by a
                // caller exclude (local frame).
                foreach (string ge in grantExclude)
                {
                    string cge = Paths.Canonicalize(ge, granterPeerId);
                    if (!Paths.PatternsOverlap(ct, cge))
                    {
                        continue;
                    }
                    if (!IsCoveredBy(cge, callerExclude, localPeerId))
                    {
                        return false;
                    }
                }
            }
            else
            {
                // Concrete target must not be in grant exclude (granter frame).
                foreach (string ge in grantExclude)
                {
                    if (Paths.MatchesPattern(ct, Paths.Canonicalize(ge, granterPeerId)))
                    {
                        return false;
                    }
                }
            }
        }
        return true;
    }

    private static bool IsCoveredBy(string pathOrPattern, IReadOnlyList<string> patternSet, string localPeerId)
    {
        foreach (string p in patternSet)
        {
            if (Paths.MatchesPattern(pathOrPattern, Paths.Canonicalize(p, localPeerId)))
            {
                return true;
            }
        }
        return false;
    }
}
