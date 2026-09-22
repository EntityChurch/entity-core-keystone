using EntityCore.Protocol.Codec;
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
            if (!grant.Operations.Matches(operation, localPeerId, ScopeKind.Id)) continue;
            if (!grant.Handlers.Matches(handlerPattern, localPeerId, ScopeKind.Path)) continue;
            if (!grant.EffectivePeers(localPeerId).Matches(targetPeer, localPeerId, ScopeKind.Id)) continue;
            if (resourceTarget is not null && !CheckResourceScope(resourceTarget, grant.Resources, localPeerId, granterPeerId)) continue;
            return true;
        }
        return false;
    }

    /// <summary>
    /// The result of <see cref="EffectiveTargets"/>: the surviving targets and whether the
    /// EXECUTE carried a <c>resource</c> AT ALL.
    /// <para>
    /// THE PAIR IS THE NON-LOSSY PROJECTION §3.3 REQUIRES <c>[MUST]</c> (0.8.2.25, N11):
    /// <em>"where an implementation projects <c>resource.targets</c> onto the effective set
    /// ahead of the handler, that projection MUST NOT be lossy about its own emptiness —
    /// narrow when narrowing leaves something, and retain the raw pair when narrowing would
    /// empty it."</em> A function returning only a list cannot satisfy that: collapsing
    /// <c>[qA] exclude [qA]</c> to <c>[]</c> deletes the two-empties discriminator before
    /// any handler can read it, and the handler's refusal arm becomes dead code that only a
    /// WIRE drive can detect.
    /// </para>
    /// </summary>
    public readonly record struct EffectiveTargetSet(IReadOnlyList<string> Survivors, bool HasResource);

    /// <summary>
    /// §5.2's effective target list (0.8.2.20): the caller's own <c>resource.exclude</c>
    /// removes entries from <c>resource.targets</c> BEFORE anything else looks at the
    /// request.
    /// <para>
    /// The survivors are returned in the caller's OWN SPELLING, not canonicalized —
    /// 0.8.2.21 is explicit that <c>effective_targets</c> yields raw survivors, and the
    /// distinction is load-bearing because the value flows on to the tree lookup, which
    /// canonicalizes for itself.
    /// </para>
    /// <para>
    /// READ OFF THE RAW <c>resource</c> VALUE, not through <see cref="ResourceTarget"/>.
    /// That type is an ADMISSION parser: it throws for an absent or empty <c>targets</c>
    /// (§3.2's "MUST contain at least one entry"), which is the right answer at the
    /// dispatch boundary and the wrong shape here, where the §3.3 ladder has to tell "no
    /// resource" from "a resource whose every target was excluded" and answer each with its
    /// own disposition.
    /// </para>
    /// <para>
    /// A PRESENT-BUT-ILL-TYPED <c>targets</c> IS <b>PRESENT</b>, with an empty survivor
    /// list. Reporting it absent would serve the WIDER absent-case answer to a request that
    /// named a resource, which is N11's own defect one field over.
    /// </para>
    /// <para>
    /// The caller-exclude arm is fail-OPEN on an unmatchable pattern — §5.4 rules it
    /// separately from the grant arm — and that is INHERITED here rather than restated: the
    /// pattern canonicalizes to <see cref="Paths.NeverMatch"/>,
    /// <see cref="Paths.MatchesPattern"/> then answers false, and the target simply
    /// survives.
    /// </para>
    /// <para>
    /// <em>"Every seam that narrows is exempted alike."</em> This peer has exactly ONE
    /// narrowing seam — this function, called by the tree handler — and §6.5's dispatch
    /// chain does not project: the dispatcher passes the EXECUTE through untouched and
    /// <see cref="CheckPermission"/> reads <c>resource</c> for itself. There is no second
    /// door to keep in step, and adding a projection at dispatch would create one.
    /// </para>
    /// </summary>
    public static EffectiveTargetSet EffectiveTargets(Execute execute, string localPeerId)
    {
        EcfValue? raw = Ecf.Field(execute.Entity.Data, "resource");
        if (raw is not EcfValue.Map)
        {
            return new EffectiveTargetSet(System.Array.Empty<string>(), false);
        }
        EcfValue? targetsField = Ecf.Field(raw, "targets");
        if (targetsField is null)
        {
            return new EffectiveTargetSet(System.Array.Empty<string>(), false);
        }
        List<string> targets = targetsField is EcfValue.Array ta
            ? ta.Items.OfType<EcfValue.Text>().Select(t => t.Value).ToList()
            : new List<string>();
        List<string> exclude = Ecf.Field(raw, "exclude") is EcfValue.Array xa
            ? xa.Items.OfType<EcfValue.Text>().Select(t => t.Value).ToList()
            : new List<string>();

        var survivors = new List<string>(targets.Count);
        foreach (string target in targets)
        {
            string ct = Paths.CanonForMatch(target, localPeerId);
            bool dropped = false;
            foreach (string x in exclude)
            {
                if (Paths.MatchesPattern(ct, Paths.CanonForMatch(x, localPeerId)))
                {
                    dropped = true;
                    break;
                }
            }
            if (!dropped)
            {
                survivors.Add(target);
            }
        }
        return new EffectiveTargetSet(survivors, true);
    }

    /// <summary>
    /// §6.3's handler-level path check.
    /// <para>
    /// IT IS NOT A SECONDARY CHECK (§6.3, 0.8.2.20). It is the enforcement wherever the
    /// subject is derived after dispatch, and the dispatch-level check can be made VACUOUS
    /// by caller-controlled input: a caller who excludes the one target its capability does
    /// not cover removes that target from <see cref="CheckPermission"/>'s view entirely,
    /// and a handler that then acts on it has authorized nothing.
    /// </para>
    /// <para>
    /// THREE DIMENSIONS, NOT FOUR. <c>peers</c> is not consulted — the path is local by
    /// construction at this point (§1.4's inbound rule refuses a foreign namespace at §6.5
    /// step 3, before any handler runs), and §6.3's signature names only handlers,
    /// operations and resources.
    /// </para>
    /// <para>
    /// THE FRAME IS THE LOCAL PEER, NOT THE GRANTER, and that is the spec's own signature
    /// rather than a choice: §6.3's block reads
    /// <c>matches_scope(canonical_path, grant.resources, "path-scope", local_peer_id)</c> —
    /// there is no granter parameter to pass. §5.5a governs chain ATTENUATION, where the
    /// subject is a pattern compared against a parent's pattern; this call site compares a
    /// CONCRETE local path the handler is about to touch.
    /// </para>
    /// <para>
    /// An empty <c>resources.include</c> is a legal grant shape (§5.2: handlers that touch
    /// no tree paths) and DENIES every path here, which is what that note says it should.
    /// </para>
    /// </summary>
    public static bool CheckPathPermission(string operation, string path, CapabilityToken capability, string handlerPattern, string localPeerId)
    {
        // Canonicalization is total in a matcher position (0.8.2.20): a malformed path
        // answers NeverMatch, which matches no grant (§5.4), so it falls through to DENY
        // rather than being matched against anything — or, worse, escaping as a throw the
        // §6.5 frame would answer with the ADMISSION disposition.
        string canonicalPath = Paths.CanonForMatch(path, localPeerId);
        foreach (GrantEntry grant in capability.Grants)
        {
            if (!grant.Handlers.Matches(handlerPattern, localPeerId, ScopeKind.Path)) continue;
            if (!grant.Operations.Matches(operation, localPeerId, ScopeKind.Id)) continue;
            if (!grant.Resources.Matches(canonicalPath, localPeerId, ScopeKind.Path)) continue;
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

        // An unmatchable GRANT exclude excludes everything (0.8.2.21). FIRST, before any
        // target: the coverage tests below are correct in isolation and are simply never
        // reached on a sentinel, because MatchesPattern answers false.
        if (Paths.ExcludeIsUnmatchable(grantExclude, granterPeerId))
        {
            return false;
        }

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

    // ── §1.4 PD-2: outbound sub-dispatch authorization ──────────────────────────

    /// <summary>
    /// Strip the §1.4 scheme and leading peer segment, answering the PEER-RELATIVE path.
    /// <para>
    /// §1.4 admits three spellings of one address — <c>system/tree</c>,
    /// <c>/{peer}/system/tree</c> and <c>entity://{peer}/system/tree</c> — and §1.4's PD-2
    /// block requires Dimension 1's handler pattern to be the target uri's peer-relative
    /// path, because a grant names HANDLERS and a handler pattern never carries a peer
    /// segment. Matching a grant against the absolute or schemed form matches nothing,
    /// silently, which reads at the wire as an authority refusal.
    /// </para>
    /// <para>
    /// The first segment is dropped ONLY when it is a peer_id. A peer-relative
    /// <c>system/protocol/connect</c> must not lose <c>system</c> — the standing defect on
    /// <c>smalltalk</c> and <c>forth</c>, where an unconditional strip made every
    /// self-minted grant unusable while the handshake stayed green.
    /// </para>
    /// </summary>
    public static string PeerRelativeOf(string uri)
    {
        string p = uri.StartsWith("entity://", System.StringComparison.Ordinal)
            ? "/" + uri["entity://".Length..]
            : uri;
        if (!p.StartsWith('/')) return p;
        string body = p[1..];
        int slash = body.IndexOf('/');
        string first = slash < 0 ? body : body[..slash];
        if (Paths.IsPeerId(first)) return slash < 0 ? string.Empty : body[(slash + 1)..];
        return body;
    }

    /// <summary>
    /// Store key of a handler's OWN grant (§6.8:
    /// <c>system/capability/grants/{pattern}</c>), tolerant of the pattern arriving
    /// absolute or peer-relative.
    /// <para>
    /// §6.6's tree walk answers an ABSOLUTE pattern because store keys are absolute, while
    /// the grant path is built from the PEER-RELATIVE one. The two are one segment apart
    /// and concatenating the wrong one yields a doubled peer segment whose lookup misses —
    /// which fails closed as "no handler grant" and is indistinguishable, at the wire,
    /// from a genuine authority refusal.
    /// </para>
    /// </summary>
    public static string GrantPathFor(string localPeerId, string pattern)
    {
        string prefix = "/" + localPeerId + "/";
        string rel = pattern.StartsWith(prefix, System.StringComparison.Ordinal)
            ? pattern[prefix.Length..]
            : pattern;
        return "/" + localPeerId + "/system/capability/grants/" + rel;
    }

    /// <summary>
    /// §1.4's PD-2 gate: <c>check_permission</c> run before a locally-originated
    /// sub-dispatch LEAVES the peer, with all four dimensions applied.
    /// <para>
    /// ONE GATE AND ONE EXEMPTION, in §1.4's own words: the EXECUTING HANDLER'S GRANT
    /// decides all four dimensions (§6.8), evaluated in the LOCAL frame, with Dimension
    /// 1's pattern the target uri's PEER-RELATIVE path; and a valid capability MINTED BY
    /// THE TARGET PEER naming this peer as <c>grantee</c> relaxes Dimension 4
    /// (<c>peers</c>) AND ONLY DIMENSION 4, to the peers that capability covers.
    /// </para>
    /// <para>
    /// <em>"The target answers WHERE; the handler's grant answers WHAT."</em> A credential
    /// is NOT a grant: with no handler grant there is nothing to supply Dimensions 1-3, so
    /// the sub-dispatch is refused however good the credential is. That is the COMPOSE,
    /// and the BYPASS it is distinguished from is a peer that treats the credential as a
    /// standalone authorizer and steers past its own grant — §6.8's confused-deputy
    /// substitution. Both obvious vectors agree under either reading (sources agree ->
    /// allow, no source -> refuse), so the only input that separates them is a VALID
    /// credential presented to a handler whose own grant does NOT cover the request,
    /// which MUST refuse.
    /// </para>
    /// <para>
    /// <paramref name="relaxTo"/> is the peers scope the credential earned, decided by the
    /// caller (which owns resolution, the clock and the revocation read); <c>null</c> is
    /// BOTH the ambient arm and a credential that failed a clause. A credential failing
    /// verification relaxes NOTHING and the handler grant gates unrelaxed — it does not
    /// turn the verdict into an error.
    /// </para>
    /// <para>
    /// <paramref name="targetPeerId"/> is supplied by the caller rather than derived here:
    /// on the §6.11 reentry seam the uri may be PEER-RELATIVE and the destination is the
    /// connection's remote, so <c>ExtractPeer(uri, local)</c> would answer the LOCAL peer
    /// and Dimension 4 would pass vacuously on the default <c>{include: [local]}</c> — the
    /// exemption would then never be exercised and a bypass would read as a compose.
    /// </para>
    /// </summary>
    public static bool CheckOutboundSubDispatch(
        CapabilityToken handlerGrant, string localPeerId, string targetPeerId,
        string handlerPattern, string operation, ResourceTarget resource, Scope? relaxTo)
    {
        foreach (GrantEntry grant in handlerGrant.Grants)
        {
            if (!grant.Handlers.Matches(handlerPattern, localPeerId, ScopeKind.Path)) continue;
            if (!grant.Operations.Matches(operation, localPeerId, ScopeKind.Id)) continue;
            if (!CheckResourceScope(resource, grant.Resources, localPeerId, localPeerId)) continue;
            // Dimension 4. §5.2's default for an absent `peers` scope is
            // {include: [local_peer_id]}, so a foreign target fails unless this grant names
            // it or a target-minted credential relaxes it.
            if (grant.EffectivePeers(localPeerId).Matches(targetPeerId, localPeerId, ScopeKind.Id)) return true;
            if (relaxTo is not null && relaxTo.Matches(targetPeerId, localPeerId, ScopeKind.Id)) return true;
        }
        return false;
    }
}
