namespace EntityCore.Protocol.Capability;

/// <summary>
/// The declared identity → capability seed policy (V7 §6.9a Peer Authority
/// Bootstrap). At peer-init the policy is materialized into the tree under
/// <c>system/capability/policy/{key}</c> (the §6.9a Bootstrap L0 write-set); §4.6
/// authenticate reads it back via the v7.64 dual-form lookup (hex → Base58 →
/// <c>default</c>) and UNIONs the matched scope with the §4.4 discovery floor
/// before minting the caller's grant.
/// <para>
/// This replaces the hardcoded <c>initialGrants()</c> / <c>openGrants()</c> fork
/// that §6.9a declares non-conformant. The peer-owner authority is the always-present
/// <c>self</c> entry (materialized by <see cref="Peer"/> directly, since it is a real
/// owner capability, not a scope template). The degenerate <c>default → *</c> policy
/// (<see cref="DebugOpen"/>) is the retired <c>--debug-open-grants</c> behaviour —
/// deprecated in v7.74, removed in v7.75.
/// </para>
/// </summary>
internal sealed class SeedPolicy
{
    private SeedPolicy(IReadOnlyList<GrantEntry> defaultGrants, IReadOnlyList<SeedPolicyEntry> namedEntries)
    {
        DefaultGrants = defaultGrants;
        NamedEntries = namedEntries;
    }

    /// <summary>Scope minted for any authenticated identity not explicitly named (the <c>default</c> entry, §6.9a.0).</summary>
    public IReadOnlyList<GrantEntry> DefaultGrants { get; }

    /// <summary>
    /// Explicitly-named operator / admin / reader entries, each keyed by the grantee's
    /// identity-hash hex (canonical) or Base58 peer-id (pre-contact form) per §6.9a.1.
    /// </summary>
    public IReadOnlyList<SeedPolicyEntry> NamedEntries { get; }

    /// <summary>
    /// The §4.4 discovery floor: every authenticated identity gets at least this —
    /// read <c>system/type/*</c> + <c>system/handler/*</c>; invoke
    /// <c>system/capability:request</c>. UNION'd into every derived grant (§6.9a).
    /// </summary>
    public static IReadOnlyList<GrantEntry> DiscoveryFloor() => new[]
    {
        new GrantEntry(
            Handlers: new Scope(new[] { "system/tree" }, null),
            Resources: new Scope(new[] { "system/type/*", "system/handler/*" }, null),
            Operations: new Scope(new[] { "get" }, null),
            Peers: null, Constraints: null, Allowances: null),
        new GrantEntry(
            Handlers: new Scope(new[] { "system/capability" }, null),
            Resources: Scope.Empty,
            Operations: new Scope(new[] { "request" }, null),
            Peers: null, Constraints: null, Allowances: null),
    };

    /// <summary>
    /// A wide-open admin scope (every handler, resource, operation; both peer-local
    /// <c>*</c> and cross-peer <c>/*/*</c> resource forms). The degenerate
    /// <c>default → *</c> policy corresponds to the retired <c>--debug-open-grants</c>.
    /// </summary>
    public static IReadOnlyList<GrantEntry> OpenGrants() => new[]
    {
        new GrantEntry(
            Handlers: new Scope(new[] { "*" }, null),
            Resources: new Scope(new[] { "*", "/*/*" }, null),
            Operations: new Scope(new[] { "*" }, null),
            Peers: null, Constraints: null, Allowances: null),
    };

    /// <summary>
    /// Full owner authority over the local namespace <c>/{peer_id}/*</c> (§6.9a) — the
    /// scope of the <c>self</c>-owner capability the peer mints for its own identity.
    /// Local namespace only (no cross-peer <c>/*/*</c>): bare <c>*</c> canonicalizes to
    /// <c>/{peer_id}/*</c> on the granter (= local) frame.
    /// </summary>
    public static IReadOnlyList<GrantEntry> OwnerGrants(string localPeerId) => new[]
    {
        new GrantEntry(
            Handlers: new Scope(new[] { "*" }, null),
            Resources: new Scope(new[] { "*" }, null),
            Operations: new Scope(new[] { "*" }, null),
            Peers: new Scope(new[] { localPeerId }, null),
            Constraints: null, Allowances: null),
    };

    /// <summary>The conformant default seed policy: <c>default</c> = the §4.4 discovery floor.</summary>
    public static SeedPolicy Standard() =>
        new(DiscoveryFloor(), System.Array.Empty<SeedPolicyEntry>());

    /// <summary>
    /// The degenerate debug seed policy: <c>default → *</c> — the retired
    /// <c>--debug-open-grants</c> behaviour (every authenticating identity receives the
    /// wide-open admin grant), now routed through the real §6.9a mechanism rather than a
    /// hardcoded fork. Deprecated in v7.74, removed in v7.75.
    /// </summary>
    public static SeedPolicy DebugOpen() =>
        new(OpenGrants(), System.Array.Empty<SeedPolicyEntry>());

    /// <summary>Build a custom seed policy (the <c>with_seed_policy</c> builder affordance, §6.9a(e)).</summary>
    public static SeedPolicy Of(IReadOnlyList<GrantEntry> defaultGrants, IReadOnlyList<SeedPolicyEntry>? named = null) =>
        new(defaultGrants, named ?? System.Array.Empty<SeedPolicyEntry>());
}

/// <summary>
/// A named seed-policy entry (§6.9a.1): the grantee key (identity-hash hex or Base58
/// peer-id) and the scope to mint for that identity at authenticate.
/// </summary>
internal sealed record SeedPolicyEntry(string Key, IReadOnlyList<GrantEntry> Grants);
