namespace EntityCore.Protocol.Capability;

/// <summary>
/// URI normalization and path / pattern matching (V7 §1.4, §5.4). Canonicalization
/// is one-directional (peer-relative → absolute); pattern matching operates on
/// canonicalized absolute paths. This is CONFORMANCE-class logic (§7) — the exact
/// steps may vary but the ALLOW/DENY outcome must match across impls.
/// </summary>
internal static class Paths
{
    /// <summary>Base58 (Bitcoin) alphabet — the legal character set for a peer id (§8.5).</summary>
    private const string Base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

    /// <summary>Strip the <c>entity://</c> scheme, producing an absolute path (§1.4).</summary>
    public static string Normalize(string uri) =>
        uri.StartsWith("entity://", StringComparison.Ordinal) ? "/" + uri["entity://".Length..] : uri;

    /// <summary>
    /// The unmatchable value (0.8.2.20). Unreachable as a canonical path by
    /// CONSTRUCTION: its first segment cannot be a peer id, since a peer id needs
    /// >= 46 Base58 characters and <c>-</c> is outside the Base58 alphabet.
    /// </summary>
    public const string NeverMatch = "/never-match";

    /// <summary>
    /// Resolve a peer-relative path to absolute form against the local peer (§5.4).
    /// <para>
    /// TOTAL for the two RESERVED forms (0.8.2.20): <c>./</c> <c>../</c> and <c>*/</c>
    /// return <see cref="NeverMatch"/> instead of throwing. The throw was reachable from
    /// the wire — every normative call site is a matcher with no error channel to consume
    /// one — so <c>../x</c> in a resource exclude escaped the matcher and was answered by
    /// the §6.5 frame, which is the admission answer for the CALLER arm and the wrong one
    /// for the GRANT arm, where 0.8.2.21 pins a 403 DENY.
    /// </para>
    /// <para>
    /// The empty-segment (<c>//</c>) throw is LEFT IN PLACE deliberately: §1.4 forbids an
    /// empty segment, the landed <c>canonicalize</c> pseudocode has no arm for it, and
    /// turning that refusal into a silent non-match would weaken an admission check to
    /// fix a matcher one.
    /// </para>
    /// </summary>
    public static string Canonicalize(string path, string localPeerId)
    {
        // §1.4: an empty path segment ("a//b") is malformed — every segment of a tree
        // path is a non-empty name. (Callers strip a single trailing '/' for listings
        // before canonicalizing, so an interior "//" is always an empty segment.)
        if (path.Contains("//", StringComparison.Ordinal))
        {
            throw new EntityProtocolException("empty path segment (§1.4)");
        }
        if (path.StartsWith("./", StringComparison.Ordinal) || path.StartsWith("../", StringComparison.Ordinal))
        {
            return NeverMatch;      // reserved: directory-relative (§1.4)
        }
        if (path.StartsWith("*/", StringComparison.Ordinal))
        {
            return NeverMatch;      // ambiguous bare peer wildcard: use /*/rest (§5.4)
        }
        if (path.StartsWith('/'))
        {
            return path;
        }
        return "/" + localPeerId + "/" + path;
    }

    /// <summary>
    /// MUST hold for every canonicalized tree path: absolute, with a valid peer id
    /// as its first segment (§5.4). NOT called on patterns (wildcard segments are
    /// not valid peer ids).
    /// </summary>
    public static void ValidateAbsolutePath(string path)
    {
        if (!path.StartsWith('/'))
        {
            throw new EntityProtocolException("not absolute");
        }
        string[] segments = path[1..].Split('/');
        if (segments.Length == 0 || !IsPeerId(segments[0]))
        {
            throw new EntityProtocolException("invalid peer_id segment");
        }
    }

    /// <summary>
    /// Reject a caller-supplied tree target that violates §1.4 path validity
    /// (V7 v7.72 §9.5a CORE-TREE-PATH-FLEX-1): any C0 control byte (NUL included) or
    /// DEL in a segment, or a leading-slash (absolute) form whose first segment is not
    /// a valid peer_id. Peer-relative targets and legitimate cross-peer absolute paths
    /// (<c>/{peer_id}/...</c>) pass through. The <c>//</c> / <c>./</c> / <c>../</c>
    /// rejections live in <see cref="Canonicalize"/>. Throws
    /// <see cref="EntityProtocolException"/>; the handler maps it to 400 <c>invalid_path</c>.
    /// </summary>
    public static void ValidateCallerTarget(string target)
    {
        foreach (char ch in target)
        {
            if (ch < 0x20 || ch == 0x7f)
            {
                throw new EntityProtocolException("control byte in path segment (§1.4)");
            }
        }
        if (target.StartsWith('/'))
        {
            string rest = target[1..];
            int slash = rest.IndexOf('/');
            string first = slash < 0 ? rest : rest[..slash];
            if (!IsPeerId(first))
            {
                throw new EntityProtocolException("leading / on caller-supplied path must name a peer_id (§1.4)");
            }
        }
    }

    /// <summary>Dispatch path resolution: normalize, canonicalize, validate (§1.4).</summary>
    public static string DispatchPath(string uri, string localPeerId)
    {
        string canonical = Canonicalize(Normalize(uri), localPeerId);
        ValidateAbsolutePath(canonical);
        return canonical;
    }

    public static bool IsPeerId(string segment)
    {
        if (segment.Length < 46)
        {
            return false;
        }
        foreach (char ch in segment)
        {
            if (Base58Alphabet.IndexOf(ch) < 0)
            {
                return false;
            }
        }
        return true;
    }

    public static bool IsPattern(string path) => path.Contains('*');

    /// <summary>
    /// True if any exclude pattern canonicalizes to <see cref="NeverMatch"/>.
    /// <para>
    /// AN UNMATCHABLE EXCLUDE EXCLUDES EVERYTHING (0.8.2.21). The sentinel is fail-CLOSED
    /// in an include (covers nothing -&gt; the grant grants nothing) and fail-OPEN in an
    /// exclude (carves out nothing -&gt; the grant is SILENTLY WIDER than its author
    /// wrote): same value, same matcher, opposite safety direction, so the reading is
    /// chosen where the POSITION is known and <see cref="MatchesPattern"/> stays uniform
    /// over its operands.
    /// </para>
    /// </summary>
    public static bool ExcludeIsUnmatchable(IReadOnlyList<string> exclude, string frame)
    {
        foreach (string p in exclude)
        {
            if (Canonicalize(p, frame) == NeverMatch)
            {
                return true;
            }
        }
        return false;
    }

    /// <summary>Match a canonicalized path against a canonicalized pattern (§5.4).</summary>
    public static bool MatchesPattern(string path, string pattern)
    {
        // NeverMatch never matches, in EITHER operand (0.8.2.20). FIRST, and a matcher
        // rule rather than a property of the string: the arm below returns true for a
        // bare "*", so safety must not rest on a value merely looking unmatchable.
        if (path == NeverMatch || pattern == NeverMatch)
        {
            return false;
        }
        if (pattern == "*")
        {
            return true;
        }

        // Peer wildcard: /*/rest — match any peer's subtree.
        if (pattern.StartsWith("/*/", StringComparison.Ordinal))
        {
            string remainder = pattern[3..];
            int secondSlash = path.Length > 1 ? path.IndexOf('/', 1) : -1;
            if (secondSlash < 0)
            {
                return false;
            }
            string pathRest = path[(secondSlash + 1)..];
            return MatchesPattern(pathRest, remainder);
        }

        // Subtree: pattern/* — prefix match.
        if (pattern.EndsWith("/*", StringComparison.Ordinal))
        {
            string prefix = pattern[..^1]; // keep trailing slash, drop '*'
            return path.StartsWith(prefix, StringComparison.Ordinal);
        }

        return path == pattern;
    }

    /// <summary>Extract the prefix from a pattern for overlap comparison (§5.2).</summary>
    public static string StripWildcard(string pattern)
    {
        if (pattern.EndsWith("/*", StringComparison.Ordinal))
        {
            return pattern[..^2];
        }
        if (pattern == "*")
        {
            return string.Empty;
        }
        return pattern;
    }

    /// <summary>True if any concrete path could match both patterns (§5.2).</summary>
    public static bool PatternsOverlap(string a, string b)
    {
        string prefixA = StripWildcard(a);
        string prefixB = StripWildcard(b);
        return prefixA.StartsWith(prefixB, StringComparison.Ordinal)
            || prefixB.StartsWith(prefixA, StringComparison.Ordinal);
    }

    /// <summary>Extract the peer id from a uri path; local peer for short-form paths (§5.2).</summary>
    public static string ExtractPeer(string uri, string localPeerId)
    {
        string normalized = Normalize(uri);
        string trimmed = normalized.StartsWith('/') ? normalized[1..] : normalized;
        int slash = trimmed.IndexOf('/');
        string first = slash < 0 ? trimmed : trimmed[..slash];
        return IsPeerId(first) ? first : localPeerId;
    }
}
