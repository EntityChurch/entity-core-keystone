using EntityCore.Protocol.Store;
using static EntityCore.Protocol.Types.FSpec;

namespace EntityCore.Protocol.Types;

/// <summary>
/// The core type registry the peer publishes at <c>system/type/*</c> (TYPE-SYSTEM
/// §8–§10). Scope is core + operational + the type-system bootstrap only — the 53
/// types of <c>status/S4-TYPE-SCOPE.txt</c>; extension vocabularies and the type
/// extension (validate/merge) are NOT published by a core peer (refined G4 / F17).
/// <para>
/// Declared natively in C# (single source of truth in code), rendered through the
/// byte-green codec, and diffed for content-hash equality against the Go-rendered
/// vector set <c>test-vectors/v0.8.0/type-registry-vectors-v1.cbor</c>.
/// </para>
/// </summary>
internal static class CoreTypeRegistry
{
    /// <summary>The 53 core type definitions, in declaration order.</summary>
    public static IReadOnlyList<TypeDefinition> All { get; } = Build();

    /// <summary>Seed every core type entity into the tree at <c>system/type/&lt;name&gt;</c>.</summary>
    public static void Seed(EntityTree tree, string localPeerId)
    {
        foreach (TypeDefinition def in All)
        {
            tree.Put("/" + localPeerId + "/" + def.TreePath, def.ToEntity());
        }
    }

    private static List<TypeDefinition> Build()
    {
        var b = new List<TypeDefinition>();

        // ----- primitives (8) -----
        foreach (string p in new[] { "any", "bool", "bytes", "float", "int", "null", "string", "uint" })
        {
            b.Add(new TypeDefinition { Name = "primitive/" + p });
        }

        // ----- structural roots + envelopes (5) -----
        b.Add(T("entity")
            .F("type", Ref("primitive/string"))
            .F("data", Ref("primitive/any")));
        b.Add(T("core/entity")
            .F("type", Ref("primitive/string"))
            .F("data", Ref("primitive/any"))
            .F("content_hash", Ref("system/hash")));
        b.Add(T("core/envelope")
            .F("root", Ref("core/entity"))
            .F("included", Map(Ref("core/entity"), "system/hash").Opt()));
        b.Add(T("system/envelope").Ext("core/envelope"));
        b.Add(T("system/protocol/envelope").Ext("core/envelope"));

        // ----- identity / hash / signature (4) -----
        b.Add(T("system/hash").Ext("primitive/bytes")
            .F("format_code", Ref("primitive/uint").Size(1))
            .F("digest", Ref("primitive/bytes"))
            .Lay("format_code", "digest"));
        b.Add(T("system/peer")
            .F("key_type", Ref("primitive/string"))
            .F("peer_id", Ref("system/peer-id"))
            .F("public_key", Ref("primitive/bytes")));
        b.Add(T("system/peer-id").Ext("primitive/string"));
        b.Add(T("system/signature")
            .F("algorithm", Ref("primitive/string"))
            .F("signature", Ref("primitive/bytes"))
            .F("signer", Ref("system/hash"))
            .F("target", Ref("system/hash")));

        // ----- protocol surface (6) -----
        b.Add(T("system/protocol/connect/authenticate")
            .F("key_type", Ref("primitive/string"))
            .F("nonce", Ref("primitive/bytes"))
            .F("peer_id", Ref("system/peer-id"))
            .F("public_key", Ref("primitive/bytes")));
        b.Add(T("system/protocol/connect/hello")
            .F("protocols", Array(Ref("primitive/string")))
            .F("nonce", Ref("primitive/bytes"))
            .F("peer_id", Ref("system/peer-id"))
            .F("timestamp", Ref("primitive/uint"))
            .F("compression", Array(Ref("primitive/string")).Opt())
            .F("encryption", Array(Ref("primitive/string")).Opt())
            .F("hash_formats", Array(Ref("primitive/string")).Opt())
            .F("key_types", Array(Ref("primitive/string")).Opt()));
        b.Add(T("system/protocol/error")
            .F("code", Ref("primitive/string"))
            .F("message", Ref("primitive/string").Opt())
            .F("rejected_marker", Ref("system/hash").Opt()));
        b.Add(T("system/protocol/execute")
            .F("operation", Ref("primitive/string"))
            .F("params", Ref("core/entity"))
            .F("request_id", Ref("primitive/string"))
            .F("uri", Ref("system/tree/path"))
            .F("author", Ref("system/hash").Opt())
            .F("bounds", Ref("system/bounds").Opt())
            .F("capability", Ref("system/hash").Opt())
            .F("deliver_to", Ref("system/delivery-spec").Opt())
            .F("deliver_token", Ref("system/hash").Opt())
            .F("durability_request", Ref("system/durability-request").Opt())
            .F("resource", Ref("system/protocol/resource-target").Opt()));
        b.Add(T("system/protocol/execute/response")
            .F("request_id", Ref("primitive/string"))
            .F("result", Ref("core/entity"))
            .F("status", Ref("primitive/uint"))
            .F("durability", Ref("system/durability-result").Opt()));
        b.Add(T("system/protocol/resource-target")
            .F("targets", Array(Ref("system/tree/path")))
            .F("exclude", Array(Ref("system/tree/path")).Opt()));

        // ----- capability (12) -----
        b.Add(T("system/capability/grant")
            .F("token", Ref("system/hash")));
        b.Add(T("system/capability/grant-entry")
            .F("handlers", Ref("system/capability/path-scope"))
            .F("operations", Ref("system/capability/id-scope"))
            .F("resources", Ref("system/capability/path-scope"))
            .F("allowances", Map(Ref("primitive/any")).Opt())
            .F("constraints", Map(Ref("primitive/any")).Opt())
            .F("peers", Ref("system/capability/id-scope").Opt()));
        b.Add(T("system/capability/id-scope")
            .F("include", Array(Ref("primitive/string")))
            .F("exclude", Array(Ref("primitive/string")).Opt()));
        b.Add(T("system/capability/path-scope")
            .F("include", Array(Ref("system/tree/path")))
            .F("exclude", Array(Ref("system/tree/path")).Opt()));
        b.Add(T("system/capability/request")
            .F("grants", Array(Ref("system/capability/grant-entry")))
            .F("ttl_ms", Ref("primitive/uint").Opt()));
        b.Add(T("system/capability/revocation")
            .F("token", Ref("system/hash"))
            .F("revoked_at", Ref("primitive/uint"))
            .F("reason", Ref("primitive/string").Opt()));
        b.Add(T("system/capability/revoke-request")
            .F("token", Ref("system/hash"))
            .F("reason", Ref("primitive/string").Opt()));
        b.Add(T("system/capability/delegate-request")
            .F("grants", Array(Ref("system/capability/grant-entry")))
            .F("parent", Ref("system/hash"))
            .F("ttl_ms", Ref("primitive/uint").Opt()));
        b.Add(T("system/capability/delegation-caveats")
            .F("max_delegation_depth", Ref("primitive/uint").Opt())
            .F("max_delegation_ttl", Ref("primitive/uint").Opt())
            .F("no_delegation", Ref("primitive/bool").Opt()));
        b.Add(T("system/capability/policy-entry")
            .F("grants", Array(Ref("system/capability/grant-entry")))
            .F("peer_pattern", Ref("primitive/string"))
            .F("notes", Ref("primitive/string").Opt())
            .F("ttl_ms", Ref("primitive/uint").Opt()));
        b.Add(T("system/capability/token")
            .F("created_at", Ref("primitive/uint"))
            .F("grantee", Ref("system/hash"))
            .F("granter", Union(Ref("system/hash"), Ref("system/capability/multi-granter")))
            .F("grants", Array(Ref("system/capability/grant-entry")))
            .F("delegation_caveats", Ref("system/capability/delegation-caveats").Opt())
            .F("expires_at", Ref("primitive/uint").Opt())
            .F("not_before", Ref("primitive/uint").Opt())
            .F("parent", Ref("system/hash").Opt())
            .F("resource_limits", Ref("system/resource-limits").Opt()));
        b.Add(T("system/capability/multi-granter")
            .F("signers", Array(Ref("system/hash")))
            .F("threshold", Ref("primitive/uint")));

        // ----- handler machinery (6) -----
        b.Add(T("system/handler")
            .F("interface", Ref("system/tree/path"))
            .F("expression_path", Ref("system/tree/path").Opt())
            .F("internal_scope", Array(Ref("system/capability/grant-entry")).Opt())
            .F("max_scope", Array(Ref("system/capability/grant-entry")).Opt()));
        b.Add(T("system/handler/interface")
            .F("name", Ref("primitive/string"))
            .F("operations", Map(Ref("system/handler/operation-spec")))
            .F("pattern", Ref("system/tree/path")));
        b.Add(T("system/handler/manifest").Ext("system/handler/interface")
            .F("name", Ref("primitive/string"))
            .F("operations", Map(Ref("system/handler/operation-spec")))
            .F("pattern", Ref("system/tree/path"))
            .F("expression_path", Ref("system/tree/path").Opt())
            .F("internal_scope", Array(Ref("system/capability/grant-entry")).Opt())
            .F("max_scope", Array(Ref("system/capability/grant-entry")).Opt()));
        b.Add(T("system/handler/operation-spec")
            .F("input_type", Ref("system/type/name").Opt())
            .F("output_type", Ref("system/type/name").Opt()));
        b.Add(T("system/handler/register-request")
            .F("manifest", Ref("system/handler/manifest"))
            .F("requested_scope", Array(Ref("system/capability/grant-entry")).Opt())
            .F("types", Map(Ref("system/type")).Opt()));
        b.Add(T("system/handler/register-result")
            .F("grant", Ref("system/capability/token"))
            .F("pattern", Ref("system/tree/path")));

        // ----- tree (5) -----
        b.Add(T("system/tree/get-request")
            .F("limit", Ref("primitive/uint").Opt())
            .F("mode", Ref("primitive/string").Opt())
            .F("offset", Ref("primitive/uint").Opt())
            .F("tree_id", Ref("primitive/string").Opt()));
        b.Add(T("system/tree/put-request")
            .F("entity", Ref("core/entity").Opt())
            .F("expected_hash", Ref("system/hash").Opt())
            .F("tree_id", Ref("primitive/string").Opt()));
        b.Add(T("system/tree/listing")
            .F("count", Ref("primitive/uint"))
            .F("entries", Map(Ref("system/tree/listing-entry")))
            .F("offset", Ref("primitive/uint"))
            .F("path", Ref("system/tree/path"))
            .F("next_page", Ref("system/hash").Opt()));
        b.Add(T("system/tree/listing-entry")
            .F("has_children", Ref("primitive/bool"))
            .F("hash", Ref("system/hash").Opt()));
        b.Add(T("system/tree/path").Ext("primitive/string"));

        // ----- type-system bootstrap (3) -----
        b.Add(T("system/type")
            .F("name", Ref("system/type/name"))
            .F("extends", Ref("system/type/name").Opt())
            .F("fields", Map(Ref("system/type/field-spec")).Opt())
            .F("layout", Array(Ref("primitive/string")).Opt())
            .F("type_args", Map(Ref("system/type/name")).Opt())
            .F("type_params", Array(Ref("primitive/string")).Opt()));
        b.Add(T("system/type/field-spec")
            .F("type_ref", Ref("system/type/name").Opt())
            .F("optional", Ref("primitive/bool").Opt())
            .F("array_of", Ref("system/type/field-spec").Opt())
            .F("map_of", Ref("system/type/field-spec").Opt())
            .F("union_of", Array(Ref("system/type/field-spec")).Opt())
            .F("key_type", Ref("system/type/name").Opt())
            .F("byte_size", Ref("primitive/uint").Opt())
            .F("type_param", Ref("primitive/string").Opt())
            .F("type_args", Map(Ref("system/type/name")).Opt())
            .F("default", Ref("primitive/any").Opt())
            .F("constraints", Array(Ref("core/entity")).Opt()));
        b.Add(T("system/type/name").Ext("primitive/string"));

        // ----- operational (4) -----
        b.Add(T("system/bounds")
            .F("budget", Ref("primitive/uint").Opt())
            .F("cascade_depth", Ref("primitive/uint").Opt())
            .F("chain_id", Ref("primitive/string").Opt())
            .F("parent_chain_id", Ref("primitive/string").Opt())
            .F("ttl", Ref("primitive/uint").Opt())
            .F("visited", Array(Ref("system/tree/path")).Opt()));
        b.Add(T("system/resource-limits")
            .F("max_budget", Ref("primitive/uint").Opt())
            .F("max_ttl", Ref("primitive/uint").Opt())
            .F("max_visited_length", Ref("primitive/uint").Opt()));
        b.Add(T("system/delivery-spec")
            .F("operation", Ref("primitive/string"))
            .F("uri", Ref("system/tree/path")));
        b.Add(new TypeDefinition { Name = "system/deletion-marker" });

        return b;
    }

    // ----- terse builder -----
    private static Builder T(string name) => new(name);

    private sealed class Builder
    {
        private readonly string _name;
        private string? _extends;
        private readonly List<KeyValuePair<string, FSpec>> _fields = new();
        private List<string>? _layout;

        public Builder(string name) => _name = name;

        public Builder Ext(string extends) { _extends = extends; return this; }
        public Builder F(string key, FSpec spec) { _fields.Add(new(key, spec)); return this; }
        public Builder Lay(params string[] layout) { _layout = layout.ToList(); return this; }

        public static implicit operator TypeDefinition(Builder b) => new()
        {
            Name = b._name,
            Extends = b._extends,
            Fields = b._fields.Count > 0 ? b._fields : null,
            Layout = b._layout,
        };
    }
}
