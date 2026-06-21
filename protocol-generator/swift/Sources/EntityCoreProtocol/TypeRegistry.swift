// TypeRegistry.swift — §9.5 Core Type Floor render-from-model (S4, A-SW-009 resolved).
//
// THE RENDER SEAM (the cross-peer ruling — memory: type-registry-render-design):
// a peer renders its `system/type/{name}` entities NATIVELY from an in-code
// declaration (the single source of truth — the FSpec/TypeDef builder below)
// through the byte-green S2 codec — NOT by ingesting reference bytes. The
// resulting content_hash is the S8 drift target (byte-identical to the Go
// reference type-registry vectors). C# `CoreTypeRegistry`, TS `core-type-registry`,
// OCaml `type_defs_data`, Zig `type_defs` all follow this exact shape; Swift
// renders the same 53 floor types as value-type declarations.
//
// SCOPE — core + operational + type-system bootstrap ONLY: the 53 types of the
// §9.5 floor. Extension vocabularies (compute/*, content/*, subscription/*, …)
// are NOT published by a core peer (refined G4 / F17). The oracle's `type_system`
// category matches the 53 floor as a hard FAIL gate and WARNs (matched-if-present)
// on the non-floor types it also probes.
//
// OMIT-EMPTY semantics: an absent/false/zero field drops its key, so the rendered
// ECF map is byte-identical to the Go reference encoder. The S2 codec sorts map
// keys canonically (RFC 8949 §4.2.1 / ENTITY-CBOR §2.2), so declaration order
// here is irrelevant to the bytes — only the present key/value set matters.

// MARK: - FSpec — a field spec inside a TypeDef (system/type/field-spec shape)
//
// Exactly one structural carrier is set per field: a `type_ref`, an `array_of`,
// a `map_of`, or a `union_of`. Rendered omit-empty into the field-spec ECF map.

struct FSpec: Sendable {
    var typeRef: String? = nil
    var optional: Bool = false
    var arrayOf: FSpecBox? = nil
    var mapOf: FSpecBox? = nil
    var unionOf: [FSpec]? = nil
    var keyType: String? = nil
    var byteSize: UInt64? = nil

    /// Render this spec to an ECF data map (omit-empty).
    func toData() -> CBORValue {
        var pairs: [(String, CBORValue)] = []
        if let t = typeRef { pairs.append(("type_ref", .text(t))) }
        if optional { pairs.append(("optional", .bool(true))) }
        if let inner = arrayOf { pairs.append(("array_of", inner.value.toData())) }
        if let inner = mapOf { pairs.append(("map_of", inner.value.toData())) }
        if let variants = unionOf {
            pairs.append(("union_of", .array(variants.map { $0.toData() })))
        }
        if let kt = keyType { pairs.append(("key_type", .text(kt))) }
        if let bs = byteSize { pairs.append(("byte_size", .uint(bs))) }
        return .textMap(pairs)
    }
}

/// Indirection box so an `FSpec` can hold a nested `FSpec` (value-type recursion).
/// Immutable (`let value`) → `Sendable`-safe for the static type table.
final class FSpecBox: Sendable {
    let value: FSpec
    init(_ value: FSpec) { self.value = value }
}

// Field-spec builder helpers (mirror Zig fref/opt/sized/farray/fmap).
private func ref(_ typeRef: String) -> FSpec { FSpec(typeRef: typeRef) }
private func opt(_ s: FSpec) -> FSpec { var c = s; c.optional = true; return c }
private func sized(_ s: FSpec, _ n: UInt64) -> FSpec { var c = s; c.byteSize = n; return c }
private func arrayOf(_ elem: FSpec) -> FSpec { FSpec(arrayOf: FSpecBox(elem)) }
private func mapOf(_ value: FSpec, key keyType: String? = nil) -> FSpec {
    FSpec(mapOf: FSpecBox(value), keyType: keyType)
}
private func union(_ variants: [FSpec]) -> FSpec { FSpec(unionOf: variants) }

// MARK: - TypeDef — a core type definition (system/type entity data)

struct TypeDef: Sendable {
    let name: String
    var ext: String? = nil          // "extends"
    var fields: [(String, FSpec)] = []
    var layout: [String] = []

    /// Render the `system/type` data map (omit-empty). Declaration order of fields
    /// is preserved within the `fields` sub-map; the codec re-sorts keys canonically.
    func toData() -> CBORValue {
        var pairs: [(String, CBORValue)] = [("name", .text(name))]
        if let e = ext { pairs.append(("extends", .text(e))) }
        if !fields.isEmpty {
            let fieldPairs = fields.map { ($0.0, $0.1.toData()) }
            pairs.append(("fields", .textMap(fieldPairs)))
        }
        if !layout.isEmpty {
            pairs.append(("layout", .array(layout.map { .text($0) })))
        }
        return .textMap(pairs)
    }

    func toEntity() throws(CodecError) -> BuiltEntity {
        try Model.make(type: "system/type", data: toData())
    }
}

public enum TypeRegistry {
    // Reused nested specs (mirror the Zig const sp_* set).
    private static let spString = ref("primitive/string")
    private static let spAny = ref("primitive/any")
    private static let spBytes = ref("primitive/bytes")
    private static let spHash = ref("system/hash")
    private static let spCoreEntity = ref("core/entity")
    private static let spTreePath = ref("system/tree/path")
    private static let spTypeName = ref("system/type/name")
    private static let spGrantEntry = ref("system/capability/grant-entry")
    private static let spFieldSpec = ref("system/type/field-spec")
    private static let spOpSpec = ref("system/handler/operation-spec")
    private static let spListingEntry = ref("system/tree/listing-entry")
    private static let spType = ref("system/type")
    private static let spMultiGranter = ref("system/capability/multi-granter")

    // MARK: the 53 core type definitions
    //
    // Faithful port of the cross-blessed C#/TS/OCaml/Zig registry (byte-identical
    // to the Go oracle vectors). Spec home: §9.5 Core Type Floor Manifest.

    static let allTypes: [TypeDef] = [
        // primitives (8)
        TypeDef(name: "primitive/any"),
        TypeDef(name: "primitive/bool"),
        TypeDef(name: "primitive/bytes"),
        TypeDef(name: "primitive/float"),
        TypeDef(name: "primitive/int"),
        TypeDef(name: "primitive/null"),
        TypeDef(name: "primitive/string"),
        TypeDef(name: "primitive/uint"),

        // structural roots + envelopes (5)
        TypeDef(name: "entity", fields: [
            ("type", ref("primitive/string")),
            ("data", ref("primitive/any")),
        ]),
        TypeDef(name: "core/entity", fields: [
            ("type", ref("primitive/string")),
            ("data", ref("primitive/any")),
            ("content_hash", ref("system/hash")),
        ]),
        TypeDef(name: "core/envelope", fields: [
            ("root", ref("core/entity")),
            ("included", opt(mapOf(spCoreEntity, key: "system/hash"))),
        ]),
        TypeDef(name: "system/envelope", ext: "core/envelope"),
        TypeDef(name: "system/protocol/envelope", ext: "core/envelope"),

        // identity / hash / signature (4)
        TypeDef(name: "system/hash", ext: "primitive/bytes", fields: [
            ("format_code", sized(ref("primitive/uint"), 1)),
            ("digest", ref("primitive/bytes")),
        ], layout: ["format_code", "digest"]),
        TypeDef(name: "system/peer", fields: [
            ("key_type", ref("primitive/string")),
            ("peer_id", ref("system/peer-id")),
            ("public_key", ref("primitive/bytes")),
        ]),
        TypeDef(name: "system/peer-id", ext: "primitive/string"),
        TypeDef(name: "system/signature", fields: [
            ("algorithm", ref("primitive/string")),
            ("signature", ref("primitive/bytes")),
            ("signer", ref("system/hash")),
            ("target", ref("system/hash")),
        ]),

        // protocol surface (6)
        TypeDef(name: "system/protocol/connect/authenticate", fields: [
            ("key_type", ref("primitive/string")),
            ("nonce", ref("primitive/bytes")),
            ("peer_id", ref("system/peer-id")),
            ("public_key", ref("primitive/bytes")),
        ]),
        TypeDef(name: "system/protocol/connect/hello", fields: [
            ("protocols", arrayOf(spString)),
            ("nonce", ref("primitive/bytes")),
            ("peer_id", ref("system/peer-id")),
            ("timestamp", ref("primitive/uint")),
            ("compression", opt(arrayOf(spString))),
            ("encryption", opt(arrayOf(spString))),
            ("hash_formats", opt(arrayOf(spString))),
            ("key_types", opt(arrayOf(spString))),
        ]),
        TypeDef(name: "system/protocol/error", fields: [
            ("code", ref("primitive/string")),
            ("message", opt(ref("primitive/string"))),
            ("rejected_marker", opt(ref("system/hash"))),
        ]),
        TypeDef(name: "system/protocol/execute", fields: [
            ("operation", ref("primitive/string")),
            ("params", ref("core/entity")),
            ("request_id", ref("primitive/string")),
            ("uri", ref("system/tree/path")),
            ("author", opt(ref("system/hash"))),
            ("bounds", opt(ref("system/bounds"))),
            ("capability", opt(ref("system/hash"))),
            ("deliver_to", opt(ref("system/delivery-spec"))),
            ("deliver_token", opt(ref("system/hash"))),
            ("durability_request", opt(ref("system/durability-request"))),
            ("resource", opt(ref("system/protocol/resource-target"))),
        ]),
        TypeDef(name: "system/protocol/execute/response", fields: [
            ("request_id", ref("primitive/string")),
            ("result", ref("core/entity")),
            ("status", ref("primitive/uint")),
            ("durability", opt(ref("system/durability-result"))),
        ]),
        TypeDef(name: "system/protocol/resource-target", fields: [
            ("targets", arrayOf(spTreePath)),
            ("exclude", opt(arrayOf(spTreePath))),
        ]),

        // capability (12)
        TypeDef(name: "system/capability/grant", fields: [
            ("token", ref("system/hash")),
        ]),
        TypeDef(name: "system/capability/grant-entry", fields: [
            ("handlers", ref("system/capability/path-scope")),
            ("operations", ref("system/capability/id-scope")),
            ("resources", ref("system/capability/path-scope")),
            ("allowances", opt(mapOf(spAny))),
            ("constraints", opt(mapOf(spAny))),
            ("peers", opt(ref("system/capability/id-scope"))),
        ]),
        TypeDef(name: "system/capability/id-scope", fields: [
            ("include", arrayOf(spString)),
            ("exclude", opt(arrayOf(spString))),
        ]),
        TypeDef(name: "system/capability/path-scope", fields: [
            ("include", arrayOf(spTreePath)),
            ("exclude", opt(arrayOf(spTreePath))),
        ]),
        TypeDef(name: "system/capability/request", fields: [
            ("grants", arrayOf(spGrantEntry)),
            ("ttl_ms", opt(ref("primitive/uint"))),
        ]),
        TypeDef(name: "system/capability/revocation", fields: [
            ("token", ref("system/hash")),
            ("revoked_at", ref("primitive/uint")),
            ("reason", opt(ref("primitive/string"))),
        ]),
        TypeDef(name: "system/capability/revoke-request", fields: [
            ("token", ref("system/hash")),
            ("reason", opt(ref("primitive/string"))),
        ]),
        TypeDef(name: "system/capability/delegate-request", fields: [
            ("grants", arrayOf(spGrantEntry)),
            ("parent", ref("system/hash")),
            ("ttl_ms", opt(ref("primitive/uint"))),
        ]),
        TypeDef(name: "system/capability/delegation-caveats", fields: [
            ("max_delegation_depth", opt(ref("primitive/uint"))),
            ("max_delegation_ttl", opt(ref("primitive/uint"))),
            ("no_delegation", opt(ref("primitive/bool"))),
        ]),
        TypeDef(name: "system/capability/policy-entry", fields: [
            ("grants", arrayOf(spGrantEntry)),
            ("peer_pattern", ref("primitive/string")),
            ("notes", opt(ref("primitive/string"))),
            ("ttl_ms", opt(ref("primitive/uint"))),
        ]),
        TypeDef(name: "system/capability/token", fields: [
            ("created_at", ref("primitive/uint")),
            ("grantee", ref("system/hash")),
            ("granter", union([spHash, spMultiGranter])),
            ("grants", arrayOf(spGrantEntry)),
            ("delegation_caveats", opt(ref("system/capability/delegation-caveats"))),
            ("expires_at", opt(ref("primitive/uint"))),
            ("not_before", opt(ref("primitive/uint"))),
            ("parent", opt(ref("system/hash"))),
            ("resource_limits", opt(ref("system/resource-limits"))),
        ]),
        TypeDef(name: "system/capability/multi-granter", fields: [
            ("signers", arrayOf(spHash)),
            ("threshold", ref("primitive/uint")),
        ]),

        // handler machinery (6)
        TypeDef(name: "system/handler", fields: [
            ("interface", ref("system/tree/path")),
            ("expression_path", opt(ref("system/tree/path"))),
            ("internal_scope", opt(arrayOf(spGrantEntry))),
            ("max_scope", opt(arrayOf(spGrantEntry))),
        ]),
        TypeDef(name: "system/handler/interface", fields: [
            ("name", ref("primitive/string")),
            ("operations", mapOf(spOpSpec)),
            ("pattern", ref("system/tree/path")),
        ]),
        TypeDef(name: "system/handler/manifest", ext: "system/handler/interface", fields: [
            ("name", ref("primitive/string")),
            ("operations", mapOf(spOpSpec)),
            ("pattern", ref("system/tree/path")),
            ("expression_path", opt(ref("system/tree/path"))),
            ("internal_scope", opt(arrayOf(spGrantEntry))),
            ("max_scope", opt(arrayOf(spGrantEntry))),
        ]),
        TypeDef(name: "system/handler/operation-spec", fields: [
            ("input_type", opt(ref("system/type/name"))),
            ("output_type", opt(ref("system/type/name"))),
        ]),
        TypeDef(name: "system/handler/register-request", fields: [
            ("manifest", ref("system/handler/manifest")),
            ("requested_scope", opt(arrayOf(spGrantEntry))),
            ("types", opt(mapOf(spType))),
        ]),
        TypeDef(name: "system/handler/register-result", fields: [
            ("grant", ref("system/capability/token")),
            ("pattern", ref("system/tree/path")),
        ]),

        // tree (5)
        TypeDef(name: "system/tree/get-request", fields: [
            ("limit", opt(ref("primitive/uint"))),
            ("mode", opt(ref("primitive/string"))),
            ("offset", opt(ref("primitive/uint"))),
            ("tree_id", opt(ref("primitive/string"))),
        ]),
        TypeDef(name: "system/tree/put-request", fields: [
            ("entity", opt(ref("core/entity"))),
            ("expected_hash", opt(ref("system/hash"))),
            ("tree_id", opt(ref("primitive/string"))),
        ]),
        TypeDef(name: "system/tree/listing", fields: [
            ("count", ref("primitive/uint")),
            ("entries", mapOf(spListingEntry)),
            ("offset", ref("primitive/uint")),
            ("path", ref("system/tree/path")),
            ("next_page", opt(ref("system/hash"))),
        ]),
        TypeDef(name: "system/tree/listing-entry", fields: [
            ("has_children", ref("primitive/bool")),
            ("hash", opt(ref("system/hash"))),
        ]),
        TypeDef(name: "system/tree/path", ext: "primitive/string"),

        // type-system bootstrap (3)
        TypeDef(name: "system/type", fields: [
            ("name", ref("system/type/name")),
            ("extends", opt(ref("system/type/name"))),
            ("fields", opt(mapOf(spFieldSpec))),
            ("layout", opt(arrayOf(spString))),
            ("type_args", opt(mapOf(spTypeName))),
            ("type_params", opt(arrayOf(spString))),
        ]),
        TypeDef(name: "system/type/field-spec", fields: [
            ("type_ref", opt(ref("system/type/name"))),
            ("optional", opt(ref("primitive/bool"))),
            ("array_of", opt(ref("system/type/field-spec"))),
            ("map_of", opt(ref("system/type/field-spec"))),
            ("union_of", opt(arrayOf(spFieldSpec))),
            ("key_type", opt(ref("system/type/name"))),
            ("byte_size", opt(ref("primitive/uint"))),
            ("type_param", opt(ref("primitive/string"))),
            ("type_args", opt(mapOf(spTypeName))),
            ("default", opt(ref("primitive/any"))),
            ("constraints", opt(arrayOf(spCoreEntity))),
        ]),
        TypeDef(name: "system/type/name", ext: "primitive/string"),

        // operational (4)
        TypeDef(name: "system/bounds", fields: [
            ("budget", opt(ref("primitive/uint"))),
            ("cascade_depth", opt(ref("primitive/uint"))),
            ("chain_id", opt(ref("primitive/string"))),
            ("parent_chain_id", opt(ref("primitive/string"))),
            ("ttl", opt(ref("primitive/uint"))),
            ("visited", opt(arrayOf(spTreePath))),
        ]),
        TypeDef(name: "system/resource-limits", fields: [
            ("max_budget", opt(ref("primitive/uint"))),
            ("max_ttl", opt(ref("primitive/uint"))),
            ("max_visited_length", opt(ref("primitive/uint"))),
        ]),
        TypeDef(name: "system/delivery-spec", fields: [
            ("operation", ref("primitive/string")),
            ("uri", ref("system/tree/path")),
        ]),
        TypeDef(name: "system/deletion-marker"),
    ]

    /// The 53 core-type names (§9.5) — derived from the declarations (single source).
    public static var coreTypeNames: [String] { allTypes.map { $0.name } }

    /// Number of core types published (53).
    public static var coreTypeCount: Int { allTypes.count }

    /// Render every core type entity and publish at /{peer}/system/type/{name}.
    public static func publish(into store: Store, localPeerID: String) async throws {
        for td in allTypes {
            let e = try td.toEntity()
            await store.bind(path: "/" + localPeerID + "/system/type/" + td.name, e.entity)
        }
    }

    /// Render the (name, 32-byte SHA-256 digest) for every core type — the byte-diff
    /// surface against the Go `type-registry-vectors-v1.cbor` set (S8 drift target).
    static func renderedDigests() throws(CodecError) -> [(String, [UInt8])] {
        var out: [(String, [UInt8])] = []
        for td in allTypes {
            let e = try td.toEntity()
            // e.hash is 33 bytes: 0x00 format byte ‖ 32-byte SHA-256 digest.
            out.append((td.name, Array(e.hash.dropFirst())))
        }
        return out
    }
}
