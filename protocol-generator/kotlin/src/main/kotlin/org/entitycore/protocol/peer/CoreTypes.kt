package org.entitycore.protocol.peer

import org.entitycore.protocol.codec.EcfValue

/**
 * Core type floor (V7 §9.5) — render-from-model.
 *
 * Publishes the FULL 53-type §9.5 core floor as `system/type` entities under the local
 * namespace. The per-type `data` maps come from the in-code override table
 * [CoreTypeDefs] (the cross-impl Go-rendered type model); each entity's content_hash is
 * computed by our OWN S2-green codec over `{type, data}` (render-from-model, not
 * ingest-bytes), and is the surface the oracle's `type_system` category fetches at
 * `system/type/<name>` (the §9.5 53/53 floor). Non-floor type vocabularies are
 * extension-owned and intentionally absent.
 */
internal object CoreTypes {

    /** (type-name → rendered system/type entity) for the full §9.5 53-type core floor. */
    fun entities(): Map<String, Entity> =
        CoreTypeDefs.models().mapValues { (_, data) -> Entity.make("system/type", data) }

    /** Publish every core type at /{peer}/system/type/{name}. */
    fun publish(store: Store, localPeer: String) {
        for ((name, e) in entities()) {
            store.bind("/$localPeer/system/type/$name", e)
        }
    }
}

/**
 * The in-code §9.5 core-type override table (render-from-model, V7 §9.5). 53 core types;
 * each value is the `data` map of a `system/type` entity. Ported from the cross-impl
 * type model (the shared Go-rendered shapes the cohort diffs byte-for-byte). The
 * byte-identity check against the canonical type-registry vectors is an S4 item; at S3
 * these are the bootstrapped floor.
 */
internal object CoreTypeDefs {

    private val TRUE: EcfValue = EcfValue.Bool.TRUE

    private fun m(vararg kvs: Any?): EcfValue.MapVal = Cbor.map(*kvs)
    private fun arr(vararg items: EcfValue): EcfValue.Arr = EcfValue.Arr(items.toList())
    private fun strArr(vararg items: String): EcfValue.Arr = Cbor.textArray(*items)

    /** (type-name → data-map) for the 53 §9.5 core types, in floor order. */
    fun models(): Map<String, EcfValue.MapVal> {
        val out = LinkedHashMap<String, EcfValue.MapVal>()
        out["primitive/any"] = m("name", "primitive/any")
        out["primitive/bool"] = m("name", "primitive/bool")
        out["primitive/bytes"] = m("name", "primitive/bytes")
        out["primitive/float"] = m("name", "primitive/float")
        out["primitive/int"] = m("name", "primitive/int")
        out["primitive/null"] = m("name", "primitive/null")
        out["primitive/string"] = m("name", "primitive/string")
        out["primitive/uint"] = m("name", "primitive/uint")
        out["entity"] = m("name", "entity", "fields", m("data", m("type_ref", "primitive/any"), "type", m("type_ref", "primitive/string")))
        out["core/entity"] = m("name", "core/entity", "fields", m("content_hash", m("type_ref", "system/hash"), "data", m("type_ref", "primitive/any"), "type", m("type_ref", "primitive/string")))
        out["core/envelope"] = m("name", "core/envelope", "fields", m("included", m("optional", TRUE, "map_of", m("type_ref", "core/entity"), "key_type", "system/hash"), "root", m("type_ref", "core/entity")))
        out["system/envelope"] = m("name", "system/envelope", "extends", "core/envelope")
        out["system/protocol/envelope"] = m("name", "system/protocol/envelope", "extends", "core/envelope")
        out["system/hash"] = m("name", "system/hash", "fields", m("digest", m("type_ref", "primitive/bytes"), "format_code", m("type_ref", "primitive/uint", "byte_size", 1L)), "extends", "primitive/bytes", "layout", strArr("format_code", "digest"))
        out["system/peer"] = m("name", "system/peer", "fields", m("key_type", m("type_ref", "primitive/string"), "peer_id", m("type_ref", "system/peer-id"), "public_key", m("type_ref", "primitive/bytes")))
        out["system/peer-id"] = m("name", "system/peer-id", "extends", "primitive/string")
        out["system/signature"] = m("name", "system/signature", "fields", m("algorithm", m("type_ref", "primitive/string"), "signature", m("type_ref", "primitive/bytes"), "signer", m("type_ref", "system/hash"), "target", m("type_ref", "system/hash")))
        out["system/protocol/connect/authenticate"] = m("name", "system/protocol/connect/authenticate", "fields", m("key_type", m("type_ref", "primitive/string"), "nonce", m("type_ref", "primitive/bytes"), "peer_id", m("type_ref", "system/peer-id"), "public_key", m("type_ref", "primitive/bytes")))
        out["system/protocol/connect/hello"] = m("name", "system/protocol/connect/hello", "fields", m("compression", m("optional", TRUE, "array_of", m("type_ref", "primitive/string")), "encryption", m("optional", TRUE, "array_of", m("type_ref", "primitive/string")), "hash_formats", m("optional", TRUE, "array_of", m("type_ref", "primitive/string")), "key_types", m("optional", TRUE, "array_of", m("type_ref", "primitive/string")), "nonce", m("type_ref", "primitive/bytes"), "peer_id", m("type_ref", "system/peer-id"), "protocols", m("array_of", m("type_ref", "primitive/string")), "timestamp", m("type_ref", "primitive/uint")))
        out["system/protocol/error"] = m("name", "system/protocol/error", "fields", m("code", m("type_ref", "primitive/string"), "message", m("type_ref", "primitive/string", "optional", TRUE), "rejected_marker", m("type_ref", "system/hash", "optional", TRUE)))
        out["system/protocol/execute"] = m("name", "system/protocol/execute", "fields", m("author", m("type_ref", "system/hash", "optional", TRUE), "bounds", m("type_ref", "system/bounds", "optional", TRUE), "capability", m("type_ref", "system/hash", "optional", TRUE), "deliver_to", m("type_ref", "system/delivery-spec", "optional", TRUE), "deliver_token", m("type_ref", "system/hash", "optional", TRUE), "durability_request", m("type_ref", "system/durability-request", "optional", TRUE), "operation", m("type_ref", "primitive/string"), "params", m("type_ref", "core/entity"), "request_id", m("type_ref", "primitive/string"), "resource", m("type_ref", "system/protocol/resource-target", "optional", TRUE), "uri", m("type_ref", "system/tree/path")))
        out["system/protocol/execute/response"] = m("name", "system/protocol/execute/response", "fields", m("durability", m("type_ref", "system/durability-result", "optional", TRUE), "request_id", m("type_ref", "primitive/string"), "result", m("type_ref", "core/entity"), "status", m("type_ref", "primitive/uint")))
        out["system/protocol/resource-target"] = m("name", "system/protocol/resource-target", "fields", m("exclude", m("optional", TRUE, "array_of", m("type_ref", "system/tree/path")), "targets", m("array_of", m("type_ref", "system/tree/path"))))
        out["system/capability/grant"] = m("name", "system/capability/grant", "fields", m("token", m("type_ref", "system/hash")))
        out["system/capability/grant-entry"] = m("name", "system/capability/grant-entry", "fields", m("allowances", m("optional", TRUE, "map_of", m("type_ref", "primitive/any")), "constraints", m("optional", TRUE, "map_of", m("type_ref", "primitive/any")), "handlers", m("type_ref", "system/capability/path-scope"), "operations", m("type_ref", "system/capability/id-scope"), "peers", m("type_ref", "system/capability/id-scope", "optional", TRUE), "resources", m("type_ref", "system/capability/path-scope")))
        out["system/capability/id-scope"] = m("name", "system/capability/id-scope", "fields", m("exclude", m("optional", TRUE, "array_of", m("type_ref", "primitive/string")), "include", m("array_of", m("type_ref", "primitive/string"))))
        out["system/capability/path-scope"] = m("name", "system/capability/path-scope", "fields", m("exclude", m("optional", TRUE, "array_of", m("type_ref", "system/tree/path")), "include", m("array_of", m("type_ref", "system/tree/path"))))
        out["system/capability/request"] = m("name", "system/capability/request", "fields", m("grants", m("array_of", m("type_ref", "system/capability/grant-entry")), "ttl_ms", m("type_ref", "primitive/uint", "optional", TRUE)))
        out["system/capability/revocation"] = m("name", "system/capability/revocation", "fields", m("reason", m("type_ref", "primitive/string", "optional", TRUE), "revoked_at", m("type_ref", "primitive/uint"), "token", m("type_ref", "system/hash")))
        out["system/capability/revoke-request"] = m("name", "system/capability/revoke-request", "fields", m("reason", m("type_ref", "primitive/string", "optional", TRUE), "token", m("type_ref", "system/hash")))
        out["system/capability/delegate-request"] = m("name", "system/capability/delegate-request", "fields", m("grants", m("array_of", m("type_ref", "system/capability/grant-entry")), "parent", m("type_ref", "system/hash"), "ttl_ms", m("type_ref", "primitive/uint", "optional", TRUE)))
        out["system/capability/delegation-caveats"] = m("name", "system/capability/delegation-caveats", "fields", m("max_delegation_depth", m("type_ref", "primitive/uint", "optional", TRUE), "max_delegation_ttl", m("type_ref", "primitive/uint", "optional", TRUE), "no_delegation", m("type_ref", "primitive/bool", "optional", TRUE)))
        out["system/capability/policy-entry"] = m("name", "system/capability/policy-entry", "fields", m("grants", m("array_of", m("type_ref", "system/capability/grant-entry")), "notes", m("type_ref", "primitive/string", "optional", TRUE), "peer_pattern", m("type_ref", "primitive/string"), "ttl_ms", m("type_ref", "primitive/uint", "optional", TRUE)))
        out["system/capability/token"] = m("name", "system/capability/token", "fields", m("created_at", m("type_ref", "primitive/uint"), "delegation_caveats", m("type_ref", "system/capability/delegation-caveats", "optional", TRUE), "expires_at", m("type_ref", "primitive/uint", "optional", TRUE), "grantee", m("type_ref", "system/hash"), "granter", m("union_of", arr(m("type_ref", "system/hash"), m("type_ref", "system/capability/multi-granter"))), "grants", m("array_of", m("type_ref", "system/capability/grant-entry")), "not_before", m("type_ref", "primitive/uint", "optional", TRUE), "parent", m("type_ref", "system/hash", "optional", TRUE), "resource_limits", m("type_ref", "system/resource-limits", "optional", TRUE)))
        out["system/capability/multi-granter"] = m("name", "system/capability/multi-granter", "fields", m("signers", m("array_of", m("type_ref", "system/hash")), "threshold", m("type_ref", "primitive/uint")))
        out["system/handler"] = m("name", "system/handler", "fields", m("expression_path", m("type_ref", "system/tree/path", "optional", TRUE), "interface", m("type_ref", "system/tree/path"), "internal_scope", m("optional", TRUE, "array_of", m("type_ref", "system/capability/grant-entry")), "max_scope", m("optional", TRUE, "array_of", m("type_ref", "system/capability/grant-entry"))))
        out["system/handler/interface"] = m("name", "system/handler/interface", "fields", m("name", m("type_ref", "primitive/string"), "operations", m("map_of", m("type_ref", "system/handler/operation-spec")), "pattern", m("type_ref", "system/tree/path")))
        out["system/handler/manifest"] = m("name", "system/handler/manifest", "fields", m("expression_path", m("type_ref", "system/tree/path", "optional", TRUE), "internal_scope", m("optional", TRUE, "array_of", m("type_ref", "system/capability/grant-entry")), "max_scope", m("optional", TRUE, "array_of", m("type_ref", "system/capability/grant-entry")), "name", m("type_ref", "primitive/string"), "operations", m("map_of", m("type_ref", "system/handler/operation-spec")), "pattern", m("type_ref", "system/tree/path")), "extends", "system/handler/interface")
        out["system/handler/operation-spec"] = m("name", "system/handler/operation-spec", "fields", m("input_type", m("type_ref", "system/type/name", "optional", TRUE), "output_type", m("type_ref", "system/type/name", "optional", TRUE)))
        out["system/handler/register-request"] = m("name", "system/handler/register-request", "fields", m("manifest", m("type_ref", "system/handler/manifest"), "requested_scope", m("optional", TRUE, "array_of", m("type_ref", "system/capability/grant-entry")), "types", m("optional", TRUE, "map_of", m("type_ref", "system/type"))))
        out["system/handler/register-result"] = m("name", "system/handler/register-result", "fields", m("grant", m("type_ref", "system/capability/token"), "pattern", m("type_ref", "system/tree/path")))
        out["system/tree/get-request"] = m("name", "system/tree/get-request", "fields", m("limit", m("type_ref", "primitive/uint", "optional", TRUE), "mode", m("type_ref", "primitive/string", "optional", TRUE), "offset", m("type_ref", "primitive/uint", "optional", TRUE), "tree_id", m("type_ref", "primitive/string", "optional", TRUE)))
        out["system/tree/put-request"] = m("name", "system/tree/put-request", "fields", m("entity", m("type_ref", "core/entity", "optional", TRUE), "expected_hash", m("type_ref", "system/hash", "optional", TRUE), "tree_id", m("type_ref", "primitive/string", "optional", TRUE)))
        out["system/tree/listing"] = m("name", "system/tree/listing", "fields", m("count", m("type_ref", "primitive/uint"), "entries", m("map_of", m("type_ref", "system/tree/listing-entry")), "next_page", m("type_ref", "system/hash", "optional", TRUE), "offset", m("type_ref", "primitive/uint"), "path", m("type_ref", "system/tree/path")))
        out["system/tree/listing-entry"] = m("name", "system/tree/listing-entry", "fields", m("has_children", m("type_ref", "primitive/bool"), "hash", m("type_ref", "system/hash", "optional", TRUE)))
        out["system/tree/path"] = m("name", "system/tree/path", "extends", "primitive/string")
        out["system/type"] = m("name", "system/type", "fields", m("extends", m("type_ref", "system/type/name", "optional", TRUE), "fields", m("optional", TRUE, "map_of", m("type_ref", "system/type/field-spec")), "layout", m("optional", TRUE, "array_of", m("type_ref", "primitive/string")), "name", m("type_ref", "system/type/name"), "type_args", m("optional", TRUE, "map_of", m("type_ref", "system/type/name")), "type_params", m("optional", TRUE, "array_of", m("type_ref", "primitive/string"))))
        out["system/type/field-spec"] = m("name", "system/type/field-spec", "fields", m("array_of", m("type_ref", "system/type/field-spec", "optional", TRUE), "byte_size", m("type_ref", "primitive/uint", "optional", TRUE), "constraints", m("optional", TRUE, "array_of", m("type_ref", "core/entity")), "default", m("type_ref", "primitive/any", "optional", TRUE), "key_type", m("type_ref", "system/type/name", "optional", TRUE), "map_of", m("type_ref", "system/type/field-spec", "optional", TRUE), "optional", m("type_ref", "primitive/bool", "optional", TRUE), "type_args", m("optional", TRUE, "map_of", m("type_ref", "system/type/name")), "type_param", m("type_ref", "primitive/string", "optional", TRUE), "type_ref", m("type_ref", "system/type/name", "optional", TRUE), "union_of", m("optional", TRUE, "array_of", m("type_ref", "system/type/field-spec"))))
        out["system/type/name"] = m("name", "system/type/name", "extends", "primitive/string")
        out["system/bounds"] = m("name", "system/bounds", "fields", m("budget", m("type_ref", "primitive/uint", "optional", TRUE), "cascade_depth", m("type_ref", "primitive/uint", "optional", TRUE), "chain_id", m("type_ref", "primitive/string", "optional", TRUE), "parent_chain_id", m("type_ref", "primitive/string", "optional", TRUE), "ttl", m("type_ref", "primitive/uint", "optional", TRUE), "visited", m("optional", TRUE, "array_of", m("type_ref", "system/tree/path"))))
        out["system/resource-limits"] = m("name", "system/resource-limits", "fields", m("max_budget", m("type_ref", "primitive/uint", "optional", TRUE), "max_ttl", m("type_ref", "primitive/uint", "optional", TRUE), "max_visited_length", m("type_ref", "primitive/uint", "optional", TRUE)))
        out["system/delivery-spec"] = m("name", "system/delivery-spec", "fields", m("operation", m("type_ref", "primitive/string"), "uri", m("type_ref", "system/tree/path")))
        out["system/deletion-marker"] = m("name", "system/deletion-marker")
        return out
    }
}
