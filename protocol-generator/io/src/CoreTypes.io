// entity-core-protocol-io — §9.5 core type floor (53 types) — RENDER-FROM-MODEL.
// Each type's `data` map is the in-code model (ported field-for-field from the
// cohort's Go-rendered shapes); the content_hash is computed by THIS peer's
// S2-green codec over {type, data}. Non-floor vocabularies are extension-owned
// and intentionally absent. The oracle's type_system category fetches these at
// system/type/<name>.

CoreTypes := Object clone do(
    // field-spec / model helpers over EcMap (values auto-classified: nested
    // EcMap passes through; Number stays Number; "true" -> true; else text).
    m := method(
        mp := EcMap clone
        args := call message arguments
        i := 0
        while(i < args size,
            k := call sender doMessage(args at(i))
            v := call sender doMessage(args at(i + 1))
            mp atPut(k, if(v == "true", true, v))
            i = i + 2
        )
        mp
    )
    a := method(
        out := List clone
        call message arguments foreach(arg, out append(call sender doMessage(arg)))
        out
    )

    models := method(
        o := List clone     // list of list(name, dataMap) — insertion order
        add := block(name, data, o append(list(name, data)))

        // primitives (8)
        list("primitive/any","primitive/bool","primitive/bytes","primitive/float",
             "primitive/int","primitive/null","primitive/string","primitive/uint") foreach(p,
            add call(p, m("name", p)))

        add call("entity", m("name","entity","fields", m(
            "data", m("type_ref","primitive/any"),
            "type", m("type_ref","primitive/string"))))
        add call("core/entity", m("name","core/entity","fields", m(
            "content_hash", m("type_ref","system/hash"),
            "data", m("type_ref","primitive/any"),
            "type", m("type_ref","primitive/string"))))
        add call("core/envelope", m("name","core/envelope","fields", m(
            "included", m("optional","true","map_of", m("type_ref","core/entity"),"key_type","system/hash"),
            "root", m("type_ref","core/entity"))))
        add call("system/envelope", m("name","system/envelope","extends","core/envelope"))
        add call("system/protocol/envelope", m("name","system/protocol/envelope","extends","core/envelope"))

        add call("system/hash", m("name","system/hash","fields", m(
            "digest", m("type_ref","primitive/bytes"),
            "format_code", m("type_ref","primitive/uint","byte_size",1)),
            "extends","primitive/bytes","layout", a("format_code","digest")))
        // system/peer: the oracle's type-registry shape carries peer_id (the
        // render-from-model byte-exact exception; the ENTITY entity itself drops
        // peer_id from the hashable basis per v7.65 — Identity.io — but the TYPE
        // DEFINITION shape mirrors the oracle so type_system stays 0-drift).
        add call("system/peer", m("name","system/peer","fields", m(
            "key_type", m("type_ref","primitive/string"),
            "peer_id", m("type_ref","system/peer-id"),
            "public_key", m("type_ref","primitive/bytes"))))
        add call("system/peer-id", m("name","system/peer-id","extends","primitive/string"))
        add call("system/signature", m("name","system/signature","fields", m(
            "algorithm", m("type_ref","primitive/string"),
            "signature", m("type_ref","primitive/bytes"),
            "signer", m("type_ref","system/hash"),
            "target", m("type_ref","system/hash"))))

        add call("system/protocol/connect/authenticate", m("name","system/protocol/connect/authenticate","fields", m(
            "key_type", m("type_ref","primitive/string"),
            "nonce", m("type_ref","primitive/bytes"),
            "peer_id", m("type_ref","system/peer-id"),
            "public_key", m("type_ref","primitive/bytes"))))
        add call("system/protocol/connect/hello", m("name","system/protocol/connect/hello","fields", m(
            "compression", m("optional","true","array_of", m("type_ref","primitive/string")),
            "encryption", m("optional","true","array_of", m("type_ref","primitive/string")),
            "hash_formats", m("optional","true","array_of", m("type_ref","primitive/string")),
            "key_types", m("optional","true","array_of", m("type_ref","primitive/string")),
            "nonce", m("type_ref","primitive/bytes"),
            "peer_id", m("type_ref","system/peer-id"),
            "protocols", m("array_of", m("type_ref","primitive/string")),
            "timestamp", m("type_ref","primitive/uint"))))
        add call("system/protocol/error", m("name","system/protocol/error","fields", m(
            "code", m("type_ref","primitive/string"),
            "message", m("type_ref","primitive/string","optional","true"),
            "rejected_marker", m("type_ref","system/hash","optional","true"))))
        add call("system/protocol/execute", m("name","system/protocol/execute","fields", m(
            "author", m("type_ref","system/hash","optional","true"),
            "bounds", m("type_ref","system/bounds","optional","true"),
            "capability", m("type_ref","system/hash","optional","true"),
            "deliver_to", m("type_ref","system/delivery-spec","optional","true"),
            "deliver_token", m("type_ref","system/hash","optional","true"),
            "durability_request", m("type_ref","system/durability-request","optional","true"),
            "operation", m("type_ref","primitive/string"),
            "params", m("type_ref","core/entity"),
            "request_id", m("type_ref","primitive/string"),
            "resource", m("type_ref","system/protocol/resource-target","optional","true"),
            "uri", m("type_ref","system/tree/path"))))
        add call("system/protocol/execute/response", m("name","system/protocol/execute/response","fields", m(
            "durability", m("type_ref","system/durability-result","optional","true"),
            "request_id", m("type_ref","primitive/string"),
            "result", m("type_ref","core/entity"),
            "status", m("type_ref","primitive/uint"))))
        add call("system/protocol/resource-target", m("name","system/protocol/resource-target","fields", m(
            "exclude", m("optional","true","array_of", m("type_ref","system/tree/path")),
            "targets", m("array_of", m("type_ref","system/tree/path")))))

        add call("system/capability/grant", m("name","system/capability/grant","fields", m(
            "token", m("type_ref","system/hash"))))
        add call("system/capability/grant-entry", m("name","system/capability/grant-entry","fields", m(
            "allowances", m("optional","true","map_of", m("type_ref","primitive/any")),
            "constraints", m("optional","true","map_of", m("type_ref","primitive/any")),
            "handlers", m("type_ref","system/capability/path-scope"),
            "operations", m("type_ref","system/capability/id-scope"),
            "peers", m("type_ref","system/capability/id-scope","optional","true"),
            "resources", m("type_ref","system/capability/path-scope"))))
        add call("system/capability/id-scope", m("name","system/capability/id-scope","fields", m(
            "exclude", m("optional","true","array_of", m("type_ref","primitive/string")),
            "include", m("array_of", m("type_ref","primitive/string")))))
        add call("system/capability/path-scope", m("name","system/capability/path-scope","fields", m(
            "exclude", m("optional","true","array_of", m("type_ref","system/tree/path")),
            "include", m("array_of", m("type_ref","system/tree/path")))))
        add call("system/capability/request", m("name","system/capability/request","fields", m(
            "grants", m("array_of", m("type_ref","system/capability/grant-entry")),
            "ttl_ms", m("type_ref","primitive/uint","optional","true"))))
        add call("system/capability/revocation", m("name","system/capability/revocation","fields", m(
            "reason", m("type_ref","primitive/string","optional","true"),
            "revoked_at", m("type_ref","primitive/uint"),
            "token", m("type_ref","system/hash"))))
        add call("system/capability/revoke-request", m("name","system/capability/revoke-request","fields", m(
            "reason", m("type_ref","primitive/string","optional","true"),
            "token", m("type_ref","system/hash"))))
        add call("system/capability/delegate-request", m("name","system/capability/delegate-request","fields", m(
            "grants", m("array_of", m("type_ref","system/capability/grant-entry")),
            "parent", m("type_ref","system/hash"),
            "ttl_ms", m("type_ref","primitive/uint","optional","true"))))
        add call("system/capability/delegation-caveats", m("name","system/capability/delegation-caveats","fields", m(
            "max_delegation_depth", m("type_ref","primitive/uint","optional","true"),
            "max_delegation_ttl", m("type_ref","primitive/uint","optional","true"),
            "no_delegation", m("type_ref","primitive/bool","optional","true"))))
        add call("system/capability/policy-entry", m("name","system/capability/policy-entry","fields", m(
            "grants", m("array_of", m("type_ref","system/capability/grant-entry")),
            "notes", m("type_ref","primitive/string","optional","true"),
            "peer_pattern", m("type_ref","primitive/string"),
            "ttl_ms", m("type_ref","primitive/uint","optional","true"))))
        add call("system/capability/token", m("name","system/capability/token","fields", m(
            "created_at", m("type_ref","primitive/uint"),
            "delegation_caveats", m("type_ref","system/capability/delegation-caveats","optional","true"),
            "expires_at", m("type_ref","primitive/uint","optional","true"),
            "grantee", m("type_ref","system/hash"),
            "granter", m("union_of", a(m("type_ref","system/hash"), m("type_ref","system/capability/multi-granter"))),
            "grants", m("array_of", m("type_ref","system/capability/grant-entry")),
            "not_before", m("type_ref","primitive/uint","optional","true"),
            "parent", m("type_ref","system/hash","optional","true"),
            "resource_limits", m("type_ref","system/resource-limits","optional","true"))))
        add call("system/capability/multi-granter", m("name","system/capability/multi-granter","fields", m(
            "signers", m("array_of", m("type_ref","system/hash")),
            "threshold", m("type_ref","primitive/uint"))))

        add call("system/handler", m("name","system/handler","fields", m(
            "expression_path", m("type_ref","system/tree/path","optional","true"),
            "interface", m("type_ref","system/tree/path"),
            "internal_scope", m("optional","true","array_of", m("type_ref","system/capability/grant-entry")),
            "max_scope", m("optional","true","array_of", m("type_ref","system/capability/grant-entry")))))
        add call("system/handler/interface", m("name","system/handler/interface","fields", m(
            "name", m("type_ref","primitive/string"),
            "operations", m("map_of", m("type_ref","system/handler/operation-spec")),
            "pattern", m("type_ref","system/tree/path"))))
        add call("system/handler/manifest", m("name","system/handler/manifest","fields", m(
            "expression_path", m("type_ref","system/tree/path","optional","true"),
            "internal_scope", m("optional","true","array_of", m("type_ref","system/capability/grant-entry")),
            "max_scope", m("optional","true","array_of", m("type_ref","system/capability/grant-entry")),
            "name", m("type_ref","primitive/string"),
            "operations", m("map_of", m("type_ref","system/handler/operation-spec")),
            "pattern", m("type_ref","system/tree/path")),
            "extends","system/handler/interface"))
        add call("system/handler/operation-spec", m("name","system/handler/operation-spec","fields", m(
            "input_type", m("type_ref","system/type/name","optional","true"),
            "output_type", m("type_ref","system/type/name","optional","true"))))
        add call("system/handler/register-request", m("name","system/handler/register-request","fields", m(
            "manifest", m("type_ref","system/handler/manifest"),
            "requested_scope", m("optional","true","array_of", m("type_ref","system/capability/grant-entry")),
            "types", m("optional","true","map_of", m("type_ref","system/type")))))
        add call("system/handler/register-result", m("name","system/handler/register-result","fields", m(
            "grant", m("type_ref","system/capability/token"),
            "pattern", m("type_ref","system/tree/path"))))

        add call("system/tree/get-request", m("name","system/tree/get-request","fields", m(
            "limit", m("type_ref","primitive/uint","optional","true"),
            "mode", m("type_ref","primitive/string","optional","true"),
            "offset", m("type_ref","primitive/uint","optional","true"),
            "tree_id", m("type_ref","primitive/string","optional","true"))))
        add call("system/tree/put-request", m("name","system/tree/put-request","fields", m(
            "entity", m("type_ref","core/entity","optional","true"),
            "expected_hash", m("type_ref","system/hash","optional","true"),
            "tree_id", m("type_ref","primitive/string","optional","true"))))
        add call("system/tree/listing", m("name","system/tree/listing","fields", m(
            "count", m("type_ref","primitive/uint"),
            "entries", m("map_of", m("type_ref","system/tree/listing-entry")),
            "next_page", m("type_ref","system/hash","optional","true"),
            "offset", m("type_ref","primitive/uint"),
            "path", m("type_ref","system/tree/path"))))
        add call("system/tree/listing-entry", m("name","system/tree/listing-entry","fields", m(
            "has_children", m("type_ref","primitive/bool"),
            "hash", m("type_ref","system/hash","optional","true"))))
        add call("system/tree/path", m("name","system/tree/path","extends","primitive/string"))

        add call("system/type", m("name","system/type","fields", m(
            "extends", m("type_ref","system/type/name","optional","true"),
            "fields", m("optional","true","map_of", m("type_ref","system/type/field-spec")),
            "layout", m("optional","true","array_of", m("type_ref","primitive/string")),
            "name", m("type_ref","system/type/name"),
            "type_args", m("optional","true","map_of", m("type_ref","system/type/name")),
            "type_params", m("optional","true","array_of", m("type_ref","primitive/string")))))
        add call("system/type/field-spec", m("name","system/type/field-spec","fields", m(
            "array_of", m("type_ref","system/type/field-spec","optional","true"),
            "byte_size", m("type_ref","primitive/uint","optional","true"),
            "constraints", m("optional","true","array_of", m("type_ref","core/entity")),
            "default", m("type_ref","primitive/any","optional","true"),
            "key_type", m("type_ref","system/type/name","optional","true"),
            "map_of", m("type_ref","system/type/field-spec","optional","true"),
            "optional", m("type_ref","primitive/bool","optional","true"),
            "type_args", m("optional","true","map_of", m("type_ref","system/type/name")),
            "type_param", m("type_ref","primitive/string","optional","true"),
            "type_ref", m("type_ref","system/type/name","optional","true"),
            "union_of", m("optional","true","array_of", m("type_ref","system/type/field-spec")))))
        add call("system/type/name", m("name","system/type/name","extends","primitive/string"))

        add call("system/bounds", m("name","system/bounds","fields", m(
            "budget", m("type_ref","primitive/uint","optional","true"),
            "cascade_depth", m("type_ref","primitive/uint","optional","true"),
            "chain_id", m("type_ref","primitive/string","optional","true"),
            "parent_chain_id", m("type_ref","primitive/string","optional","true"),
            "ttl", m("type_ref","primitive/uint","optional","true"),
            "visited", m("optional","true","array_of", m("type_ref","system/tree/path")))))
        add call("system/resource-limits", m("name","system/resource-limits","fields", m(
            "max_budget", m("type_ref","primitive/uint","optional","true"),
            "max_ttl", m("type_ref","primitive/uint","optional","true"),
            "max_visited_length", m("type_ref","primitive/uint","optional","true"))))
        add call("system/delivery-spec", m("name","system/delivery-spec","fields", m(
            "operation", m("type_ref","primitive/string"),
            "uri", m("type_ref","system/tree/path"))))
        add call("system/deletion-marker", m("name","system/deletion-marker"))

        o
    )

    publish := method(storeObj, localPeer,
        models foreach(pair,
            name := pair at(0)
            data := pair at(1)
            storeObj bind("/" .. localPeer .. "/system/type/" .. name, Entity with("system/type", data))
        )
        self
    )
)
