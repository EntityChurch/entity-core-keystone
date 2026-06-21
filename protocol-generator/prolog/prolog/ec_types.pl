:- module(ec_types, [core_type_model/2, core_type_names/1]).
% GENERATED from common-lisp/src/type-defs-data.lisp (+core-type-models+).
% The 53 core type (§9.5) data-models in the Prolog value-term language
% (map([K-V,..]) | [..] | int(N) | bool(b) | null | "text"). Byte-identity
% with the type-registry diag is the S3 gate (test/type_registry.pl).

core_type_model("primitive/any",
    map(["name"-"primitive/any"])).
core_type_model("primitive/bool",
    map(["name"-"primitive/bool"])).
core_type_model("primitive/bytes",
    map(["name"-"primitive/bytes"])).
core_type_model("primitive/float",
    map(["name"-"primitive/float"])).
core_type_model("primitive/int",
    map(["name"-"primitive/int"])).
core_type_model("primitive/null",
    map(["name"-"primitive/null"])).
core_type_model("primitive/string",
    map(["name"-"primitive/string"])).
core_type_model("primitive/uint",
    map(["name"-"primitive/uint"])).
core_type_model("entity",
    map(["name"-"entity", "fields"-map(["data"-map(["type_ref"-"primitive/any"]), "type"-map(["type_ref"-"primitive/string"])])])).
core_type_model("core/entity",
    map(["name"-"core/entity", "fields"-map(["content_hash"-map(["type_ref"-"system/hash"]), "data"-map(["type_ref"-"primitive/any"]), "type"-map(["type_ref"-"primitive/string"])])])).
core_type_model("core/envelope",
    map(["name"-"core/envelope", "fields"-map(["included"-map(["optional"-bool(true), "map_of"-map(["type_ref"-"core/entity"]), "key_type"-"system/hash"]), "root"-map(["type_ref"-"core/entity"])])])).
core_type_model("system/envelope",
    map(["name"-"system/envelope", "extends"-"core/envelope"])).
core_type_model("system/protocol/envelope",
    map(["name"-"system/protocol/envelope", "extends"-"core/envelope"])).
core_type_model("system/hash",
    map(["name"-"system/hash", "fields"-map(["digest"-map(["type_ref"-"primitive/bytes"]), "format_code"-map(["type_ref"-"primitive/uint", "byte_size"-int(1)])]), "extends"-"primitive/bytes", "layout"-["format_code", "digest"]])).
core_type_model("system/peer",
    map(["name"-"system/peer", "fields"-map(["key_type"-map(["type_ref"-"primitive/string"]), "peer_id"-map(["type_ref"-"system/peer-id"]), "public_key"-map(["type_ref"-"primitive/bytes"])])])).
core_type_model("system/peer-id",
    map(["name"-"system/peer-id", "extends"-"primitive/string"])).
core_type_model("system/signature",
    map(["name"-"system/signature", "fields"-map(["algorithm"-map(["type_ref"-"primitive/string"]), "signature"-map(["type_ref"-"primitive/bytes"]), "signer"-map(["type_ref"-"system/hash"]), "target"-map(["type_ref"-"system/hash"])])])).
core_type_model("system/protocol/connect/authenticate",
    map(["name"-"system/protocol/connect/authenticate", "fields"-map(["key_type"-map(["type_ref"-"primitive/string"]), "nonce"-map(["type_ref"-"primitive/bytes"]), "peer_id"-map(["type_ref"-"system/peer-id"]), "public_key"-map(["type_ref"-"primitive/bytes"])])])).
core_type_model("system/protocol/connect/hello",
    map(["name"-"system/protocol/connect/hello", "fields"-map(["compression"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"primitive/string"])]), "encryption"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"primitive/string"])]), "hash_formats"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"primitive/string"])]), "key_types"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"primitive/string"])]), "nonce"-map(["type_ref"-"primitive/bytes"]), "peer_id"-map(["type_ref"-"system/peer-id"]), "protocols"-map(["array_of"-map(["type_ref"-"primitive/string"])]), "timestamp"-map(["type_ref"-"primitive/uint"])])])).
core_type_model("system/protocol/error",
    map(["name"-"system/protocol/error", "fields"-map(["code"-map(["type_ref"-"primitive/string"]), "message"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "rejected_marker"-map(["type_ref"-"system/hash", "optional"-bool(true)])])])).
core_type_model("system/protocol/execute",
    map(["name"-"system/protocol/execute", "fields"-map(["author"-map(["type_ref"-"system/hash", "optional"-bool(true)]), "bounds"-map(["type_ref"-"system/bounds", "optional"-bool(true)]), "capability"-map(["type_ref"-"system/hash", "optional"-bool(true)]), "deliver_to"-map(["type_ref"-"system/delivery-spec", "optional"-bool(true)]), "deliver_token"-map(["type_ref"-"system/hash", "optional"-bool(true)]), "durability_request"-map(["type_ref"-"system/durability-request", "optional"-bool(true)]), "operation"-map(["type_ref"-"primitive/string"]), "params"-map(["type_ref"-"core/entity"]), "request_id"-map(["type_ref"-"primitive/string"]), "resource"-map(["type_ref"-"system/protocol/resource-target", "optional"-bool(true)]), "uri"-map(["type_ref"-"system/tree/path"])])])).
core_type_model("system/protocol/execute/response",
    map(["name"-"system/protocol/execute/response", "fields"-map(["durability"-map(["type_ref"-"system/durability-result", "optional"-bool(true)]), "request_id"-map(["type_ref"-"primitive/string"]), "result"-map(["type_ref"-"core/entity"]), "status"-map(["type_ref"-"primitive/uint"])])])).
core_type_model("system/protocol/resource-target",
    map(["name"-"system/protocol/resource-target", "fields"-map(["exclude"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/tree/path"])]), "targets"-map(["array_of"-map(["type_ref"-"system/tree/path"])])])])).
core_type_model("system/capability/grant",
    map(["name"-"system/capability/grant", "fields"-map(["token"-map(["type_ref"-"system/hash"])])])).
core_type_model("system/capability/grant-entry",
    map(["name"-"system/capability/grant-entry", "fields"-map(["allowances"-map(["optional"-bool(true), "map_of"-map(["type_ref"-"primitive/any"])]), "constraints"-map(["optional"-bool(true), "map_of"-map(["type_ref"-"primitive/any"])]), "handlers"-map(["type_ref"-"system/capability/path-scope"]), "operations"-map(["type_ref"-"system/capability/id-scope"]), "peers"-map(["type_ref"-"system/capability/id-scope", "optional"-bool(true)]), "resources"-map(["type_ref"-"system/capability/path-scope"])])])).
core_type_model("system/capability/id-scope",
    map(["name"-"system/capability/id-scope", "fields"-map(["exclude"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"primitive/string"])]), "include"-map(["array_of"-map(["type_ref"-"primitive/string"])])])])).
core_type_model("system/capability/path-scope",
    map(["name"-"system/capability/path-scope", "fields"-map(["exclude"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/tree/path"])]), "include"-map(["array_of"-map(["type_ref"-"system/tree/path"])])])])).
core_type_model("system/capability/request",
    map(["name"-"system/capability/request", "fields"-map(["grants"-map(["array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "ttl_ms"-map(["type_ref"-"primitive/uint", "optional"-bool(true)])])])).
core_type_model("system/capability/revocation",
    map(["name"-"system/capability/revocation", "fields"-map(["reason"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "revoked_at"-map(["type_ref"-"primitive/uint"]), "token"-map(["type_ref"-"system/hash"])])])).
core_type_model("system/capability/revoke-request",
    map(["name"-"system/capability/revoke-request", "fields"-map(["reason"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "token"-map(["type_ref"-"system/hash"])])])).
core_type_model("system/capability/delegate-request",
    map(["name"-"system/capability/delegate-request", "fields"-map(["grants"-map(["array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "parent"-map(["type_ref"-"system/hash"]), "ttl_ms"-map(["type_ref"-"primitive/uint", "optional"-bool(true)])])])).
core_type_model("system/capability/delegation-caveats",
    map(["name"-"system/capability/delegation-caveats", "fields"-map(["max_delegation_depth"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "max_delegation_ttl"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "no_delegation"-map(["type_ref"-"primitive/bool", "optional"-bool(true)])])])).
core_type_model("system/capability/policy-entry",
    map(["name"-"system/capability/policy-entry", "fields"-map(["grants"-map(["array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "notes"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "peer_pattern"-map(["type_ref"-"primitive/string"]), "ttl_ms"-map(["type_ref"-"primitive/uint", "optional"-bool(true)])])])).
core_type_model("system/capability/token",
    map(["name"-"system/capability/token", "fields"-map(["created_at"-map(["type_ref"-"primitive/uint"]), "delegation_caveats"-map(["type_ref"-"system/capability/delegation-caveats", "optional"-bool(true)]), "expires_at"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "grantee"-map(["type_ref"-"system/hash"]), "granter"-map(["union_of"-[map(["type_ref"-"system/hash"]), map(["type_ref"-"system/capability/multi-granter"])]]), "grants"-map(["array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "not_before"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "parent"-map(["type_ref"-"system/hash", "optional"-bool(true)]), "resource_limits"-map(["type_ref"-"system/resource-limits", "optional"-bool(true)])])])).
core_type_model("system/capability/multi-granter",
    map(["name"-"system/capability/multi-granter", "fields"-map(["signers"-map(["array_of"-map(["type_ref"-"system/hash"])]), "threshold"-map(["type_ref"-"primitive/uint"])])])).
core_type_model("system/handler",
    map(["name"-"system/handler", "fields"-map(["expression_path"-map(["type_ref"-"system/tree/path", "optional"-bool(true)]), "interface"-map(["type_ref"-"system/tree/path"]), "internal_scope"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "max_scope"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/capability/grant-entry"])])])])).
core_type_model("system/handler/interface",
    map(["name"-"system/handler/interface", "fields"-map(["name"-map(["type_ref"-"primitive/string"]), "operations"-map(["map_of"-map(["type_ref"-"system/handler/operation-spec"])]), "pattern"-map(["type_ref"-"system/tree/path"])])])).
core_type_model("system/handler/manifest",
    map(["name"-"system/handler/manifest", "fields"-map(["expression_path"-map(["type_ref"-"system/tree/path", "optional"-bool(true)]), "internal_scope"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "max_scope"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "name"-map(["type_ref"-"primitive/string"]), "operations"-map(["map_of"-map(["type_ref"-"system/handler/operation-spec"])]), "pattern"-map(["type_ref"-"system/tree/path"])]), "extends"-"system/handler/interface"])).
core_type_model("system/handler/operation-spec",
    map(["name"-"system/handler/operation-spec", "fields"-map(["input_type"-map(["type_ref"-"system/type/name", "optional"-bool(true)]), "output_type"-map(["type_ref"-"system/type/name", "optional"-bool(true)])])])).
core_type_model("system/handler/register-request",
    map(["name"-"system/handler/register-request", "fields"-map(["manifest"-map(["type_ref"-"system/handler/manifest"]), "requested_scope"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/capability/grant-entry"])]), "types"-map(["optional"-bool(true), "map_of"-map(["type_ref"-"system/type"])])])])).
core_type_model("system/handler/register-result",
    map(["name"-"system/handler/register-result", "fields"-map(["grant"-map(["type_ref"-"system/capability/token"]), "pattern"-map(["type_ref"-"system/tree/path"])])])).
core_type_model("system/tree/get-request",
    map(["name"-"system/tree/get-request", "fields"-map(["limit"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "mode"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "offset"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "tree_id"-map(["type_ref"-"primitive/string", "optional"-bool(true)])])])).
core_type_model("system/tree/put-request",
    map(["name"-"system/tree/put-request", "fields"-map(["entity"-map(["type_ref"-"core/entity", "optional"-bool(true)]), "expected_hash"-map(["type_ref"-"system/hash", "optional"-bool(true)]), "tree_id"-map(["type_ref"-"primitive/string", "optional"-bool(true)])])])).
core_type_model("system/tree/listing",
    map(["name"-"system/tree/listing", "fields"-map(["count"-map(["type_ref"-"primitive/uint"]), "entries"-map(["map_of"-map(["type_ref"-"system/tree/listing-entry"])]), "next_page"-map(["type_ref"-"system/hash", "optional"-bool(true)]), "offset"-map(["type_ref"-"primitive/uint"]), "path"-map(["type_ref"-"system/tree/path"])])])).
core_type_model("system/tree/listing-entry",
    map(["name"-"system/tree/listing-entry", "fields"-map(["has_children"-map(["type_ref"-"primitive/bool"]), "hash"-map(["type_ref"-"system/hash", "optional"-bool(true)])])])).
core_type_model("system/tree/path",
    map(["name"-"system/tree/path", "extends"-"primitive/string"])).
core_type_model("system/type",
    map(["name"-"system/type", "fields"-map(["extends"-map(["type_ref"-"system/type/name", "optional"-bool(true)]), "fields"-map(["optional"-bool(true), "map_of"-map(["type_ref"-"system/type/field-spec"])]), "layout"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"primitive/string"])]), "name"-map(["type_ref"-"system/type/name"]), "type_args"-map(["optional"-bool(true), "map_of"-map(["type_ref"-"system/type/name"])]), "type_params"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"primitive/string"])])])])).
core_type_model("system/type/field-spec",
    map(["name"-"system/type/field-spec", "fields"-map(["array_of"-map(["type_ref"-"system/type/field-spec", "optional"-bool(true)]), "byte_size"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "constraints"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"core/entity"])]), "default"-map(["type_ref"-"primitive/any", "optional"-bool(true)]), "key_type"-map(["type_ref"-"system/type/name", "optional"-bool(true)]), "map_of"-map(["type_ref"-"system/type/field-spec", "optional"-bool(true)]), "optional"-map(["type_ref"-"primitive/bool", "optional"-bool(true)]), "type_args"-map(["optional"-bool(true), "map_of"-map(["type_ref"-"system/type/name"])]), "type_param"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "type_ref"-map(["type_ref"-"system/type/name", "optional"-bool(true)]), "union_of"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/type/field-spec"])])])])).
core_type_model("system/type/name",
    map(["name"-"system/type/name", "extends"-"primitive/string"])).
core_type_model("system/bounds",
    map(["name"-"system/bounds", "fields"-map(["budget"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "cascade_depth"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "chain_id"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "parent_chain_id"-map(["type_ref"-"primitive/string", "optional"-bool(true)]), "ttl"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "visited"-map(["optional"-bool(true), "array_of"-map(["type_ref"-"system/tree/path"])])])])).
core_type_model("system/resource-limits",
    map(["name"-"system/resource-limits", "fields"-map(["max_budget"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "max_ttl"-map(["type_ref"-"primitive/uint", "optional"-bool(true)]), "max_visited_length"-map(["type_ref"-"primitive/uint", "optional"-bool(true)])])])).
core_type_model("system/delivery-spec",
    map(["name"-"system/delivery-spec", "fields"-map(["operation"-map(["type_ref"-"primitive/string"]), "uri"-map(["type_ref"-"system/tree/path"])])])).
core_type_model("system/deletion-marker",
    map(["name"-"system/deletion-marker"])).

core_type_names(["primitive/any", "primitive/bool", "primitive/bytes", "primitive/float", "primitive/int", "primitive/null", "primitive/string", "primitive/uint", "entity", "core/entity", "core/envelope", "system/envelope", "system/protocol/envelope", "system/hash", "system/peer", "system/peer-id", "system/signature", "system/protocol/connect/authenticate", "system/protocol/connect/hello", "system/protocol/error", "system/protocol/execute", "system/protocol/execute/response", "system/protocol/resource-target", "system/capability/grant", "system/capability/grant-entry", "system/capability/id-scope", "system/capability/path-scope", "system/capability/request", "system/capability/revocation", "system/capability/revoke-request", "system/capability/delegate-request", "system/capability/delegation-caveats", "system/capability/policy-entry", "system/capability/token", "system/capability/multi-granter", "system/handler", "system/handler/interface", "system/handler/manifest", "system/handler/operation-spec", "system/handler/register-request", "system/handler/register-result", "system/tree/get-request", "system/tree/put-request", "system/tree/listing", "system/tree/listing-entry", "system/tree/path", "system/type", "system/type/field-spec", "system/type/name", "system/bounds", "system/resource-limits", "system/delivery-spec", "system/deletion-marker"]).
