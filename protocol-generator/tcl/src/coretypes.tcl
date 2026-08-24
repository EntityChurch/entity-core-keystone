# entity-core-protocol-tcl — core type floor (§9.5) — render-from-model.
#
# Publishes the FULL 53-type §9.5 core floor as `system/type` entities under the
# local namespace. The per-type `data` maps are the in-code override table (the
# cross-impl Go-rendered type model, ported field-for-field from the cohort shapes);
# each entity's content_hash is computed by THIS peer's S2-green codec over
# {type, data} (render-from-model, NOT ingest-bytes) — the surface the oracle's
# `type_system` category fetches at system/type/<name> (§9.5 53/53). Non-floor
# vocabularies are extension-owned and intentionally absent.

package require Tcl 8.6-
if {[info exists ::_entity_core_loaded([info script])]} return; set ::_entity_core_loaded([info script]) 1
source [file join [file dirname [info script]] entity.tcl]
source [file join [file dirname [info script]] store.tcl]
source [file join [file dirname [info script]] ecf.tcl]

namespace eval ::entity::core::coretypes {
    namespace export models publish
    variable TAGS {text bytes int array map float bool null undef simple}
}

# classify a bare value into a tagged ECF node: an already-tagged node passes
# through; the literal `true` → bool; an integer → int; anything else → text.
proc ::entity::core::coretypes::_v {v} {
    variable TAGS
    if {[lindex $v 0] in $TAGS} { return $v }
    if {$v eq "true"} { return [::entity::core::ecf::tbool 1] }
    if {[string is entier -strict $v]} { return [::entity::core::ecf::tint $v] }
    return [::entity::core::ecf::tstr $v]
}

# build a `data` map from alternating key value pairs (values auto-classified).
proc ::entity::core::coretypes::m {args} {
    set kv {}
    foreach {k v} $args { lappend kv $k [_v $v] }
    return [::entity::core::ecf::map {*}$kv]
}

# a CBOR array (mt4) whose items are auto-classified (text strings OR nested maps).
proc ::entity::core::coretypes::a {args} {
    set items {}
    foreach it $args { lappend items [_v $it] }
    return [list array $items]
}

# (type-name -> `data` map) for the 53 §9.5 core types, in floor order.
proc ::entity::core::coretypes::models {} {
    set o [dict create]
    dict set o primitive/any    [m name primitive/any]
    dict set o primitive/bool   [m name primitive/bool]
    dict set o primitive/bytes  [m name primitive/bytes]
    dict set o primitive/float  [m name primitive/float]
    dict set o primitive/int    [m name primitive/int]
    dict set o primitive/null   [m name primitive/null]
    dict set o primitive/string [m name primitive/string]
    dict set o primitive/uint   [m name primitive/uint]
    dict set o entity [m name entity fields [m \
        data [m type_ref primitive/any] \
        type [m type_ref primitive/string]]]
    dict set o core/entity [m name core/entity fields [m \
        content_hash [m type_ref system/hash] \
        data [m type_ref primitive/any] \
        type [m type_ref primitive/string]]]
    dict set o core/envelope [m name core/envelope fields [m \
        included [m optional true map_of [m type_ref core/entity] key_type system/hash] \
        root [m type_ref core/entity]]]
    dict set o system/envelope [m name system/envelope extends core/envelope]
    dict set o system/protocol/envelope [m name system/protocol/envelope extends core/envelope]
    dict set o system/hash [m name system/hash fields [m \
        digest [m type_ref primitive/bytes] \
        format_code [m type_ref primitive/uint byte_size 1]] \
        extends primitive/bytes layout [a format_code digest]]
    dict set o system/peer [m name system/peer fields [m \
        key_type [m type_ref primitive/string] \
        peer_id [m type_ref system/peer-id] \
        public_key [m type_ref primitive/bytes]]]
    dict set o system/peer-id [m name system/peer-id extends primitive/string]
    dict set o system/signature [m name system/signature fields [m \
        algorithm [m type_ref primitive/string] \
        signature [m type_ref primitive/bytes] \
        signer [m type_ref system/hash] \
        target [m type_ref system/hash]]]
    dict set o system/protocol/connect/authenticate [m name system/protocol/connect/authenticate fields [m \
        key_type [m type_ref primitive/string] \
        nonce [m type_ref primitive/bytes] \
        peer_id [m type_ref system/peer-id] \
        public_key [m type_ref primitive/bytes]]]
    dict set o system/protocol/connect/hello [m name system/protocol/connect/hello fields [m \
        compression [m optional true array_of [m type_ref primitive/string]] \
        encryption [m optional true array_of [m type_ref primitive/string]] \
        hash_formats [m optional true array_of [m type_ref primitive/string]] \
        key_types [m optional true array_of [m type_ref primitive/string]] \
        nonce [m type_ref primitive/bytes] \
        peer_id [m type_ref system/peer-id] \
        protocols [m array_of [m type_ref primitive/string]] \
        timestamp [m type_ref primitive/uint]]]
    dict set o system/protocol/error [m name system/protocol/error fields [m \
        code [m type_ref primitive/string] \
        message [m type_ref primitive/string optional true] \
        rejected_marker [m type_ref system/hash optional true]]]
    dict set o system/protocol/execute [m name system/protocol/execute fields [m \
        author [m type_ref system/hash optional true] \
        bounds [m type_ref system/bounds optional true] \
        capability [m type_ref system/hash optional true] \
        deliver_to [m type_ref system/delivery-spec optional true] \
        deliver_token [m type_ref system/hash optional true] \
        durability_request [m type_ref system/durability-request optional true] \
        operation [m type_ref primitive/string] \
        params [m type_ref core/entity] \
        request_id [m type_ref primitive/string] \
        resource [m type_ref system/protocol/resource-target optional true] \
        uri [m type_ref system/tree/path]]]
    dict set o system/protocol/execute/response [m name system/protocol/execute/response fields [m \
        durability [m type_ref system/durability-result optional true] \
        request_id [m type_ref primitive/string] \
        result [m type_ref core/entity] \
        status [m type_ref primitive/uint]]]
    dict set o system/protocol/resource-target [m name system/protocol/resource-target fields [m \
        exclude [m optional true array_of [m type_ref system/tree/path]] \
        targets [m array_of [m type_ref system/tree/path]]]]
    dict set o system/capability/grant [m name system/capability/grant fields [m \
        token [m type_ref system/hash]]]
    dict set o system/capability/grant-entry [m name system/capability/grant-entry fields [m \
        allowances [m optional true map_of [m type_ref primitive/any]] \
        constraints [m optional true map_of [m type_ref primitive/any]] \
        handlers [m type_ref system/capability/path-scope] \
        operations [m type_ref system/capability/id-scope] \
        peers [m type_ref system/capability/id-scope optional true] \
        resources [m type_ref system/capability/path-scope]]]
    dict set o system/capability/id-scope [m name system/capability/id-scope fields [m \
        exclude [m optional true array_of [m type_ref primitive/string]] \
        include [m array_of [m type_ref primitive/string]]]]
    dict set o system/capability/path-scope [m name system/capability/path-scope fields [m \
        exclude [m optional true array_of [m type_ref system/tree/path]] \
        include [m array_of [m type_ref system/tree/path]]]]
    dict set o system/capability/request [m name system/capability/request fields [m \
        grants [m array_of [m type_ref system/capability/grant-entry]] \
        ttl_ms [m type_ref primitive/uint optional true]]]
    dict set o system/capability/revocation [m name system/capability/revocation fields [m \
        reason [m type_ref primitive/string optional true] \
        revoked_at [m type_ref primitive/uint] \
        token [m type_ref system/hash]]]
    dict set o system/capability/revoke-request [m name system/capability/revoke-request fields [m \
        reason [m type_ref primitive/string optional true] \
        token [m type_ref system/hash]]]
    dict set o system/capability/delegate-request [m name system/capability/delegate-request fields [m \
        grants [m array_of [m type_ref system/capability/grant-entry]] \
        parent [m type_ref system/hash] \
        ttl_ms [m type_ref primitive/uint optional true]]]
    dict set o system/capability/delegation-caveats [m name system/capability/delegation-caveats fields [m \
        max_delegation_depth [m type_ref primitive/uint optional true] \
        max_delegation_ttl [m type_ref primitive/uint optional true] \
        no_delegation [m type_ref primitive/bool optional true]]]
    dict set o system/capability/policy-entry [m name system/capability/policy-entry fields [m \
        grants [m array_of [m type_ref system/capability/grant-entry]] \
        notes [m type_ref primitive/string optional true] \
        peer_pattern [m type_ref primitive/string] \
        ttl_ms [m type_ref primitive/uint optional true]]]
    dict set o system/capability/token [m name system/capability/token fields [m \
        created_at [m type_ref primitive/uint] \
        delegation_caveats [m type_ref system/capability/delegation-caveats optional true] \
        expires_at [m type_ref primitive/uint optional true] \
        grantee [m type_ref system/hash] \
        granter [m union_of [a [m type_ref system/hash] [m type_ref system/capability/multi-granter]]] \
        grants [m array_of [m type_ref system/capability/grant-entry]] \
        not_before [m type_ref primitive/uint optional true] \
        parent [m type_ref system/hash optional true] \
        resource_limits [m type_ref system/resource-limits optional true]]]
    dict set o system/capability/multi-granter [m name system/capability/multi-granter fields [m \
        signers [m array_of [m type_ref system/hash]] \
        threshold [m type_ref primitive/uint]]]
    dict set o system/handler [m name system/handler fields [m \
        expression_path [m type_ref system/tree/path optional true] \
        interface [m type_ref system/tree/path] \
        internal_scope [m optional true array_of [m type_ref system/capability/grant-entry]] \
        max_scope [m optional true array_of [m type_ref system/capability/grant-entry]]]]
    dict set o system/handler/interface [m name system/handler/interface fields [m \
        name [m type_ref primitive/string] \
        operations [m map_of [m type_ref system/handler/operation-spec]] \
        pattern [m type_ref system/tree/path]]]
    dict set o system/handler/manifest [m name system/handler/manifest fields [m \
        expression_path [m type_ref system/tree/path optional true] \
        internal_scope [m optional true array_of [m type_ref system/capability/grant-entry]] \
        max_scope [m optional true array_of [m type_ref system/capability/grant-entry]] \
        name [m type_ref primitive/string] \
        operations [m map_of [m type_ref system/handler/operation-spec]] \
        pattern [m type_ref system/tree/path]] \
        extends system/handler/interface]
    dict set o system/handler/operation-spec [m name system/handler/operation-spec fields [m \
        input_type [m type_ref system/type/name optional true] \
        output_type [m type_ref system/type/name optional true]]]
    dict set o system/handler/register-request [m name system/handler/register-request fields [m \
        manifest [m type_ref system/handler/manifest] \
        requested_scope [m optional true array_of [m type_ref system/capability/grant-entry]] \
        types [m optional true map_of [m type_ref system/type]]]]
    dict set o system/handler/register-result [m name system/handler/register-result fields [m \
        grant [m type_ref system/capability/token] \
        pattern [m type_ref system/tree/path]]]
    dict set o system/tree/get-request [m name system/tree/get-request fields [m \
        limit [m type_ref primitive/uint optional true] \
        mode [m type_ref primitive/string optional true] \
        offset [m type_ref primitive/uint optional true] \
        tree_id [m type_ref primitive/string optional true]]]
    dict set o system/tree/put-request [m name system/tree/put-request fields [m \
        entity [m type_ref core/entity optional true] \
        expected_hash [m type_ref system/hash optional true] \
        tree_id [m type_ref primitive/string optional true]]]
    dict set o system/tree/listing [m name system/tree/listing fields [m \
        count [m type_ref primitive/uint] \
        entries [m map_of [m type_ref system/tree/listing-entry]] \
        next_page [m type_ref system/hash optional true] \
        offset [m type_ref primitive/uint] \
        path [m type_ref system/tree/path]]]
    dict set o system/tree/listing-entry [m name system/tree/listing-entry fields [m \
        has_children [m type_ref primitive/bool] \
        hash [m type_ref system/hash optional true]]]
    dict set o system/tree/path [m name system/tree/path extends primitive/string]
    dict set o system/type [m name system/type fields [m \
        extends [m type_ref system/type/name optional true] \
        fields [m optional true map_of [m type_ref system/type/field-spec]] \
        layout [m optional true array_of [m type_ref primitive/string]] \
        name [m type_ref system/type/name] \
        type_args [m optional true map_of [m type_ref system/type/name]] \
        type_params [m optional true array_of [m type_ref primitive/string]]]]
    dict set o system/type/field-spec [m name system/type/field-spec fields [m \
        array_of [m type_ref system/type/field-spec optional true] \
        byte_size [m type_ref primitive/uint optional true] \
        constraints [m optional true array_of [m type_ref core/entity]] \
        default [m type_ref primitive/any optional true] \
        key_type [m type_ref system/type/name optional true] \
        map_of [m type_ref system/type/field-spec optional true] \
        optional [m type_ref primitive/bool optional true] \
        type_args [m optional true map_of [m type_ref system/type/name]] \
        type_param [m type_ref primitive/string optional true] \
        type_ref [m type_ref system/type/name optional true] \
        union_of [m optional true array_of [m type_ref system/type/field-spec]]]]
    dict set o system/type/name [m name system/type/name extends primitive/string]
    dict set o system/bounds [m name system/bounds fields [m \
        budget [m type_ref primitive/uint optional true] \
        cascade_depth [m type_ref primitive/uint optional true] \
        chain_id [m type_ref primitive/string optional true] \
        parent_chain_id [m type_ref primitive/string optional true] \
        ttl [m type_ref primitive/uint optional true] \
        visited [m optional true array_of [m type_ref system/tree/path]]]]
    dict set o system/resource-limits [m name system/resource-limits fields [m \
        max_budget [m type_ref primitive/uint optional true] \
        max_ttl [m type_ref primitive/uint optional true] \
        max_visited_length [m type_ref primitive/uint optional true]]]
    dict set o system/delivery-spec [m name system/delivery-spec fields [m \
        operation [m type_ref primitive/string] \
        uri [m type_ref system/tree/path]]]
    dict set o system/deletion-marker [m name system/deletion-marker]
    return $o
}

# publish every core type at /{peer}/system/type/{name}.
proc ::entity::core::coretypes::publish {store_h local_peer} {
    dict for {name data} [models] {
        ::entity::core::store::bind $store_h "/$local_peer/system/type/$name" \
            [::entity::core::entity::make system/type $data]
    }
}
