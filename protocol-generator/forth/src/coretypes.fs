\ entity-core-protocol-forth — core type floor (§9.5) — render-from-model.
\
\ Publishes the FULL 53-type §9.5 core floor as system/type entities under the local
\ namespace at /{peer}/system/type/{name}. Each per-type `data` map is the in-code
\ override table (the cross-impl type model, ported field-for-field from the cohort
\ shape in rexx/src/coretypes.rex); each entity's content_hash is computed by THIS peer's
\ S2-green codec over {type, data} (render-from-model, NOT ingest-bytes) — the surface the
\ oracle's type_system category fetches at system/type/<name>. Non-floor vocabularies are
\ extension-owned and intentionally absent.
\
\ Canonical map-key ORDER is irrelevant here (the codec sorts on encode, §4.2.1), so the
\ field maps below are built in any order; only the logical content must match.
\
\ THE STACK-MACHINE MODEL (A-FT-009): a value TV is built by APPENDING into the arena and
\ handed back as a span. tv-text/tv-bytes/tv-uint/tv-true APPEND IN PLACE (A-FT-014: their
\ returned span is already in the arena — 2drop it, never re-bytes, it). So a map is built by
\ opening `am-mark [char] m b, <n> 4 >be`, then emitting each key+value TV in sequence, then
\ `am-span`. The field-spec helpers below each append ONE complete value TV in place.

\ ── low-level in-place TV appenders ──
\ ct-key ( a u -- )  append a text-key TV in place.
: ct-key ( a u -- )  tv-text 2drop ;
\ ct-str ( a u -- )  append a text-value TV in place (same shape as a key; distinct name
\ for readability at value sites).
: ct-str ( a u -- )  tv-text 2drop ;

\ ── field-spec value helpers (each appends a complete map value TV in place) ──
\ ct-ref ( name-a name-u -- )   {type_ref: name}
: ct-ref { na nu -- }
  am-mark [char] m b, 1 4 >be
    s" type_ref" ct-key  na nu ct-str
  drop ;
\ ct-refo ( name-a name-u -- )  {type_ref: name, optional: true}
: ct-refo { na nu -- }
  am-mark [char] m b, 2 4 >be
    s" type_ref" ct-key  na nu ct-str
    s" optional" ct-key  tv-true 2drop
  drop ;
\ ct-arr ( name-a name-u -- )   {array_of: {type_ref: name}}
: ct-arr { na nu -- }
  am-mark [char] m b, 1 4 >be
    s" array_of" ct-key  na nu ct-ref
  drop ;
\ ct-arro ( name-a name-u -- )  {optional: true, array_of: {type_ref: name}}
: ct-arro { na nu -- }
  am-mark [char] m b, 2 4 >be
    s" optional" ct-key  tv-true 2drop
    s" array_of" ct-key  na nu ct-ref
  drop ;
\ ct-map ( name-a name-u -- )   {map_of: {type_ref: name}}
: ct-map { na nu -- }
  am-mark [char] m b, 1 4 >be
    s" map_of" ct-key  na nu ct-ref
  drop ;
\ ct-mapo ( name-a name-u -- )  {optional: true, map_of: {type_ref: name}}
: ct-mapo { na nu -- }
  am-mark [char] m b, 2 4 >be
    s" optional" ct-key  tv-true 2drop
    s" map_of"   ct-key  na nu ct-ref
  drop ;

\ ── the bind path buffer: /{local}/system/type/{name} ──
create ct-path-buf 512 allot
variable ct-local-addr   variable ct-local-len

\ ct-path ( name-a name-u -- p-a p-u )  build /{local}/system/type/{name} into ct-path-buf.
: ct-path { na nu -- pa pu }
  0 { c }
  s" /" ct-path-buf c + swap dup { s1 } move  c s1 + to c
  ct-local-addr @ ct-path-buf c + ct-local-len @ move  c ct-local-len @ + to c
  s" /system/type/" ct-path-buf c + swap dup { s2 } move  c s2 + to c
  na ct-path-buf c + nu move  c nu + to c
  ct-path-buf c ;

\ ct-bind-map ( name-a name-u  map-a map-u -- )  make a system/type entity from a data-map
\ span + bind it at the type path. The map span was just built in the arena.
: ct-bind-map { na nu ma mu -- }
  s" system/type" ma mu ent-make { ea eu }        \ ( ea eu ): locals bind in stack order
  na nu ct-path  ea eu store-bind ;

\ ct-begin ( -- )  reset the working arena + scratch before building one type. Each type is
\ fully consumed into the durable STORE heap by store-bind (ent-make -> store-dup) before the
\ next, so recycling the 1 MiB arena per type keeps 53 type builds from accreting past it
\ (A-FT-009 arena discipline; the name spans are dictionary literals, stable across a reset).
: ct-begin ( -- )  arena-reset scratch-reset ;

\ ── the three trivial shapes (mirror _ct_nm / _ct_ext / _ct_flds) ──
\ ct-nm ( name-a name-u -- )  {name: X}. NOTE the name string must stay stable across the
\ map build; ct-path re-reads it AFTER the map is built, so copy nothing — na/nu are literal
\ s" ..." spans in the dictionary, stable.
: ct-nm { na nu -- }
  ct-begin
  am-mark { mk } [char] m b, 1 4 >be
    s" name" ct-key  na nu ct-str
  mk am-span { ma mu }
  na nu ma mu ct-bind-map ;

\ ct-ext ( name-a name-u base-a base-u -- )  {name: X, extends: Y}
: ct-ext { na nu ba bu -- }
  ct-begin
  am-mark { mk } [char] m b, 2 4 >be
    s" name"    ct-key  na nu ct-str
    s" extends" ct-key  ba bu ct-str
  mk am-span { ma mu }
  na nu ma mu ct-bind-map ;

\ For a `{name: X, fields: {...}}` type the fields map is variable-shaped, so rather than a
\ single ct-flds helper we OPEN the outer map inline at each type, emit `name` + `fields`
\ (whose body is a nested map the type builds in place), then close + bind. Two helper words
\ bracket that: ct-open ( name-a name-u nfields -- name-a name-u mk ) opens the OUTER
\ {name, fields:{...}} map — pushing the mark — and writes the name pair + the `fields` key +
\ the inner map header; ct-close ( name-a name-u mk innern -- ) is not used (inner count is
\ written by ct-fopen). We instead use an explicit inline idiom per type (below).

\ ct-fopen ( name-a name-u innern -- name-a name-u outer-mk )  open a {name:X, fields:{...}}
\ where the inner fields map has `innern` pairs. After this, emit the innern field key+value
\ pairs in place, then ct-fclose.
: ct-fopen { na nu innern -- na nu mk }
  ct-begin
  am-mark { mk }
  [char] m b, 2 4 >be                 \ outer map: {name, fields}
    s" name"   ct-key  na nu ct-str
    s" fields" ct-key
    [char] m b, innern 4 >be          \ inner fields map header (innern pairs follow in place)
  na nu mk ;
\ ct-fclose ( name-a name-u mk -- )  close the {name, fields} map + bind it.
: ct-fclose { na nu mk -- }
  mk am-span { ma mu }
  na nu ma mu ct-bind-map ;

\ ── the publisher ── ct-publish ( local-addr local-u -- )
: ct-publish { laddr llen -- }
  laddr ct-local-addr !  llen ct-local-len !

  \ ── primitives (8) — _ct_nm ──
  s" primitive/any"    ct-nm
  s" primitive/bool"   ct-nm
  s" primitive/bytes"  ct-nm
  s" primitive/float"  ct-nm
  s" primitive/int"    ct-nm
  s" primitive/null"   ct-nm
  s" primitive/string" ct-nm
  s" primitive/uint"   ct-nm

  \ ── entity / envelope (5) ──
  \ entity: {data: ref(primitive/any), type: ref(primitive/string)}
  s" entity" 2 ct-fopen
    s" data" ct-key  s" primitive/any"    ct-ref
    s" type" ct-key  s" primitive/string" ct-ref
  ct-fclose
  \ core/entity: {content_hash: ref(system/hash), data: ref(primitive/any), type: ref(primitive/string)}
  s" core/entity" 3 ct-fopen
    s" content_hash" ct-key  s" system/hash"      ct-ref
    s" data"         ct-key  s" primitive/any"    ct-ref
    s" type"         ct-key  s" primitive/string" ct-ref
  ct-fclose
  \ core/envelope: {included: {optional:true, map_of:ref(core/entity), key_type:"system/hash"}, root: ref(core/entity)}
  \ NOTE the `included` field-spec has an extra `key_type` text field beyond ct-mapo — build inline.
  s" core/envelope" 2 ct-fopen
    s" included" ct-key
      am-mark [char] m b, 3 4 >be
        s" optional" ct-key  tv-true 2drop
        s" map_of"   ct-key  s" core/entity" ct-ref
        s" key_type" ct-key  s" system/hash"  ct-str
      drop
    s" root" ct-key  s" core/entity" ct-ref
  ct-fclose
  s" system/envelope"          s" core/envelope" ct-ext
  s" system/protocol/envelope" s" core/envelope" ct-ext

  \ ── hash / peer / signature (5) ──
  \ system/hash: {name, fields:{digest: ref(primitive/bytes), format_code:{type_ref:primitive/uint, byte_size:1}},
  \               extends: primitive/bytes, layout: [format_code, digest]}
  \ Non-standard shape (name+fields+extends+layout) — build fully inline.
  ct-begin
  am-mark { hmk }
  [char] m b, 4 4 >be
    s" name" ct-key  s" system/hash" ct-str
    s" fields" ct-key
      [char] m b, 2 4 >be
        s" digest"      ct-key  s" primitive/bytes" ct-ref
        s" format_code" ct-key
          [char] m b, 2 4 >be
            s" type_ref"  ct-key  s" primitive/uint" ct-str
            s" byte_size" ct-key  1 tv-uint 2drop
    s" extends" ct-key  s" primitive/bytes" ct-str
    s" layout" ct-key
      [char] a b, 2 4 >be
        s" format_code" tv-text 2drop
        s" digest"      tv-text 2drop
  hmk am-span { hma hmu }
  s" system/hash" hma hmu ct-bind-map
  \ system/peer: {key_type: ref(primitive/string), peer_id: ref(system/peer-id), public_key: ref(primitive/bytes)}
  s" system/peer" 3 ct-fopen
    s" key_type"   ct-key  s" primitive/string" ct-ref
    s" peer_id"    ct-key  s" system/peer-id"   ct-ref
    s" public_key" ct-key  s" primitive/bytes"  ct-ref
  ct-fclose
  s" system/peer-id" s" primitive/string" ct-ext
  \ system/signature: {algorithm, signature, signer, target}
  s" system/signature" 4 ct-fopen
    s" algorithm" ct-key  s" primitive/string" ct-ref
    s" signature" ct-key  s" primitive/bytes"  ct-ref
    s" signer"    ct-key  s" system/hash"      ct-ref
    s" target"    ct-key  s" system/hash"      ct-ref
  ct-fclose

  \ ── connect (2) ──
  \ system/protocol/connect/authenticate: {key_type, nonce, peer_id, public_key}
  s" system/protocol/connect/authenticate" 4 ct-fopen
    s" key_type"   ct-key  s" primitive/string" ct-ref
    s" nonce"      ct-key  s" primitive/bytes"  ct-ref
    s" peer_id"    ct-key  s" system/peer-id"   ct-ref
    s" public_key" ct-key  s" primitive/bytes"  ct-ref
  ct-fclose
  \ system/protocol/connect/hello:
  \ {compression: arro(str), encryption: arro(str), hash_formats: arro(str), key_types: arro(str),
  \  nonce: ref(bytes), peer_id: ref(peer-id), protocols: arr(str), timestamp: ref(uint)}
  s" system/protocol/connect/hello" 8 ct-fopen
    s" compression"  ct-key  s" primitive/string" ct-arro
    s" encryption"   ct-key  s" primitive/string" ct-arro
    s" hash_formats" ct-key  s" primitive/string" ct-arro
    s" key_types"    ct-key  s" primitive/string" ct-arro
    s" nonce"        ct-key  s" primitive/bytes"  ct-ref
    s" peer_id"      ct-key  s" system/peer-id"   ct-ref
    s" protocols"    ct-key  s" primitive/string" ct-arr
    s" timestamp"    ct-key  s" primitive/uint"   ct-ref
  ct-fclose

  \ ── protocol error / execute / response / resource-target (4) ──
  \ system/protocol/error: {code: ref(str), message: refo(str), rejected_marker: refo(hash)}
  s" system/protocol/error" 3 ct-fopen
    s" code"            ct-key  s" primitive/string" ct-ref
    s" message"         ct-key  s" primitive/string" ct-refo
    s" rejected_marker" ct-key  s" system/hash"      ct-refo
  ct-fclose
  \ system/protocol/execute (11 fields)
  s" system/protocol/execute" 11 ct-fopen
    s" author"            ct-key  s" system/hash"                    ct-refo
    s" bounds"            ct-key  s" system/bounds"                  ct-refo
    s" capability"        ct-key  s" system/hash"                    ct-refo
    s" deliver_to"        ct-key  s" system/delivery-spec"           ct-refo
    s" deliver_token"     ct-key  s" system/hash"                    ct-refo
    s" durability_request" ct-key s" system/durability-request"      ct-refo
    s" operation"         ct-key  s" primitive/string"               ct-ref
    s" params"            ct-key  s" core/entity"                    ct-ref
    s" request_id"        ct-key  s" primitive/string"               ct-ref
    s" resource"          ct-key  s" system/protocol/resource-target" ct-refo
    s" uri"               ct-key  s" system/tree/path"               ct-ref
  ct-fclose
  \ system/protocol/execute/response: {durability: refo, request_id: ref(str), result: ref(core/entity), status: ref(uint)}
  s" system/protocol/execute/response" 4 ct-fopen
    s" durability" ct-key  s" system/durability-result" ct-refo
    s" request_id" ct-key  s" primitive/string"         ct-ref
    s" result"     ct-key  s" core/entity"              ct-ref
    s" status"     ct-key  s" primitive/uint"           ct-ref
  ct-fclose
  \ system/protocol/resource-target: {exclude: arro(tree/path), targets: arr(tree/path)}
  s" system/protocol/resource-target" 2 ct-fopen
    s" exclude" ct-key  s" system/tree/path" ct-arro
    s" targets" ct-key  s" system/tree/path" ct-arr
  ct-fclose

  \ ── capability (11) ──
  \ system/capability/grant: {token: ref(hash)}
  s" system/capability/grant" 1 ct-fopen
    s" token" ct-key  s" system/hash" ct-ref
  ct-fclose
  \ system/capability/grant-entry: {allowances: mapo(any), constraints: mapo(any),
  \   handlers: ref(path-scope), operations: ref(id-scope), peers: refo(id-scope), resources: ref(path-scope)}
  s" system/capability/grant-entry" 6 ct-fopen
    s" allowances"  ct-key  s" primitive/any"                ct-mapo
    s" constraints" ct-key  s" primitive/any"                ct-mapo
    s" handlers"    ct-key  s" system/capability/path-scope" ct-ref
    s" operations"  ct-key  s" system/capability/id-scope"   ct-ref
    s" peers"       ct-key  s" system/capability/id-scope"   ct-refo
    s" resources"   ct-key  s" system/capability/path-scope" ct-ref
  ct-fclose
  \ system/capability/id-scope: {exclude: arro(str), include: arr(str)}
  s" system/capability/id-scope" 2 ct-fopen
    s" exclude" ct-key  s" primitive/string" ct-arro
    s" include" ct-key  s" primitive/string" ct-arr
  ct-fclose
  \ system/capability/path-scope: {exclude: arro(tree/path), include: arr(tree/path)}
  s" system/capability/path-scope" 2 ct-fopen
    s" exclude" ct-key  s" system/tree/path" ct-arro
    s" include" ct-key  s" system/tree/path" ct-arr
  ct-fclose
  \ system/capability/request: {grants: arr(grant-entry), ttl_ms: refo(uint)}
  s" system/capability/request" 2 ct-fopen
    s" grants" ct-key  s" system/capability/grant-entry" ct-arr
    s" ttl_ms" ct-key  s" primitive/uint"                ct-refo
  ct-fclose
  \ system/capability/revocation: {reason: refo(str), revoked_at: ref(uint), token: ref(hash)}
  s" system/capability/revocation" 3 ct-fopen
    s" reason"     ct-key  s" primitive/string" ct-refo
    s" revoked_at" ct-key  s" primitive/uint"   ct-ref
    s" token"      ct-key  s" system/hash"      ct-ref
  ct-fclose
  \ system/capability/revoke-request: {reason: refo(str), token: ref(hash)}
  s" system/capability/revoke-request" 2 ct-fopen
    s" reason" ct-key  s" primitive/string" ct-refo
    s" token"  ct-key  s" system/hash"      ct-ref
  ct-fclose
  \ system/capability/delegate-request: {grants: arr(grant-entry), parent: ref(hash), ttl_ms: refo(uint)}
  s" system/capability/delegate-request" 3 ct-fopen
    s" grants" ct-key  s" system/capability/grant-entry" ct-arr
    s" parent" ct-key  s" system/hash"                   ct-ref
    s" ttl_ms" ct-key  s" primitive/uint"                ct-refo
  ct-fclose
  \ system/capability/delegation-caveats: {max_delegation_depth: refo(uint), max_delegation_ttl: refo(uint), no_delegation: refo(bool)}
  s" system/capability/delegation-caveats" 3 ct-fopen
    s" max_delegation_depth" ct-key  s" primitive/uint" ct-refo
    s" max_delegation_ttl"   ct-key  s" primitive/uint" ct-refo
    s" no_delegation"        ct-key  s" primitive/bool" ct-refo
  ct-fclose
  \ system/capability/policy-entry: {grants: arr(grant-entry), notes: refo(str), peer_pattern: ref(str), ttl_ms: refo(uint)}
  s" system/capability/policy-entry" 4 ct-fopen
    s" grants"       ct-key  s" system/capability/grant-entry" ct-arr
    s" notes"        ct-key  s" primitive/string"              ct-refo
    s" peer_pattern" ct-key  s" primitive/string"              ct-ref
    s" ttl_ms"       ct-key  s" primitive/uint"                ct-refo
  ct-fclose
  \ system/capability/token (9 fields; granter is a union {union_of: [{type_ref:hash},{type_ref:multi-granter}]})
  s" system/capability/token" 9 ct-fopen
    s" created_at"          ct-key  s" primitive/uint"                        ct-ref
    s" delegation_caveats"  ct-key  s" system/capability/delegation-caveats"  ct-refo
    s" expires_at"          ct-key  s" primitive/uint"                        ct-refo
    s" grantee"             ct-key  s" system/hash"                           ct-ref
    s" granter"             ct-key
      am-mark [char] m b, 1 4 >be
        s" union_of" ct-key
          [char] a b, 2 4 >be
            s" system/hash"                     ct-ref
            s" system/capability/multi-granter" ct-ref
      drop
    s" grants"              ct-key  s" system/capability/grant-entry"         ct-arr
    s" not_before"          ct-key  s" primitive/uint"                        ct-refo
    s" parent"              ct-key  s" system/hash"                           ct-refo
    s" resource_limits"     ct-key  s" system/resource-limits"                ct-refo
  ct-fclose
  \ system/capability/multi-granter: {signers: arr(hash), threshold: ref(uint)}
  s" system/capability/multi-granter" 2 ct-fopen
    s" signers"   ct-key  s" system/hash"    ct-arr
    s" threshold" ct-key  s" primitive/uint" ct-ref
  ct-fclose

  \ ── handler (6) ──
  \ system/handler: {expression_path: refo(tree/path), interface: ref(tree/path), internal_scope: arro(grant-entry), max_scope: arro(grant-entry)}
  s" system/handler" 4 ct-fopen
    s" expression_path" ct-key  s" system/tree/path"              ct-refo
    s" interface"       ct-key  s" system/tree/path"              ct-ref
    s" internal_scope"  ct-key  s" system/capability/grant-entry" ct-arro
    s" max_scope"       ct-key  s" system/capability/grant-entry" ct-arro
  ct-fclose
  \ system/handler/interface: {name: ref(str), operations: map(operation-spec), pattern: ref(tree/path)}
  s" system/handler/interface" 3 ct-fopen
    s" name"       ct-key  s" primitive/string"                  ct-ref
    s" operations" ct-key  s" system/handler/operation-spec"     ct-map
    s" pattern"    ct-key  s" system/tree/path"                  ct-ref
  ct-fclose
  \ system/handler/manifest: {name, fields:{expression_path, internal_scope, max_scope, name, operations, pattern}, extends: system/handler/interface}
  ct-begin
  am-mark { mmk }
  [char] m b, 3 4 >be
    s" name" ct-key  s" system/handler/manifest" ct-str
    s" fields" ct-key
      [char] m b, 6 4 >be
        s" expression_path" ct-key  s" system/tree/path"              ct-refo
        s" internal_scope"  ct-key  s" system/capability/grant-entry" ct-arro
        s" max_scope"       ct-key  s" system/capability/grant-entry" ct-arro
        s" name"            ct-key  s" primitive/string"              ct-ref
        s" operations"      ct-key  s" system/handler/operation-spec" ct-map
        s" pattern"         ct-key  s" system/tree/path"              ct-ref
    s" extends" ct-key  s" system/handler/interface" ct-str
  mmk am-span { mma mmu }
  s" system/handler/manifest" mma mmu ct-bind-map
  \ system/handler/operation-spec: {input_type: refo(type/name), output_type: refo(type/name)}
  s" system/handler/operation-spec" 2 ct-fopen
    s" input_type"  ct-key  s" system/type/name" ct-refo
    s" output_type" ct-key  s" system/type/name" ct-refo
  ct-fclose
  \ system/handler/register-request: {manifest: ref(manifest), requested_scope: arro(grant-entry), types: mapo(system/type)}
  s" system/handler/register-request" 3 ct-fopen
    s" manifest"        ct-key  s" system/handler/manifest"       ct-ref
    s" requested_scope" ct-key  s" system/capability/grant-entry" ct-arro
    s" types"           ct-key  s" system/type"                   ct-mapo
  ct-fclose
  \ system/handler/register-result: {grant: ref(token), pattern: ref(tree/path)}
  s" system/handler/register-result" 2 ct-fopen
    s" grant"   ct-key  s" system/capability/token" ct-ref
    s" pattern" ct-key  s" system/tree/path"        ct-ref
  ct-fclose

  \ ── tree (5) ──
  \ system/tree/get-request: {limit: refo(uint), mode: refo(str), offset: refo(uint), tree_id: refo(str)}
  s" system/tree/get-request" 4 ct-fopen
    s" limit"   ct-key  s" primitive/uint"   ct-refo
    s" mode"    ct-key  s" primitive/string" ct-refo
    s" offset"  ct-key  s" primitive/uint"   ct-refo
    s" tree_id" ct-key  s" primitive/string" ct-refo
  ct-fclose
  \ system/tree/put-request: {entity: refo(core/entity), expected_hash: refo(hash), tree_id: refo(str)}
  s" system/tree/put-request" 3 ct-fopen
    s" entity"        ct-key  s" core/entity"      ct-refo
    s" expected_hash" ct-key  s" system/hash"      ct-refo
    s" tree_id"       ct-key  s" primitive/string" ct-refo
  ct-fclose
  \ system/tree/listing: {count: ref(uint), entries: map(listing-entry), next_page: refo(hash), offset: ref(uint), path: ref(tree/path)}
  s" system/tree/listing" 5 ct-fopen
    s" count"     ct-key  s" primitive/uint"               ct-ref
    s" entries"   ct-key  s" system/tree/listing-entry"    ct-map
    s" next_page" ct-key  s" system/hash"                  ct-refo
    s" offset"    ct-key  s" primitive/uint"               ct-ref
    s" path"      ct-key  s" system/tree/path"             ct-ref
  ct-fclose
  \ system/tree/listing-entry: {has_children: ref(bool), hash: refo(hash)}
  s" system/tree/listing-entry" 2 ct-fopen
    s" has_children" ct-key  s" primitive/bool" ct-ref
    s" hash"         ct-key  s" system/hash"    ct-refo
  ct-fclose
  s" system/tree/path" s" primitive/string" ct-ext

  \ ── type system (3) ──
  \ system/type: {extends: refo(type/name), fields: mapo(field-spec), layout: arro(str), name: ref(type/name), type_args: mapo(type/name), type_params: arro(str)}
  s" system/type" 6 ct-fopen
    s" extends"     ct-key  s" system/type/name"            ct-refo
    s" fields"      ct-key  s" system/type/field-spec"      ct-mapo
    s" layout"      ct-key  s" primitive/string"            ct-arro
    s" name"        ct-key  s" system/type/name"            ct-ref
    s" type_args"   ct-key  s" system/type/name"            ct-mapo
    s" type_params" ct-key  s" primitive/string"            ct-arro
  ct-fclose
  \ system/type/field-spec: {array_of: refo(field-spec), byte_size: refo(uint), constraints: arro(core/entity),
  \   default: refo(any), key_type: refo(type/name), map_of: refo(field-spec), optional: refo(bool),
  \   type_args: mapo(type/name), type_param: refo(str), type_ref: refo(type/name), union_of: arro(field-spec)}
  s" system/type/field-spec" 11 ct-fopen
    s" array_of"    ct-key  s" system/type/field-spec" ct-refo
    s" byte_size"   ct-key  s" primitive/uint"         ct-refo
    s" constraints" ct-key  s" core/entity"            ct-arro
    s" default"     ct-key  s" primitive/any"          ct-refo
    s" key_type"    ct-key  s" system/type/name"       ct-refo
    s" map_of"      ct-key  s" system/type/field-spec" ct-refo
    s" optional"    ct-key  s" primitive/bool"         ct-refo
    s" type_args"   ct-key  s" system/type/name"       ct-mapo
    s" type_param"  ct-key  s" primitive/string"       ct-refo
    s" type_ref"    ct-key  s" system/type/name"       ct-refo
    s" union_of"    ct-key  s" system/type/field-spec" ct-arro
  ct-fclose
  s" system/type/name" s" primitive/string" ct-ext

  \ ── bounds / limits / delivery / deletion (4) ──
  \ system/bounds: {budget: refo(uint), cascade_depth: refo(uint), chain_id: refo(str), parent_chain_id: refo(str), ttl: refo(uint), visited: arro(tree/path)}
  s" system/bounds" 6 ct-fopen
    s" budget"          ct-key  s" primitive/uint"   ct-refo
    s" cascade_depth"   ct-key  s" primitive/uint"   ct-refo
    s" chain_id"        ct-key  s" primitive/string" ct-refo
    s" parent_chain_id" ct-key  s" primitive/string" ct-refo
    s" ttl"             ct-key  s" primitive/uint"   ct-refo
    s" visited"         ct-key  s" system/tree/path" ct-arro
  ct-fclose
  \ system/resource-limits: {max_budget: refo(uint), max_ttl: refo(uint), max_visited_length: refo(uint)}
  s" system/resource-limits" 3 ct-fopen
    s" max_budget"         ct-key  s" primitive/uint" ct-refo
    s" max_ttl"            ct-key  s" primitive/uint" ct-refo
    s" max_visited_length" ct-key  s" primitive/uint" ct-refo
  ct-fclose
  \ system/delivery-spec: {operation: ref(str), uri: ref(tree/path)}
  s" system/delivery-spec" 2 ct-fopen
    s" operation" ct-key  s" primitive/string" ct-ref
    s" uri"       ct-key  s" system/tree/path" ct-ref
  ct-fclose
  \ system/deletion-marker: {name: X}
  s" system/deletion-marker" ct-nm
;
