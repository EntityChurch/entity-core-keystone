%% entity-core-protocol-oz — typestore.oz
%% Publishes the §9.5 53-type Core Type Floor as system/type entities under the
%% local namespace (render-from-model: each entity's content_hash is computed by
%% THIS peer's codec over {type, data}, NOT ingested bytes). Field shapes ported
%% from the cohort model (the Rexx/cohort coretypes shapes). Map-key order is
%% irrelevant (the codec sorts on encode); only the logical content matters.
functor
import
   Val at 'val.ozf'
   Ent at 'entity.ozf'
   Store at 'store.ozf'
   Util at 'util.ozf'
export
   Publish
define
   %% field-spec helpers
   fun {Ref X} map([{Val.mkPair "type_ref" {Val.txt X}}]) end
   fun {RefO X} map([{Val.mkPair "type_ref" {Val.txt X}} {Val.mkPair "optional" bool(true)}]) end
   fun {ArrOf X} map([{Val.mkPair "array_of" {Ref X}}]) end
   fun {ArrO X} map([{Val.mkPair "optional" bool(true)} {Val.mkPair "array_of" {Ref X}}]) end
   fun {MapOf X} map([{Val.mkPair "map_of" {Ref X}}]) end
   fun {MapO X} map([{Val.mkPair "optional" bool(true)} {Val.mkPair "map_of" {Ref X}}]) end
   fun {P K V} {Val.mkPair K V} end
   fun {M L} map(L) end

   proc {Bind St Local Name Data}
      Path = {Append &/|Local {Append "/system/type/" Name}}
   in
      {Store.bind St Path {Ent.make "system/type" Data}}
   end
   proc {Nm St Local Name} {Bind St Local Name {M [{P "name" {Val.txt Name}}]}} end
   proc {Xt St Local Name Base}
      {Bind St Local Name {M [{P "name" {Val.txt Name}} {P "extends" {Val.txt Base}}]}}
   end
   proc {Fl St Local Name Fields}
      {Bind St Local Name {M [{P "name" {Val.txt Name}} {P "fields" Fields}]}}
   end

   proc {Publish St Local}
      %% primitives (8)
      {Nm St Local "primitive/any"} {Nm St Local "primitive/bool"}
      {Nm St Local "primitive/bytes"} {Nm St Local "primitive/float"}
      {Nm St Local "primitive/int"} {Nm St Local "primitive/null"}
      {Nm St Local "primitive/string"} {Nm St Local "primitive/uint"}

      %% entity / envelope (5)
      {Fl St Local "entity" {M [{P "type" {Ref "primitive/string"}} {P "data" {Ref "primitive/any"}}]}}
      {Fl St Local "core/entity" {M [{P "type" {Ref "primitive/string"}} {P "data" {Ref "primitive/any"}} {P "content_hash" {Ref "system/hash"}}]}}
      {Fl St Local "core/envelope"
       {M [{P "root" {Ref "core/entity"}}
           {P "included" {M [{P "optional" bool(true)} {P "map_of" {Ref "core/entity"}} {P "key_type" {Val.txt "system/hash"}}]}}]}}
      {Xt St Local "system/envelope" "core/envelope"}
      {Xt St Local "system/protocol/envelope" "core/envelope"}

      %% hash / peer / signature (4)
      {Bind St Local "system/hash"
       {M [{P "name" {Val.txt "system/hash"}} {P "extends" {Val.txt "primitive/bytes"}}
           {P "fields" {M [{P "format_code" {M [{P "type_ref" {Val.txt "primitive/uint"}} {P "byte_size" int(1)}]}} {P "digest" {Ref "primitive/bytes"}}]}}
           {P "layout" {Val.textArray [{Util.vsToBytes "format_code"} {Util.vsToBytes "digest"}]}}]}}
      {Fl St Local "system/peer" {M [{P "public_key" {Ref "primitive/bytes"}} {P "key_type" {Ref "primitive/string"}} {P "peer_id" {Ref "system/peer-id"}}]}}
      {Xt St Local "system/peer-id" "primitive/string"}
      {Fl St Local "system/signature" {M [{P "target" {Ref "system/hash"}} {P "signer" {Ref "system/hash"}} {P "algorithm" {Ref "primitive/string"}} {P "signature" {Ref "primitive/bytes"}}]}}

      %% protocol surface (6)
      {Fl St Local "system/protocol/connect/authenticate" {M [{P "peer_id" {Ref "system/peer-id"}} {P "public_key" {Ref "primitive/bytes"}} {P "key_type" {Ref "primitive/string"}} {P "nonce" {Ref "primitive/bytes"}}]}}
      {Fl St Local "system/protocol/connect/hello"
       {M [{P "peer_id" {Ref "system/peer-id"}} {P "nonce" {Ref "primitive/bytes"}}
           {P "protocols" {ArrOf "primitive/string"}} {P "timestamp" {Ref "primitive/uint"}}
           {P "hash_formats" {ArrO "primitive/string"}} {P "key_types" {ArrO "primitive/string"}}
           {P "compression" {ArrO "primitive/string"}} {P "encryption" {ArrO "primitive/string"}}]}}
      {Fl St Local "system/protocol/error" {M [{P "code" {Ref "primitive/string"}} {P "message" {RefO "primitive/string"}}]}}
      {Fl St Local "system/protocol/execute"
       {M [{P "request_id" {Ref "primitive/string"}} {P "uri" {Ref "system/tree/path"}}
           {P "operation" {Ref "primitive/string"}} {P "resource" {RefO "system/protocol/resource-target"}}
           {P "params" {Ref "core/entity"}} {P "bounds" {RefO "system/bounds"}}
           {P "deliver_to" {RefO "system/delivery-spec"}} {P "author" {RefO "system/hash"}}
           {P "capability" {RefO "system/hash"}}]}}
      {Fl St Local "system/protocol/execute/response" {M [{P "request_id" {Ref "primitive/string"}} {P "status" {Ref "primitive/uint"}} {P "result" {Ref "core/entity"}} {P "budget_consumed" {RefO "primitive/uint"}}]}}
      {Fl St Local "system/protocol/resource-target" {M [{P "targets" {ArrOf "system/tree/path"}} {P "exclude" {ArrO "system/tree/path"}}]}}

      %% capability (12)
      {Fl St Local "system/capability/grant" {M [{P "token" {Ref "system/hash"}}]}}
      {Fl St Local "system/capability/grant-entry"
       {M [{P "handlers" {Ref "system/capability/path-scope"}} {P "resources" {Ref "system/capability/path-scope"}}
           {P "operations" {Ref "system/capability/id-scope"}} {P "peers" {RefO "system/capability/id-scope"}}
           {P "constraints" {MapO "primitive/any"}} {P "allowances" {MapO "primitive/any"}}]}}
      {Fl St Local "system/capability/id-scope" {M [{P "include" {ArrOf "primitive/string"}} {P "exclude" {ArrO "primitive/string"}}]}}
      {Fl St Local "system/capability/path-scope" {M [{P "include" {ArrOf "system/tree/path"}} {P "exclude" {ArrO "system/tree/path"}}]}}
      {Fl St Local "system/capability/request" {M [{P "grants" {ArrOf "system/capability/grant-entry"}} {P "ttl_ms" {RefO "primitive/uint"}}]}}
      {Fl St Local "system/capability/revocation" {M [{P "token" {Ref "system/hash"}} {P "reason" {RefO "primitive/string"}} {P "revoked_at" {Ref "primitive/uint"}}]}}
      {Fl St Local "system/capability/revoke-request" {M [{P "token" {Ref "system/hash"}} {P "reason" {RefO "primitive/string"}}]}}
      {Fl St Local "system/capability/delegate-request" {M [{P "parent" {Ref "system/hash"}} {P "grants" {ArrOf "system/capability/grant-entry"}} {P "ttl_ms" {RefO "primitive/uint"}}]}}
      {Fl St Local "system/capability/delegation-caveats" {M [{P "no_delegation" {RefO "primitive/bool"}} {P "max_delegation_depth" {RefO "primitive/uint"}} {P "max_delegation_ttl" {RefO "primitive/uint"}}]}}
      {Fl St Local "system/capability/policy-entry" {M [{P "peer_pattern" {Ref "primitive/string"}} {P "grants" {ArrOf "system/capability/grant-entry"}} {P "ttl_ms" {RefO "primitive/uint"}} {P "notes" {RefO "primitive/string"}}]}}
      {Fl St Local "system/capability/token"
       {M [{P "grants" {ArrOf "system/capability/grant-entry"}}
           {P "granter" {M [{P "union_of" {Val.arrOfList [{Ref "system/hash"} {Ref "system/capability/multi-granter"}]}}]}}
           {P "grantee" {Ref "system/hash"}} {P "parent" {RefO "system/hash"}}
           {P "created_at" {Ref "primitive/uint"}} {P "expires_at" {RefO "primitive/uint"}}
           {P "not_before" {RefO "primitive/uint"}} {P "delegation_caveats" {RefO "system/capability/delegation-caveats"}}
           {P "resource_limits" {RefO "system/resource-limits"}}]}}
      {Fl St Local "system/capability/multi-granter" {M [{P "signers" {ArrOf "system/hash"}} {P "threshold" {Ref "primitive/uint"}}]}}

      %% handler machinery (6)
      {Fl St Local "system/handler" {M [{P "interface" {Ref "system/tree/path"}} {P "max_scope" {ArrO "system/capability/grant-entry"}} {P "internal_scope" {ArrO "system/capability/grant-entry"}} {P "expression_path" {RefO "system/tree/path"}}]}}
      {Fl St Local "system/handler/interface" {M [{P "pattern" {Ref "system/tree/path"}} {P "name" {Ref "primitive/string"}} {P "operations" {MapOf "system/handler/operation-spec"}}]}}
      {Bind St Local "system/handler/manifest"
       {M [{P "name" {Val.txt "system/handler/manifest"}} {P "extends" {Val.txt "system/handler/interface"}}
           {P "fields" {M [{P "pattern" {Ref "system/tree/path"}} {P "name" {Ref "primitive/string"}}
                           {P "operations" {MapOf "system/handler/operation-spec"}}
                           {P "max_scope" {ArrO "system/capability/grant-entry"}} {P "internal_scope" {ArrO "system/capability/grant-entry"}}
                           {P "expression_path" {RefO "system/tree/path"}}]}}]}}
      {Fl St Local "system/handler/operation-spec" {M [{P "input_type" {RefO "system/type/name"}} {P "output_type" {RefO "system/type/name"}}]}}
      {Fl St Local "system/handler/register-request" {M [{P "manifest" {Ref "system/handler/manifest"}} {P "types" {MapO "system/type"}} {P "requested_scope" {ArrO "system/capability/grant-entry"}}]}}
      {Fl St Local "system/handler/register-result" {M [{P "pattern" {Ref "system/tree/path"}} {P "grant" {Ref "system/capability/token"}}]}}

      %% tree (5)
      {Fl St Local "system/tree/get-request" {M [{P "tree_id" {RefO "primitive/string"}} {P "mode" {RefO "primitive/string"}} {P "limit" {RefO "primitive/uint"}} {P "offset" {RefO "primitive/uint"}}]}}
      {Fl St Local "system/tree/put-request" {M [{P "entity" {RefO "core/entity"}} {P "expected_hash" {RefO "system/hash"}} {P "tree_id" {RefO "primitive/string"}}]}}
      {Fl St Local "system/tree/listing" {M [{P "path" {Ref "system/tree/path"}} {P "entries" {MapOf "system/tree/listing-entry"}} {P "count" {Ref "primitive/uint"}} {P "offset" {Ref "primitive/uint"}} {P "next_page" {RefO "system/hash"}}]}}
      {Fl St Local "system/tree/listing-entry" {M [{P "hash" {RefO "system/hash"}} {P "has_children" {Ref "primitive/bool"}}]}}
      {Xt St Local "system/tree/path" "primitive/string"}

      %% type-system bootstrap (3)
      {Fl St Local "system/type" {M [{P "name" {Ref "system/type/name"}} {P "extends" {RefO "system/type/name"}} {P "fields" {MapO "system/type/field-spec"}} {P "layout" {ArrO "primitive/string"}}]}}
      {Fl St Local "system/type/field-spec"
       {M [{P "type_ref" {RefO "system/type/name"}} {P "optional" {RefO "primitive/bool"}}
           {P "array_of" {RefO "system/type/field-spec"}} {P "map_of" {RefO "system/type/field-spec"}}
           {P "key_type" {RefO "system/type/name"}} {P "union_of" {ArrO "system/type/field-spec"}}
           {P "byte_size" {RefO "primitive/uint"}} {P "default" {RefO "primitive/any"}}
           {P "constraints" {ArrO "core/entity"}}]}}
      {Xt St Local "system/type/name" "primitive/string"}

      %% operational (4)
      {Fl St Local "system/bounds" {M [{P "ttl" {RefO "primitive/uint"}} {P "budget" {RefO "primitive/uint"}} {P "chain_id" {RefO "primitive/string"}} {P "parent_chain_id" {RefO "primitive/string"}} {P "cascade_depth" {RefO "primitive/uint"}} {P "visited" {ArrO "system/tree/path"}}]}}
      {Fl St Local "system/resource-limits" {M [{P "max_budget" {RefO "primitive/uint"}} {P "max_ttl" {RefO "primitive/uint"}} {P "max_visited_length" {RefO "primitive/uint"}}]}}
      {Fl St Local "system/delivery-spec" {M [{P "uri" {Ref "system/tree/path"}} {P "operation" {RefO "primitive/string"}}]}}
      {Nm St Local "system/deletion-marker"}
   end
end
