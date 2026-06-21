import { type EntityTree } from "../store/index.js";
import { FSpec, TypeDef } from "./type-definition.js";

/**
 * The core type registry the peer publishes at `system/type/*` (TYPE-SYSTEM
 * §8–§10). Scope is core + operational + the type-system bootstrap only — the 53
 * types of `status/S4-TYPE-SCOPE.txt`; extension vocabularies and the type
 * extension (validate/merge) are NOT published by a core peer (refined G4 / F17).
 *
 * Declared natively in code (single source of truth), rendered through the
 * byte-green codec, and diffed for content-hash equality against the Go-rendered
 * vector set (memory: type-registry-render-design / type-registry-core-vs-extension).
 */

const ref = FSpec.ref;
const array = FSpec.array;
const map = FSpec.map;
const union = FSpec.union;
const t = (name: string): TypeDef => new TypeDef(name);

function build(): TypeDef[] {
  const b: TypeDef[] = [];

  // ----- primitives (8) -----
  for (const p of ["any", "bool", "bytes", "float", "int", "null", "string", "uint"]) {
    b.push(t("primitive/" + p));
  }

  // ----- structural roots + envelopes (5) -----
  b.push(t("entity").f("type", ref("primitive/string")).f("data", ref("primitive/any")));
  b.push(
    t("core/entity")
      .f("type", ref("primitive/string"))
      .f("data", ref("primitive/any"))
      .f("content_hash", ref("system/hash")),
  );
  b.push(t("core/envelope").f("root", ref("core/entity")).f("included", map(ref("core/entity"), "system/hash").opt()));
  b.push(t("system/envelope").ext("core/envelope"));
  b.push(t("system/protocol/envelope").ext("core/envelope"));

  // ----- identity / hash / signature (4) -----
  b.push(
    t("system/hash")
      .ext("primitive/bytes")
      .f("format_code", ref("primitive/uint").size(1n))
      .f("digest", ref("primitive/bytes"))
      .lay("format_code", "digest"),
  );
  b.push(
    t("system/peer")
      .f("key_type", ref("primitive/string"))
      .f("peer_id", ref("system/peer-id"))
      .f("public_key", ref("primitive/bytes")),
  );
  b.push(t("system/peer-id").ext("primitive/string"));
  b.push(
    t("system/signature")
      .f("algorithm", ref("primitive/string"))
      .f("signature", ref("primitive/bytes"))
      .f("signer", ref("system/hash"))
      .f("target", ref("system/hash")),
  );

  // ----- protocol surface (6) -----
  b.push(
    t("system/protocol/connect/authenticate")
      .f("key_type", ref("primitive/string"))
      .f("nonce", ref("primitive/bytes"))
      .f("peer_id", ref("system/peer-id"))
      .f("public_key", ref("primitive/bytes")),
  );
  b.push(
    t("system/protocol/connect/hello")
      .f("protocols", array(ref("primitive/string")))
      .f("nonce", ref("primitive/bytes"))
      .f("peer_id", ref("system/peer-id"))
      .f("timestamp", ref("primitive/uint"))
      .f("compression", array(ref("primitive/string")).opt())
      .f("encryption", array(ref("primitive/string")).opt())
      .f("hash_formats", array(ref("primitive/string")).opt())
      .f("key_types", array(ref("primitive/string")).opt()),
  );
  b.push(
    t("system/protocol/error")
      .f("code", ref("primitive/string"))
      .f("message", ref("primitive/string").opt())
      .f("rejected_marker", ref("system/hash").opt()),
  );
  b.push(
    t("system/protocol/execute")
      .f("operation", ref("primitive/string"))
      .f("params", ref("core/entity"))
      .f("request_id", ref("primitive/string"))
      .f("uri", ref("system/tree/path"))
      .f("author", ref("system/hash").opt())
      .f("bounds", ref("system/bounds").opt())
      .f("capability", ref("system/hash").opt())
      .f("deliver_to", ref("system/delivery-spec").opt())
      .f("deliver_token", ref("system/hash").opt())
      .f("durability_request", ref("system/durability-request").opt())
      .f("resource", ref("system/protocol/resource-target").opt()),
  );
  b.push(
    t("system/protocol/execute/response")
      .f("request_id", ref("primitive/string"))
      .f("result", ref("core/entity"))
      .f("status", ref("primitive/uint"))
      .f("durability", ref("system/durability-result").opt()),
  );
  b.push(
    t("system/protocol/resource-target")
      .f("targets", array(ref("system/tree/path")))
      .f("exclude", array(ref("system/tree/path")).opt()),
  );

  // ----- capability (12) -----
  b.push(t("system/capability/grant").f("token", ref("system/hash")));
  b.push(
    t("system/capability/grant-entry")
      .f("handlers", ref("system/capability/path-scope"))
      .f("operations", ref("system/capability/id-scope"))
      .f("resources", ref("system/capability/path-scope"))
      .f("allowances", map(ref("primitive/any")).opt())
      .f("constraints", map(ref("primitive/any")).opt())
      .f("peers", ref("system/capability/id-scope").opt()),
  );
  b.push(
    t("system/capability/id-scope")
      .f("include", array(ref("primitive/string")))
      .f("exclude", array(ref("primitive/string")).opt()),
  );
  b.push(
    t("system/capability/path-scope")
      .f("include", array(ref("system/tree/path")))
      .f("exclude", array(ref("system/tree/path")).opt()),
  );
  b.push(
    t("system/capability/request")
      .f("grants", array(ref("system/capability/grant-entry")))
      .f("ttl_ms", ref("primitive/uint").opt()),
  );
  b.push(
    t("system/capability/revocation")
      .f("token", ref("system/hash"))
      .f("revoked_at", ref("primitive/uint"))
      .f("reason", ref("primitive/string").opt()),
  );
  b.push(
    t("system/capability/revoke-request")
      .f("token", ref("system/hash"))
      .f("reason", ref("primitive/string").opt()),
  );
  b.push(
    t("system/capability/delegate-request")
      .f("grants", array(ref("system/capability/grant-entry")))
      .f("parent", ref("system/hash"))
      .f("ttl_ms", ref("primitive/uint").opt()),
  );
  b.push(
    t("system/capability/delegation-caveats")
      .f("max_delegation_depth", ref("primitive/uint").opt())
      .f("max_delegation_ttl", ref("primitive/uint").opt())
      .f("no_delegation", ref("primitive/bool").opt()),
  );
  b.push(
    t("system/capability/policy-entry")
      .f("grants", array(ref("system/capability/grant-entry")))
      .f("peer_pattern", ref("primitive/string"))
      .f("notes", ref("primitive/string").opt())
      .f("ttl_ms", ref("primitive/uint").opt()),
  );
  b.push(
    t("system/capability/token")
      .f("created_at", ref("primitive/uint"))
      .f("grantee", ref("system/hash"))
      .f("granter", union(ref("system/hash"), ref("system/capability/multi-granter")))
      .f("grants", array(ref("system/capability/grant-entry")))
      .f("delegation_caveats", ref("system/capability/delegation-caveats").opt())
      .f("expires_at", ref("primitive/uint").opt())
      .f("not_before", ref("primitive/uint").opt())
      .f("parent", ref("system/hash").opt())
      .f("resource_limits", ref("system/resource-limits").opt()),
  );
  b.push(
    t("system/capability/multi-granter")
      .f("signers", array(ref("system/hash")))
      .f("threshold", ref("primitive/uint")),
  );

  // ----- handler machinery (6) -----
  b.push(
    t("system/handler")
      .f("interface", ref("system/tree/path"))
      .f("expression_path", ref("system/tree/path").opt())
      .f("internal_scope", array(ref("system/capability/grant-entry")).opt())
      .f("max_scope", array(ref("system/capability/grant-entry")).opt()),
  );
  b.push(
    t("system/handler/interface")
      .f("name", ref("primitive/string"))
      .f("operations", map(ref("system/handler/operation-spec")))
      .f("pattern", ref("system/tree/path")),
  );
  b.push(
    t("system/handler/manifest")
      .ext("system/handler/interface")
      .f("name", ref("primitive/string"))
      .f("operations", map(ref("system/handler/operation-spec")))
      .f("pattern", ref("system/tree/path"))
      .f("expression_path", ref("system/tree/path").opt())
      .f("internal_scope", array(ref("system/capability/grant-entry")).opt())
      .f("max_scope", array(ref("system/capability/grant-entry")).opt()),
  );
  b.push(
    t("system/handler/operation-spec")
      .f("input_type", ref("system/type/name").opt())
      .f("output_type", ref("system/type/name").opt()),
  );
  b.push(
    t("system/handler/register-request")
      .f("manifest", ref("system/handler/manifest"))
      .f("requested_scope", array(ref("system/capability/grant-entry")).opt())
      .f("types", map(ref("system/type")).opt()),
  );
  b.push(
    t("system/handler/register-result")
      .f("grant", ref("system/capability/token"))
      .f("pattern", ref("system/tree/path")),
  );

  // ----- tree (5) -----
  b.push(
    t("system/tree/get-request")
      .f("limit", ref("primitive/uint").opt())
      .f("mode", ref("primitive/string").opt())
      .f("offset", ref("primitive/uint").opt())
      .f("tree_id", ref("primitive/string").opt()),
  );
  b.push(
    t("system/tree/put-request")
      .f("entity", ref("core/entity").opt())
      .f("expected_hash", ref("system/hash").opt())
      .f("tree_id", ref("primitive/string").opt()),
  );
  b.push(
    t("system/tree/listing")
      .f("count", ref("primitive/uint"))
      .f("entries", map(ref("system/tree/listing-entry")))
      .f("offset", ref("primitive/uint"))
      .f("path", ref("system/tree/path"))
      .f("next_page", ref("system/hash").opt()),
  );
  b.push(
    t("system/tree/listing-entry")
      .f("has_children", ref("primitive/bool"))
      .f("hash", ref("system/hash").opt()),
  );
  b.push(t("system/tree/path").ext("primitive/string"));

  // ----- type-system bootstrap (3) -----
  b.push(
    t("system/type")
      .f("name", ref("system/type/name"))
      .f("extends", ref("system/type/name").opt())
      .f("fields", map(ref("system/type/field-spec")).opt())
      .f("layout", array(ref("primitive/string")).opt())
      .f("type_args", map(ref("system/type/name")).opt())
      .f("type_params", array(ref("primitive/string")).opt()),
  );
  b.push(
    t("system/type/field-spec")
      .f("type_ref", ref("system/type/name").opt())
      .f("optional", ref("primitive/bool").opt())
      .f("array_of", ref("system/type/field-spec").opt())
      .f("map_of", ref("system/type/field-spec").opt())
      .f("union_of", array(ref("system/type/field-spec")).opt())
      .f("key_type", ref("system/type/name").opt())
      .f("byte_size", ref("primitive/uint").opt())
      .f("type_param", ref("primitive/string").opt())
      .f("type_args", map(ref("system/type/name")).opt())
      .f("default", ref("primitive/any").opt())
      .f("constraints", array(ref("core/entity")).opt()),
  );
  b.push(t("system/type/name").ext("primitive/string"));

  // ----- operational (4) -----
  b.push(
    t("system/bounds")
      .f("budget", ref("primitive/uint").opt())
      .f("cascade_depth", ref("primitive/uint").opt())
      .f("chain_id", ref("primitive/string").opt())
      .f("parent_chain_id", ref("primitive/string").opt())
      .f("ttl", ref("primitive/uint").opt())
      .f("visited", array(ref("system/tree/path")).opt()),
  );
  b.push(
    t("system/resource-limits")
      .f("max_budget", ref("primitive/uint").opt())
      .f("max_ttl", ref("primitive/uint").opt())
      .f("max_visited_length", ref("primitive/uint").opt()),
  );
  b.push(
    t("system/delivery-spec").f("operation", ref("primitive/string")).f("uri", ref("system/tree/path")),
  );
  b.push(t("system/deletion-marker"));

  return b;
}

/** The 53 core type definitions, in declaration order. */
export const ALL_CORE_TYPES: readonly TypeDef[] = build();

/** Seed every core type entity into the tree at `system/type/<name>`. */
export function seedCoreTypes(tree: EntityTree, localPeerId: string): void {
  for (const def of ALL_CORE_TYPES) {
    tree.put("/" + localPeerId + "/" + def.treePath, def.toEntity());
  }
}
