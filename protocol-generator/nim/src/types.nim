## The core type registry the peer publishes at `system/type/*` (TYPE-SYSTEM
## §8–§10). Scope is core + operational + the type-system bootstrap only — the 53
## floor types (§9.5); a core peer does NOT pre-publish extension vocabularies.
##
## Declared NATIVELY in code (single source of truth), rendered through this peer's
## own byte-green ECF codec, and diffed for content-hash equality against the
## Go-rendered vector set (shared/test-vectors/v0.8.0/type-registry-vectors-v1.diag)
## — the S8 drift target (AGENTS.md "render from the model, don't ingest bytes").
## Ported field-for-field from the cohort reference (TS core-type-registry.ts).
##
## Each field is omit-empty: an absent/false/zero carrier drops the key, so the
## rendered CBOR is byte-identical to the Go reference encoder.
##
## SPDX-License-Identifier: Apache-2.0

import ./ecf
import ./model
import ./store

# ── field spec (system/type/field-spec) ────────────────────────────────────────

type FSpec = ref object
  typeRef: string
  optional: bool
  arrayOf: FSpec
  mapOf: FSpec
  unionOf: seq[FSpec]
  keyType: string
  byteSize: uint64
  hasByteSize: bool

proc fref(typeRef: string): FSpec = FSpec(typeRef: typeRef)
proc farray(element: FSpec): FSpec = FSpec(arrayOf: element)
proc fmap(value: FSpec; keyType = ""): FSpec = FSpec(mapOf: value, keyType: keyType)
proc funion(variants: varargs[FSpec]): FSpec = FSpec(unionOf: @variants)
proc opt(s: FSpec): FSpec = s.optional = true; s
proc size(s: FSpec; n: uint64): FSpec = s.byteSize = n; s.hasByteSize = true; s

proc toData(s: FSpec): EcValue =
  var pairs: seq[EcPair]
  if s.typeRef.len > 0: pairs.add EcPair(key: textV("type_ref"), val: textV(s.typeRef))
  if s.optional: pairs.add EcPair(key: textV("optional"), val: boolV(true))
  if s.arrayOf != nil: pairs.add EcPair(key: textV("array_of"), val: s.arrayOf.toData())
  if s.mapOf != nil: pairs.add EcPair(key: textV("map_of"), val: s.mapOf.toData())
  if s.unionOf.len > 0:
    var arr: seq[EcValue]
    for u in s.unionOf: arr.add u.toData()
    pairs.add EcPair(key: textV("union_of"), val: arrV(arr))
  if s.keyType.len > 0: pairs.add EcPair(key: textV("key_type"), val: textV(s.keyType))
  if s.hasByteSize: pairs.add EcPair(key: textV("byte_size"), val: uintV(s.byteSize))
  mapV(pairs)

# ── type definition (system/type) ──────────────────────────────────────────────

type TypeDef = ref object
  name: string
  extends: string
  fields: seq[tuple[k: string, spec: FSpec]]
  layout: seq[string]

proc t(name: string): TypeDef = TypeDef(name: name)
proc ext(d: TypeDef; e: string): TypeDef = d.extends = e; d
proc f(d: TypeDef; key: string; spec: FSpec): TypeDef = d.fields.add((key, spec)); d
proc lay(d: TypeDef; parts: varargs[string]): TypeDef = d.layout = @parts; d

proc toData(d: TypeDef): EcValue =
  var pairs = @[EcPair(key: textV("name"), val: textV(d.name))]
  if d.extends.len > 0: pairs.add EcPair(key: textV("extends"), val: textV(d.extends))
  if d.fields.len > 0:
    var fp: seq[EcPair]
    for fld in d.fields: fp.add EcPair(key: textV(fld.k), val: fld.spec.toData())
    pairs.add EcPair(key: textV("fields"), val: mapV(fp))
  if d.layout.len > 0:
    var arr: seq[EcValue]
    for l in d.layout: arr.add textV(l)
    pairs.add EcPair(key: textV("layout"), val: arrV(arr))
  mapV(pairs)

proc toEntity(d: TypeDef): Entity = makeEntity("system/type", d.toData())

# ── the 53 core type definitions (declaration order per the reference) ──────────

proc buildCoreTypes(): seq[TypeDef] =
  # primitives (8)
  for p in ["any", "bool", "bytes", "float", "int", "null", "string", "uint"]:
    result.add t("primitive/" & p)
  # structural roots + envelopes (5)
  result.add t("entity").f("type", fref("primitive/string")).f("data", fref("primitive/any"))
  result.add t("core/entity").f("type", fref("primitive/string")).f("data", fref("primitive/any"))
    .f("content_hash", fref("system/hash"))
  result.add t("core/envelope").f("root", fref("core/entity"))
    .f("included", fmap(fref("core/entity"), "system/hash").opt())
  result.add t("system/envelope").ext("core/envelope")
  result.add t("system/protocol/envelope").ext("core/envelope")
  # identity / hash / signature (4)
  result.add t("system/hash").ext("primitive/bytes")
    .f("format_code", fref("primitive/uint").size(1)).f("digest", fref("primitive/bytes"))
    .lay("format_code", "digest")
  result.add t("system/peer").f("key_type", fref("primitive/string"))
    .f("peer_id", fref("system/peer-id")).f("public_key", fref("primitive/bytes"))
  result.add t("system/peer-id").ext("primitive/string")
  result.add t("system/signature").f("algorithm", fref("primitive/string"))
    .f("signature", fref("primitive/bytes")).f("signer", fref("system/hash"))
    .f("target", fref("system/hash"))
  # protocol surface (6)
  result.add t("system/protocol/connect/authenticate").f("key_type", fref("primitive/string"))
    .f("nonce", fref("primitive/bytes")).f("peer_id", fref("system/peer-id"))
    .f("public_key", fref("primitive/bytes"))
  result.add t("system/protocol/connect/hello").f("protocols", farray(fref("primitive/string")))
    .f("nonce", fref("primitive/bytes")).f("peer_id", fref("system/peer-id"))
    .f("timestamp", fref("primitive/uint"))
    .f("compression", farray(fref("primitive/string")).opt())
    .f("encryption", farray(fref("primitive/string")).opt())
    .f("hash_formats", farray(fref("primitive/string")).opt())
    .f("key_types", farray(fref("primitive/string")).opt())
  result.add t("system/protocol/error").f("code", fref("primitive/string"))
    .f("message", fref("primitive/string").opt()).f("rejected_marker", fref("system/hash").opt())
  result.add t("system/protocol/execute").f("operation", fref("primitive/string"))
    .f("params", fref("core/entity")).f("request_id", fref("primitive/string"))
    .f("uri", fref("system/tree/path")).f("author", fref("system/hash").opt())
    .f("bounds", fref("system/bounds").opt()).f("capability", fref("system/hash").opt())
    .f("deliver_to", fref("system/delivery-spec").opt()).f("deliver_token", fref("system/hash").opt())
    .f("durability_request", fref("system/durability-request").opt())
    .f("resource", fref("system/protocol/resource-target").opt())
  result.add t("system/protocol/execute/response").f("request_id", fref("primitive/string"))
    .f("result", fref("core/entity")).f("status", fref("primitive/uint"))
    .f("durability", fref("system/durability-result").opt())
  result.add t("system/protocol/resource-target").f("targets", farray(fref("system/tree/path")))
    .f("exclude", farray(fref("system/tree/path")).opt())
  # capability (12)
  result.add t("system/capability/grant").f("token", fref("system/hash"))
  result.add t("system/capability/grant-entry")
    .f("handlers", fref("system/capability/path-scope"))
    .f("operations", fref("system/capability/id-scope"))
    .f("resources", fref("system/capability/path-scope"))
    .f("allowances", fmap(fref("primitive/any")).opt())
    .f("constraints", fmap(fref("primitive/any")).opt())
    .f("peers", fref("system/capability/id-scope").opt())
  result.add t("system/capability/id-scope").f("include", farray(fref("primitive/string")))
    .f("exclude", farray(fref("primitive/string")).opt())
  result.add t("system/capability/path-scope").f("include", farray(fref("system/tree/path")))
    .f("exclude", farray(fref("system/tree/path")).opt())
  result.add t("system/capability/request").f("grants", farray(fref("system/capability/grant-entry")))
    .f("ttl_ms", fref("primitive/uint").opt())
  result.add t("system/capability/revocation").f("token", fref("system/hash"))
    .f("revoked_at", fref("primitive/uint")).f("reason", fref("primitive/string").opt())
  result.add t("system/capability/revoke-request").f("token", fref("system/hash"))
    .f("reason", fref("primitive/string").opt())
  result.add t("system/capability/delegate-request").f("grants", farray(fref("system/capability/grant-entry")))
    .f("parent", fref("system/hash")).f("ttl_ms", fref("primitive/uint").opt())
  result.add t("system/capability/delegation-caveats")
    .f("max_delegation_depth", fref("primitive/uint").opt())
    .f("max_delegation_ttl", fref("primitive/uint").opt())
    .f("no_delegation", fref("primitive/bool").opt())
  result.add t("system/capability/policy-entry").f("grants", farray(fref("system/capability/grant-entry")))
    .f("peer_pattern", fref("primitive/string")).f("notes", fref("primitive/string").opt())
    .f("ttl_ms", fref("primitive/uint").opt())
  result.add t("system/capability/token").f("created_at", fref("primitive/uint"))
    .f("grantee", fref("system/hash"))
    .f("granter", funion(fref("system/hash"), fref("system/capability/multi-granter")))
    .f("grants", farray(fref("system/capability/grant-entry")))
    .f("delegation_caveats", fref("system/capability/delegation-caveats").opt())
    .f("expires_at", fref("primitive/uint").opt()).f("not_before", fref("primitive/uint").opt())
    .f("parent", fref("system/hash").opt()).f("resource_limits", fref("system/resource-limits").opt())
  result.add t("system/capability/multi-granter").f("signers", farray(fref("system/hash")))
    .f("threshold", fref("primitive/uint"))
  # handler machinery (6)
  result.add t("system/handler").f("interface", fref("system/tree/path"))
    .f("expression_path", fref("system/tree/path").opt())
    .f("internal_scope", farray(fref("system/capability/grant-entry")).opt())
    .f("max_scope", farray(fref("system/capability/grant-entry")).opt())
  result.add t("system/handler/interface").f("name", fref("primitive/string"))
    .f("operations", fmap(fref("system/handler/operation-spec"))).f("pattern", fref("system/tree/path"))
  result.add t("system/handler/manifest").ext("system/handler/interface")
    .f("name", fref("primitive/string")).f("operations", fmap(fref("system/handler/operation-spec")))
    .f("pattern", fref("system/tree/path")).f("expression_path", fref("system/tree/path").opt())
    .f("internal_scope", farray(fref("system/capability/grant-entry")).opt())
    .f("max_scope", farray(fref("system/capability/grant-entry")).opt())
  result.add t("system/handler/operation-spec").f("input_type", fref("system/type/name").opt())
    .f("output_type", fref("system/type/name").opt())
  result.add t("system/handler/register-request").f("manifest", fref("system/handler/manifest"))
    .f("requested_scope", farray(fref("system/capability/grant-entry")).opt())
    .f("types", fmap(fref("system/type")).opt())
  result.add t("system/handler/register-result").f("grant", fref("system/capability/token"))
    .f("pattern", fref("system/tree/path"))
  # tree (5)
  result.add t("system/tree/get-request").f("limit", fref("primitive/uint").opt())
    .f("mode", fref("primitive/string").opt()).f("offset", fref("primitive/uint").opt())
    .f("tree_id", fref("primitive/string").opt())
  result.add t("system/tree/put-request").f("entity", fref("core/entity").opt())
    .f("expected_hash", fref("system/hash").opt()).f("tree_id", fref("primitive/string").opt())
  result.add t("system/tree/listing").f("count", fref("primitive/uint"))
    .f("entries", fmap(fref("system/tree/listing-entry"))).f("offset", fref("primitive/uint"))
    .f("path", fref("system/tree/path")).f("next_page", fref("system/hash").opt())
  result.add t("system/tree/listing-entry").f("has_children", fref("primitive/bool"))
    .f("hash", fref("system/hash").opt())
  result.add t("system/tree/path").ext("primitive/string")
  # type-system bootstrap (3)
  result.add t("system/type").f("name", fref("system/type/name"))
    .f("extends", fref("system/type/name").opt())
    .f("fields", fmap(fref("system/type/field-spec")).opt())
    .f("layout", farray(fref("primitive/string")).opt())
    .f("type_args", fmap(fref("system/type/name")).opt())
    .f("type_params", farray(fref("primitive/string")).opt())
  result.add t("system/type/field-spec").f("type_ref", fref("system/type/name").opt())
    .f("optional", fref("primitive/bool").opt()).f("array_of", fref("system/type/field-spec").opt())
    .f("map_of", fref("system/type/field-spec").opt())
    .f("union_of", farray(fref("system/type/field-spec")).opt())
    .f("key_type", fref("system/type/name").opt()).f("byte_size", fref("primitive/uint").opt())
    .f("type_param", fref("primitive/string").opt()).f("type_args", fmap(fref("system/type/name")).opt())
    .f("default", fref("primitive/any").opt()).f("constraints", farray(fref("core/entity")).opt())
  result.add t("system/type/name").ext("primitive/string")
  # operational (4)
  result.add t("system/bounds").f("budget", fref("primitive/uint").opt())
    .f("cascade_depth", fref("primitive/uint").opt()).f("chain_id", fref("primitive/string").opt())
    .f("parent_chain_id", fref("primitive/string").opt()).f("ttl", fref("primitive/uint").opt())
    .f("visited", farray(fref("system/tree/path")).opt())
  result.add t("system/resource-limits").f("max_budget", fref("primitive/uint").opt())
    .f("max_ttl", fref("primitive/uint").opt()).f("max_visited_length", fref("primitive/uint").opt())
  result.add t("system/delivery-spec").f("operation", fref("primitive/string"))
    .f("uri", fref("system/tree/path"))
  result.add t("system/deletion-marker")

let coreTypes = buildCoreTypes()

proc typeEntity*(name: string): Entity =
  ## The system/type entity for a core type name (used by the register `types` map
  ## default). Returns a bare {name} type when the name is not a core floor type.
  for d in coreTypes:
    if d.name == name: return d.toEntity()
  makeEntity("system/type", mapV(@[EcPair(key: textV("name"), val: textV(name))]))

proc seedCoreTypes*(s: Store; localPeerId: string) =
  ## Bind every core type entity into the tree at `/{peer}/system/type/<name>`.
  for d in coreTypes:
    s.bindAt("/" & localPeerId & "/system/type/" & d.name, d.toEntity())
