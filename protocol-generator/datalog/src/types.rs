//! types.rs — the core type registry the peer publishes at `system/type/*`
//! (TYPE-SYSTEM §8–§10; the V7 v7.72 §9.5 53-type Core Type Floor).
//!
//! Per the durable keystone lesson ("Type registry: render natively, don't ingest
//! bytes"): the 53 core type definitions are declared NATIVELY here (single source
//! of truth in code), rendered through the byte-green C-ABI codec into `system/type`
//! entities, and seeded into the tree at `system/type/<name>`. The Go-rendered
//! vector set (`shared/test-vectors/v0.8.0/type-registry-shapes.json`) is the
//! byte-exact drift target — NOT a byte source we echo.
//!
//! Scope is core + operational + the type-system bootstrap ONLY. A core peer never
//! pre-publishes extension vocabularies (compute/*, role/*, tree extension ops, …);
//! those types WARN under `--profile core` (matched-if-present, not-a-FAIL-if-absent)
//! and arrive with their handler when a community installs the extension.

use crate::cbor_host::{self, Key, Value};
use crate::model::Entity;

/// A field spec inside a [`TypeDef`] — the `system/type/field-spec` shape
/// (TYPE-SYSTEM §4.2). Exactly one structural carrier is set (a `type_ref`, an
/// `array_of`, a `map_of`, or a `union_of`). Rendered omit-empty so the CBOR is
/// byte-identical to the Go reference encoder (absent/false/zero drops the key).
#[derive(Clone)]
pub struct FSpec {
    type_ref: Option<String>,
    optional: bool,
    array_of: Option<Box<FSpec>>,
    map_of: Option<Box<FSpec>>,
    union_of: Option<Vec<FSpec>>,
    key_type: Option<String>,
    byte_size: Option<u64>,
}

impl FSpec {
    fn empty() -> FSpec {
        FSpec {
            type_ref: None,
            optional: false,
            array_of: None,
            map_of: None,
            union_of: None,
            key_type: None,
            byte_size: None,
        }
    }
    fn reff(t: &str) -> FSpec {
        FSpec {
            type_ref: Some(t.into()),
            ..FSpec::empty()
        }
    }
    fn array(el: FSpec) -> FSpec {
        FSpec {
            array_of: Some(Box::new(el)),
            ..FSpec::empty()
        }
    }
    fn map_of(v: FSpec) -> FSpec {
        FSpec {
            map_of: Some(Box::new(v)),
            ..FSpec::empty()
        }
    }
    fn map_kt(v: FSpec, kt: &str) -> FSpec {
        FSpec {
            map_of: Some(Box::new(v)),
            key_type: Some(kt.into()),
            ..FSpec::empty()
        }
    }
    fn union(vs: Vec<FSpec>) -> FSpec {
        FSpec {
            union_of: Some(vs),
            ..FSpec::empty()
        }
    }
    fn opt(mut self) -> FSpec {
        self.optional = true;
        self
    }
    fn size(mut self, bytes: u64) -> FSpec {
        self.byte_size = Some(bytes);
        self
    }

    /// Render to the ECF data map (omit-empty; the FFI canonicalizer sorts keys).
    fn to_data(&self) -> Value {
        let mut m: Vec<(Key, Value)> = vec![];
        if let Some(t) = &self.type_ref {
            m.push((Key::Text("type_ref".into()), cbor_host::text(t)));
        }
        if self.optional {
            m.push((Key::Text("optional".into()), Value::Bool(true)));
        }
        if let Some(a) = &self.array_of {
            m.push((Key::Text("array_of".into()), a.to_data()));
        }
        if let Some(mp) = &self.map_of {
            m.push((Key::Text("map_of".into()), mp.to_data()));
        }
        if let Some(u) = &self.union_of {
            m.push((
                Key::Text("union_of".into()),
                Value::Array(u.iter().map(|x| x.to_data()).collect()),
            ));
        }
        if let Some(kt) = &self.key_type {
            m.push((Key::Text("key_type".into()), cbor_host::text(kt)));
        }
        if let Some(bs) = &self.byte_size {
            m.push((Key::Text("byte_size".into()), Value::UInt(*bs)));
        }
        Value::Map(m)
    }
}

/// A core type definition — the data payload of a `system/type` entity
/// (TYPE-SYSTEM §4.1). A fluent builder; rendered natively via [`Self::to_entity`].
pub struct TypeDef {
    name: String,
    extends: Option<String>,
    fields: Vec<(String, FSpec)>,
    layout: Option<Vec<String>>,
}

impl TypeDef {
    fn new(name: &str) -> TypeDef {
        TypeDef {
            name: name.into(),
            extends: None,
            fields: vec![],
            layout: None,
        }
    }
    fn ext(mut self, e: &str) -> TypeDef {
        self.extends = Some(e.into());
        self
    }
    fn f(mut self, key: &str, spec: FSpec) -> TypeDef {
        self.fields.push((key.into(), spec));
        self
    }
    fn lay(mut self, layout: &[&str]) -> TypeDef {
        self.layout = Some(layout.iter().map(|s| s.to_string()).collect());
        self
    }

    /// Location-index path: `system/type/<name>`.
    pub fn tree_path(&self) -> String {
        format!("system/type/{}", self.name)
    }

    fn to_data(&self) -> Value {
        let mut m: Vec<(Key, Value)> =
            vec![(Key::Text("name".into()), cbor_host::text(&self.name))];
        if let Some(e) = &self.extends {
            m.push((Key::Text("extends".into()), cbor_host::text(e)));
        }
        if !self.fields.is_empty() {
            let fm: Vec<(Key, Value)> = self
                .fields
                .iter()
                .map(|(k, s)| (Key::Text(k.clone()), s.to_data()))
                .collect();
            m.push((Key::Text("fields".into()), Value::Map(fm)));
        }
        if let Some(l) = &self.layout {
            if !l.is_empty() {
                m.push((
                    Key::Text("layout".into()),
                    Value::Array(l.iter().map(|s| cbor_host::text(s)).collect()),
                ));
            }
        }
        Value::Map(m)
    }

    pub fn to_entity(&self) -> Entity {
        Entity::make("system/type", self.to_data())
    }
}

/// The 53 core type definitions, in declaration order (mirrors the reference
/// registry; scope = core + operational + the type-system bootstrap).
pub fn all_core_types() -> Vec<TypeDef> {
    let reff = FSpec::reff;
    let array = FSpec::array;
    let map_of = FSpec::map_of;
    let map_kt = FSpec::map_kt;
    let union = FSpec::union;
    let t = TypeDef::new;
    let mut b: Vec<TypeDef> = vec![];

    // ----- primitives (8) -----
    for p in [
        "any", "bool", "bytes", "float", "int", "null", "string", "uint",
    ] {
        b.push(t(&format!("primitive/{p}")));
    }

    // ----- structural roots + envelopes (5) -----
    b.push(
        t("entity")
            .f("type", reff("primitive/string"))
            .f("data", reff("primitive/any")),
    );
    b.push(
        t("core/entity")
            .f("type", reff("primitive/string"))
            .f("data", reff("primitive/any"))
            .f("content_hash", reff("system/hash")),
    );
    b.push(
        t("core/envelope")
            .f("root", reff("core/entity"))
            .f("included", map_kt(reff("core/entity"), "system/hash").opt()),
    );
    b.push(t("system/envelope").ext("core/envelope"));
    b.push(t("system/protocol/envelope").ext("core/envelope"));

    // ----- identity / hash / signature (4) -----
    b.push(
        t("system/hash")
            .ext("primitive/bytes")
            .f("format_code", reff("primitive/uint").size(1))
            .f("digest", reff("primitive/bytes"))
            .lay(&["format_code", "digest"]),
    );
    b.push(
        t("system/peer")
            .f("key_type", reff("primitive/string"))
            .f("peer_id", reff("system/peer-id"))
            .f("public_key", reff("primitive/bytes")),
    );
    b.push(t("system/peer-id").ext("primitive/string"));
    b.push(
        t("system/signature")
            .f("algorithm", reff("primitive/string"))
            .f("signature", reff("primitive/bytes"))
            .f("signer", reff("system/hash"))
            .f("target", reff("system/hash")),
    );

    // ----- protocol surface (6) -----
    b.push(
        t("system/protocol/connect/authenticate")
            .f("key_type", reff("primitive/string"))
            .f("nonce", reff("primitive/bytes"))
            .f("peer_id", reff("system/peer-id"))
            .f("public_key", reff("primitive/bytes")),
    );
    b.push(
        t("system/protocol/connect/hello")
            .f("protocols", array(reff("primitive/string")))
            .f("nonce", reff("primitive/bytes"))
            .f("peer_id", reff("system/peer-id"))
            .f("timestamp", reff("primitive/uint"))
            .f("compression", array(reff("primitive/string")).opt())
            .f("encryption", array(reff("primitive/string")).opt())
            .f("hash_formats", array(reff("primitive/string")).opt())
            .f("key_types", array(reff("primitive/string")).opt()),
    );
    b.push(
        t("system/protocol/error")
            .f("code", reff("primitive/string"))
            .f("message", reff("primitive/string").opt())
            .f("rejected_marker", reff("system/hash").opt()),
    );
    b.push(
        t("system/protocol/execute")
            .f("operation", reff("primitive/string"))
            .f("params", reff("core/entity"))
            .f("request_id", reff("primitive/string"))
            .f("uri", reff("system/tree/path"))
            .f("author", reff("system/hash").opt())
            .f("bounds", reff("system/bounds").opt())
            .f("capability", reff("system/hash").opt())
            .f("deliver_to", reff("system/delivery-spec").opt())
            .f("deliver_token", reff("system/hash").opt())
            .f(
                "durability_request",
                reff("system/durability-request").opt(),
            )
            .f("resource", reff("system/protocol/resource-target").opt()),
    );
    b.push(
        t("system/protocol/execute/response")
            .f("request_id", reff("primitive/string"))
            .f("result", reff("core/entity"))
            .f("status", reff("primitive/uint"))
            .f("durability", reff("system/durability-result").opt()),
    );
    b.push(
        t("system/protocol/resource-target")
            .f("targets", array(reff("system/tree/path")))
            .f("exclude", array(reff("system/tree/path")).opt()),
    );

    // ----- capability (12) -----
    b.push(t("system/capability/grant").f("token", reff("system/hash")));
    b.push(
        t("system/capability/grant-entry")
            .f("handlers", reff("system/capability/path-scope"))
            .f("operations", reff("system/capability/id-scope"))
            .f("resources", reff("system/capability/path-scope"))
            .f("allowances", map_of(reff("primitive/any")).opt())
            .f("constraints", map_of(reff("primitive/any")).opt())
            .f("peers", reff("system/capability/id-scope").opt()),
    );
    b.push(
        t("system/capability/id-scope")
            .f("include", array(reff("primitive/string")))
            .f("exclude", array(reff("primitive/string")).opt()),
    );
    b.push(
        t("system/capability/path-scope")
            .f("include", array(reff("system/tree/path")))
            .f("exclude", array(reff("system/tree/path")).opt()),
    );
    b.push(
        t("system/capability/request")
            .f("grants", array(reff("system/capability/grant-entry")))
            .f("ttl_ms", reff("primitive/uint").opt()),
    );
    b.push(
        t("system/capability/revocation")
            .f("token", reff("system/hash"))
            .f("revoked_at", reff("primitive/uint"))
            .f("reason", reff("primitive/string").opt()),
    );
    b.push(
        t("system/capability/revoke-request")
            .f("token", reff("system/hash"))
            .f("reason", reff("primitive/string").opt()),
    );
    b.push(
        t("system/capability/delegate-request")
            .f("grants", array(reff("system/capability/grant-entry")))
            .f("parent", reff("system/hash"))
            .f("ttl_ms", reff("primitive/uint").opt()),
    );
    b.push(
        t("system/capability/delegation-caveats")
            .f("max_delegation_depth", reff("primitive/uint").opt())
            .f("max_delegation_ttl", reff("primitive/uint").opt())
            .f("no_delegation", reff("primitive/bool").opt()),
    );
    b.push(
        t("system/capability/policy-entry")
            .f("grants", array(reff("system/capability/grant-entry")))
            .f("peer_pattern", reff("primitive/string"))
            .f("notes", reff("primitive/string").opt())
            .f("ttl_ms", reff("primitive/uint").opt()),
    );
    b.push(
        t("system/capability/token")
            .f("created_at", reff("primitive/uint"))
            .f("grantee", reff("system/hash"))
            .f(
                "granter",
                union(vec![
                    reff("system/hash"),
                    reff("system/capability/multi-granter"),
                ]),
            )
            .f("grants", array(reff("system/capability/grant-entry")))
            .f(
                "delegation_caveats",
                reff("system/capability/delegation-caveats").opt(),
            )
            .f("expires_at", reff("primitive/uint").opt())
            .f("not_before", reff("primitive/uint").opt())
            .f("parent", reff("system/hash").opt())
            .f("resource_limits", reff("system/resource-limits").opt()),
    );
    b.push(
        t("system/capability/multi-granter")
            .f("signers", array(reff("system/hash")))
            .f("threshold", reff("primitive/uint")),
    );

    // ----- handler machinery (6) -----
    b.push(
        t("system/handler")
            .f("interface", reff("system/tree/path"))
            .f("expression_path", reff("system/tree/path").opt())
            .f(
                "internal_scope",
                array(reff("system/capability/grant-entry")).opt(),
            )
            .f(
                "max_scope",
                array(reff("system/capability/grant-entry")).opt(),
            ),
    );
    b.push(
        t("system/handler/interface")
            .f("name", reff("primitive/string"))
            .f("operations", map_of(reff("system/handler/operation-spec")))
            .f("pattern", reff("system/tree/path")),
    );
    b.push(
        t("system/handler/manifest")
            .ext("system/handler/interface")
            .f("name", reff("primitive/string"))
            .f("operations", map_of(reff("system/handler/operation-spec")))
            .f("pattern", reff("system/tree/path"))
            .f("expression_path", reff("system/tree/path").opt())
            .f(
                "internal_scope",
                array(reff("system/capability/grant-entry")).opt(),
            )
            .f(
                "max_scope",
                array(reff("system/capability/grant-entry")).opt(),
            ),
    );
    b.push(
        t("system/handler/operation-spec")
            .f("input_type", reff("system/type/name").opt())
            .f("output_type", reff("system/type/name").opt()),
    );
    b.push(
        t("system/handler/register-request")
            .f("manifest", reff("system/handler/manifest"))
            .f(
                "requested_scope",
                array(reff("system/capability/grant-entry")).opt(),
            )
            .f("types", map_of(reff("system/type")).opt()),
    );
    b.push(
        t("system/handler/register-result")
            .f("grant", reff("system/capability/token"))
            .f("pattern", reff("system/tree/path")),
    );

    // ----- tree (5) -----
    b.push(
        t("system/tree/get-request")
            .f("limit", reff("primitive/uint").opt())
            .f("mode", reff("primitive/string").opt())
            .f("offset", reff("primitive/uint").opt())
            .f("tree_id", reff("primitive/string").opt()),
    );
    b.push(
        t("system/tree/put-request")
            .f("entity", reff("core/entity").opt())
            .f("expected_hash", reff("system/hash").opt())
            .f("tree_id", reff("primitive/string").opt()),
    );
    b.push(
        t("system/tree/listing")
            .f("count", reff("primitive/uint"))
            .f("entries", map_of(reff("system/tree/listing-entry")))
            .f("offset", reff("primitive/uint"))
            .f("path", reff("system/tree/path"))
            .f("next_page", reff("system/hash").opt()),
    );
    b.push(
        t("system/tree/listing-entry")
            .f("has_children", reff("primitive/bool"))
            .f("hash", reff("system/hash").opt()),
    );
    b.push(t("system/tree/path").ext("primitive/string"));

    // ----- type-system bootstrap (3) -----
    b.push(
        t("system/type")
            .f("name", reff("system/type/name"))
            .f("extends", reff("system/type/name").opt())
            .f("fields", map_of(reff("system/type/field-spec")).opt())
            .f("layout", array(reff("primitive/string")).opt())
            .f("type_args", map_of(reff("system/type/name")).opt())
            .f("type_params", array(reff("primitive/string")).opt()),
    );
    b.push(
        t("system/type/field-spec")
            .f("type_ref", reff("system/type/name").opt())
            .f("optional", reff("primitive/bool").opt())
            .f("array_of", reff("system/type/field-spec").opt())
            .f("map_of", reff("system/type/field-spec").opt())
            .f("union_of", array(reff("system/type/field-spec")).opt())
            .f("key_type", reff("system/type/name").opt())
            .f("byte_size", reff("primitive/uint").opt())
            .f("type_param", reff("primitive/string").opt())
            .f("type_args", map_of(reff("system/type/name")).opt())
            .f("default", reff("primitive/any").opt())
            .f("constraints", array(reff("core/entity")).opt()),
    );
    b.push(t("system/type/name").ext("primitive/string"));

    // ----- operational (4) -----
    b.push(
        t("system/bounds")
            .f("budget", reff("primitive/uint").opt())
            .f("cascade_depth", reff("primitive/uint").opt())
            .f("chain_id", reff("primitive/string").opt())
            .f("parent_chain_id", reff("primitive/string").opt())
            .f("ttl", reff("primitive/uint").opt())
            .f("visited", array(reff("system/tree/path")).opt()),
    );
    b.push(
        t("system/resource-limits")
            .f("max_budget", reff("primitive/uint").opt())
            .f("max_ttl", reff("primitive/uint").opt())
            .f("max_visited_length", reff("primitive/uint").opt()),
    );
    b.push(
        t("system/delivery-spec")
            .f("operation", reff("primitive/string"))
            .f("uri", reff("system/tree/path")),
    );
    b.push(t("system/deletion-marker"));

    b
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_floor_is_53_types() {
        assert_eq!(all_core_types().len(), 53);
    }

    #[test]
    fn primitive_any_is_bare_name_only() {
        let types = all_core_types();
        let any = types.iter().find(|d| d.name == "primitive/any").unwrap();
        // A bare primitive renders as just {name}; the FFI hash is stable + 33 bytes.
        let e = any.to_entity();
        assert_eq!(e.typ, "system/type");
        assert_eq!(e.hash.len(), 33);
        assert_eq!(
            cbor_host::map_get(&e.data, "name"),
            Some(&cbor_host::text("primitive/any"))
        );
        assert!(cbor_host::map_get(&e.data, "fields").is_none());
    }

    #[test]
    fn tree_path_maps_name_to_segments() {
        assert_eq!(
            TypeDef::new("primitive/any").tree_path(),
            "system/type/primitive/any"
        );
    }
}
