//! Core type floor (V7 §9.5) — render-from-model.
//!
//! The peer publishes its 53 core `system/type/<name>` entities at
//! `/{peer}/system/type/{name}`. Each type's data is rendered NATIVELY from an
//! in-code declaration (the single source of truth) through the byte-green S2
//! codec; the resulting content_hash is byte-identical to the Go-rendered
//! `type-registry-vectors-v1.cbor` set (the cohort drift target — every peer
//! diffs against it). This is the render-from-model design the whole cohort
//! follows (mirrors the Zig type_defs / C# CoreTypeRegistry / OCaml
//! type_defs_data).
//!
//! Scope is core + operational + type-system bootstrap ONLY — 53 types. Extension
//! vocabularies (compute/*, content/*, subscription/*, …) are NOT published by a
//! core peer. The oracle's type_system category matches the 53 floor as a hard
//! FAIL gate and WARNs (matched-if-present) on the non-floor types it also probes.
//!
//! Omit-empty semantics: an absent/false/zero field drops the key, so the rendered
//! ECF map is byte-identical to the Go reference encoder. The codec sorts map keys
//! canonically (RFC 8949 §4.2.1), so declaration order here is irrelevant — only
//! the present key/value set matters.

use crate::value::{Key, Value};

use super::model::Entity;
use super::store::Store;

// ── FSpec — a field spec (system/type/field-spec shape) ────────────────────────

/// A field spec. Exactly one structural carrier is set (a `type_ref`, an
/// `array_of`, a `map_of`, or a `union_of`). Rendered omit-empty.
#[derive(Clone)]
enum FSpec {
    Ref(&'static str),
    Optional(Box<FSpec>),
    Sized(Box<FSpec>, u64),
    Array(Box<FSpec>),
    /// map_of value-spec + optional key_type.
    Map(Box<FSpec>, Option<&'static str>),
    Union(Vec<FSpec>),
}

impl FSpec {
    fn to_data(&self) -> Value {
        match self {
            FSpec::Ref(t) => map(vec![("type_ref", text(t))]),
            FSpec::Optional(inner) => {
                let mut v = inner.to_data();
                set_key(&mut v, "optional", Value::Bool(true));
                v
            }
            FSpec::Sized(inner, n) => {
                let mut v = inner.to_data();
                set_key(&mut v, "byte_size", Value::UInt(*n));
                v
            }
            FSpec::Array(elem) => map(vec![("array_of", elem.to_data())]),
            FSpec::Map(val, key_type) => {
                let mut pairs = vec![("map_of", val.to_data())];
                if let Some(kt) = key_type {
                    pairs.push(("key_type", text(kt)));
                }
                map(pairs)
            }
            FSpec::Union(variants) => map(vec![(
                "union_of",
                Value::Array(variants.iter().map(|v| v.to_data()).collect()),
            )]),
        }
    }
}

fn fref(t: &'static str) -> FSpec {
    FSpec::Ref(t)
}
fn opt(s: FSpec) -> FSpec {
    FSpec::Optional(Box::new(s))
}
fn sized(s: FSpec, n: u64) -> FSpec {
    FSpec::Sized(Box::new(s), n)
}
fn farray(elem: FSpec) -> FSpec {
    FSpec::Array(Box::new(elem))
}
fn fmap(val: FSpec, key_type: Option<&'static str>) -> FSpec {
    FSpec::Map(Box::new(val), key_type)
}

// ── small Value helpers (insertion order; codec re-sorts) ──────────────────────

fn text(s: &str) -> Value {
    Value::Text(s.to_string())
}
fn map(pairs: Vec<(&str, Value)>) -> Value {
    Value::Map(
        pairs
            .into_iter()
            .map(|(k, v)| (Key::Text(k.to_string()), v))
            .collect(),
    )
}
fn set_key(v: &mut Value, key: &str, val: Value) {
    if let Value::Map(entries) = v {
        entries.push((Key::Text(key.to_string()), val));
    }
}

// ── TypeDef — a core type definition (system/type entity data) ──────────────────

struct TypeDef {
    name: &'static str,
    extends: Option<&'static str>,
    fields: Vec<(&'static str, FSpec)>,
    layout: Vec<&'static str>,
}

impl TypeDef {
    fn to_data(&self) -> Value {
        let mut pairs: Vec<(Key, Value)> = vec![(Key::Text("name".into()), text(self.name))];
        if let Some(e) = self.extends {
            pairs.push((Key::Text("extends".into()), text(e)));
        }
        if !self.fields.is_empty() {
            let field_pairs: Vec<(Key, Value)> = self
                .fields
                .iter()
                .map(|(k, spec)| (Key::Text(k.to_string()), spec.to_data()))
                .collect();
            pairs.push((Key::Text("fields".into()), Value::Map(field_pairs)));
        }
        if !self.layout.is_empty() {
            pairs.push((
                Key::Text("layout".into()),
                Value::Array(self.layout.iter().map(|s| text(s)).collect()),
            ));
        }
        Value::Map(pairs)
    }

    fn to_entity(&self) -> Entity {
        Entity::make("system/type", self.to_data())
    }
}

fn def(name: &'static str) -> TypeDef {
    TypeDef {
        name,
        extends: None,
        fields: vec![],
        layout: vec![],
    }
}
fn def_fields(name: &'static str, fields: Vec<(&'static str, FSpec)>) -> TypeDef {
    TypeDef {
        name,
        extends: None,
        fields,
        layout: vec![],
    }
}
fn def_extends(name: &'static str, extends: &'static str) -> TypeDef {
    TypeDef {
        name,
        extends: Some(extends),
        fields: vec![],
        layout: vec![],
    }
}

// ── the 53 core type definitions ────────────────────────────────────────────────
//
// Faithful render of the cross-blessed cohort registry (byte-identical to the Go
// oracle / the v7.71 type-registry vector set).

fn all_types() -> Vec<TypeDef> {
    vec![
        // primitives (8)
        def("primitive/any"),
        def("primitive/bool"),
        def("primitive/bytes"),
        def("primitive/float"),
        def("primitive/int"),
        def("primitive/null"),
        def("primitive/string"),
        def("primitive/uint"),
        // structural roots + envelopes (5)
        def_fields(
            "entity",
            vec![
                ("type", fref("primitive/string")),
                ("data", fref("primitive/any")),
            ],
        ),
        def_fields(
            "core/entity",
            vec![
                ("type", fref("primitive/string")),
                ("data", fref("primitive/any")),
                ("content_hash", fref("system/hash")),
            ],
        ),
        def_fields(
            "core/envelope",
            vec![
                ("root", fref("core/entity")),
                (
                    "included",
                    opt(fmap(fref("core/entity"), Some("system/hash"))),
                ),
            ],
        ),
        def_extends("system/envelope", "core/envelope"),
        def_extends("system/protocol/envelope", "core/envelope"),
        // identity / hash / signature (4)
        TypeDef {
            name: "system/hash",
            extends: Some("primitive/bytes"),
            fields: vec![
                ("format_code", sized(fref("primitive/uint"), 1)),
                ("digest", fref("primitive/bytes")),
            ],
            layout: vec!["format_code", "digest"],
        },
        def_fields(
            "system/peer",
            vec![
                ("key_type", fref("primitive/string")),
                ("peer_id", fref("system/peer-id")),
                ("public_key", fref("primitive/bytes")),
            ],
        ),
        def_extends("system/peer-id", "primitive/string"),
        def_fields(
            "system/signature",
            vec![
                ("algorithm", fref("primitive/string")),
                ("signature", fref("primitive/bytes")),
                ("signer", fref("system/hash")),
                ("target", fref("system/hash")),
            ],
        ),
        // protocol surface (6)
        def_fields(
            "system/protocol/connect/authenticate",
            vec![
                ("key_type", fref("primitive/string")),
                ("nonce", fref("primitive/bytes")),
                ("peer_id", fref("system/peer-id")),
                ("public_key", fref("primitive/bytes")),
            ],
        ),
        def_fields(
            "system/protocol/connect/hello",
            vec![
                ("protocols", farray(fref("primitive/string"))),
                ("nonce", fref("primitive/bytes")),
                ("peer_id", fref("system/peer-id")),
                ("timestamp", fref("primitive/uint")),
                ("compression", opt(farray(fref("primitive/string")))),
                ("encryption", opt(farray(fref("primitive/string")))),
                ("hash_formats", opt(farray(fref("primitive/string")))),
                ("key_types", opt(farray(fref("primitive/string")))),
            ],
        ),
        def_fields(
            "system/protocol/error",
            vec![
                ("code", fref("primitive/string")),
                ("message", opt(fref("primitive/string"))),
                ("rejected_marker", opt(fref("system/hash"))),
            ],
        ),
        def_fields(
            "system/protocol/execute",
            vec![
                ("operation", fref("primitive/string")),
                ("params", fref("core/entity")),
                ("request_id", fref("primitive/string")),
                ("uri", fref("system/tree/path")),
                ("author", opt(fref("system/hash"))),
                ("bounds", opt(fref("system/bounds"))),
                ("capability", opt(fref("system/hash"))),
                ("deliver_to", opt(fref("system/delivery-spec"))),
                ("deliver_token", opt(fref("system/hash"))),
                ("durability_request", opt(fref("system/durability-request"))),
                ("resource", opt(fref("system/protocol/resource-target"))),
            ],
        ),
        def_fields(
            "system/protocol/execute/response",
            vec![
                ("request_id", fref("primitive/string")),
                ("result", fref("core/entity")),
                ("status", fref("primitive/uint")),
                ("durability", opt(fref("system/durability-result"))),
            ],
        ),
        def_fields(
            "system/protocol/resource-target",
            vec![
                ("targets", farray(fref("system/tree/path"))),
                ("exclude", opt(farray(fref("system/tree/path")))),
            ],
        ),
        // capability (12)
        def_fields(
            "system/capability/grant",
            vec![("token", fref("system/hash"))],
        ),
        def_fields(
            "system/capability/grant-entry",
            vec![
                ("handlers", fref("system/capability/path-scope")),
                ("operations", fref("system/capability/id-scope")),
                ("resources", fref("system/capability/path-scope")),
                ("allowances", opt(fmap(fref("primitive/any"), None))),
                ("constraints", opt(fmap(fref("primitive/any"), None))),
                ("peers", opt(fref("system/capability/id-scope"))),
            ],
        ),
        def_fields(
            "system/capability/id-scope",
            vec![
                ("include", farray(fref("primitive/string"))),
                ("exclude", opt(farray(fref("primitive/string")))),
            ],
        ),
        def_fields(
            "system/capability/path-scope",
            vec![
                ("include", farray(fref("system/tree/path"))),
                ("exclude", opt(farray(fref("system/tree/path")))),
            ],
        ),
        def_fields(
            "system/capability/request",
            vec![
                ("grants", farray(fref("system/capability/grant-entry"))),
                ("ttl_ms", opt(fref("primitive/uint"))),
            ],
        ),
        def_fields(
            "system/capability/revocation",
            vec![
                ("token", fref("system/hash")),
                ("revoked_at", fref("primitive/uint")),
                ("reason", opt(fref("primitive/string"))),
            ],
        ),
        def_fields(
            "system/capability/revoke-request",
            vec![
                ("token", fref("system/hash")),
                ("reason", opt(fref("primitive/string"))),
            ],
        ),
        def_fields(
            "system/capability/delegate-request",
            vec![
                ("grants", farray(fref("system/capability/grant-entry"))),
                ("parent", fref("system/hash")),
                ("ttl_ms", opt(fref("primitive/uint"))),
            ],
        ),
        def_fields(
            "system/capability/delegation-caveats",
            vec![
                ("max_delegation_depth", opt(fref("primitive/uint"))),
                ("max_delegation_ttl", opt(fref("primitive/uint"))),
                ("no_delegation", opt(fref("primitive/bool"))),
            ],
        ),
        def_fields(
            "system/capability/policy-entry",
            vec![
                ("grants", farray(fref("system/capability/grant-entry"))),
                ("peer_pattern", fref("primitive/string")),
                ("notes", opt(fref("primitive/string"))),
                ("ttl_ms", opt(fref("primitive/uint"))),
            ],
        ),
        def_fields(
            "system/capability/token",
            vec![
                ("created_at", fref("primitive/uint")),
                ("grantee", fref("system/hash")),
                (
                    "granter",
                    FSpec::Union(vec![
                        fref("system/hash"),
                        fref("system/capability/multi-granter"),
                    ]),
                ),
                ("grants", farray(fref("system/capability/grant-entry"))),
                (
                    "delegation_caveats",
                    opt(fref("system/capability/delegation-caveats")),
                ),
                ("expires_at", opt(fref("primitive/uint"))),
                ("not_before", opt(fref("primitive/uint"))),
                ("parent", opt(fref("system/hash"))),
                ("resource_limits", opt(fref("system/resource-limits"))),
            ],
        ),
        def_fields(
            "system/capability/multi-granter",
            vec![
                ("signers", farray(fref("system/hash"))),
                ("threshold", fref("primitive/uint")),
            ],
        ),
        // handler machinery (6)
        def_fields(
            "system/handler",
            vec![
                ("interface", fref("system/tree/path")),
                ("expression_path", opt(fref("system/tree/path"))),
                (
                    "internal_scope",
                    opt(farray(fref("system/capability/grant-entry"))),
                ),
                (
                    "max_scope",
                    opt(farray(fref("system/capability/grant-entry"))),
                ),
            ],
        ),
        def_fields(
            "system/handler/interface",
            vec![
                ("name", fref("primitive/string")),
                (
                    "operations",
                    fmap(fref("system/handler/operation-spec"), None),
                ),
                ("pattern", fref("system/tree/path")),
            ],
        ),
        TypeDef {
            name: "system/handler/manifest",
            extends: Some("system/handler/interface"),
            fields: vec![
                ("name", fref("primitive/string")),
                (
                    "operations",
                    fmap(fref("system/handler/operation-spec"), None),
                ),
                ("pattern", fref("system/tree/path")),
                ("expression_path", opt(fref("system/tree/path"))),
                (
                    "internal_scope",
                    opt(farray(fref("system/capability/grant-entry"))),
                ),
                (
                    "max_scope",
                    opt(farray(fref("system/capability/grant-entry"))),
                ),
            ],
            layout: vec![],
        },
        def_fields(
            "system/handler/operation-spec",
            vec![
                ("input_type", opt(fref("system/type/name"))),
                ("output_type", opt(fref("system/type/name"))),
            ],
        ),
        def_fields(
            "system/handler/register-request",
            vec![
                ("manifest", fref("system/handler/manifest")),
                (
                    "requested_scope",
                    opt(farray(fref("system/capability/grant-entry"))),
                ),
                ("types", opt(fmap(fref("system/type"), None))),
            ],
        ),
        def_fields(
            "system/handler/register-result",
            vec![
                ("grant", fref("system/capability/token")),
                ("pattern", fref("system/tree/path")),
            ],
        ),
        // tree (5)
        def_fields(
            "system/tree/get-request",
            vec![
                ("limit", opt(fref("primitive/uint"))),
                ("mode", opt(fref("primitive/string"))),
                ("offset", opt(fref("primitive/uint"))),
                ("tree_id", opt(fref("primitive/string"))),
            ],
        ),
        def_fields(
            "system/tree/put-request",
            vec![
                ("entity", opt(fref("core/entity"))),
                ("expected_hash", opt(fref("system/hash"))),
                ("tree_id", opt(fref("primitive/string"))),
            ],
        ),
        def_fields(
            "system/tree/listing",
            vec![
                ("count", fref("primitive/uint")),
                ("entries", fmap(fref("system/tree/listing-entry"), None)),
                ("offset", fref("primitive/uint")),
                ("path", fref("system/tree/path")),
                ("next_page", opt(fref("system/hash"))),
            ],
        ),
        def_fields(
            "system/tree/listing-entry",
            vec![
                ("has_children", fref("primitive/bool")),
                ("hash", opt(fref("system/hash"))),
            ],
        ),
        def_extends("system/tree/path", "primitive/string"),
        // type-system bootstrap (3)
        def_fields(
            "system/type",
            vec![
                ("name", fref("system/type/name")),
                ("extends", opt(fref("system/type/name"))),
                ("fields", opt(fmap(fref("system/type/field-spec"), None))),
                ("layout", opt(farray(fref("primitive/string")))),
                ("type_args", opt(fmap(fref("system/type/name"), None))),
                ("type_params", opt(farray(fref("primitive/string")))),
            ],
        ),
        def_fields(
            "system/type/field-spec",
            vec![
                ("type_ref", opt(fref("system/type/name"))),
                ("optional", opt(fref("primitive/bool"))),
                ("array_of", opt(fref("system/type/field-spec"))),
                ("map_of", opt(fref("system/type/field-spec"))),
                ("union_of", opt(farray(fref("system/type/field-spec")))),
                ("key_type", opt(fref("system/type/name"))),
                ("byte_size", opt(fref("primitive/uint"))),
                ("type_param", opt(fref("primitive/string"))),
                ("type_args", opt(fmap(fref("system/type/name"), None))),
                ("default", opt(fref("primitive/any"))),
                ("constraints", opt(farray(fref("core/entity")))),
            ],
        ),
        def_extends("system/type/name", "primitive/string"),
        // operational (4)
        def_fields(
            "system/bounds",
            vec![
                ("budget", opt(fref("primitive/uint"))),
                ("cascade_depth", opt(fref("primitive/uint"))),
                ("chain_id", opt(fref("primitive/string"))),
                ("parent_chain_id", opt(fref("primitive/string"))),
                ("ttl", opt(fref("primitive/uint"))),
                ("visited", opt(farray(fref("system/tree/path")))),
            ],
        ),
        def_fields(
            "system/resource-limits",
            vec![
                ("max_budget", opt(fref("primitive/uint"))),
                ("max_ttl", opt(fref("primitive/uint"))),
                ("max_visited_length", opt(fref("primitive/uint"))),
            ],
        ),
        def_fields(
            "system/delivery-spec",
            vec![
                ("operation", fref("primitive/string")),
                ("uri", fref("system/tree/path")),
            ],
        ),
        def("system/deletion-marker"),
    ]
}

/// Number of core types published (53).
pub fn core_type_count() -> usize {
    all_types().len()
}

/// Seed every core type entity into the store at `/{peer}/system/type/{name}`.
pub fn publish(st: &Store, local_peer: &str) {
    for td in all_types() {
        let e = td.to_entity();
        let path = format!("/{local_peer}/system/type/{}", td.name);
        st.bind(&path, &e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_type_count_is_53() {
        assert_eq!(core_type_count(), 53);
    }

    /// The type-registry conformance gate: every core type's content_hash is
    /// byte-identical to the v7.71 Go vector set (the cohort drift target).
    #[test]
    fn type_registry_renders_byte_identical_to_vector_set() {
        use super::super::model::hex;
        use std::collections::HashMap;

        // Load the vector file (array of {name, content_hash, ...}).
        let candidates = [
            "../shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor",
            "protocol-generator/shared/test-vectors/v0.8.0/type-registry-vectors-v1.cbor",
        ];
        let bytes = candidates.iter().find_map(|p| std::fs::read(p).ok());
        let bytes = match bytes {
            Some(b) => b,
            None => {
                eprintln!("skip: type-registry vector file not found");
                return;
            }
        };
        let fixture = crate::cbor::decode(&bytes).expect("decode vector file");
        let vectors = match fixture {
            Value::Array(arr) => arr,
            _ => panic!("vector file is not an array"),
        };

        // name → 64-char digest hex (after the "ecf-sha256:" prefix).
        let mut want: HashMap<String, String> = HashMap::new();
        for v in &vectors {
            let name = match super::super::model::map_get(v, "name") {
                Some(Value::Text(s)) => s.clone(),
                _ => continue,
            };
            let ch = match super::super::model::map_get(v, "content_hash") {
                Some(Value::Text(s)) => s.clone(),
                _ => continue,
            };
            if let Some(digest) = ch.strip_prefix("ecf-sha256:") {
                want.insert(name, digest.to_string());
            }
        }
        assert!(want.len() >= core_type_count());

        let mut mismatches = 0usize;
        let mut matched = 0usize;
        for td in all_types() {
            let e = td.to_entity();
            // e.hash is 33 bytes: 0x00 format byte ‖ 32-byte digest.
            let got_hex = hex(&e.hash[1..]);
            match want.get(td.name) {
                Some(expect) if *expect == got_hex => matched += 1,
                Some(expect) => {
                    eprintln!(
                        "MISMATCH {}\n  want {}\n  got  {}",
                        td.name, expect, got_hex
                    );
                    mismatches += 1;
                }
                None => {
                    eprintln!("MISSING from vectors: {}", td.name);
                    mismatches += 1;
                }
            }
        }
        assert_eq!(mismatches, 0, "{matched} matched, {mismatches} mismatch");
        assert_eq!(matched, core_type_count());
    }
}
