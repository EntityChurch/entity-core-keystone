//! The §6.9a identity → capability seed policy, as a VALUE.
//!
//! The peer used to take `open_grants: bool` and pick between two hardcoded scopes, so
//! no policy between `default → *` and the §4.4 discovery floor could be constructed at
//! all — not from the CLI and not from inside the process. Every authorization finding
//! at the extension layer is unobservable under `default → *` (a correct audit and an
//! under-authorizing one score identically), so a narrow policy is the only posture in
//! which that class can be measured. Routed by `entity-system-generator`.
//!
//! The file format and the CLI flag are the keystone cross-peer convention
//! (`protocol-generator/shared/seed-policy/README.md` + `seed-policy.schema.json`); the
//! normative contract is §6.9a. [`SeedPolicy`] is the §5 builder value that convention
//! names; [`SeedPolicy::from_json`] is its file form.

use crate::value::{Key, Value};

use super::capability as cap;
use super::json::{self, Json};
use super::model;

/// A named policy entry (§6.9a.1): the key it is bound under at
/// `system/capability/policy/{key}` and the grants materialized there.
#[derive(Clone, Debug, PartialEq)]
pub struct SeedPolicyEntry {
    /// A 66/98-char lowercase identity-hash hex, or a Base58 peer id.
    pub key: String,
    /// §3.6 grant-entry maps. May be empty: an empty entry is the CAP-2 withdrawal
    /// form (the entry matches and grants nothing, suppressing `default`).
    pub grants: Vec<Value>,
}

/// The declared seed policy a peer materializes at init (§6.9a Bootstrap L0) and
/// consults at §4.6 authenticate. The `self` owner capability is not part of it: the
/// peer mints that regardless, because it is a real root capability, not a template.
#[derive(Clone, Debug, PartialEq)]
pub struct SeedPolicy {
    default_grants: Vec<Value>,
    named: Vec<SeedPolicyEntry>,
}

impl Default for SeedPolicy {
    fn default() -> Self {
        SeedPolicy::standard()
    }
}

impl SeedPolicy {
    /// The conformant default: `default` = the §4.4 discovery floor, nothing named.
    pub fn standard() -> SeedPolicy {
        SeedPolicy {
            default_grants: discovery_floor(),
            named: vec![],
        }
    }

    /// The degenerate `default → *` policy — what the deprecated `--debug-open-grants`
    /// selects. Routed through the real §6.9a mechanism, never a fork.
    pub fn debug_open() -> SeedPolicy {
        SeedPolicy {
            default_grants: open_grants(),
            named: vec![],
        }
    }

    /// Any policy: the `default` entry's grants plus named entries.
    pub fn of(default_grants: Vec<Value>, named: Vec<SeedPolicyEntry>) -> SeedPolicy {
        SeedPolicy {
            default_grants,
            named,
        }
    }

    pub fn default_grants(&self) -> &[Value] {
        &self.default_grants
    }

    pub fn named_entries(&self) -> &[SeedPolicyEntry] {
        &self.named
    }

    /// Read a seed-policy file (`--seed-policy <path>`).
    pub fn from_file(path: &str) -> Result<SeedPolicy, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("{path}: {e}"))?;
        SeedPolicy::from_json(&text).map_err(|e| format!("{path}: {e}"))
    }

    /// Parse the keystone seed-policy JSON format.
    ///
    /// Refuses rather than approximates, on each of the following, because every one
    /// of them would otherwise be an authorization decision nobody wrote down:
    ///
    /// - an unknown key (the schema is `additionalProperties: false`). Keys beginning
    ///   with `_` are comments and are skipped — the shipped `examples/` carry
    ///   `_comment`, which the schema as written does not admit;
    /// - `grantee: "self"` — the owner capability lives at the self key and is minted by
    ///   the peer; a policy entry there would overwrite it;
    /// - `bounds` — `system/capability/policy-entry` (§6.2) carries `peer_pattern`,
    ///   `grants` and `ttl_ms` only, so there is nowhere to materialize a
    ///   `not_before`/`expires_at` and dropping it would widen the policy silently;
    /// - a grantee that is not `default`, an identity-hash hex, or a Base58 peer id;
    /// - the same grantee twice.
    ///
    /// A file with no `default` entry gets the §4.4 discovery floor as `default`, the
    /// convention's documented behaviour when no wider default is declared.
    pub fn from_json(text: &str) -> Result<SeedPolicy, String> {
        let root = json::parse(text)?;
        let root_kvs = object(&root, "seed policy")?;
        check_keys(root_kvs, &["version", "entries"], "seed policy")?;
        match root.get("version") {
            Some(Json::UInt(1)) => {}
            Some(_) => return Err("seed policy: version must be 1".into()),
            None => return Err("seed policy: missing version".into()),
        }
        let entries = match root.get("entries") {
            Some(Json::Array(a)) => a,
            Some(_) => return Err("seed policy: entries must be an array".into()),
            None => return Err("seed policy: missing entries".into()),
        };

        let mut default_grants: Option<Vec<Value>> = None;
        let mut named: Vec<SeedPolicyEntry> = vec![];
        for (i, entry) in entries.iter().enumerate() {
            let what = format!("entries[{i}]");
            let kvs = object(entry, &what)?;
            check_keys(kvs, &["grantee", "grants", "bounds"], &what)?;
            if entry.get("bounds").is_some() {
                return Err(format!(
                    "{what}: bounds is not supported — system/capability/policy-entry (section 6.2) \
                     carries peer_pattern, grants and ttl_ms only, so a not_before/expires_at here \
                     would be dropped"
                ));
            }
            let grantee = match entry.get("grantee") {
                Some(Json::Str(s)) if !s.is_empty() => s.clone(),
                _ => return Err(format!("{what}: grantee must be a non-empty string")),
            };
            let grants = match entry.get("grants") {
                Some(Json::Array(a)) => a
                    .iter()
                    .enumerate()
                    .map(|(j, g)| grant_value(g, &format!("{what}.grants[{j}]")))
                    .collect::<Result<Vec<_>, _>>()?,
                _ => return Err(format!("{what}: grants must be an array")),
            };
            if grantee == "default" {
                if default_grants.is_some() {
                    return Err(format!("{what}: a second default entry"));
                }
                default_grants = Some(grants);
            } else if grantee == "self" {
                return Err(format!(
                    "{what}: grantee \"self\" is materialized by the peer as its owner capability; \
                     a policy entry at that key would overwrite it"
                ));
            } else if is_identity_hex(&grantee) || cap::is_peer_id(&grantee) {
                if named.iter().any(|e| e.key == grantee) {
                    return Err(format!("{what}: grantee {grantee} appears twice"));
                }
                named.push(SeedPolicyEntry {
                    key: grantee,
                    grants,
                });
            } else {
                return Err(format!(
                    "{what}: grantee \"{grantee}\" is not default, an identity-hash hex, or a Base58 peer id"
                ));
            }
        }
        Ok(SeedPolicy {
            default_grants: default_grants.unwrap_or_else(discovery_floor),
            named,
        })
    }
}

fn is_identity_hex(s: &str) -> bool {
    (s.len() == 66 || s.len() == 98)
        && s
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn object<'a>(v: &'a Json, what: &str) -> Result<&'a [(String, Json)], String> {
    match v {
        Json::Object(kvs) => Ok(kvs),
        _ => Err(format!("{what}: must be an object")),
    }
}

fn check_keys(kvs: &[(String, Json)], allowed: &[&str], what: &str) -> Result<(), String> {
    for (k, _) in kvs {
        if !k.starts_with('_') && !allowed.contains(&k.as_str()) {
            return Err(format!("{what}: unknown key \"{k}\""));
        }
    }
    Ok(())
}

fn scope_value(v: &Json, what: &str) -> Result<Value, String> {
    let kvs = object(v, what)?;
    check_keys(kvs, &["include", "exclude"], what)?;
    let list = |key: &str| -> Result<Option<Value>, String> {
        match v.get(key) {
            None => Ok(None),
            Some(Json::Array(a)) => a
                .iter()
                .map(|s| match s {
                    Json::Str(s) => Ok(Value::Text(s.clone())),
                    _ => Err(format!("{what}.{key}: entries must be strings")),
                })
                .collect::<Result<Vec<_>, _>>()
                .map(|items| Some(Value::Array(items))),
            Some(_) => Err(format!("{what}.{key}: must be an array")),
        }
    };
    let include = list("include")?.ok_or_else(|| format!("{what}: missing include"))?;
    let mut pairs = vec![(Key::Text("include".into()), include)];
    if let Some(ex) = list("exclude")? {
        pairs.push((Key::Text("exclude".into()), ex));
    }
    Ok(Value::Map(pairs))
}

fn grant_value(v: &Json, what: &str) -> Result<Value, String> {
    let kvs = object(v, what)?;
    check_keys(
        kvs,
        &["handlers", "resources", "operations", "peers", "constraints", "allowances"],
        what,
    )?;
    let mut pairs = vec![];
    for dim in ["handlers", "resources", "operations"] {
        let s = v
            .get(dim)
            .ok_or_else(|| format!("{what}: missing {dim}"))?;
        pairs.push((Key::Text(dim.into()), scope_value(s, &format!("{what}.{dim}"))?));
    }
    if let Some(p) = v.get("peers") {
        pairs.push((Key::Text("peers".into()), scope_value(p, &format!("{what}.peers"))?));
    }
    for extra in ["constraints", "allowances"] {
        if let Some(x) = v.get(extra) {
            if !matches!(x, Json::Object(_)) {
                return Err(format!("{what}.{extra}: must be an object"));
            }
            pairs.push((Key::Text(extra.into()), json_to_value(x)));
        }
    }
    Ok(Value::Map(pairs))
}

fn json_to_value(v: &Json) -> Value {
    match v {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::UInt(u) => Value::UInt(*u),
        // value = -1 - n  ⇒  n = -1 - value, which fits u64 for every i64 < 0.
        Json::Int(i) => Value::NInt((-1 - *i) as u64),
        Json::Str(s) => Value::Text(s.clone()),
        Json::Array(a) => Value::Array(a.iter().map(json_to_value).collect()),
        Json::Object(kvs) => Value::Map(
            kvs.iter()
                .map(|(k, x)| (Key::Text(k.clone()), json_to_value(x)))
                .collect(),
        ),
    }
}

// ── the scopes the peer materializes (§4.4 / §5.4) ───────────────────────────────

fn scope_val(incl: &[&str]) -> Value {
    model::map(vec![("include", model::text_array(incl))])
}

/// Build one §3.6 grant-entry map.
pub fn grant(handlers: &[&str], resources: &[&str], operations: &[&str], peers: Option<&[&str]>) -> Value {
    let mut pairs = vec![
        ("handlers", scope_val(handlers)),
        ("resources", scope_val(resources)),
        ("operations", scope_val(operations)),
    ];
    if let Some(p) = peers {
        pairs.push(("peers", scope_val(p)));
    }
    model::map(pairs)
}

/// §4.4 discovery floor: every authenticated identity gets at least this.
pub fn discovery_floor() -> Vec<Value> {
    vec![
        grant(
            &["system/tree"],
            &["system/type/*", "system/handler/*"],
            &["get"],
            None,
        ),
        grant(&["system/capability"], &[], &["request"], None),
    ]
}

/// The wide-open admin scope of the degenerate `default → *` policy.
pub fn open_grants() -> Vec<Value> {
    vec![grant(&["*"], &["*", "/*/*"], &["*"], Some(&["*"]))]
}

/// Full owner authority over the local namespace (§6.9a) — the `self` owner cap.
pub fn owner_grants(local_peer: &str) -> Vec<Value> {
    vec![grant(&["*"], &["*"], &["*"], Some(&[local_peer]))]
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../shared/seed-policy/examples");

    #[test]
    fn shipped_examples_parse() {
        let floor = SeedPolicy::from_file(&format!("{EXAMPLES}/default-floor.json")).unwrap();
        assert_eq!(floor.default_grants(), discovery_floor().as_slice());
        assert!(floor.named_entries().is_empty());

        let open = SeedPolicy::from_file(&format!("{EXAMPLES}/debug-open.json")).unwrap();
        assert_eq!(open.default_grants().len(), 1);

        // operator-admin.json names its operator with a placeholder hex whose shape is
        // valid, so it parses; the grant carries `peers: ["self"]` verbatim.
        let admin = SeedPolicy::from_file(&format!("{EXAMPLES}/operator-admin.json")).unwrap();
        assert_eq!(admin.named_entries().len(), 1);
        assert_eq!(admin.default_grants(), discovery_floor().as_slice());
    }

    #[test]
    fn a_narrow_policy_is_expressible() {
        let p = SeedPolicy::from_json(
            r#"{"version":1,"entries":[{"grantee":"default","grants":[
                {"handlers":{"include":["app/x"]},"resources":{"include":["app/x/*"],"exclude":["app/x/secret"]},
                 "operations":{"include":["get"]}}]}]}"#,
        )
        .unwrap();
        let g = &p.default_grants()[0];
        let res = model::map_get(g, "resources").unwrap();
        assert!(model::map_get(res, "exclude").is_some(), "exclude must survive");
    }

    #[test]
    fn refuses_what_it_cannot_materialize() {
        let wrap = |entry: &str| format!(r#"{{"version":1,"entries":[{entry}]}}"#);
        let g = r#""grants":[]"#;
        for (bad, why) in [
            (wrap(&format!(r#"{{"grantee":"self",{g}}}"#)), "self"),
            (wrap(&format!(r#"{{"grantee":"default",{g},"bounds":{{"expires_at":1}}}}"#)), "bounds"),
            (wrap(&format!(r#"{{"grantee":"*",{g}}}"#)), "bad grantee"),
            (wrap(&format!(r#"{{"grantee":"default",{g},"ttl":1}}"#)), "unknown key"),
            (
                wrap(&format!(r#"{{"grantee":"default",{g}}},{{"grantee":"default",{g}}}"#)),
                "second default",
            ),
            (r#"{"version":2,"entries":[]}"#.to_string(), "version"),
        ] {
            assert!(SeedPolicy::from_json(&bad).is_err(), "{why} must be refused");
        }
        // CAP-2: an empty grants list is the withdrawal form and is legal.
        let ok = SeedPolicy::from_json(&wrap(&format!(r#"{{"grantee":"default",{g}}}"#))).unwrap();
        assert!(ok.default_grants().is_empty());
    }
}
