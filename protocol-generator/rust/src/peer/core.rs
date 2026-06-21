//! Peer assembly (L1–L4 + foundation) — bootstrap, the four MUST system handlers
//! (§6.2: tree, handler, capability, connect), the dispatch chain (§6.5/§6.6), and
//! the §6.9a peer-authority seed bootstrap.
//!
//! This module is the pure protocol brain: a function from an inbound envelope to
//! an outbound response envelope, plus per-connection state. Transport (TCP, the
//! reader-demux) lives in [`super::transport`]. The store is the only shared
//! mutable state and is `RwLock`-guarded (§4.8); `Peer` is `Send + Sync` so it can
//! be shared by `Arc` across connection threads.
//!
//! Outbound reentry (§6.11 / §6.13(b)) is exposed via an [`OutboundFn`] hook bound
//! into [`Conn`] by the transport for the duration of a dispatch — the §7a
//! dispatch-outbound handler originates back over the inbound connection through it.

use std::sync::Arc;

use crate::value::{Key, Value};

use super::capability as cap;
use super::identity::{self, Identity};
use super::model::{self, hex, Entity, Envelope};
use super::store::Store;
use super::type_defs;
use super::wire;

/// An outbound-reentry hook (§6.11): given a request envelope, originate it over
/// the live inbound connection and return the correlated response.
pub type OutboundFn = dyn Fn(Envelope) -> Option<Envelope> + Send + Sync;

/// Per-connection state (§4.2).
#[derive(Default)]
pub struct Conn {
    pub established: bool,
    pub issued_nonce: Option<[u8; 32]>,
    pub hello_peer_id: Option<String>,
    /// §6.11 reentry seam, bound by the transport for the duration of a dispatch.
    pub outbound: Option<Arc<OutboundFn>>,
    pub out_counter: u32,
}

impl Conn {
    pub fn new() -> Conn {
        Conn::default()
    }
}

/// A handler outcome: status, the result entity, and protocol entities to bundle.
struct Outcome {
    status: u64,
    result: Entity,
    included: Vec<Entity>,
}

fn ok(result: Entity) -> Outcome {
    Outcome {
        status: 200,
        result,
        included: vec![],
    }
}
fn ok_inc(result: Entity, included: Vec<Entity>) -> Outcome {
    Outcome {
        status: 200,
        result,
        included,
    }
}
fn err_out(status: u64, code: &str, message: Option<&str>) -> Outcome {
    Outcome {
        status,
        result: wire::error_result(code, message),
        included: vec![],
    }
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// A 32-byte handshake nonce (§4.6 SHOULD ≥32-byte CSPRNG). We read the OS CSPRNG
/// directly from `/dev/urandom` rather than pulling a `rand`/`getrandom` crate
/// (dep-minimization, A-RUST-003-adjacent). On the (unexpected) read failure we
/// fall back to a SHA-256 of high-resolution time ‖ a process-global counter ‖ a
/// stack address — non-cryptographic, but the nonce only needs uniqueness for a
/// single handshake and the urandom path is the live one on every supported host.
fn random_nonce() -> [u8; 32] {
    use std::io::Read;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // fallback (best-effort uniqueness; not for production crypto).
    use sha2::{Digest, Sha256};
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let stack_marker = &buf as *const _ as usize as u64;
    let mut h = Sha256::new();
    h.update(n.to_le_bytes());
    h.update(t.to_le_bytes());
    h.update(stack_marker.to_le_bytes());
    buf.copy_from_slice(&h.finalize());
    buf
}

/// The peer (§6.9). Shared across connection threads by `Arc`.
pub struct Peer {
    pub identity: Identity,
    pub store: Store,
    pub local_peer: String,
    pub open_grants: bool,
    pub conformance: bool,
}

/// Builder options for [`Peer::create`].
#[derive(Default)]
pub struct CreateOptions {
    pub seed: [u8; 32],
    pub open_grants: bool,
    pub conformance: bool,
}

// ── grant construction (§4.4 / §5.4) ───────────────────────────────────────────

fn scope_val(incl: &[&str]) -> Value {
    model::map(vec![("include", model::text_array(incl))])
}

fn grant_val(
    handlers: &[&str],
    resources: &[&str],
    operations: &[&str],
    peers: Option<&[&str]>,
) -> Value {
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
fn discovery_floor() -> Vec<Value> {
    vec![
        grant_val(
            &["system/tree"],
            &["system/type/*", "system/handler/*"],
            &["get"],
            None,
        ),
        grant_val(&["system/capability"], &[], &["request"], None),
    ]
}

/// The degenerate `default → *` (= retired --debug-open-grants).
fn open_grants_scope() -> Vec<Value> {
    vec![grant_val(&["*"], &["*", "/*/*"], &["*"], Some(&["*"]))]
}

/// Full owner authority over the local namespace (§6.9a).
fn owner_grants(local_peer: &str) -> Vec<Value> {
    vec![grant_val(&["*"], &["*"], &["*"], Some(&[local_peer]))]
}

// ── token minting (§4.4 / §5.4) ────────────────────────────────────────────────

struct Minted {
    token: Entity,
    signature: Entity,
}

/// Mint a capability token granted by us to `grantee_hash`; sign it (peer-level
/// signature over the token's content_hash).
fn mint_token(
    id: &Identity,
    grantee_hash: &[u8],
    parent: Option<&[u8]>,
    grants: Vec<Value>,
) -> Minted {
    let mut pairs = vec![
        (Key::Text("granter".into()), model::bytes(&id.identity_hash)),
        (Key::Text("grantee".into()), model::bytes(grantee_hash)),
        (Key::Text("grants".into()), Value::Array(grants)),
        (Key::Text("created_at".into()), Value::UInt(now_ms())),
    ];
    if let Some(ph) = parent {
        pairs.push((Key::Text("parent".into()), model::bytes(ph)));
    }
    let token = Entity::make("system/capability/token", Value::Map(pairs));
    let signature = id.sign_entity(&token);
    Minted { token, signature }
}

impl Peer {
    /// Build and bootstrap a peer (§6.9 + §6.9a). The peer owns its store + identity.
    pub fn create(opts: CreateOptions) -> Peer {
        let identity = Identity::of_seed(opts.seed);
        let store = Store::new();
        let local_peer = identity.peer_id.clone();

        let peer = Peer {
            identity,
            store,
            local_peer,
            open_grants: opts.open_grants,
            conformance: opts.conformance,
        };

        // local identity entity in the store (root-granter resolution + §3.13 self).
        peer.store.put_entity(&peer.identity.peer_entity);
        peer.store.bind(
            &format!("/{}/system/peer/self", peer.local_peer),
            &peer.identity.peer_entity,
        );

        // §9.5 core type floor.
        type_defs::publish(&peer.store, &peer.local_peer);

        // the four MUST handlers (§6.2), plus §7a scaffolding when conformance=true.
        for bh in BOOTSTRAP_HANDLERS {
            peer.bootstrap_handler(bh);
        }
        if peer.conformance {
            for bh in CONFORMANCE_HANDLERS {
                peer.bootstrap_handler(bh);
            }
        }

        // §6.9a peer-authority bootstrap: self-owner cap + default policy entry.
        let policy_base = format!("/{}/system/capability/policy/", peer.local_peer);
        let owner = mint_token(
            &peer.identity,
            &peer.identity.identity_hash,
            None,
            owner_grants(&peer.local_peer),
        );
        let ohex = hex(&peer.identity.identity_hash);
        peer.store
            .bind(&format!("{policy_base}{ohex}"), &owner.token);
        let othex = hex(&owner.token.hash);
        peer.store.bind(
            &format!("/{}/system/signature/{othex}", peer.local_peer),
            &owner.signature,
        );

        let default_grants = if peer.open_grants {
            open_grants_scope()
        } else {
            discovery_floor()
        };
        let default_entry = Entity::make(
            "system/capability/policy-entry",
            Value::Map(vec![
                (Key::Text("peer_pattern".into()), model::text("default")),
                (Key::Text("grants".into()), Value::Array(default_grants)),
            ]),
        );
        peer.store
            .bind(&format!("{policy_base}default"), &default_entry);

        peer
    }

    // ── bootstrap helper (§6.2) ─────────────────────────────────────────────────

    fn bootstrap_handler(&self, bh: &BootHandler) {
        let handler_e = Entity::make(
            "system/handler",
            model::map(vec![(
                "interface",
                model::text(&format!("system/handler/{}", bh.pattern)),
            )]),
        );
        self.store
            .bind(&format!("/{}/{}", self.local_peer, bh.pattern), &handler_e);

        let ops_map = Value::Map(
            bh.operations
                .iter()
                .map(|op| (Key::Text(op.to_string()), Value::Map(vec![])))
                .collect(),
        );
        let iface_e = Entity::make(
            "system/handler/interface",
            model::map(vec![
                ("pattern", model::text(bh.pattern)),
                ("name", model::text(bh.name)),
                ("operations", ops_map),
            ]),
        );
        self.store.bind(
            &format!("/{}/system/handler/{}", self.local_peer, bh.pattern),
            &iface_e,
        );

        let minted = mint_token(&self.identity, &self.identity.identity_hash, None, vec![]);
        self.store.bind(
            &format!(
                "/{}/system/capability/grants/{}",
                self.local_peer, bh.pattern
            ),
            &minted.token,
        );
    }

    // ── dispatch (§6.5) ─────────────────────────────────────────────────────────

    /// Materialize the inbound envelope into an outbound response envelope. Returns
    /// `None` for a non-EXECUTE root (§3.3 server ignores it). Never panics on a
    /// protocol error — every failure is a status, the connection stays alive.
    pub fn dispatch(&self, conn: &mut Conn, env: &Envelope) -> Option<Envelope> {
        if env.root.typ != "system/protocol/execute" {
            return None; // §3.3
        }
        let request_id = env.root.text_field("request_id").unwrap_or("").to_string();
        let outcome = self.dispatch_outcome(conn, env);
        let mut response = Envelope::new(wire::make_response(
            &request_id,
            outcome.status,
            &outcome.result,
        ));
        for e in outcome.included {
            response.included.insert(e.hash.clone(), e);
        }
        Some(response)
    }

    fn dispatch_outcome(&self, conn: &mut Conn, env: &Envelope) -> Outcome {
        let exec = &env.root;
        let uri = exec.text_field("uri").unwrap_or("").to_string();
        if uri == "system/protocol/connect" {
            return self.connect_handler(conn, exec, env);
        }

        self.ingest_signatures(env);

        // §5.2 verify_request — 3-way verdict (+ §4.10(b) chain-depth pre-check).
        match cap::verify_request(env, &self.store, &self.local_peer) {
            cap::ReqVerdict::AuthnFail => {
                return err_out(401, "authentication_failed", None);
            }
            cap::ReqVerdict::UnresolvableGrantee => {
                return err_out(401, "unresolvable_grantee", None);
            }
            cap::ReqVerdict::AuthzDeny => return err_out(403, "capability_denied", None),
            cap::ReqVerdict::ChainTooDeep => {
                return err_out(400, "chain_depth_exceeded", None);
            }
            cap::ReqVerdict::Allow => {}
        }

        let norm = cap::normalize_uri(&uri);
        let path = cap::canonicalize(&self.local_peer, &norm);
        // §1.4: inbound dispatch must target the local peer.
        let tp = cap::extract_peer(&self.local_peer, &path);
        if tp != self.local_peer {
            return err_out(404, "handler_not_found", Some("not local peer"));
        }
        let pattern = match self.resolve_handler(&path) {
            Some(p) => p,
            None => return err_out(404, "handler_not_found", Some(&path)),
        };

        // check_permission at the granter frame (§5.2 / §PR-8).
        let caller_cap = exec
            .bytes_field("capability")
            .and_then(|ch| env.included_get(ch).cloned());
        let cc = match &caller_cap {
            Some(c) => c.clone(),
            None => return err_out(403, "capability_denied", None),
        };
        let granter_peer = cap::granter_frame(env, &self.store, &self.local_peer, &cc);
        if cap::check_permission(&self.local_peer, &granter_peer, exec, &cc, &pattern)
            == cap::Verdict::Deny
        {
            return err_out(403, "capability_denied", None);
        }

        let stripped = self.strip_local(&pattern);
        match stripped.as_str() {
            "system/tree" => self.tree_handler(exec),
            "system/capability" => self.capability_handler(exec, caller_cap.as_ref()),
            "system/handler" => self.handlers_handler(exec),
            "system/type" => err_out(501, "unsupported_operation", exec.text_field("operation")),
            _ => {
                if self.conformance && stripped.starts_with("system/validate/") {
                    return self.conformance_handler(conn, exec, &stripped);
                }
                // a dynamically-registered handler: dispatch its entity-native body.
                if let Some(handler_entity) = self.store.get_at(&pattern) {
                    if handler_entity.typ == "system/handler" {
                        return self.entity_native_dispatch(&handler_entity);
                    }
                }
                err_out(501, "no_handler_body", Some(&stripped))
            }
        }
    }

    /// §6.5 dispatcher-level signature ingestion: persist signatures + their signer
    /// peers so chain-walk + authenticate can resolve them.
    fn ingest_signatures(&self, env: &Envelope) {
        for e in env.included.values() {
            if e.typ != "system/signature" {
                continue;
            }
            self.store.put_entity(e);
            let signer_h = match e.bytes_field("signer") {
                Some(s) => s.to_vec(),
                None => continue,
            };
            let signer_peer = match env.included_get(&signer_h) {
                Some(p) => p.clone(),
                None => continue,
            };
            self.store.put_entity(&signer_peer);
            let target = match e.bytes_field("target") {
                Some(t) => t.to_vec(),
                None => continue,
            };
            let pk = match signer_peer.bytes_field("public_key") {
                Some(p) => p,
                None => continue,
            };
            let pid = identity::peer_id_of_pubkey(pk);
            let path = format!("/{pid}/system/signature/{}", hex(&target));
            self.store.bind(&path, e);
        }
    }

    /// §6.6 handler resolution — backward tree-walk over successively shorter
    /// prefixes; the first bound `system/handler` wins.
    fn resolve_handler(&self, path: &str) -> Option<String> {
        let mut end = path.len();
        loop {
            let prefix = &path[..end];
            if let Some(e) = self.store.get_at(prefix) {
                if e.typ == "system/handler" {
                    return Some(prefix.to_string());
                }
            }
            match path[..end].rfind('/') {
                Some(i) => end = i,
                None => return None,
            }
        }
    }

    fn strip_local(&self, pattern: &str) -> String {
        let prefix = format!("/{}/", self.local_peer);
        pattern
            .strip_prefix(&prefix)
            .map(|s| s.to_string())
            .unwrap_or_else(|| pattern.to_string())
    }

    // ── connect handler (§4.1, §4.6) ────────────────────────────────────────────

    fn connect_handler(&self, conn: &mut Conn, exec: &Entity, env: &Envelope) -> Outcome {
        let op = exec.text_field("operation").unwrap_or("");
        if op == "hello" {
            if conn.established {
                return err_out(409, "connection_already_established", None);
            }
            if let Some(params) = exec.entity_field("params") {
                if negotiation_reject(&params, "hash_formats", "ecfv1-sha256") {
                    return err_out(400, "incompatible_hash_format", None);
                }
                if negotiation_reject(&params, "key_types", "ed25519") {
                    return err_out(400, "unsupported_key_type", None);
                }
                if let Some(pid) = params.text_field("peer_id") {
                    conn.hello_peer_id = Some(pid.to_string());
                }
            }
            let nonce = random_nonce();
            conn.issued_nonce = Some(nonce);
            let hello = Entity::make(
                "system/protocol/connect/hello",
                model::map(vec![
                    ("peer_id", model::text(&self.local_peer)),
                    ("nonce", model::bytes(&nonce)),
                    ("protocols", model::text_array(&["entity-core/1.0"])),
                    ("timestamp", Value::UInt(now_ms())),
                    ("hash_formats", model::text_array(&["ecfv1-sha256"])),
                    ("key_types", model::text_array(&["ed25519"])),
                ]),
            );
            return ok(hello);
        }
        if op == "authenticate" {
            if conn.established {
                return err_out(409, "connection_already_established", None);
            }
            let issued = match conn.issued_nonce {
                Some(n) => n,
                None => return err_out(401, "invalid_nonce", None),
            };
            let auth = match exec.entity_field("params") {
                Some(a) => a,
                None => return err_out(401, "authentication_failed", None),
            };
            // §4.6 hardening: reject an unsupported key_type.
            if let Some(kt) = auth.text_field("key_type") {
                if kt != "ed25519" {
                    return err_out(400, "unsupported_key_type", None);
                }
            }
            if let Some(pk) = auth.bytes_field("public_key") {
                if pk.len() != 32 {
                    return err_out(400, "unsupported_key_type", None);
                }
            }
            if let Some(pid) = auth.text_field("peer_id") {
                if let Ok(parsed) = crate::peer_id::parse(pid) {
                    if parsed.key_type != 0x01 {
                        return err_out(400, "unsupported_key_type", None);
                    }
                }
            }
            let echoed = auth.bytes_field("nonce");
            if echoed != Some(issued.as_slice()) {
                return err_out(401, "invalid_nonce", None);
            }
            let public_key = match auth.bytes_field("public_key") {
                Some(pk) => pk.to_vec(),
                None => return err_out(401, "authentication_failed", None),
            };
            // step 2: proof of possession — the auth signature over auth.hash.
            let sig_ok = match cap::find_signature(env, &auth.hash) {
                Some(sgn) => {
                    let signer_peer = identity::peer_entity_of_pubkey(&public_key);
                    identity::verify_signature(&sgn, &signer_peer)
                }
                None => false,
            };
            if !sig_ok {
                return err_out(401, "authentication_failed", None);
            }
            // step 3: identity binding.
            let derived = identity::peer_id_of_pubkey(&public_key);
            let claimed = match auth.text_field("peer_id") {
                Some(c) => c.to_string(),
                None => return err_out(401, "identity_mismatch", None),
            };
            if claimed != derived {
                return err_out(401, "identity_mismatch", None);
            }
            if let Some(hp) = &conn.hello_peer_id {
                if hp != &claimed {
                    return err_out(401, "identity_mismatch", None);
                }
            }
            // success: mint the initial capability (§4.4 / §6.9a seed-policy).
            let remote_peer = identity::peer_entity_of_pubkey(&public_key);
            let grants = self.derive_seed_grants(&remote_peer, &claimed);
            let minted = mint_token(&self.identity, &remote_peer.hash, None, grants);
            conn.established = true;
            let grant_result = Entity::make(
                "system/capability/grant",
                model::map(vec![("token", model::bytes(&minted.token.hash))]),
            );
            return ok_inc(
                grant_result,
                vec![
                    minted.token,
                    self.identity.peer_entity.clone(),
                    minted.signature,
                ],
            );
        }
        err_out(501, "unsupported_operation", Some(op))
    }

    // ── §6.9a seed-policy derivation ───────────────────────────────────────────

    /// authenticate-time derivation: dual-form lookup (hex → Base58 → default),
    /// then UNION the matched scope with the §4.4 discovery floor.
    fn derive_seed_grants(&self, remote_peer: &Entity, remote_peer_id: &str) -> Vec<Value> {
        let base = format!("/{}/system/capability/policy/", self.local_peer);
        let entry = self
            .store
            .get_at(&format!("{base}{}", hex(&remote_peer.hash)))
            .or_else(|| self.store.get_at(&format!("{base}{remote_peer_id}")))
            .or_else(|| self.store.get_at(&format!("{base}default")));
        let floor = discovery_floor();
        let policy_grants = match entry {
            Some(e) => self.seed_entry_grants(&e),
            None => vec![],
        };
        if policy_grants.is_empty() {
            return floor;
        }
        let mut out = floor;
        out.extend(policy_grants);
        out
    }

    /// Extract grants from a seed-policy entry, handling both §6.9a.0 shapes: a
    /// capability token (detached-signature shape — verify the sig at the §3.5
    /// pointer first) or a policy-entry (scope template).
    fn seed_entry_grants(&self, e: &Entity) -> Vec<Value> {
        let grants_of = |ent: &Entity| match ent.field("grants") {
            Some(Value::Array(arr)) => arr.clone(),
            _ => vec![],
        };
        if e.typ == "system/capability/token" {
            let sig_path = format!("/{}/system/signature/{}", self.local_peer, hex(&e.hash));
            if let Some(sgn) = self.store.get_at(&sig_path) {
                if identity::verify_signature(&sgn, &self.identity.peer_entity) {
                    return grants_of(e);
                }
            }
            vec![] // unverifiable seed cap → no authority
        } else if e.typ == "system/capability/policy-entry" {
            grants_of(e)
        } else {
            vec![]
        }
    }

    // ── tree handler (§6.3) ─────────────────────────────────────────────────────

    fn tree_handler(&self, exec: &Entity) -> Outcome {
        let op = exec.text_field("operation").unwrap_or("");
        let target = resource_target(exec);
        if matches!(op, "get" | "put") {
            if let Some(t) = &target {
                if !path_flex_ok(t) {
                    return err_out(400, "invalid_path", Some(t));
                }
            }
        }
        match op {
            "get" => {
                let target = match target {
                    None => {
                        return self.build_listing(&format!("/{}/", self.local_peer));
                    }
                    Some(t) => t,
                };
                if target.is_empty() || target.ends_with('/') {
                    return self.build_listing(&cap::canonicalize(&self.local_peer, &target));
                }
                let path = cap::canonicalize(&self.local_peer, &target);
                let e = match self.store.get_at(&path) {
                    Some(e) => e,
                    None => return err_out(404, "not_found", Some(&path)),
                };
                if let Some(params) = exec.entity_field("params") {
                    if params.text_field("mode") == Some("hash") {
                        return ok(Entity::make("system/hash", model::bytes(&e.hash)));
                    }
                }
                ok(e)
            }
            "put" => {
                let target = match target {
                    Some(t) => t,
                    None => {
                        return err_out(
                            400,
                            "ambiguous_resource",
                            Some("tree: missing resource target"),
                        )
                    }
                };
                let path = cap::canonicalize(&self.local_peer, &target);
                let params = exec.entity_field("params");
                let entity = params.as_ref().and_then(|p| p.entity_field("entity"));
                let expected = params.as_ref().and_then(|p| p.bytes_field("expected_hash"));
                // §3.9 CAS.
                let current = self.store.hash_at(&path);
                let zero33 = [0u8; 33];
                let cas_ok = match expected {
                    Some(h) => {
                        if h == zero33 {
                            current.is_none()
                        } else {
                            current.as_deref() == Some(h)
                        }
                    }
                    None => true,
                };
                if !cas_ok {
                    return err_out(409, "hash_mismatch", Some(&path));
                }
                match entity {
                    Some(e) => {
                        self.store.bind(&path, &e);
                        ok(Entity::make("system/hash", model::bytes(&e.hash)))
                    }
                    None => err_out(400, "unexpected_params", Some("put: missing entity")),
                }
            }
            _ => err_out(501, "unsupported_operation", Some(op)),
        }
    }

    fn build_listing(&self, path: &str) -> Outcome {
        let entries = self.store.listing(path);
        let mut entry_pairs: Vec<(Key, Value)> = vec![];
        let mut emitted: u64 = 0;
        for le in entries {
            // §6.3 / CORE-TREE-DELETE-1: a leaf bound to a deletion-marker is a
            // tombstone — omit it from the listing.
            if let Some(h) = &le.hash {
                if let Some(bound) = self.store.get_by_hash(h) {
                    if bound.typ == "system/deletion-marker" {
                        continue;
                    }
                }
            }
            let mut fields = vec![("has_children", Value::Bool(le.has_children))];
            if let Some(h) = &le.hash {
                fields.push(("hash", model::bytes(h)));
            }
            let le_entity = Entity::make("system/tree/listing-entry", model::map(fields));
            entry_pairs.push((Key::Text(le.seg), le_entity.to_cbor()));
            emitted += 1;
        }
        let listing = Entity::make(
            "system/tree/listing",
            Value::Map(vec![
                (Key::Text("path".into()), model::text(path)),
                (Key::Text("entries".into()), Value::Map(entry_pairs)),
                (Key::Text("count".into()), Value::UInt(emitted)),
                (Key::Text("offset".into()), Value::UInt(0)),
            ]),
        );
        ok(listing)
    }

    // ── capability handler (§6.2) ───────────────────────────────────────────────

    fn capability_handler(&self, exec: &Entity, caller_cap: Option<&Entity>) -> Outcome {
        let op = exec.text_field("operation").unwrap_or("");
        let params = exec.entity_field("params");
        let author = exec.bytes_field("author").map(|b| b.to_vec());
        match op {
            "request" => {
                let grantee = match author {
                    Some(a) => a,
                    None => return err_out(403, "capability_denied", None),
                };
                self.mint_bounded(caller_cap, req_grants(params.as_ref()), &grantee, None)
            }
            "delegate" => {
                let parent = params
                    .as_ref()
                    .and_then(|p| p.bytes_field("parent"))
                    .map(|b| b.to_vec());
                let parent = match parent {
                    Some(p) if !is_zero(&p) => p,
                    _ => {
                        return err_out(400, "unexpected_params", Some("delegate: parent required"))
                    }
                };
                // delegate is same-peer-only in v1.
                match &author {
                    Some(a) if a == &self.identity.identity_hash => {
                        self.mint_bounded(caller_cap, req_grants(params.as_ref()), a, Some(&parent))
                    }
                    _ => err_out(
                        501,
                        "unsupported_operation",
                        Some("delegate: same-peer-only in v1"),
                    ),
                }
            }
            "revoke" => {
                let token_h = params
                    .as_ref()
                    .and_then(|p| p.bytes_field("token"))
                    .map(|b| b.to_vec());
                let token_h = match token_h {
                    Some(t) if !is_zero(&t) => t,
                    _ => return err_out(400, "unexpected_params", Some("revoke: missing token")),
                };
                let marker = Entity::make(
                    "system/capability/revocation",
                    model::map(vec![
                        ("token", model::bytes(&token_h)),
                        ("revoked_at", Value::UInt(now_ms())),
                    ]),
                );
                let path = format!(
                    "/{}/system/capability/revocations/{}",
                    self.local_peer,
                    hex(&token_h)
                );
                self.store.bind(&path, &marker);
                ok(wire::empty_params())
            }
            "configure" => {
                let pp = params
                    .as_ref()
                    .and_then(|p| p.text_field("peer_pattern"))
                    .map(|s| s.to_string());
                let pp = match pp {
                    Some(p) => p,
                    None => {
                        return err_out(
                            400,
                            "unexpected_params",
                            Some("configure: missing peer_pattern"),
                        )
                    }
                };
                let is_hex = pp.len() == 66
                    && pp
                        .bytes()
                        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
                if !(pp == "default" || is_hex || cap::is_peer_id(&pp)) {
                    return err_out(400, "invalid_peer_pattern", Some(&pp));
                }
                if let Some(p) = &params {
                    let path = format!("/{}/system/capability/policy/{pp}", self.local_peer);
                    self.store.bind(&path, p);
                }
                ok(wire::empty_params())
            }
            _ => err_out(501, "unsupported_operation", Some(op)),
        }
    }

    fn mint_bounded(
        &self,
        caller_cap: Option<&Entity>,
        req_grants: Vec<Value>,
        grantee_hash: &[u8],
        parent: Option<&[u8]>,
    ) -> Outcome {
        let bounded = match caller_cap {
            Some(cc) => cap::requested_grants_within(&self.local_peer, &req_grants, cc),
            None => false,
        };
        if !bounded {
            return err_out(403, "scope_exceeds_authority", None);
        }
        let minted = mint_token(&self.identity, grantee_hash, parent, req_grants);
        let grant_result = Entity::make(
            "system/capability/grant",
            model::map(vec![("token", model::bytes(&minted.token.hash))]),
        );
        ok_inc(
            grant_result,
            vec![
                minted.token,
                self.identity.peer_entity.clone(),
                minted.signature,
            ],
        )
    }

    // ── handlers handler (§6.2 / §6.13(a)) — register/unregister ────────────────

    fn handlers_handler(&self, exec: &Entity) -> Outcome {
        match exec.text_field("operation").unwrap_or("") {
            "register" => self.register_handler(exec),
            "unregister" => self.unregister_handler(exec),
            op => err_out(501, "unsupported_operation", Some(op)),
        }
    }

    fn register_handler(&self, exec: &Entity) -> Outcome {
        let pattern = match register_pattern(exec) {
            Ok(p) => p,
            Err(o) => return o,
        };
        let req = match exec.entity_field("params") {
            Some(r) => r,
            None => return err_out(400, "unexpected_params", Some("register: missing params")),
        };
        if req.typ != "system/handler/register-request" {
            return err_out(
                400,
                "unexpected_params",
                Some("register expects register-request"),
            );
        }
        let manifest = req.field("manifest").cloned().unwrap_or(Value::Map(vec![]));
        let name = match model::map_get(&manifest, "name") {
            Some(Value::Text(s)) => s.clone(),
            _ => pattern.clone(),
        };
        let operations = model::map_get(&manifest, "operations")
            .cloned()
            .unwrap_or(Value::Map(vec![]));
        let expression_path = match model::map_get(&manifest, "expression_path") {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        };
        let internal_scope = model::map_get(&manifest, "internal_scope").cloned();

        // grant scope = requested_scope ?? internal_scope ?? [].
        let grant_scope: Vec<Value> = match req.field("requested_scope") {
            Some(Value::Array(arr)) => arr.clone(),
            _ => match &internal_scope {
                Some(Value::Array(arr)) => arr.clone(),
                _ => vec![],
            },
        };

        let interface_rel = format!("system/handler/{pattern}");
        // (1) handler manifest at the pattern path.
        let mut hpairs = vec![("interface", model::text(&interface_rel))];
        if let Some(ep) = &expression_path {
            hpairs.push(("expression_path", model::text(ep)));
        }
        if let Some(is) = &internal_scope {
            hpairs.push(("internal_scope", is.clone()));
        }
        let handler_e = Entity::make("system/handler", model::map(hpairs));
        self.store
            .bind(&format!("/{}/{pattern}", self.local_peer), &handler_e);

        // (2) associated types.
        if let Some(Value::Map(kvs)) = req.field("types") {
            for (k, v) in kvs {
                if let Key::Text(tn) = k {
                    let te = Entity::make("system/type", v.clone());
                    self.store
                        .bind(&format!("/{}/system/type/{tn}", self.local_peer), &te);
                }
            }
        }

        // (3)+(4) self-issued signed handler grant + grant-signature at the §3.5 pointer.
        let minted = mint_token(
            &self.identity,
            &self.identity.identity_hash,
            None,
            grant_scope,
        );
        self.store.bind(
            &format!("/{}/system/capability/grants/{pattern}", self.local_peer),
            &minted.token,
        );
        let thex = hex(&minted.token.hash);
        self.store.bind(
            &format!("/{}/system/signature/{thex}", self.local_peer),
            &minted.signature,
        );

        // (5) handler interface entity (discovery index).
        let iface_e = Entity::make(
            "system/handler/interface",
            model::map(vec![
                ("pattern", model::text(&pattern)),
                ("name", model::text(&name)),
                ("operations", operations),
            ]),
        );
        self.store
            .bind(&format!("/{}/{interface_rel}", self.local_peer), &iface_e);

        let result = Entity::make(
            "system/handler/register-result",
            Value::Map(vec![
                (Key::Text("pattern".into()), model::text(&pattern)),
                (Key::Text("grant".into()), minted.token.data.clone()),
            ]),
        );
        ok(result)
    }

    fn unregister_handler(&self, exec: &Entity) -> Outcome {
        let pattern = match register_pattern(exec) {
            Ok(p) => p,
            Err(o) => return o,
        };
        let grant_path = format!("/{}/system/capability/grants/{pattern}", self.local_peer);
        if let Some(g) = self.store.get_at(&grant_path) {
            let ghex = hex(&g.hash);
            self.store
                .unbind(&format!("/{}/system/signature/{ghex}", self.local_peer));
            self.store.unbind(&grant_path);
        }
        self.store
            .unbind(&format!("/{}/{pattern}", self.local_peer));
        self.store
            .unbind(&format!("/{}/system/handler/{pattern}", self.local_peer));
        ok(wire::empty_params())
    }

    // ── entity-native handler dispatch (§6.13(a)) ───────────────────────────────

    fn entity_native_dispatch(&self, handler_entity: &Entity) -> Outcome {
        let expr_path_rel = match handler_entity.text_field("expression_path") {
            Some(p) => p,
            None => {
                return err_out(
                    501,
                    "no_handler_body",
                    Some("registered handler has no expression_path"),
                )
            }
        };
        let expr_path = cap::canonicalize(&self.local_peer, expr_path_rel);
        let expr = match self.store.get_at(&expr_path) {
            Some(e) => e,
            None => return err_out(404, "expression_not_found", Some(&expr_path)),
        };
        if expr.typ == "compute/literal" {
            let value = expr.field("value").cloned().unwrap_or(Value::Null);
            let result = Entity::make(
                "compute/result",
                Value::Map(vec![
                    (Key::Text("value".into()), value),
                    (Key::Text("expression".into()), model::bytes(&expr.hash)),
                ]),
            );
            return ok(result);
        }
        err_out(501, "unsupported_expression", Some(&expr.typ))
    }

    // ── §7a conformance handlers ────────────────────────────────────────────────

    fn conformance_handler(&self, conn: &mut Conn, exec: &Entity, stripped: &str) -> Outcome {
        match stripped {
            "system/validate/echo" => self.echo_handler(exec),
            "system/validate/dispatch-outbound" => self.dispatch_outbound_handler(conn, exec),
            _ => err_out(501, "no_handler_body", Some(stripped)),
        }
    }

    /// §7a echo: returns the params entity verbatim (the literal round-trips out).
    fn echo_handler(&self, exec: &Entity) -> Outcome {
        match exec.entity_field("params") {
            Some(params) => ok(params),
            None => ok(wire::empty_params()),
        }
    }

    /// §7a dispatch-outbound: originate one outbound EXECUTE via the §6.11 reentry
    /// seam (`conn.outbound`) back to the caller, invoking `operation` on `target`
    /// with `value`, and return the downstream response. The reentry direction is
    /// authorized by the caller, which carries the minted authority in-band.
    fn dispatch_outbound_handler(&self, conn: &mut Conn, exec: &Entity) -> Outcome {
        let out_fn = match &conn.outbound {
            Some(f) => f.clone(),
            None => {
                return err_out(
                    503,
                    "no_outbound_seam",
                    Some("dispatch-outbound requires a live §6.11 reentry connection"),
                )
            }
        };
        let params = match exec.entity_field("params") {
            Some(p) => p,
            None => {
                return err_out(
                    400,
                    "unexpected_params",
                    Some("dispatch-outbound: missing params"),
                )
            }
        };
        let target = match params.text_field("target") {
            Some(t) => t.to_string(),
            None => return err_out(400, "unexpected_params", Some("missing target")),
        };
        let operation = match params.text_field("operation") {
            Some(o) => o.to_string(),
            None => return err_out(400, "unexpected_params", Some("missing operation")),
        };
        let value = match params.field("value") {
            Some(v) => v.clone(),
            None => return err_out(400, "unexpected_params", Some("missing value")),
        };
        let cap_e = match params.entity_field("reentry_capability") {
            Some(e) => e,
            None => return err_out(400, "unexpected_params", Some("missing reentry_capability")),
        };
        let granter_e = match params.entity_field("reentry_granter") {
            Some(e) => e,
            None => return err_out(400, "unexpected_params", Some("missing reentry_granter")),
        };
        let capsig_e = match params.entity_field("reentry_cap_signature") {
            Some(e) => e,
            None => {
                return err_out(
                    400,
                    "unexpected_params",
                    Some("missing reentry_cap_signature"),
                )
            }
        };

        // §7a.1: the `value` field IS the outbound params entity data — pass it
        // through (re-wrapping double-wraps and breaks echo's result.value).
        let inner = Entity::make("primitive/any", value);

        conn.out_counter += 1;
        let rid = format!("ro-{}", conn.out_counter);
        let resource = Value::Map(vec![(
            Key::Text("targets".into()),
            Value::Array(vec![model::text(&format!("system/handler/{target}"))]),
        )]);
        let req_exec = wire::make_execute(wire::ExecuteFields {
            request_id: &rid,
            uri: &target,
            operation: &operation,
            params: inner,
            resource: Some(resource),
            author: Some(&self.identity.identity_hash),
            capability: Some(&cap_e.hash),
        });
        let exec_sig = self.identity.sign_entity(&req_exec);
        let req_env = Envelope::with_included(req_exec, vec![cap_e, granter_e, capsig_e, exec_sig]);
        let resp = match out_fn(req_env) {
            Some(r) => r,
            None => return err_out(504, "outbound_timeout", Some("downstream did not reply")),
        };
        let status = resp.root.uint_field("status").unwrap_or(0);
        let result = resp.root.field("result").cloned().unwrap_or(Value::Null);
        ok(Entity::make(
            "primitive/any",
            Value::Map(vec![
                (Key::Text("status".into()), Value::UInt(status)),
                (Key::Text("result".into()), result),
            ]),
        ))
    }
}

// ── free helpers ────────────────────────────────────────────────────────────────

struct BootHandler {
    pattern: &'static str,
    name: &'static str,
    operations: &'static [&'static str],
}

const BOOTSTRAP_HANDLERS: &[BootHandler] = &[
    BootHandler {
        pattern: "system/tree",
        name: "Tree",
        operations: &["get", "put"],
    },
    BootHandler {
        pattern: "system/handler",
        name: "Handlers",
        operations: &["register", "unregister"],
    },
    BootHandler {
        pattern: "system/type",
        name: "Types",
        operations: &[],
    },
    BootHandler {
        pattern: "system/capability",
        name: "Capability",
        operations: &["request", "delegate", "revoke"],
    },
    BootHandler {
        pattern: "system/protocol/connect",
        name: "Connect",
        operations: &["hello", "authenticate"],
    },
];

const CONFORMANCE_HANDLERS: &[BootHandler] = &[
    BootHandler {
        pattern: "system/validate/echo",
        name: "validate-echo",
        operations: &["echo"],
    },
    BootHandler {
        pattern: "system/validate/dispatch-outbound",
        name: "validate-dispatch-outbound",
        operations: &["dispatch"],
    },
];

fn negotiation_reject(params: &Entity, key: &str, required: &str) -> bool {
    match params.field(key) {
        Some(Value::Array(arr)) => !arr
            .iter()
            .any(|it| matches!(it, Value::Text(s) if s == required)),
        _ => false, // absent → no rejection
    }
}

fn resource_target(exec: &Entity) -> Option<String> {
    let r = exec.field("resource")?;
    let targets = model::map_get(r, "targets")?;
    match targets {
        Value::Array(arr) => match arr.first() {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// §1.4 / §5.4 path-flex validation: reject null byte, non-peer-id leading slash,
/// `.`/`..`, interior empty segments. A single trailing `/` is the listing marker.
fn path_flex_ok(target: &str) -> bool {
    if target.contains('\0') {
        return false;
    }
    let mut body = target;
    if let Some(rest) = target.strip_prefix('/') {
        match rest.find('/') {
            None => return cap::is_peer_id(rest),
            Some(i) => {
                if !cap::is_peer_id(&rest[..i]) {
                    return false;
                }
                body = &rest[i + 1..];
            }
        }
    }
    let body = body.strip_suffix('/').unwrap_or(body);
    if body.is_empty() {
        return true; // bare peer-root listing
    }
    body.split('/')
        .all(|seg| !seg.is_empty() && seg != "." && seg != "..")
}

fn register_pattern(exec: &Entity) -> Result<String, Outcome> {
    let target = resource_target(exec).ok_or_else(|| {
        err_out(
            400,
            "ambiguous_resource",
            Some("register/unregister require exactly one resource target"),
        )
    })?;
    let prefix = "system/handler/";
    match target.strip_prefix(prefix) {
        Some(p) if !p.is_empty() => Ok(p.to_string()),
        _ => Err(err_out(
            400,
            "invalid_resource",
            Some("resource target MUST be system/handler/{pattern}"),
        )),
    }
}

fn req_grants(params: Option<&Entity>) -> Vec<Value> {
    match params.and_then(|p| p.field("grants")) {
        Some(Value::Array(arr)) => arr.clone(),
        _ => vec![],
    }
}

fn is_zero(b: &[u8]) -> bool {
    b.iter().all(|&c| c == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_bootstrap_seeds_types_and_handlers() {
        let p = Peer::create(CreateOptions {
            seed: [3u8; 32],
            ..Default::default()
        });
        let type_path = format!("/{}/system/type/system/peer", p.local_peer);
        assert!(p.store.get_at(&type_path).is_some());
        let connect_path = format!("/{}/system/protocol/connect", p.local_peer);
        assert!(p.store.get_at(&connect_path).is_some());
    }

    #[test]
    fn dispatch_hello_returns_hello_response() {
        let p = Peer::create(CreateOptions {
            seed: [5u8; 32],
            ..Default::default()
        });
        let mut conn = Conn::new();
        let exec = wire::make_execute(wire::ExecuteFields {
            request_id: "r1",
            uri: "system/protocol/connect",
            operation: "hello",
            params: wire::empty_params(),
            resource: None,
            author: None,
            capability: None,
        });
        let env = Envelope::new(exec);
        let resp = p.dispatch(&mut conn, &env).unwrap();
        assert_eq!(resp.root.uint_field("status"), Some(200));
        assert!(conn.issued_nonce.is_some());
    }

    #[test]
    fn echo_handler_round_trips_params() {
        let p = Peer::create(CreateOptions {
            seed: [9u8; 32],
            open_grants: true,
            conformance: true,
        });
        let iface = format!("/{}/system/handler/system/validate/echo", p.local_peer);
        assert!(p.store.get_at(&iface).is_some());
        let exec = wire::make_execute(wire::ExecuteFields {
            request_id: "e1",
            uri: "system/validate/echo",
            operation: "echo",
            params: Entity::make("primitive/any", model::map(vec![("ping", Value::UInt(42))])),
            resource: None,
            author: None,
            capability: None,
        });
        let out = p.echo_handler(&exec);
        assert_eq!(out.status, 200);
        assert_eq!(out.result.uint_field("ping"), Some(42));
    }

    #[test]
    fn deletion_marker_omitted_from_listing() {
        let p = Peer::create(CreateOptions {
            seed: [7u8; 32],
            ..Default::default()
        });
        let base = format!("/{}/app/del", p.local_peer);
        let real = Entity::make("system/test", Value::Map(vec![]));
        p.store.bind(&format!("{base}/target"), &real);
        let sib = Entity::make("system/test2", Value::Map(vec![]));
        p.store.bind(&format!("{base}/keep"), &sib);
        let out1 = p.build_listing(&format!("{base}/"));
        assert_eq!(out1.result.uint_field("count"), Some(2));
        let marker = Entity::make("system/deletion-marker", Value::Map(vec![]));
        p.store.bind(&format!("{base}/target"), &marker);
        let out2 = p.build_listing(&format!("{base}/"));
        assert_eq!(out2.result.uint_field("count"), Some(1));
    }
}
