//! dispatch.rs — the STATEFUL-SEQUENTIAL half the profile expects to leak host-side
//! (`[authored] leaks_to_host`): §6.5 op-switch + dispatch sequencing, the §4
//! handshake connection-lifecycle state machine, and the §6.9a peer-authority seed
//! bootstrap. Datalog has no sequencing and no mutable connection state, so this is
//! Rust — and its being here IS part of the seam-split finding (A-DL-013).
//!
//! CRUCIALLY, this module does NOT decide authorization. It ESTABLISHES FACTS — it
//! runs the crypto (via the C-ABI), decides the string-glob scope match, reads the
//! clock, walks the parent chain — and hands the DECISION to `authority::authorize`
//! (the §5.5 closure + §3.6 count + §5.5a conjunction + §5.2 fail-closed verdict) and
//! `authority::resolve_handler` (§6.6 longest-prefix). The host establishes; the
//! logic derives (profile `[authored] fact_flow`).

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::authority::{self, AuthFacts};
use crate::cbor_host::{self, Key, Value};
use crate::identity::{self, Identity};
use crate::model::{hex, Entity, Envelope};
use crate::store::Store;

/// §4.10(b) max capability-chain depth (recommended default 64).
pub const MAX_CHAIN_DEPTH: usize = 64;

/// §4.5 negotiation — the content_hash_format families this peer accepts (the §9.1
/// SHA-256 floor + the validated SHA-384 agility name). A hello advertising a
/// non-empty `hash_formats` set disjoint from these is rejected.
const SUPPORTED_HASH_FORMATS: &[&str] = &["ecfv1-sha256", "ecfv1-sha384"];
/// §1.5 / §9.1 — this peer's own signing key_type (the Ed25519 floor). A hello
/// whose `key_types` accept-set excludes it cannot verify our signatures → reject.
const LOCAL_KEY_TYPE: &str = "ed25519";

/// An outbound-reentry hook (§6.11): originate a request over the live inbound
/// connection, return the correlated response.
pub type OutboundFn = dyn Fn(Envelope) -> Option<Envelope> + Send + Sync;

/// Per-connection state (§4.2) — the host's §4 handshake state machine.
#[derive(Default)]
pub struct Conn {
    pub established: bool,
    pub issued_nonce: Option<[u8; 32]>,
    pub hello_peer_id: Option<String>,
    pub outbound: Option<Arc<OutboundFn>>,
    pub out_counter: u32,
}

impl Conn {
    pub fn new() -> Conn {
        Conn::default()
    }
}

/// content-addressed mint timestamp — MILLISECONDS (A-PD-016: second-truncation
/// aliases same-scope same-second mints → the revoke/session-floor probe cascade).
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn random_nonce() -> [u8; 32] {
    use std::io::Read;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    let t = now_ms();
    let d = crate::codec_ffi::sha256(&t.to_le_bytes()).unwrap_or([0u8; 32]);
    buf.copy_from_slice(&d);
    buf
}

// ── the peer ─────────────────────────────────────────────────────────────────

pub struct Peer {
    pub identity: Identity,
    pub store: Store,
    pub local_peer: String,
    pub open_grants: bool,
    pub conformance: bool,
}

#[derive(Default)]
pub struct CreateOptions {
    pub seed: [u8; 32],
    pub open_grants: bool,
    pub conformance: bool,
}

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
fn err_out(status: u64, code: &str) -> Outcome {
    Outcome {
        status,
        result: error_result(code),
        included: vec![],
    }
}

/// §6.2: `"system"` itself or any `"system/..."` prefix is reserved for system
/// handlers; user-installed handlers MUST NOT register there.
fn is_reserved_system_pattern(pattern: &str) -> bool {
    pattern == "system" || pattern.starts_with("system/")
}

fn error_result(code: &str) -> Entity {
    Entity::make(
        "system/protocol/error",
        cbor_host::map(vec![("code", cbor_host::text(code))]),
    )
}
pub fn empty_params() -> Entity {
    Entity::make("primitive/any", Value::Map(vec![]))
}
fn make_response(request_id: &str, status: u64, result: &Entity) -> Entity {
    Entity::make(
        "system/protocol/execute/response",
        Value::Map(vec![
            (Key::Text("request_id".into()), cbor_host::text(request_id)),
            (Key::Text("status".into()), Value::UInt(status)),
            (Key::Text("result".into()), result.to_cbor()),
        ]),
    )
}

// ── grant construction (§4.4 / §5.4 / §6.9a) ───────────────────────────────────

fn scope_val(incl: &[&str]) -> Value {
    cbor_host::map(vec![("include", cbor_host::text_array(incl))])
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
    cbor_host::map(pairs)
}
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
/// A-PD-017: the open/debug seed needs the DUAL resource form `["*", "/*/*"]` —
/// bare-star is granter-local (§5.5a), never universal.
fn open_grants_scope() -> Vec<Value> {
    vec![grant_val(&["*"], &["*", "/*/*"], &["*"], Some(&["*"]))]
}
fn owner_grants(local_peer: &str) -> Vec<Value> {
    vec![grant_val(&["*"], &["*"], &["*"], Some(&[local_peer]))]
}

struct Minted {
    token: Entity,
    signature: Entity,
}
/// `mint_token_at` at the current instant with no §5.6 ceiling. Used by the paths that
/// mint a self-issued grant from local authority (bootstrap, handler registration, the
/// §4.4 handshake), where no MIN_DEFINED term is in play.
fn mint_token(
    id: &Identity,
    grantee_hash: &[u8],
    parent: Option<&[u8]>,
    grants: Vec<Value>,
) -> Minted {
    mint_token_at(id, now_ms(), grantee_hash, parent, grants, None)
}

/// Mint at a caller-supplied instant, carrying §5.6's MIN_DEFINED ceiling.
///
/// `expires_at = None` means no term was defined and the token genuinely has no expiry
/// (the ONLY "no bound" spelling). A present value is emitted verbatim — including one
/// equal to `created_at`, which §5.6 rule 2 requires for `ttl_ms == 0` and which means
/// "already expired at every observable instant", not "unbounded".
///
/// `created_at` is supplied rather than sampled here so a computed expiry is guaranteed to
/// be relative to the SAME instant that lands in the token; sampling the clock twice skews
/// the two.
fn mint_token_at(
    id: &Identity,
    created_at: u64,
    grantee_hash: &[u8],
    parent: Option<&[u8]>,
    grants: Vec<Value>,
    expires_at: Option<u64>,
) -> Minted {
    let mut pairs = vec![
        (
            Key::Text("granter".into()),
            cbor_host::bytes(&id.identity_hash),
        ),
        (Key::Text("grantee".into()), cbor_host::bytes(grantee_hash)),
        (Key::Text("grants".into()), Value::Array(grants)),
        (Key::Text("created_at".into()), Value::UInt(created_at)),
    ];
    if let Some(ex) = expires_at {
        pairs.push((Key::Text("expires_at".into()), Value::UInt(ex)));
    }
    if let Some(ph) = parent {
        pairs.push((Key::Text("parent".into()), cbor_host::bytes(ph)));
    }
    let token = Entity::make("system/capability/token", Value::Map(pairs));
    let signature = id.sign_entity(&token);
    Minted { token, signature }
}

/// §5.6 rule 1: convert a DURATION term (ttl_ms) to an absolute timestamp relative to
/// `created_at`. Rule 3: a conversion that is not representable is treated as ABSENT
/// (`None`) exactly as a null term is — it MUST NOT wrap and MUST NOT saturate to a
/// representable maximum, since saturation manufactures expires_at == 2^64-1, a finite
/// bound no reader can distinguish from a deliberate one.
///
/// `ttl == 0` is NOT a special case and deliberately so: rule 2 makes 0 a DEFINED value
/// yielding `created_at` (expire immediately). The absent field is the only "no bound"
/// spelling, and falling out of the arithmetic is what keeps the two from collapsing.
fn add_ttl(created_at: u64, ttl: u64) -> Option<u64> {
    created_at.checked_add(ttl)
}

/// §6.2 CAP-6a: every temporal field on a RECEIVED token is either absent (legal) or
/// representable as a `u64`.
///
/// This is the reader-side half of CAP-6 and it is where a peer fails OPEN. `uint_field`
/// answers `None` BOTH when a field is ABSENT and when it is PRESENT but not a `Value::UInt`
/// — a negative integer or a bignum — so a token carrying `expires_at: -1` silently skipped
/// the expiry check and was honored with 200. §6.2 CAP-6a is explicit: such a token "is
/// malformed. A verifier MUST refuse it and MUST NOT treat the unrepresentable field as
/// absent." An absent expires_at stays legal and is NOT rejected here.
///
/// The guard reads `field` (which distinguishes absent from present) rather than
/// `uint_field` (which does not) — that disagreement IS the check. `u64` is the wire's
/// domain, so a `Value::UInt` is representable by construction and needs no range test.
fn temporal_fields_representable(tok: &Entity) -> bool {
    ["expires_at", "not_before", "created_at"]
        .iter()
        .all(|k| match tok.field(k) {
            None => true,
            Some(Value::UInt(_)) => true,
            Some(_) => false,
        })
}

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

impl Peer {
    pub fn create(opts: CreateOptions) -> Peer {
        let identity = Identity::of_seed(opts.seed);
        let local_peer = identity.peer_id.clone();
        let peer = Peer {
            identity,
            store: Store::new(),
            local_peer,
            open_grants: opts.open_grants,
            conformance: opts.conformance,
        };
        peer.store.put_entity(&peer.identity.peer_entity);
        peer.store.bind(
            &format!("/{}/system/peer/self", peer.local_peer),
            &peer.identity.peer_entity,
        );
        for bh in BOOTSTRAP_HANDLERS {
            peer.bootstrap_handler(bh);
        }
        // §9.5 Core Type Floor: publish the 53 core type definitions at
        // `system/type/<name>`, rendered natively (crate::types) — the type floor a
        // `--profile core` peer must serve via tree get (durable keystone lesson).
        for def in crate::types::all_core_types() {
            peer.store.bind(
                &format!("/{}/{}", peer.local_peer, def.tree_path()),
                &def.to_entity(),
            );
        }
        if peer.conformance {
            for bh in CONFORMANCE_HANDLERS {
                peer.bootstrap_handler(bh);
            }
        }
        // §6.9a seed bootstrap: owner cap + default policy entry.
        let policy_base = format!("/{}/system/capability/policy/", peer.local_peer);
        let owner = mint_token(
            &peer.identity,
            &peer.identity.identity_hash,
            None,
            owner_grants(&peer.local_peer),
        );
        peer.store.bind(
            &format!("{policy_base}{}", hex(&peer.identity.identity_hash)),
            &owner.token,
        );
        peer.store.bind(
            &format!(
                "/{}/system/signature/{}",
                peer.local_peer,
                hex(&owner.token.hash)
            ),
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
                (Key::Text("peer_pattern".into()), cbor_host::text("default")),
                (Key::Text("grants".into()), Value::Array(default_grants)),
            ]),
        );
        peer.store
            .bind(&format!("{policy_base}default"), &default_entry);
        peer
    }

    fn bootstrap_handler(&self, bh: &BootHandler) {
        let handler_e = Entity::make(
            "system/handler",
            cbor_host::map(vec![(
                "interface",
                cbor_host::text(&format!("system/handler/{}", bh.pattern)),
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
            cbor_host::map(vec![
                ("pattern", cbor_host::text(bh.pattern)),
                ("name", cbor_host::text(bh.name)),
                ("operations", ops_map),
            ]),
        );
        self.store.bind(
            &format!("/{}/system/handler/{}", self.local_peer, bh.pattern),
            &iface_e,
        );
    }

    // ── dispatch (§6.5) ─────────────────────────────────────────────────────────

    /// Materialize an inbound envelope into a response envelope (§3.3). `None` for a
    /// non-EXECUTE root (server ignores it). Never panics on a protocol error — every
    /// failure is a status, the connection stays alive (§4.9 deliver-or-signal).
    pub fn dispatch(&self, conn: &mut Conn, env: &Envelope) -> Option<Envelope> {
        if env.root.typ != "system/protocol/execute" {
            return None;
        }
        let request_id = env.root.text_field("request_id").unwrap_or("").to_string();
        let outcome = self.dispatch_outcome(conn, env);
        let mut response =
            Envelope::new(make_response(&request_id, outcome.status, &outcome.result));
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

        // §5.2 authn (host crypto → 401) + §4.10(b) chain-depth (→ 400) + the
        // ascent-derived authz verdict (→ 403). The authz DECISION is Datalog's.
        match self.verify_request(env) {
            ReqVerdict::AuthnFail => return err_out(401, "authentication_failed"),
            ReqVerdict::UnresolvableGrantee => return err_out(401, "unresolvable_grantee"),
            ReqVerdict::ChainTooDeep => return err_out(400, "chain_depth_exceeded"),
            ReqVerdict::AuthzDeny => return err_out(403, "capability_denied"),
            ReqVerdict::Allow => {}
        }

        // §6.6 handler resolution as the Datalog longest-prefix selection.
        let path = canonicalize(&self.local_peer, &normalize_uri(&uri));
        if extract_peer(&self.local_peer, &path) != self.local_peer {
            return err_out(404, "handler_not_found");
        }
        let pattern = match self.resolve_handler(&path) {
            Some(p) => p,
            None => return err_out(404, "handler_not_found"),
        };
        let stripped = self.strip_local(&pattern);
        let caller_cap = exec
            .bytes_field("capability")
            .and_then(|ch| env.included_get(ch).cloned());
        match stripped.as_str() {
            "system/tree" => self.tree_handler(exec),
            "system/capability" => self.capability_handler(exec, caller_cap.as_ref()),
            "system/handler" => self.handlers_handler(exec),
            "system/type" => err_out(501, "unsupported_operation"),
            _ => {
                if self.conformance && stripped.starts_with("system/validate/") {
                    return self.conformance_handler(conn, exec, &stripped);
                }
                err_out(501, "no_handler_body")
            }
        }
    }

    /// §6.5 signature ingestion — persist cap/identity/handshake signatures + signer
    /// peers so the chain-walk resolves them. SCOPING (A-IO-022 / A-RX-014, memory-
    /// primary): the transient per-request EXECUTE signature (target == the root
    /// EXECUTE hash) is consumed inline by `verify_request` and never looked up
    /// post-dispatch — binding one unique entity per request grows the store
    /// unboundedly. Ingest reused sigs (cap/identity/handshake), skip the request sig.
    fn ingest_signatures(&self, env: &Envelope) {
        let exec_hash = env.root.hash.as_slice();
        for e in env.included.values() {
            if e.typ != "system/signature" {
                continue;
            }
            // skip the transient request signature (target == this EXECUTE).
            if e.bytes_field("target") == Some(exec_hash) {
                continue;
            }
            self.store.put_entity(e);
            let signer_h = match e.bytes_field("signer") {
                Some(s) => s.to_vec(),
                None => continue,
            };
            if let Some(sp) = env.included_get(&signer_h) {
                self.store.put_entity(sp);
                if let (Some(t), Some(pk)) = (e.bytes_field("target"), sp.bytes_field("public_key"))
                {
                    let pid = identity::peer_id_of_pubkey(pk);
                    self.store
                        .bind(&format!("/{pid}/system/signature/{}", hex(t)), e);
                }
            }
        }
    }

    fn strip_local(&self, pattern: &str) -> String {
        pattern
            .strip_prefix(&format!("/{}/", self.local_peer))
            .map(|s| s.to_string())
            .unwrap_or_else(|| pattern.to_string())
    }

    /// §6.6 — gather bound `system/handler` patterns that are prefixes of `path`,
    /// then let Datalog pick the longest (the tree-walk as a rule, not a host loop).
    fn resolve_handler(&self, path: &str) -> Option<String> {
        // Enumerate handler-bearing ancestor prefixes; the host provides MEMBERSHIP,
        // the Datalog `Resolver` provides the longest-prefix SELECTION.
        let mut patterns = Vec::new();
        let mut end = path.len();
        loop {
            let prefix = &path[..end];
            if let Some(e) = self.store.get_at(prefix) {
                if e.typ == "system/handler" {
                    patterns.push(prefix.to_string());
                }
            }
            match path[..end].rfind('/') {
                Some(i) => end = i,
                None => break,
            }
        }
        authority::resolve_handler(&patterns, path)
    }

    // ── §5.2 verify_request — host authn + ascent-derived authz ─────────────────

    fn verify_request(&self, env: &Envelope) -> ReqVerdict {
        let exec = &env.root;
        // 1. authn (host crypto): a signature over the EXECUTE by its author.
        let sgn = match find_signature(env, &exec.hash) {
            Some(s) => s,
            None => return ReqVerdict::AuthnFail,
        };
        let author_h = match exec.bytes_field("author") {
            Some(a) => a.to_vec(),
            None => return ReqVerdict::AuthnFail,
        };
        if sgn.bytes_field("signer") != Some(author_h.as_slice()) {
            return ReqVerdict::AuthnFail;
        }
        let author = match env.included_get(&author_h) {
            Some(a) => a.clone(),
            None => return ReqVerdict::AuthnFail,
        };
        if !identity::verify_signature(&sgn, &author) {
            return ReqVerdict::AuthnFail;
        }
        // 2. capability present.
        let cap_h = match exec.bytes_field("capability") {
            Some(c) => c.to_vec(),
            None => return ReqVerdict::AuthzDeny,
        };
        let leaf = match env.included_get(&cap_h) {
            Some(c) => c.clone(),
            None => return ReqVerdict::AuthzDeny,
        };
        // 3. §4.10(b) structural chain-depth pre-check BEFORE the authz walk.
        if self.chain_exceeds_depth(env, &leaf) {
            return ReqVerdict::ChainTooDeep;
        }
        // 4. build FACTS (host: crypto/glob/clock/structure) → authorize (ascent).
        match self.build_auth_facts(env, exec, &leaf, &author_h) {
            FactResult::Unresolvable => ReqVerdict::UnresolvableGrantee,
            FactResult::Facts(facts) => {
                if authority::authorize(*facts) {
                    ReqVerdict::Allow
                } else {
                    ReqVerdict::AuthzDeny
                }
            }
        }
    }

    /// §4.10(b) structural pre-check: walk parent pointers counting depth WITHOUT
    /// verifying signatures. An over-deep chain → `400 chain_depth_exceeded`
    /// (structural excess, NOT 403). An unreachable parent is NOT a depth problem.
    fn chain_exceeds_depth(&self, env: &Envelope, leaf: &Entity) -> bool {
        let mut current = leaf.clone();
        let mut depth = 0usize;
        loop {
            if depth > MAX_CHAIN_DEPTH {
                return true;
            }
            let ph = match current.bytes_field("parent") {
                Some(p) => p.to_vec(),
                None => return false,
            };
            match self.resolve(env, &ph) {
                Some(p) => current = p,
                None => return false,
            }
            depth += 1;
        }
    }

    fn resolve(&self, env: &Envelope, h: &[u8]) -> Option<Entity> {
        env.included_get(h)
            .cloned()
            .or_else(|| self.store.get_by_hash(h))
    }

    /// Establish the per-request EDB from the presented chain (the SEAM half). The
    /// host does ALL the crypto (via C-ABI), glob (string), clock, and structural
    /// checks here; the returned [`AuthFacts`] is pure readable facts the engine
    /// combines. Returns `Unresolvable` for the §5.5 grantee carve-out (→ 401).
    fn build_auth_facts(
        &self,
        env: &Envelope,
        exec: &Entity,
        leaf: &Entity,
        author_h: &[u8],
    ) -> FactResult {
        let mut f = AuthFacts::default();
        let leaf_id = hex(&leaf.hash);
        f.request_cap.push(leaf_id.clone());

        // grantee binding (§5.2): leaf.grantee == author.
        if leaf.bytes_field("grantee") == Some(author_h) {
            f.grantee_is_author.push(leaf_id.clone());
        }
        // revocation (§5.1): leaf + root.
        if !self.is_revoked(env, leaf) {
            f.not_revoked.push(leaf_id.clone());
        }
        // §5.5a scope facts on the LEAF cap (the host decides the glob per dimension).
        self.push_scope_facts(exec, leaf, &leaf_id, &mut f);

        // walk the chain, asserting verified_root / verified_link (host crypto+clock).
        let mut current = leaf.clone();
        let now = now_ms();
        loop {
            let cur_id = hex(&current.hash);
            // grantee resolvability (§5.5) → 401 carve-out.
            match current.bytes_field("grantee") {
                Some(g) => {
                    if self.resolve(env, g).is_none() {
                        return FactResult::Unresolvable;
                    }
                }
                None => return FactResult::Unresolvable,
            }
            match granter_of(&current) {
                Granter::Multi { signers, threshold } => {
                    // §3.6 M3 structure + §5.5 M6 local-in-quorum + temporal.
                    if self.multisig_root_ok(env, &current, &signers, threshold, now) {
                        f.multisig_root.push(cur_id.clone());
                        f.threshold.push((cur_id.clone(), threshold));
                        for s in &signers {
                            if self.signer_signed(env, &current, s) {
                                f.multisig_signer.push((cur_id.clone(), hex(s)));
                            }
                        }
                    }
                    break; // multi-sig is root-only.
                }
                Granter::Single(gh) => {
                    let granter = match self.resolve(env, &gh) {
                        Some(g) => g,
                        None => break, // unreachable granter → not a root, no fact → deny
                    };
                    let sig_ok = find_signature(env, &current.hash)
                        .map(|s| {
                            s.bytes_field("signer") == Some(gh.as_slice())
                                && identity::verify_signature(&s, &granter)
                        })
                        .unwrap_or(false);
                    let temporal_ok = temporal_valid(&current, now);
                    match current.bytes_field("parent").map(|b| b.to_vec()) {
                        None => {
                            // ROOT: granter must be the local peer.
                            let is_local = granter
                                .bytes_field("public_key")
                                .map(|pk| identity::peer_id_of_pubkey(pk) == self.local_peer)
                                .unwrap_or(false);
                            if sig_ok && temporal_ok && is_local {
                                f.verified_root.push(cur_id.clone());
                            }
                            break;
                        }
                        Some(ph) => {
                            let parent = match self.resolve(env, &ph) {
                                Some(p) => p,
                                None => break,
                            };
                            // §5.6 attenuation + §5.7 caveats (host structural check).
                            // §5.5a surface 2: each side canonicalizes against THAT
                            // LINK'S OWN granter, not the verifier's.
                            let child_frame = self.granter_frame(&current);
                            let parent_frame = self.granter_frame(&parent);
                            let atten = is_attenuated(
                                &self.local_peer,
                                &child_frame,
                                &parent_frame,
                                &current,
                                &parent,
                            ) && check_caveats(&parent, &current);
                            let link_grantee_ok =
                                parent.bytes_field("grantee") == current.bytes_field("granter");
                            if sig_ok && temporal_ok && atten && link_grantee_ok {
                                f.verified_link.push((cur_id.clone(), hex(&ph)));
                            }
                            current = parent;
                        }
                    }
                }
            }
        }
        FactResult::Facts(Box::new(f))
    }

    fn push_scope_facts(&self, exec: &Entity, leaf: &Entity, leaf_id: &str, f: &mut AuthFacts) {
        let operation = exec.text_field("operation").unwrap_or("");
        let uri = exec.text_field("uri").unwrap_or("");
        let target_peer = extract_peer(&self.local_peer, uri);
        let resource = exec.field("resource");
        let granter_peer = self.granter_frame(leaf);
        let grants = match leaf.field("grants") {
            Some(Value::Array(arr)) => arr.clone(),
            _ => vec![],
        };
        for (i, g) in grants.iter().enumerate() {
            let gi = i as u32;
            f.scope_grant.push((leaf_id.to_string(), gi));
            let sc = |key: &str| scope_of(cbor_host::map_get(g, key));
            if matches_scope(&self.local_peer, operation, &sc("operations"), ScopeKind::Id) {
                f.g_op.push((leaf_id.to_string(), gi));
            }
            // handler pattern: for the wire request the "handler" dimension is the
            // canonicalized uri's handler (§5.4). Use the target path.
            let handler_pattern = strip_peer(uri);
            if matches_scope(&self.local_peer, &handler_pattern, &sc("handlers"), ScopeKind::Path) {
                f.g_handler.push((leaf_id.to_string(), gi));
            }
            let peers = match cbor_host::map_get(g, "peers") {
                Some(pv) => scope_of(Some(pv)),
                None => Scope {
                    incl: vec![self.local_peer.clone()],
                    excl: vec![],
                },
            };
            if matches_scope(&self.local_peer, target_peer, &peers, ScopeKind::Id) {
                f.g_peer.push((leaf_id.to_string(), gi));
            }
            let r_ok = match resource {
                Some(r) => {
                    check_resource_scope(&self.local_peer, &granter_peer, r, &sc("resources"))
                }
                None => true,
            };
            if r_ok {
                f.g_resource.push((leaf_id.to_string(), gi));
            }
        }
    }

    fn granter_frame(&self, cap: &Entity) -> String {
        match cap.field("granter") {
            Some(Value::Bytes(gh)) => self
                .store
                .get_by_hash(gh)
                .and_then(|g| g.bytes_field("public_key").map(identity::peer_id_of_pubkey))
                .unwrap_or_else(|| self.local_peer.clone()),
            _ => self.local_peer.clone(),
        }
    }

    fn multisig_root_ok(
        &self,
        env: &Envelope,
        cap: &Entity,
        signers: &[Vec<u8>],
        threshold: u64,
        now: u64,
    ) -> bool {
        let n = signers.len();
        if cap.bytes_field("parent").is_some() || n < 2 || threshold < 2 || threshold > n as u64 {
            return false;
        }
        if has_dupes(signers) {
            return false;
        }
        let local_in = signers.iter().any(|s| {
            self.resolve(env, s)
                .and_then(|p| p.bytes_field("public_key").map(identity::peer_id_of_pubkey))
                .as_deref()
                == Some(&self.local_peer)
        });
        local_in && temporal_valid(cap, now)
    }

    fn signer_signed(&self, env: &Envelope, cap: &Entity, signer: &[u8]) -> bool {
        let signer_peer = match self.resolve(env, signer) {
            Some(p) => p,
            None => return false,
        };
        env.included.values().any(|s| {
            s.typ == "system/signature"
                && s.bytes_field("target") == Some(cap.hash.as_slice())
                && s.bytes_field("signer") == Some(signer)
                && identity::verify_signature(s, &signer_peer)
        })
    }

    fn is_revoked(&self, env: &Envelope, cap: &Entity) -> bool {
        // root hash (walk parents) + leaf hash.
        let mut current = cap.clone();
        let mut depth = 0;
        let root_hash = loop {
            match current.bytes_field("parent").map(|b| b.to_vec()) {
                Some(ph) if depth <= MAX_CHAIN_DEPTH => match self.resolve(env, &ph) {
                    Some(p) => {
                        current = p;
                        depth += 1;
                    }
                    None => break current.hash.clone(),
                },
                _ => break current.hash.clone(),
            }
        };
        let check = |h: &[u8]| {
            self.store
                .get_at(&format!(
                    "/{}/system/capability/revocations/{}",
                    self.local_peer,
                    hex(h)
                ))
                .is_some()
        };
        check(&cap.hash) || check(&root_hash)
    }

    // ── connect handler (§4.1, §4.6) — the host state machine ───────────────────

    fn connect_handler(&self, conn: &mut Conn, exec: &Entity, env: &Envelope) -> Outcome {
        match exec.text_field("operation").unwrap_or("") {
            "hello" => {
                if conn.established {
                    return err_out(409, "connection_already_established");
                }
                if let Some(params) = exec.entity_field("params") {
                    if let Some(pid) = params.text_field("peer_id") {
                        conn.hello_peer_id = Some(pid.to_string());
                    }
                    // §4.5 negotiation: a non-empty advertisement with no overlap is a
                    // hard reject. hash_formats must overlap our supported set; the
                    // key_types accept-set must include our own signing key_type.
                    let fmts = text_list(params.field("hash_formats"));
                    if !fmts.is_empty()
                        && !fmts
                            .iter()
                            .any(|f| SUPPORTED_HASH_FORMATS.contains(&f.as_str()))
                    {
                        return err_out(400, "incompatible_hash_format");
                    }
                    let kts = text_list(params.field("key_types"));
                    if !kts.is_empty() && !kts.iter().any(|k| k == LOCAL_KEY_TYPE) {
                        return err_out(400, "unsupported_key_type");
                    }
                }
                let nonce = random_nonce();
                conn.issued_nonce = Some(nonce);
                ok(Entity::make(
                    "system/protocol/connect/hello",
                    cbor_host::map(vec![
                        ("peer_id", cbor_host::text(&self.local_peer)),
                        ("nonce", cbor_host::bytes(&nonce)),
                        ("protocols", cbor_host::text_array(&["entity-core/1.0"])),
                        ("timestamp", Value::UInt(now_ms())),
                        ("hash_formats", cbor_host::text_array(&["ecfv1-sha256"])),
                        ("key_types", cbor_host::text_array(&["ed25519"])),
                    ]),
                ))
            }
            "authenticate" => {
                if conn.established {
                    // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the
                    // consumed single-use nonce — pinned to 401 invalid_nonce, not a
                    // 409 state-conflict which under-signals the replay.
                    return err_out(401, "invalid_nonce");
                }
                let issued = match conn.issued_nonce {
                    Some(n) => n,
                    None => return err_out(401, "invalid_nonce"),
                };
                let auth = match exec.entity_field("params") {
                    Some(a) => a,
                    None => return err_out(401, "authentication_failed"),
                };
                if auth.bytes_field("nonce") != Some(issued.as_slice()) {
                    return err_out(401, "invalid_nonce");
                }
                // §4.7 / v7.66 §4.4 surface 6: reject an unsupported key_type at the
                // handshake boundary. The claimed peer_id encodes its key_type family
                // (§1.5); anything but the Ed25519 floor (0x01) is unnegotiable → 400
                // (NOT an identity_mismatch), before the peer_id-binding check.
                if let Some(claimed) = auth.text_field("peer_id") {
                    if let Ok((kt, _ht, _d)) = crate::codec_ffi::peerid_parse(claimed) {
                        if kt != 1 {
                            return err_out(400, "unsupported_key_type");
                        }
                    }
                }
                let public_key = match auth.bytes_field("public_key") {
                    Some(pk) if pk.len() == 32 => pk.to_vec(),
                    _ => return err_out(400, "unsupported_key_type"),
                };
                // proof of possession: the auth signature over auth.hash.
                let sig_ok = find_signature(env, &auth.hash)
                    .map(|s| {
                        identity::verify_signature(
                            &s,
                            &identity::peer_entity_of_pubkey(&public_key),
                        )
                    })
                    .unwrap_or(false);
                if !sig_ok {
                    return err_out(401, "authentication_failed");
                }
                let derived = identity::peer_id_of_pubkey(&public_key);
                if auth.text_field("peer_id") != Some(&derived) {
                    return err_out(401, "identity_mismatch");
                }
                if let Some(hp) = &conn.hello_peer_id {
                    if hp != &derived {
                        return err_out(401, "identity_mismatch");
                    }
                }
                // mint the seed capability (§4.4 / §6.9a).
                let remote_peer = identity::peer_entity_of_pubkey(&public_key);
                let grants = self.derive_seed_grants(&remote_peer);
                let minted = mint_token(&self.identity, &remote_peer.hash, None, grants);
                conn.established = true;
                let grant_result = Entity::make(
                    "system/capability/grant",
                    cbor_host::map(vec![("token", cbor_host::bytes(&minted.token.hash))]),
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
            op => {
                let _ = op;
                err_out(501, "unsupported_operation")
            }
        }
    }

    fn derive_seed_grants(&self, remote_peer: &Entity) -> Vec<Value> {
        let base = format!("/{}/system/capability/policy/", self.local_peer);
        let entry = self
            .store
            .get_at(&format!("{base}{}", hex(&remote_peer.hash)))
            .or_else(|| self.store.get_at(&format!("{base}default")));
        let mut out = discovery_floor();
        if let Some(e) = entry {
            if let Some(Value::Array(arr)) = e.field("grants") {
                out.extend(arr.clone());
            }
        }
        out
    }

    // ── tree handler (§6.3) — minimal get/put ───────────────────────────────────

    fn tree_handler(&self, exec: &Entity) -> Outcome {
        let op = exec.text_field("operation").unwrap_or("");
        let target = resource_target(exec);
        match op {
            "get" => {
                let target = match target {
                    None => return self.build_listing(&format!("/{}/", self.local_peer)),
                    Some(t) => t,
                };
                // §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1 path validity.
                if !valid_caller_target(&target) {
                    return err_out(400, "invalid_path");
                }
                if target.is_empty() || target.ends_with('/') {
                    return self.build_listing(&canonicalize(&self.local_peer, &target));
                }
                let path = canonicalize(&self.local_peer, &target);
                match self.store.get_at(&path) {
                    Some(e) => ok(e),
                    None => err_out(404, "not_found"),
                }
            }
            "put" => {
                let target = match target {
                    Some(t) => t,
                    None => return err_out(400, "ambiguous_resource"),
                };
                // §1.4 path validity — reject before the write reaches the store.
                if !valid_caller_target(&target) {
                    return err_out(400, "invalid_path");
                }
                let path = canonicalize(&self.local_peer, &target);
                let params = exec.entity_field("params");
                let expected = params
                    .as_ref()
                    .and_then(|p| p.bytes_field("expected_hash").map(|b| b.to_vec()));
                let entity = params.as_ref().and_then(|p| p.entity_field("entity"));
                match entity {
                    Some(e) => {
                        // §3.9 CAS: a present expected_hash is a conditional write —
                        // zero hash = create-only (must be absent), non-zero = must
                        // equal the current binding, else 409 hash_mismatch.
                        if let Some(exp) = &expected {
                            if !self.cas_ok(&path, exp) {
                                return err_out(409, "hash_mismatch");
                            }
                        }
                        // A deletion-marker binds normally; the LISTING omits it
                        // (§6.3 / CORE-TREE-DELETE-1) — the marked leaf reads as absent.
                        self.store.bind(&path, &e);
                        ok(identity::hash_entity(&e.hash))
                    }
                    None => {
                        // Remove binding (§6.3). CAS-checked when a non-zero
                        // expected_hash is present.
                        if let Some(exp) = &expected {
                            if !is_zero_hash(exp) && !self.cas_ok(&path, exp) {
                                return err_out(409, "hash_mismatch");
                            }
                        }
                        self.store.unbind(&path);
                        ok(empty_params())
                    }
                }
            }
            _ => err_out(501, "unsupported_operation"),
        }
    }

    /// §3.9 conditional-write predicate. Zero `expected` = create-only (succeeds iff
    /// nothing is bound at `path`); a non-zero `expected` must equal the current
    /// binding hash. Mirrors the reference `compareAndPut`.
    fn cas_ok(&self, path: &str, expected: &[u8]) -> bool {
        let current = self.store.hash_at(path);
        if is_zero_hash(expected) {
            current.is_none()
        } else {
            current.as_deref() == Some(expected)
        }
    }

    fn build_listing(&self, path: &str) -> Outcome {
        let entries = self.store.listing(path);
        let mut entry_pairs: Vec<(Key, Value)> = vec![];
        let mut shown = 0u64;
        for le in &entries {
            // §6.3 / v7.72 §9.5a CORE-TREE-DELETE-1: a leaf bound to a
            // system/deletion-marker reads as absent → omit it from the listing. A
            // marker that still prefixes deeper live paths survives as a pure prefix
            // (has_children) with a null hash.
            if let Some(h) = &le.hash {
                if self.store.get_by_hash(h).map(|e| e.typ) == Some("system/deletion-marker".into())
                {
                    if !le.has_children {
                        continue;
                    }
                    let e = Entity::make(
                        "system/tree/listing-entry",
                        cbor_host::map(vec![("has_children", Value::Bool(true))]),
                    );
                    entry_pairs.push((Key::Text(le.seg.clone()), e.to_cbor()));
                    shown += 1;
                    continue;
                }
            }
            let mut fields = vec![("has_children", Value::Bool(le.has_children))];
            if let Some(h) = &le.hash {
                fields.push(("hash", cbor_host::bytes(h)));
            }
            let e = Entity::make("system/tree/listing-entry", cbor_host::map(fields));
            entry_pairs.push((Key::Text(le.seg.clone()), e.to_cbor()));
            shown += 1;
        }
        ok(Entity::make(
            "system/tree/listing",
            Value::Map(vec![
                (Key::Text("path".into()), cbor_host::text(path)),
                (Key::Text("entries".into()), Value::Map(entry_pairs)),
                (Key::Text("count".into()), Value::UInt(shown)),
            ]),
        ))
    }

    // ── capability handler (§6.2) — request/delegate/revoke ─────────────────────

    fn capability_handler(&self, exec: &Entity, caller_cap: Option<&Entity>) -> Outcome {
        let op = exec.text_field("operation").unwrap_or("");
        let params = exec.entity_field("params");
        let author = exec.bytes_field("author").map(|b| b.to_vec());
        match op {
            "request" => {
                let grantee = match author {
                    Some(a) => a,
                    None => return err_out(403, "capability_denied"),
                };
                let req = req_grants(params.as_ref());
                let within = caller_cap
                    .map(|cc| requested_grants_within(&self.local_peer, &req, cc))
                    .unwrap_or(false);
                if !within {
                    return err_out(403, "scope_exceeds_authority");
                }
                // §5.6 MIN_DEFINED temporal ceiling (CAP-5 / CAP-6). Sample created_at
                // ONCE and convert the duration term against that same instant.
                //
                // Note what this is NOT: an authorization decision. An over-long ttl_ms
                // from a bounded caller MINTS a clamped token and returns 200 —
                // "rejecting it is non-conformant" (§5.6). The bound exists because
                // `request` mints a ROOT token (parent: null), so §5.6's parent-child
                // attenuation never reaches it; without this clamp, temporal attenuation
                // is the one dimension a requester could escape.
                let created_at = now_ms();
                let ceiling = [
                    caller_cap.and_then(|cc| cc.uint_field("expires_at")), // absolute
                    params
                        .as_ref()
                        .and_then(|p| p.uint_field("ttl_ms"))
                        .and_then(|t| add_ttl(created_at, t)), // duration
                ]
                .into_iter()
                .flatten()
                .min();
                let minted =
                    mint_token_at(&self.identity, created_at, &grantee, None, req, ceiling);
                let grant = Entity::make(
                    "system/capability/grant",
                    cbor_host::map(vec![("token", cbor_host::bytes(&minted.token.hash))]),
                );
                ok_inc(
                    grant,
                    vec![
                        minted.token,
                        self.identity.peer_entity.clone(),
                        minted.signature,
                    ],
                )
            }
            "configure" => {
                // v7.62 §4 / §6.2: bind a policy-entry at
                // system/capability/policy/{peer_pattern}. A MUST op on the handler.
                let entry = match &params {
                    Some(p) if p.typ == "system/capability/policy-entry" => p,
                    _ => return err_out(400, "invalid_params"),
                };
                let peer_pattern = match entry.text_field("peer_pattern") {
                    Some(p) => p.to_string(),
                    None => return err_out(400, "invalid_params"),
                };
                if !valid_policy_pattern(&peer_pattern) {
                    return err_out(400, "invalid_params");
                }
                // CAP-2 (§6.2): `grants: []` is the WITHDRAWAL form and MUST be accepted
                // -- it writes a present policy entry carrying an empty grants array,
                // which is how an operator revokes a seed policy without deleting the
                // entry. The `!a.is_empty()` guard conflated "no grants" with
                // "malformed"; the ABSENT field is malformed, the EMPTY array deliberate.
                match entry.field("grants") {
                    Some(Value::Array(_)) => {}
                    _ => return err_out(400, "invalid_params"),
                }
                self.store.bind(
                    &format!(
                        "/{}/system/capability/policy/{}",
                        self.local_peer, peer_pattern
                    ),
                    entry,
                );
                ok(empty_params())
            }
            "revoke" => {
                let token_h = params
                    .as_ref()
                    .and_then(|p| p.bytes_field("token"))
                    .map(|b| b.to_vec());
                // v7.62 §10: revoke-request.token MUST be present and non-zero.
                let token_h = match token_h {
                    Some(t) if !is_zero_hash(&t) => t,
                    _ => return err_out(400, "invalid_params"),
                };
                let marker = Entity::make(
                    "system/capability/revocation",
                    cbor_host::map(vec![
                        ("token", cbor_host::bytes(&token_h)),
                        ("revoked_at", Value::UInt(now_ms())),
                    ]),
                );
                self.store.bind(
                    &format!(
                        "/{}/system/capability/revocations/{}",
                        self.local_peer,
                        hex(&token_h)
                    ),
                    &marker,
                );
                ok(empty_params())
            }
            _ => err_out(501, "unsupported_operation"),
        }
    }

    // ── handlers handler (§6.2 / §6.13(a)) — register / unregister ──────────────

    fn handlers_handler(&self, exec: &Entity) -> Outcome {
        match exec.text_field("operation").unwrap_or("") {
            "register" => self.handler_register(exec),
            "unregister" => self.handler_unregister(exec),
            _ => err_out(501, "unsupported_operation"),
        }
    }

    /// §6.2 register: the five normative writes for the handler whose install path is
    /// `EXECUTE.resource.targets[0]` (`system/handler/{pattern}`). Behavioral presence
    /// is a v7.74 §6.13(a) MUST — a 501 from a core peer is non-conformant.
    fn handler_register(&self, exec: &Entity) -> Outcome {
        let pattern = match self.pattern_from_resource(exec) {
            Ok(p) => p,
            Err(o) => return o,
        };
        // §6.2: user-installed handlers MUST NOT register at reserved "system/*"
        // paths. Refused before any of the five normative writes below.
        if is_reserved_system_pattern(&pattern) {
            return err_out(403, "forbidden_pattern");
        }
        let params = match exec.entity_field("params") {
            Some(p) if p.typ == "system/handler/register-request" => p,
            _ => return err_out(400, "invalid_params"),
        };
        let manifest = params
            .field("manifest")
            .cloned()
            .unwrap_or(Value::Map(vec![]));
        let name = cbor_host::map_get(&manifest, "name")
            .and_then(|v| match v {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap_or_else(|| pattern.clone());
        let operations = cbor_host::map_get(&manifest, "operations")
            .cloned()
            .unwrap_or(Value::Map(vec![]));
        // Grant scope = requested_scope ?? manifest.internal_scope ?? [] (§6.2).
        let grant_scope = match params.field("requested_scope") {
            Some(Value::Array(a)) => a.clone(),
            _ => match cbor_host::map_get(&manifest, "internal_scope") {
                Some(Value::Array(a)) => a.clone(),
                _ => vec![],
            },
        };
        let iface_rel = format!("system/handler/{pattern}");

        // (1) handler manifest (dispatch target) at {pattern}.
        let mut mpairs = vec![(Key::Text("interface".into()), cbor_host::text(&iface_rel))];
        for k in ["max_scope", "internal_scope", "expression_path"] {
            if let Some(v) = cbor_host::map_get(&manifest, k) {
                mpairs.push((Key::Text(k.into()), v.clone()));
            }
        }
        let handler_e = Entity::make("system/handler", Value::Map(mpairs));
        self.store
            .bind(&format!("/{}/{}", self.local_peer, pattern), &handler_e);

        // (2) install associated types at system/type/{type_name} (register.types).
        if let Some(Value::Map(types)) = params.field("types") {
            for (k, v) in types {
                if let Key::Text(type_name) = k {
                    if let Ok(te) = crate::model::entity_of_cbor(&Value::Map(vec![
                        (Key::Text("type".into()), cbor_host::text("system/type")),
                        (Key::Text("data".into()), v.clone()),
                    ])) {
                        self.store.bind(
                            &format!("/{}/system/type/{}", self.local_peer, type_name),
                            &te,
                        );
                    }
                }
            }
        }

        // (3) self-issued, signed handler grant at system/capability/grants/{pattern}.
        let minted = mint_token(
            &self.identity,
            &self.identity.identity_hash,
            None,
            grant_scope,
        );
        self.store.bind(
            &format!("/{}/system/capability/grants/{}", self.local_peer, pattern),
            &minted.token,
        );
        // (4) grant signature at the §3.5 invariant path system/signature/{grant_hash}.
        self.store.bind(
            &format!(
                "/{}/system/signature/{}",
                self.local_peer,
                hex(&minted.token.hash)
            ),
            &minted.signature,
        );

        // (5) handler interface (discovery index) at system/handler/{pattern}.
        let iface_e = Entity::make(
            "system/handler/interface",
            Value::Map(vec![
                (Key::Text("pattern".into()), cbor_host::text(&pattern)),
                (Key::Text("name".into()), cbor_host::text(&name)),
                (Key::Text("operations".into()), operations),
            ]),
        );
        self.store
            .bind(&format!("/{}/{}", self.local_peer, iface_rel), &iface_e);

        let result = Entity::make(
            "system/handler/register-result",
            Value::Map(vec![
                (Key::Text("pattern".into()), cbor_host::text(&pattern)),
                (Key::Text("grant".into()), minted.token.data.clone()),
            ]),
        );
        ok(result)
    }

    /// §6.2 unregister: reverse all five register writes (the grant-signature at the
    /// §3.5 invariant path is removed alongside the grant — writer/unregister symmetry).
    fn handler_unregister(&self, exec: &Entity) -> Outcome {
        let pattern = match self.pattern_from_resource(exec) {
            Ok(p) => p,
            Err(o) => return o,
        };
        let grant_path = format!("/{}/system/capability/grants/{}", self.local_peer, pattern);
        if let Some(grant) = self.store.get_at(&grant_path) {
            self.store.unbind(&format!(
                "/{}/system/signature/{}",
                self.local_peer,
                hex(&grant.hash)
            ));
            self.store.unbind(&grant_path);
        }
        self.store
            .unbind(&format!("/{}/{}", self.local_peer, pattern));
        self.store
            .unbind(&format!("/{}/system/handler/{}", self.local_peer, pattern));
        ok(empty_params())
    }

    /// Derive the install pattern from `EXECUTE.resource.targets[0]`
    /// (`system/handler/{pattern}`). Exactly one target — else 400.
    fn pattern_from_resource(&self, exec: &Entity) -> Result<String, Outcome> {
        let targets = resource_targets(exec);
        if targets.len() != 1 {
            return Err(err_out(400, "ambiguous_resource"));
        }
        let prefix = "system/handler/";
        let target = &targets[0];
        if !target.starts_with(prefix) || target.len() == prefix.len() {
            return Err(err_out(400, "invalid_resource"));
        }
        Ok(target[prefix.len()..].to_string())
    }

    // ── §7a conformance handlers ────────────────────────────────────────────────

    fn conformance_handler(&self, conn: &mut Conn, exec: &Entity, stripped: &str) -> Outcome {
        match stripped {
            "system/validate/echo" => match exec.entity_field("params") {
                Some(p) => ok(p),
                None => ok(empty_params()),
            },
            "system/validate/dispatch-outbound" => self.dispatch_outbound(conn, exec),
            _ => err_out(501, "no_handler_body"),
        }
    }

    /// §7a `system/validate/dispatch-outbound` — originate exactly one outbound
    /// EXECUTE back to the calling peer over the live §6.11 reentry connection
    /// (`conn.outbound`, set by the host per request), invoking `operation` on the
    /// caller's `target` handler with the carried `value`, and return that downstream
    /// response. Proves the peer can *originate*, not just respond (closes A-013).
    ///
    /// The reentry direction (this peer → caller) is authorized by the caller, so the
    /// caller carries the capability it minted for this peer in the params (the three
    /// authority entities embedded as nested entities).
    fn dispatch_outbound(&self, conn: &mut Conn, exec: &Entity) -> Outcome {
        let outbound = match &conn.outbound {
            Some(o) => o.clone(),
            None => return err_out(503, "no_outbound_seam"),
        };
        let params = match exec.entity_field("params") {
            Some(p) => p,
            None => return err_out(400, "invalid_params"),
        };
        let target = match params.text_field("target") {
            Some(t) => t.to_string(),
            None => return err_out(400, "invalid_params"),
        };
        let operation = params.text_field("operation").unwrap_or("").to_string();
        let value = params.field("value").cloned().unwrap_or(Value::Map(vec![]));
        let cap = match params.entity_field("reentry_capability") {
            Some(e) => e,
            None => return err_out(400, "invalid_params"),
        };
        let granter = match params.entity_field("reentry_granter") {
            Some(e) => e,
            None => return err_out(400, "invalid_params"),
        };
        let cap_sig = match params.entity_field("reentry_cap_signature") {
            Some(e) => e,
            None => return err_out(400, "invalid_params"),
        };

        conn.out_counter += 1;
        let rid = format!("reentry-{}", conn.out_counter);
        // §7a.1: the `value` field IS the outbound params data — pass it through.
        let inner = Entity::make("primitive/any", value);
        let tgt = format!("system/handler/{target}");
        let resource = cbor_host::map(vec![("targets", cbor_host::text_array(&[tgt.as_str()]))]);
        let exec_out = Entity::make(
            "system/protocol/execute",
            Value::Map(vec![
                (Key::Text("request_id".into()), cbor_host::text(&rid)),
                (Key::Text("uri".into()), cbor_host::text(&target)),
                (Key::Text("operation".into()), cbor_host::text(&operation)),
                (Key::Text("params".into()), inner.to_cbor()),
                (
                    Key::Text("author".into()),
                    cbor_host::bytes(&self.identity.identity_hash),
                ),
                (Key::Text("capability".into()), cbor_host::bytes(&cap.hash)),
                (Key::Text("resource".into()), resource),
            ]),
        );
        let exec_sig = self.identity.sign_entity(&exec_out);
        let env = Envelope::with_included(
            exec_out,
            vec![
                cap,
                granter,
                self.identity.peer_entity.clone(),
                cap_sig,
                exec_sig,
            ],
        );
        let resp = match outbound(env) {
            Some(r) => r,
            None => return err_out(504, "outbound_no_response"),
        };
        let status = resp.root.uint_field("status").unwrap_or(0);
        let inner_result = resp
            .root
            .field("result")
            .cloned()
            .unwrap_or(Value::Map(vec![]));
        ok(Entity::make(
            "primitive/any",
            Value::Map(vec![
                (Key::Text("status".into()), Value::UInt(status)),
                (Key::Text("result".into()), inner_result),
            ]),
        ))
    }
}

// ── request verdict ────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReqVerdict {
    Allow,
    AuthnFail,
    AuthzDeny,
    ChainTooDeep,
    UnresolvableGrantee,
}

enum FactResult {
    /// Boxed: [`AuthFacts`] is large relative to the unit `Unresolvable` variant.
    Facts(Box<AuthFacts>),
    Unresolvable,
}

// ── host-side fact helpers (crypto is via C-ABI in identity; here: structure) ──

enum Granter {
    Single(Vec<u8>),
    Multi {
        signers: Vec<Vec<u8>>,
        threshold: u64,
    },
}
fn granter_of(cap: &Entity) -> Granter {
    match cap.field("granter") {
        Some(Value::Map(_)) => {
            let g = cap.field("granter").unwrap();
            let signers = match cbor_host::map_get(g, "signers") {
                Some(Value::Array(arr)) => arr
                    .iter()
                    .filter_map(|it| match it {
                        Value::Bytes(b) => Some(b.clone()),
                        _ => None,
                    })
                    .collect(),
                _ => vec![],
            };
            let threshold = match cbor_host::map_get(g, "threshold") {
                Some(Value::UInt(t)) => *t,
                _ => 0,
            };
            Granter::Multi { signers, threshold }
        }
        Some(Value::Bytes(b)) => Granter::Single(b.clone()),
        _ => Granter::Single(vec![]),
    }
}

fn has_dupes(signers: &[Vec<u8>]) -> bool {
    for (i, s) in signers.iter().enumerate() {
        if signers[i + 1..].iter().any(|o| o == s) {
            return true;
        }
    }
    false
}

fn temporal_valid(cap: &Entity, now: u64) -> bool {
    // CAP-6a FIRST: the two range checks below use uint_field, which cannot tell "absent"
    // from "present but not a u64" — so on their own they skip and honor the token.
    if !temporal_fields_representable(cap) {
        return false;
    }
    if let Some(nb) = cap.uint_field("not_before") {
        if now < nb {
            return false;
        }
    }
    if let Some(ex) = cap.uint_field("expires_at") {
        if ex < now {
            return false;
        }
    }
    true
}

fn find_signature(env: &Envelope, target: &[u8]) -> Option<Entity> {
    env.included.values().find_map(|e| {
        if e.typ == "system/signature" && e.bytes_field("target") == Some(target) {
            Some(e.clone())
        } else {
            None
        }
    })
}

// ── §5.4 pattern matching + scope (host string-glob; the DECISION, per A-DL-011) ─

const B58: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
pub fn is_peer_id(seg: &str) -> bool {
    seg.len() >= 46 && seg.bytes().all(|c| B58.contains(&c))
}
pub fn normalize_uri(uri: &str) -> String {
    uri.strip_prefix("entity://")
        .map(|r| format!("/{r}"))
        .unwrap_or_else(|| uri.to_string())
}
pub fn canonicalize(local_peer: &str, path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{local_peer}/{path}")
    }
}
fn first_segment(uri: &str) -> &str {
    let u = uri.strip_prefix('/').unwrap_or(uri);
    match u.find('/') {
        Some(i) => &u[..i],
        None => u,
    }
}
fn extract_peer<'a>(local_peer: &'a str, uri: &'a str) -> &'a str {
    let body = uri.strip_prefix("entity://").unwrap_or(uri);
    let first = first_segment(body);
    if is_peer_id(first) {
        first
    } else {
        local_peer
    }
}
/// The handler-relative path of a request URI: the peer segment removed, if present.
///
/// The `entity://` form has NO leading slash after the scheme -- `entity://{peer}/rest`
/// -- so `strip_prefix('/')` fails on it and the peer segment was never removed. The
/// resulting "handler pattern" was `{peer}/system/capability`, which canonicalizes to
/// `/{local}/{peer}/system/capability` and cannot be covered by a concrete handlers scope
/// naming `system/capability`.
///
/// A bare `*` covers it, which is why this stayed invisible: every self-issued and
/// open-grants capability carries `handlers: ["*"]`, and 753 of 755 checks pass on those.
/// It surfaces only for a cap whose handlers scope is CONCRETE -- exactly the bounded cap
/// the CAP-5 probe presents -- and the failure then reads as a mint bug ("over-long ttl_ms
/// rejected instead of clamping") rather than as URI parsing.
fn strip_peer(uri: &str) -> String {
    let body = uri.strip_prefix("entity://").unwrap_or(uri);
    // Both spellings reach here: `/peer/rest` (absolute path) and `peer/rest` (what the
    // entity:// scheme leaves behind). Strip the leading slash if there is one, then test
    // the first segment.
    let rest = body.strip_prefix('/').unwrap_or(body);
    if let Some(i) = rest.find('/') {
        if is_peer_id(&rest[..i]) {
            return rest[i + 1..].to_string();
        }
    }
    body.to_string()
}

fn matches_pattern(path: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(remainder) = pattern.strip_prefix("/*/") {
        let after = match path.get(1..).and_then(|p| p.find('/')) {
            Some(i) => &path[1 + i + 1..],
            None => return false,
        };
        return matches_pattern(after, remainder);
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if prefix.ends_with('/') {
            return path.starts_with(prefix);
        }
    }
    path == pattern
}

#[derive(Default, Clone)]
struct Scope {
    incl: Vec<String>,
    excl: Vec<String>,
}
fn text_list(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|it| match it {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}
fn scope_of(c: Option<&Value>) -> Scope {
    match c {
        Some(v) => Scope {
            incl: text_list(cbor_host::map_get(v, "include")),
            excl: text_list(cbor_host::map_get(v, "exclude")),
        },
        None => Scope::default(),
    }
}
fn covered(frame: &str, value: &str, pats: &[String]) -> bool {
    pats.iter()
        .any(|p| matches_pattern(value, &canonicalize(frame, p)))
}
/// Which §5.2 matcher a grant dimension uses (0.8.1, F40). No `Default` impl on purpose
/// — every call site names its dimension, so a new one cannot silently inherit the wrong
/// matcher, which is exactly the F40 defect.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ScopeKind {
    /// `operations`, `peers` — `system/capability/id-scope`.
    Id,
    /// `handlers`, `resources` — `system/capability/path-scope`.
    Path,
}

/// §5.2 id-scope match (0.8.1, F40): literal comparison with exactly two wildcard forms
/// — bare `*` and a trailing `/*` segment-prefix. None of the §5.4 path transforms
/// apply, so a pattern carrying path syntax is matched as a literal string: a non-match,
/// never a fault.
fn matches_id_pattern(value: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        if prefix.ends_with('/') {
            return value.starts_with(prefix);
        }
    }
    value == pattern
}

fn covered_id(value: &str, pats: &[String]) -> bool {
    pats.iter().any(|p| matches_id_pattern(value, p))
}

fn matches_scope(local_peer: &str, value: &str, s: &Scope, kind: ScopeKind) -> bool {
    if kind == ScopeKind::Id {
        return covered_id(value, &s.incl) && !covered_id(value, &s.excl);
    }
    let cv = canonicalize(local_peer, value);
    covered(local_peer, &cv, &s.incl) && !covered(local_peer, &cv, &s.excl)
}
fn check_resource_scope(local_peer: &str, granter_peer: &str, resource: &Value, s: &Scope) -> bool {
    let targets = text_list(cbor_host::map_get(resource, "targets"));
    if targets.is_empty() {
        return false;
    }
    let caller_excl = text_list(cbor_host::map_get(resource, "exclude"));
    for tgt in &targets {
        let ct = canonicalize(local_peer, tgt);
        if covered(local_peer, &ct, &caller_excl) {
            continue;
        }
        if !covered(granter_peer, &ct, &s.incl) || covered(granter_peer, &ct, &s.excl) {
            return false;
        }
    }
    true
}

// ── §5.6 attenuation (host structural check; gates the verified_link fact) ──────

fn grants_of(token: &Entity) -> Vec<Value> {
    match token.field("grants") {
        Some(Value::Array(arr)) => arr.clone(),
        _ => vec![],
    }
}
fn scope_subset(child_peer: &str, parent_peer: &str, child: &Scope, parent: &Scope) -> bool {
    for cp in &child.incl {
        let cc = canonicalize(child_peer, cp);
        if !parent
            .incl
            .iter()
            .any(|pp| matches_pattern(&cc, &canonicalize(parent_peer, pp)))
        {
            return false;
        }
    }
    true
}
/// Child ⊆ parent on every dimension, with the RESOURCES comparison canonicalized on the
/// two sides' own §5.5a frames.
///
/// `child_frame` / `parent_frame` are the granter peer_ids of the two links. They reach
/// only the RESOURCES comparison: §5.5a names its three surfaces and all three are
/// resource-pattern surfaces. handlers and operations stay on the LOCAL frame — passing
/// the granter frames to them is the swift over-scoping bug (ded3e07), which is invisible
/// until a delegated cap arrives and then refuses every one of them.
///
/// For the §6.2 MINT-time subset the caller passes `local` for both frames, because that
/// mint is self-issued and the granter is this peer on both sides.
fn grant_subset(
    local: &str,
    child_frame: &str,
    parent_frame: &str,
    child: &Value,
    parent: &Value,
) -> bool {
    let cs = |v: &Value, k: &str| scope_of(cbor_host::map_get(v, k));
    scope_subset(
        local,
        local,
        &cs(child, "handlers"),
        &cs(parent, "handlers"),
    ) && scope_subset(
        local,
        local,
        &cs(child, "operations"),
        &cs(parent, "operations"),
    ) && scope_subset(
        child_frame,
        parent_frame,
        &cs(child, "resources"),
        &cs(parent, "resources"),
    )
}

/// §5.5 / §5.5a SURFACE 2 — per-link attenuation with FRAME ISOLATION.
///
/// This used to pass `local` as both frames. On every same-granter chain that is
/// byte-identical to the correct answer, which is why it survived: a foreign-granted bare
/// `*` canonicalized to the VERIFIER's `/{local}/*` instead of the granter's
/// `/{granter}/*`, and so falsely covered a leaf naming the verifier's namespace. §5.5a
/// calls that out by name as "canon-against-wrong-frame" and pins three vectors at it
/// (AUTHZ-ATTENUATION-FOREIGN-GRANTER-1 / -DEEP / -WILDCARD-LEAF).
///
/// All three were reported as PASSING before 2026-08-28, and not because this was right:
/// `strip_peer` mishandled the `entity://` form, so the handlers dimension never matched a
/// concrete scope and the requests were denied one rung earlier for an unrelated reason.
/// Fixing that exposed these. A wrong denial had been standing in for a missing check.
fn is_attenuated(
    local: &str,
    child_frame: &str,
    parent_frame: &str,
    child: &Entity,
    parent: &Entity,
) -> bool {
    let cg = grants_of(child);
    let pg = grants_of(parent);
    cg.iter().all(|c| {
        pg.iter()
            .any(|p| grant_subset(local, child_frame, parent_frame, c, p))
    })
}
fn check_caveats(parent: &Entity, _child: &Entity) -> bool {
    match parent.field("delegation_caveats") {
        Some(c) => !matches!(
            cbor_host::map_get(c, "no_delegation"),
            Some(Value::Bool(true))
        ),
        None => true,
    }
}

/// §6.2 mint-bound. BOTH frames are LOCAL: the mint is self-issued, so the granter is this
/// peer on both sides. Passing the caller's granter frame here is the swift bug at the mint
/// site rather than the dispatch site, in the direction that refuses legitimate requests.
fn requested_grants_within(local: &str, req: &[Value], caller_cap: &Entity) -> bool {
    let pg = grants_of(caller_cap);
    req.iter()
        .all(|c| pg.iter().any(|p| grant_subset(local, local, local, c, p)))
}
fn req_grants(params: Option<&Entity>) -> Vec<Value> {
    match params.and_then(|p| p.field("grants")) {
        Some(Value::Array(arr)) => arr.clone(),
        _ => vec![],
    }
}
fn resource_target(exec: &Entity) -> Option<String> {
    let r = exec.field("resource")?;
    match cbor_host::map_get(r, "targets")? {
        Value::Array(arr) => match arr.first() {
            Some(Value::Text(s)) => Some(s.clone()),
            _ => None,
        },
        _ => None,
    }
}

/// All `resource.targets` entries (§6.2 register/unregister require exactly one).
fn resource_targets(exec: &Entity) -> Vec<String> {
    match exec
        .field("resource")
        .and_then(|r| cbor_host::map_get(r, "targets"))
    {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|it| match it {
                Value::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

/// A full-zero hash (any length) — the §3.9 CAS create-only sentinel + the v7.62 §10
/// zero-token reject.
fn is_zero_hash(h: &[u8]) -> bool {
    h.iter().all(|&b| b == 0)
}

/// §1.4 / v7.72 §9.5a CORE-TREE-PATH-FLEX-1 validity for a caller-supplied tree
/// target: reject C0 control bytes (NUL) + DEL; the empty-segment (`//`),
/// directory-relative (`./`, `../`), and bare peer-wildcard (`*/`) forms; and a
/// leading-slash (absolute) form whose first segment is not a valid peer_id.
fn valid_caller_target(target: &str) -> bool {
    if target
        .chars()
        .any(|c| (c as u32) < 0x20 || (c as u32) == 0x7f)
    {
        return false;
    }
    if target.contains("//") || target.starts_with("./") || target.starts_with("../") {
        return false;
    }
    if target.starts_with("*/") {
        return false;
    }
    if let Some(rest) = target.strip_prefix('/') {
        let first = rest.split('/').next().unwrap_or("");
        if !is_peer_id(first) {
            return false;
        }
    }
    true
}

/// A valid policy `peer_pattern` (v7.62 §4 + v7.65 §3.6 rule 3): the literal
/// `"default"` fallback; a canonical hex content hash (66 SHA-256 / 98 SHA-384
/// chars); or a decodable Base58 wire-form peer_id. Glob/partial-prefix patterns are
/// rejected.
fn valid_policy_pattern(p: &str) -> bool {
    if p == "default" {
        return true;
    }
    if p.contains('*') {
        return false;
    }
    if p.len() == 66 || p.len() == 98 {
        return p.chars().all(|c| c.is_ascii_hexdigit());
    }
    is_peer_id(p)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_and_hello() {
        let p = Peer::create(CreateOptions {
            seed: [5u8; 32],
            ..Default::default()
        });
        assert!(p
            .store
            .get_at(&format!("/{}/system/protocol/connect", p.local_peer))
            .is_some());
        let mut conn = Conn::new();
        let exec = crate::host::make_execute(crate::host::ExecuteFields {
            request_id: "r1",
            uri: "system/protocol/connect",
            operation: "hello",
            params: empty_params(),
            resource: None,
            author: None,
            capability: None,
        });
        let resp = p.dispatch(&mut conn, &Envelope::new(exec)).unwrap();
        assert_eq!(resp.root.uint_field("status"), Some(200));
        assert!(conn.issued_nonce.is_some());
    }
}
