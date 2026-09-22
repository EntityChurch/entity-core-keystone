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

use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

use crate::value::{Key, Value};

use super::capability as cap;
use super::handler::{
    ExpressionEvaluator, ExpressionRequest, Handler, HandlerContext, HandlerHandle, HandlerResult,
    HandlerSpec, LocalExecute, OperationSpec, RegisterError, SpecHandler, MAX_LOCAL_DISPATCH_DEPTH,
};
use super::identity::{self, Identity};
use super::model::{self, hex, Entity, Envelope};
use super::seed_policy::{discovery_floor, owner_grants, SeedPolicy};
use super::store::{ExecContext, Store};
use super::type_defs;
use super::wire;

/// An outbound-reentry hook (§6.11): given a request envelope, originate it over
/// the live inbound connection and return the correlated response.
pub type OutboundFn = dyn Fn(Envelope) -> Option<Envelope> + Send + Sync;

/// Per-connection state (§4.2).
pub struct Conn {
    pub established: bool,
    pub issued_nonce: Option<[u8; 32]>,
    pub hello_peer_id: Option<String>,
    /// §6.11 reentry seam, bound by the transport for the duration of a dispatch.
    pub outbound: Option<Arc<OutboundFn>>,
    pub out_counter: u32,
    /// H6 — the inbound frame budget this connection enforces (§1.6 / §4.10(a)). The
    /// transport stamps the peer's configured budget when it starts reading.
    pub max_frame_bytes: usize,
}

impl Default for Conn {
    fn default() -> Self {
        Conn {
            established: false,
            issued_nonce: None,
            hello_peer_id: None,
            outbound: None,
            out_counter: 0,
            max_frame_bytes: wire::MAX_FRAME,
        }
    }
}

impl Conn {
    pub fn new() -> Conn {
        Conn::default()
    }
}

/// A handler outcome: status, the result entity, and protocol entities to bundle.
/// The public spelling is [`HandlerResult`]; core handlers and installed ones return
/// the same type.
type Outcome = HandlerResult;

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
/// Digest byte length for a `content_hash_format` code per the §1.2 seed table,
/// or `None` when this peer cannot VERIFY that code. The total wire length is
/// this plus the varint prefix, which is not a constant of the code (§7.3):
/// codes >= 0x80 occupy more than one byte. This peer computes SHA-256 only.
fn hash_digest_len(format_code: u64) -> Option<usize> {
    match format_code {
        0x00 => Some(32),
        _ => None,
    }
}

/// §6.3's `put` admission ladder (normative, 0.8.2.11).
///
/// `put` is a RECEIPT path: the submitter authors the entity, the peer validates
/// what it received (§1.8 item 1) and MUST NOT author a submitted entity's
/// `content_hash` on the submitter's behalf. Two ordered steps:
///
/// 1. STRUCTURE — a map carrying a non-empty text `type`, a PRESENT `data` (any
///    CBOR value; null is a legal payload), and a `content_hash` that is a
///    well-formed `system/hash` whose total byte length matches its format code
///    (§1.2). Any failure -> 400 `invalid_request`. A well-formed hash naming a
///    format code this peer cannot verify is the separate §1.2 ingest-dispatch
///    case -> 400 `unsupported_content_hash_format`.
/// 2. HASH — carried `content_hash` vs `content_hash({type, data})`.
///    Disagreement -> 400 `hash_mismatch`.
///
/// Step 1 strictly precedes step 2 as a DATA DEPENDENCY, not a choice: step 2's
/// inputs are exactly what step 1 establishes, so a submission that is both
/// malformed and mis-hashed is step 1's and answers `invalid_request`.
///
/// Structural admission is not semantic validation: `data` is never checked
/// against the type named by `type`.
fn admit_put(v: &Value) -> Result<Entity, Outcome> {
    let refuse = |code: &str, msg: &str| Err(err_out(400, code, Some(msg)));
    if !matches!(v, Value::Map(_)) {
        return refuse("invalid_request", "put: entity is not a map");
    }
    let typ = match model::map_get(v, "type") {
        Some(Value::Text(t)) if !t.is_empty() => t.clone(),
        _ => {
            return refuse(
                "invalid_request",
                "put: entity.type absent, empty or not a text string",
            )
        }
    };
    let data = match model::map_get(v, "data") {
        Some(d) => d.clone(),
        None => return refuse("invalid_request", "put: entity.data absent"),
    };
    let carried = match model::map_get(v, "content_hash") {
        Some(Value::Bytes(b)) if !b.is_empty() => b.clone(),
        _ => {
            return refuse(
                "invalid_request",
                "put: entity.content_hash absent or not a byte string",
            )
        }
    };
    let (format_code, n) = match crate::varint::decode(&carried) {
        Ok(r) => r,
        Err(_) => {
            return refuse(
                "invalid_request",
                "put: entity.content_hash is not a well-formed system/hash",
            )
        }
    };
    let digest_len = match hash_digest_len(format_code) {
        Some(n) => n,
        // §1.2 / §4.7 row 5 — well-formed, but this peer cannot interpret it.
        // NOT invalid_request: the shape is fine, the algorithm is what we lack.
        None => {
            return Err(err_out(
                400,
                "unsupported_content_hash_format",
                Some("put: unsupported content_hash_format"),
            ))
        }
    };
    if carried.len() != n + digest_len {
        return refuse(
            "invalid_request",
            "put: content_hash length does not match its format code",
        );
    }
    if crate::content_hash::content_hash(&typ, data.clone(), format_code) != carried {
        return refuse(
            "hash_mismatch",
            "put: content_hash does not match content_hash({type, data})",
        );
    }
    // The carried hash IS the entity's address; recomputing it into the store
    // would be the authoring arm §6.3 forbids.
    Ok(Entity {
        typ,
        data,
        hash: carried,
    })
}

fn err_out(status: u64, code: &str, message: Option<&str>) -> Outcome {
    Outcome {
        status,
        result: wire::error_result(code, message),
        included: vec![],
    }
}

pub(crate) fn now_ms() -> u64 {
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
    /// Whether the peer was built with the deprecated `open_grants` switch. The
    /// policy actually in force is [`Peer::seed_policy`].
    pub open_grants: bool,
    pub conformance: bool,
    seed_policy: SeedPolicy,
    max_frame_bytes: usize,
    /// H1 — language-native handler bodies, keyed by peer-relative pattern. Private
    /// (H3): the only writers are `register_handler` / `unregister_handler` and the
    /// wire register/unregister ops, and the only reader is `route`.
    native_handlers: RwLock<HashMap<String, (u64, Arc<dyn Handler>)>>,
    /// Monotonic registration generation, so a stale [`HandlerHandle`] closes nothing.
    registration_generation: AtomicU64,
    /// H7 — the fallback evaluator for entity-native bodies.
    evaluator: RwLock<Option<Arc<dyn ExpressionEvaluator>>>,
    local_dispatch_counter: AtomicU64,
}

/// Builder options for [`Peer::create`].
#[derive(Default)]
pub struct CreateOptions {
    pub seed: [u8; 32],
    /// DEPRECATED — selects [`SeedPolicy::debug_open`] when no
    /// [`PeerConfig::seed_policy`] is supplied, and is ignored when one is.
    pub open_grants: bool,
    pub conformance: bool,
}

/// Host-contract configuration for [`Peer::create_with`]. Separate from
/// [`CreateOptions`] so that adding a knob never breaks a caller's struct literal;
/// construct it with `PeerConfig::default()` and the builder methods.
#[derive(Clone, Debug, Default)]
pub struct PeerConfig {
    /// The §6.9a seed policy. `None` = the standard policy, or the degenerate
    /// `default → *` when `CreateOptions::open_grants` is set.
    pub seed_policy: Option<SeedPolicy>,
    /// The inbound frame budget in bytes (§1.6 / §4.10(a)). `None` = 16 MiB.
    pub max_frame_bytes: Option<usize>,
}

impl PeerConfig {
    pub fn seed_policy(mut self, policy: SeedPolicy) -> PeerConfig {
        self.seed_policy = Some(policy);
        self
    }

    pub fn max_frame_bytes(mut self, bytes: usize) -> PeerConfig {
        self.max_frame_bytes = Some(bytes);
        self
    }
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
    mint_token_at(id, grantee_hash, parent, grants, now_ms(), None)
}

/// `mint_token` with an explicit `created_at` and §5.6 `expires_at`.
///
/// The two are passed together on purpose: `expires_at` is computed FROM `created_at`
/// (the duration terms are relative to it), so sampling the clock twice would let the
/// emitted `created_at` and the expiry derived from it skew apart. Callers sample once
/// and thread it through.
fn mint_token_at(
    id: &Identity,
    grantee_hash: &[u8],
    parent: Option<&[u8]>,
    grants: Vec<Value>,
    created_at: u64,
    expires_at: Option<u64>,
) -> Minted {
    let mut pairs = vec![
        (Key::Text("granter".into()), model::bytes(&id.identity_hash)),
        (Key::Text("grantee".into()), model::bytes(grantee_hash)),
        (Key::Text("grants".into()), Value::Array(grants)),
        (Key::Text("created_at".into()), Value::UInt(created_at)),
    ];
    if let Some(ex) = expires_at {
        pairs.push((Key::Text("expires_at".into()), Value::UInt(ex)));
    }
    if let Some(ph) = parent {
        pairs.push((Key::Text("parent".into()), model::bytes(ph)));
    }
    let token = Entity::make("system/capability/token", Value::Map(pairs));
    let signature = id.sign_entity(&token);
    Minted { token, signature }
}

/// Convert a DURATION term (`ttl_ms`) to an absolute timestamp, reporting whether it
/// contributes a ceiling at all (§5.6 MIN_DEFINED rule 1 + rule 3).
///
/// Overflow DROPS the term — treated as absent, exactly as a null term is. It MUST NOT
/// wrap and MUST NOT saturate: saturation encodes differently from absence and
/// manufactures `expires_at == u64::MAX`, a finite bound no reader can distinguish from
/// a deliberate one.
///
/// `ttl == 0` is NOT special-cased, deliberately: rule 2 makes 0 a DEFINED value
/// yielding `created_at` (expire immediately). Letting it fall out of the arithmetic is
/// what keeps it from collapsing into the absent/null "no bound" spelling — and that
/// collapse is exactly what `ttl_zero_and_overflow` caught here.
fn duration_term(created_at: u64, ttl: Option<u64>) -> Option<u64> {
    created_at.checked_add(ttl?)
}

/// §5.6 MIN_DEFINED: the minimum over the DEFINED terms only; `None` when none is.
fn min_defined(terms: [Option<u64>; 3]) -> Option<u64> {
    terms.into_iter().flatten().min()
}

impl Peer {
    /// Build and bootstrap a peer (§6.9 + §6.9a). The peer owns its store + identity.
    pub fn create(opts: CreateOptions) -> Peer {
        Peer::create_with(opts, PeerConfig::default())
    }

    /// [`Peer::create`] with host-contract configuration: a declared seed policy
    /// (§6.9a) and the inbound frame budget (H6).
    pub fn create_with(opts: CreateOptions, config: PeerConfig) -> Peer {
        let identity = Identity::of_seed(opts.seed);
        let store = Store::new();
        let local_peer = identity.peer_id.clone();
        let seed_policy = config.seed_policy.unwrap_or_else(|| {
            if opts.open_grants {
                SeedPolicy::debug_open()
            } else {
                SeedPolicy::standard()
            }
        });
        // A zero budget would refuse every frame, including the handshake; the length
        // prefix is a u32, so nothing past u32::MAX can be expressed on the wire.
        let max_frame_bytes = config
            .max_frame_bytes
            .unwrap_or(wire::MAX_FRAME)
            .clamp(1, u32::MAX as usize);

        let peer = Peer {
            identity,
            store,
            local_peer,
            open_grants: opts.open_grants,
            conformance: opts.conformance,
            seed_policy,
            max_frame_bytes,
            native_handlers: RwLock::new(HashMap::new()),
            registration_generation: AtomicU64::new(0),
            evaluator: RwLock::new(None),
            local_dispatch_counter: AtomicU64::new(0),
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

        // the declared policy: `default` plus every named entry, as policy-entries.
        let entry = |key: &str, grants: &[Value]| {
            Entity::make(
                "system/capability/policy-entry",
                Value::Map(vec![
                    (Key::Text("peer_pattern".into()), model::text(key)),
                    (Key::Text("grants".into()), Value::Array(grants.to_vec())),
                ]),
            )
        };
        peer.store.bind(
            &format!("{policy_base}default"),
            &entry("default", peer.seed_policy.default_grants()),
        );
        for named in peer.seed_policy.named_entries() {
            peer.store.bind(
                &format!("{policy_base}{}", named.key),
                &entry(&named.key, &named.grants),
            );
        }

        peer
    }

    // ── host contract surface (H1, H3, H6, H7) ─────────────────────────────────

    /// The §6.9a seed policy this peer materialized at init.
    pub fn seed_policy(&self) -> &SeedPolicy {
        &self.seed_policy
    }

    /// H6 — the peer's configured inbound frame budget, in bytes. A handler body reads
    /// the budget for its own request with `HandlerContext::frame_budget`.
    pub fn max_frame_bytes(&self) -> usize {
        self.max_frame_bytes
    }

    /// H1 / `SDK-OPERATIONS` §11.6 — install a language-native handler body at a pattern
    /// the peer was not compiled with, and get back the handle that removes it.
    ///
    /// Does the same work the wire `system/handler:register` op does — the spec's types
    /// at `system/type/*`, the `system/handler` entity at the pattern, the handler's
    /// self-issued signed grant (scope = `internal_scope`, EMPTY when `None`) and that
    /// grant's signature at the §3.5 pointer, the interface entity — so §6.6 resolution
    /// finds it, and then puts the body in the container `route` reads. Install at
    /// composition time, before the peer begins listening.
    ///
    /// Refuses (H3, §11.6.1, §12.5) an invalid spec with `400 invalid_handler_spec` and a
    /// pattern at which a handler — built-in, native or wire-registered — is already bound
    /// with `409 pattern_collision`, before writing anything. It does NOT refuse
    /// `system/*` (§11.6 v1.13; see the module note in `handler.rs`).
    ///
    /// **The returned handle unregisters on drop.** Keep it, or `detach()` it.
    pub fn register_handler<B>(
        self: &Arc<Self>,
        spec: HandlerSpec,
        body: B,
    ) -> Result<HandlerHandle, RegisterError>
    where
        B: Fn(&HandlerContext<'_>) -> HandlerResult + Send + Sync + 'static,
    {
        let pattern = spec.pattern.clone();
        let generation = self.register_spec(spec, Arc::new(body))?;
        Ok(HandlerHandle {
            peer: Arc::downgrade(self),
            pattern,
            generation,
            closed: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// [`Peer::register_handler`] for a body that carries its own spec as a [`Handler`], installed
    /// for the life of the peer — no handle, so it needs only `&Peer`. Remove it with
    /// [`Peer::unregister_handler`]. This is the pre-handle surface, renamed.
    ///
    /// **Not a keystone peer contract binding, and not certified.** `install.handler` measures
    /// [`Peer::register_handler`]; no contract case reaches this function. It shares the install
    /// (the same private `register_spec` writes and refusals) and differs in what it can express: a
    /// [`Handler`] carries no types, and its `internal_scope` is `None` when `grants()` is empty.
    /// Build on `register_handler(spec, body)`, and `.detach()` the handle for a peer-lifetime
    /// install.
    pub fn install_handler(&self, handler: Arc<dyn Handler>) -> Result<(), RegisterError> {
        let spec = HandlerSpec {
            pattern: handler.pattern().to_string(),
            name: handler.name().to_string(),
            description: None,
            operations: handler.operations(),
            internal_scope: Some(handler.grants()).filter(|g| !g.is_empty()),
            types: vec![],
        };
        let body = move |ctx: &HandlerContext<'_>| handler.handle(ctx);
        self.register_spec(spec, Arc::new(body)).map(|_| ())
    }

    /// The §11.6.1 install both surfaces share. Returns the registration's generation.
    fn register_spec(
        &self,
        spec: HandlerSpec,
        body: Arc<super::handler::BodyFn>,
    ) -> Result<u64, RegisterError> {
        let pattern = spec.pattern.clone();
        if !is_concrete_pattern(&pattern) {
            return Err(RegisterError::InvalidHandlerSpec(format!(
                "pattern '{pattern}' is not a concrete peer-relative path"
            )));
        }
        if spec.operations.is_empty() {
            return Err(RegisterError::InvalidHandlerSpec(format!(
                "'{pattern}' declares no operations"
            )));
        }
        let name = spec.name.clone();
        let operations = OperationSpec::operations_value(&spec.operations);
        let grants = spec.internal_scope.clone().unwrap_or_default();
        let internal_scope = spec.internal_scope.clone().map(Value::Array);
        let types = if spec.types.is_empty() {
            None
        } else {
            Some(Value::Map(
                spec.types
                    .iter()
                    .map(|(k, v)| (Key::Text(k.clone()), v.clone()))
                    .collect(),
            ))
        };
        let generation = self.registration_generation.fetch_add(1, Ordering::SeqCst) + 1;
        {
            // Check and claim under the lock; bind after releasing it, because a bind
            // fires emit consumers and a consumer may itself ask about handlers. Until
            // the entities are bound the pattern does not resolve, so the claimed body
            // is unreachable rather than half-installed.
            let mut container = self.native_handlers.write().unwrap();
            let bound = self.store.get_at(&format!("/{}/{pattern}", self.local_peer));
            if container.contains_key(&pattern)
                || bound.is_some_and(|e| e.typ == "system/handler")
            {
                return Err(RegisterError::PatternCollision(pattern));
            }
            let handler: Arc<dyn Handler> = Arc::new(SpecHandler { spec, body });
            container.insert(pattern.clone(), (generation, handler));
        }
        self.bind_handler_entities(
            &pattern,
            &name,
            operations,
            None,
            internal_scope.as_ref(),
            types.as_ref(),
            grants,
        );
        Ok(generation)
    }

    /// §11.6.2 close: dispatch index first, tree second — only if the live registration
    /// at `pattern` is still the one `generation` names.
    pub(crate) fn close_registration(&self, pattern: &str, generation: u64) -> bool {
        let removed = {
            let mut container = self.native_handlers.write().unwrap();
            match container.get(pattern) {
                Some((g, _)) if *g == generation => container.remove(pattern).is_some(),
                _ => false,
            }
        };
        if removed {
            self.unbind_handler_entities(pattern);
        }
        removed
    }

    /// Remove whatever native handler is installed at `pattern`, unbinding the entities it
    /// bound, regardless of which handle installed it. Prefer [`HandlerHandle::close`].
    /// Returns `false` when no native handler was installed there (a wire-registered
    /// handler is left to the wire `unregister` op).
    pub fn unregister_handler(&self, pattern: &str) -> bool {
        let removed = self.native_handlers.write().unwrap().remove(pattern).is_some();
        if removed {
            self.unbind_handler_entities(pattern);
        }
        removed
    }

    /// Whether a native handler body is installed at `pattern`.
    pub fn has_native_handler(&self, pattern: &str) -> bool {
        self.native_handlers.read().unwrap().contains_key(pattern)
    }

    /// H7 — install (or clear, with `None`) the evaluator for entity-native handler
    /// bodies. The built-in `compute/literal` path still answers first; the evaluator
    /// receives only bodies the peer would otherwise refuse with
    /// `501 unsupported_expression`. Install once, before listening.
    pub fn set_expression_evaluator(&self, evaluator: Option<Arc<dyn ExpressionEvaluator>>) {
        *self.evaluator.write().unwrap() = evaluator;
    }

    /// The installed entity-native evaluator, if any.
    pub fn expression_evaluator(&self) -> Option<Arc<dyn ExpressionEvaluator>> {
        self.evaluator.read().unwrap().clone()
    }

    /// The §11.6.1 dispatch entities, bound identically by the wire register op and
    /// by [`Peer::register_handler`], in the same order so the two emit the same
    /// tree-change sequence.
    fn bind_handler_entities(
        &self,
        pattern: &str,
        name: &str,
        operations: Value,
        expression_path: Option<&str>,
        internal_scope: Option<&Value>,
        types: Option<&Value>,
        grant_scope: Vec<Value>,
    ) -> Entity {
        let interface_rel = format!("system/handler/{pattern}");
        // (1) handler manifest at the pattern path.
        let mut hpairs = vec![("interface", model::text(&interface_rel))];
        if let Some(ep) = expression_path {
            hpairs.push(("expression_path", model::text(ep)));
        }
        if let Some(is) = internal_scope {
            hpairs.push(("internal_scope", is.clone()));
        }
        let handler_e = Entity::make("system/handler", model::map(hpairs));
        self.store
            .bind(&format!("/{}/{pattern}", self.local_peer), &handler_e);

        // (2) associated types.
        if let Some(Value::Map(kvs)) = types {
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
                ("pattern", model::text(pattern)),
                ("name", model::text(name)),
                ("operations", operations),
            ]),
        );
        self.store
            .bind(&format!("/{}/{interface_rel}", self.local_peer), &iface_e);
        minted.token
    }

    fn unbind_handler_entities(&self, pattern: &str) {
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

        // §6.8: the grant MUST exist at `system/capability/grants/{pattern}` and a
        // handler with no valid grant does not run — so this bind is the ceiling row 1
        // intersects against, not bookkeeping. An empty grants list is the right
        // default for a handler that never dispatches onward and the WRONG one for a
        // handler that does.
        let minted = mint_token(
            &self.identity,
            &self.identity.identity_hash,
            None,
            own_grants_for(bh.pattern),
        );
        self.store.bind(
            &format!(
                "/{}/system/capability/grants/{}",
                self.local_peer, bh.pattern
            ),
            &minted.token,
        );
    }

    // ── dispatch (§6.5) ─────────────────────────────────────────────────────────

    /// Materialize the inbound envelope into an outbound response envelope. Never panics
    /// on a protocol error — every failure is a status, the connection stays alive.
    ///
    /// The `None` in the return type is now UNREACHABLE and is kept only so the
    /// transport's write decision does not have to change shape: every inbound root
    /// reaching here is answered.
    pub fn dispatch(&self, conn: &mut Conn, env: &Envelope) -> Option<Envelope> {
        if env.root.typ != "system/protocol/execute" {
            // §6.5's "Other type?" arm, as rewritten at 0.8.2.25 (N12/N17): "400
            // invalid_request, coded frame; MAY then close (§3.3, §4.11). NOT a bare
            // close — that is indistinguishable from a network fault."
            //
            // §3.3 read "the connection MUST be closed", assigning no code and requiring
            // no frame, and this peer did something weaker still: it returned `None`, the
            // transport wrote NOTHING, and the connection stayed open — which is §4.11's
            // OTHER non-conformant behaviour, the silent drop, "the weaker of the two
            // precisely because nothing surfaces it". This is a PRE-ADMISSION refusal: the
            // root is not an EXECUTE, so nothing was ever admitted and §4.9(c) does not
            // reach it. §9.1's floor row that used to MANDATE the bare close was REPLACED
            // at the same revision (N18).
            //
            // `request_id` is read best-effort — an arbitrary root type is under no
            // obligation to carry one, and §4.11 licenses the uncorrelated frame exactly
            // there. We do NOT close: on a multiplexed connection that would cost every
            // ADMITTED in-flight request its response, and §4.11 leaves the close to us.
            let request_id = env.root.text_field("request_id").unwrap_or("");
            let result = wire::error_result(
                "invalid_request",
                Some("root entity is neither EXECUTE nor EXECUTE_RESPONSE"),
            );
            return Some(wire::response_envelope(request_id, 400, &result));
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

        // §4.7 (0.8.2.6) — THE ADDRESS IS EVALUATED BEFORE AUTHENTICATION, and this gate
        // used to sit below the verdict. A pre-establishment EXECUTE naming a FOREIGN
        // namespace therefore took the 401 an unauthenticated request takes. §4.7's own
        // reason: "a 401 directs the caller to authenticate and retry, and for a
        // foreign-namespace address that retry cannot succeed at any authentication state
        // — so the 401 names a remedy that does not exist." §6.5 step 3 calls it "a gate,
        // not an ordering preference" and §1.4 makes the downstream permission check
        // unreachable on this path, so evaluating authentication first can only mislead.
        {
            let path = cap::canonicalize(&self.local_peer, &cap::normalize_uri(&uri));
            if cap::extract_peer(&self.local_peer, &path) != self.local_peer {
                return err_out(400, "invalid_request", Some("not local peer"));
            }
        }

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

        let caller_cap = exec
            .bytes_field("capability")
            .and_then(|ch| env.included_get(ch).cloned());
        // (The §1.4 address gate that used to sit here has moved ABOVE the verdict —
        // §4.7 0.8.2.6 orders it before authentication. Reaching this line at all now
        // means the path is local.)
        self.route(conn, env, exec, caller_cap.as_ref(), 0)
    }

    /// §6.6 resolution → §5.2 `check_permission` → body selection, shared by a wire
    /// EXECUTE (after §5.2 `verify_request`) and an in-process `dispatch_execute`.
    /// `env` is the envelope the ORIGINATING request arrived in; it is read only to
    /// resolve the capability's granter frame (§PR-8) and by a body for `included`.
    fn route(
        &self,
        conn: &mut Conn,
        env: &Envelope,
        exec: &Entity,
        caller_cap: Option<&Entity>,
        depth: u32,
    ) -> Outcome {
        let uri = exec.text_field("uri").unwrap_or("");
        let path = cap::canonicalize(&self.local_peer, &cap::normalize_uri(uri));
        let pattern = match self.resolve_handler(&path) {
            Some(p) => p,
            None => return err_out(404, "handler_not_found", Some(&path)),
        };

        // check_permission at the granter frame (§5.2 / §PR-8).
        let cc = match caller_cap {
            Some(c) => c,
            None => return err_out(403, "capability_denied", None),
        };
        let granter_peer = cap::granter_frame(env, &self.store, &self.local_peer, cc);
        if cap::check_permission(&self.local_peer, &granter_peer, exec, cc, &pattern)
            == cap::Verdict::Deny
        {
            return err_out(403, "capability_denied", None);
        }

        let stripped = self.strip_local(&pattern);
        match stripped.as_str() {
            // §6.3's `check_path_permission` needs the caller's capability and the OWNING
            // handler's pattern, and the dispatch-level check above already computed both.
            // They are CARRIED rather than recomputed: recomputing invites the two to
            // drift. `pattern` here is the owner's (§6.3, 0.8.2.23) — for the tree handler
            // owner and runner coincide, so the distinction is not observable, but the
            // argument means the owner.
            //
            // This used to read "§6.8 is explicit that the authority is selected by who
            // named the path" — the discriminator §6.8 CORRECTED at 0.8.2.22 and which
            // §9.1's conformance floor kept publishing until 0.8.2.31. The rule §6.8
            // states now is the COMPOSE: an access in service of a caller's request
            // needs the caller's verified capability AND the executing handler's own
            // grant, and both must pass. Carrying the pair is still right; the reason
            // written beside it was a superseded one.
            "system/tree" => self.tree_handler(exec, caller_cap, &stripped),
            "system/capability" => self.capability_handler(exec, caller_cap),
            "system/handler" => self.handlers_handler(exec),
            "system/type" => err_out(501, "unsupported_operation", exec.text_field("operation")),
            _ => {
                if self.conformance && stripped.starts_with("system/validate/") {
                    return self.conformance_handler(conn, env, exec, &stripped);
                }
                let handler_entity = match self.store.get_at(&pattern) {
                    Some(e) if e.typ == "system/handler" => e,
                    _ => return err_out(501, "no_handler_body", Some(&stripped)),
                };
                let ctx = HandlerContext {
                    peer: self,
                    envelope: env,
                    execute: exec,
                    pattern: stripped.clone(),
                    suffix: path
                        .get(pattern.len()..)
                        .unwrap_or("")
                        .trim_start_matches('/')
                        .to_string(),
                    caller_capability: caller_cap,
                    handler_grant: self.handler_grant(&stripped),
                    conn,
                    depth,
                };
                // H1 — THE READ SITE. A language-native body installed for the resolved
                // pattern answers first. The Arc is cloned out so the container lock is
                // not held while third-party code runs (a body may itself register).
                let native = self
                    .native_handlers
                    .read()
                    .unwrap()
                    .get(&stripped)
                    .map(|(_, h)| h.clone());
                if let Some(h) = native {
                    return guarded(|| h.handle(&ctx));
                }
                // a dynamically-registered handler: dispatch its entity-native body.
                self.entity_native_dispatch(&handler_entity, &ctx)
            }
        }
    }

    fn handler_grant(&self, pattern: &str) -> Option<Entity> {
        self.store.get_at(&format!(
            "/{}/system/capability/grants/{pattern}",
            self.local_peer
        ))
    }

    /// K-5 — `HandlerContext::dispatch_execute`. The authority and bounds rules are
    /// documented there; this is their implementation.
    pub(crate) fn dispatch_local(&self, parent: &HandlerContext<'_>, req: LocalExecute) -> Outcome {
        let depth = parent.depth + 1;
        if depth > MAX_LOCAL_DISPATCH_DEPTH {
            return err_out(
                429,
                "bounds_exceeded",
                Some("local dispatch depth exceeds the peer's bound"),
            );
        }
        let capability = match req.capability.or_else(|| parent.caller_capability.cloned()) {
            Some(c) => c,
            None => {
                return err_out(403, "capability_denied", Some("no capability for local dispatch"))
            }
        };
        if !self.local_capability_admissible(parent, &capability) {
            return err_out(
                403,
                "capability_denied",
                Some("local dispatch capability is not the caller's, the handler's grant, or a valid token this peer issued"),
            );
        }

        let path = cap::canonicalize(&self.local_peer, &cap::normalize_uri(&req.uri));
        if cap::extract_peer(&self.local_peer, &path) != self.local_peer {
            return err_out(
                400,
                "invalid_request",
                Some("local dispatch targets the local peer only; a foreign namespace is the outbound seam"),
            );
        }
        if self.strip_local(&path) == "system/protocol/connect" {
            return err_out(
                400,
                "invalid_request",
                Some("the connect handler serves a connection, not a local dispatch"),
            );
        }

        let n = self.local_dispatch_counter.fetch_add(1, Ordering::Relaxed);
        let request_id = format!("{}/local-{n}", parent.request_id());
        let author = parent
            .author()
            .map(|a| a.to_vec())
            .unwrap_or_else(|| self.identity.identity_hash.clone());
        let exec = wire::make_execute(wire::ExecuteFields {
            request_id: &request_id,
            uri: &req.uri,
            operation: &req.operation,
            params: req.params,
            resource: req.resource,
            author: Some(&author),
            capability: Some(&capability.hash),
        });
        let mut sub_conn = Conn {
            established: true,
            outbound: parent.conn.outbound.clone(),
            max_frame_bytes: parent.conn.max_frame_bytes,
            ..Conn::default()
        };
        self.route(&mut sub_conn, parent.envelope, &exec, Some(&capability), depth)
    }

    /// Which capabilities an in-process dispatch may run under. The caller's verified
    /// capability and the handler's own grant are admissible by identity; any other
    /// token must be one THIS peer issued, with its signature verifiable at the §3.5
    /// pointer, inside its temporal bounds, and unrevoked.
    fn local_capability_admissible(&self, parent: &HandlerContext<'_>, c: &Entity) -> bool {
        if parent.caller_capability.is_some_and(|cc| cc.hash == c.hash)
            || parent.handler_grant.as_ref().is_some_and(|g| g.hash == c.hash)
        {
            return true;
        }
        if c.typ != "system/capability/token"
            || c.bytes_field("granter") != Some(self.identity.identity_hash.as_slice())
        {
            return false;
        }
        let sig_path = format!("/{}/system/signature/{}", self.local_peer, hex(&c.hash));
        let signed = self
            .store
            .get_at(&sig_path)
            .is_some_and(|sig| identity::verify_signature(&sig, &self.identity.peer_entity));
        if !signed {
            return false;
        }
        // CAP-6a: a present-but-unrepresentable temporal field is refused, never read
        // as absent.
        let now = now_ms();
        for (field, in_bounds) in [
            ("expires_at", (|v: u64, now: u64| now <= v) as fn(u64, u64) -> bool),
            ("not_before", |v, now| v <= now),
        ] {
            if c.field(field).is_some() && !c.uint_field(field).is_some_and(|v| in_bounds(v, now)) {
                return false;
            }
        }
        let revoked = format!(
            "/{}/system/capability/revocations/{}",
            self.local_peer,
            hex(&c.hash)
        );
        self.store.get_at(&revoked).is_none()
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
            // §4.7 out-of-order row + the 0.8.2.8 half-open note: a second hello on a
            // HALF-OPEN connection (hello done, authenticate not yet) is an operation we
            // implement arriving in a state that forbids it — the same class as
            // connection_already_established above, taking the same 409. A half-open
            // connection is NOT established, so the guard above cannot reach it; §4.7
            // names this gap explicitly because two adjacent rules each look like they
            // cover it and neither does.
            if conn.issued_nonce.is_some() {
                return err_out(409, "connection_sequence_error", None);
            }
            let params = exec.entity_field("params");
            if let Some(params) = &params {
                if negotiation_reject(params, "hash_formats", "ecfv1-sha256") {
                    return err_out(400, "incompatible_hash_format", None);
                }
                if negotiation_reject(params, "key_types", "ed25519") {
                    return err_out(400, "unsupported_key_type", None);
                }
                // §4.5 mutual verifiability, the direction that is NOT the array.
                // `key_types` is an ACCEPT-SET; the initiator's OWN key_type is not in
                // it — it rides in its `peer_id` — so a hello may advertise a perfectly
                // good accept-set and still name an identity we cannot verify. Checking
                // only the array leaves that MUST unenforced at hello, which is where
                // §4.5 wants it; authenticate catches it one leg later, which is
                // conformant but non-canonical.
                //
                // An UNPARSEABLE peer_id is deliberately left alone: that is a malformed
                // field, not a key_type we lack, and authenticate already refuses it.
                if let Some(pid) = params.text_field("peer_id") {
                    if let Ok(parsed) = crate::peer_id::parse(pid) {
                        if parsed.key_type != 0x01 {
                            return err_out(400, "unsupported_key_type", None);
                        }
                    }
                }
            }
            // §4.5 `protocols` — the one negotiated field Required with NO default, so
            // there is no floor to fall back to, and its two failure modes carry
            // different codes on purpose (§4.5 table row / §4.7 row 1):
            //
            //   absent or empty     -> 400 invalid_request       (a malformed hello)
            //   non-empty, disjoint -> 400 incompatible_protocol (we compared)
            //
            // "a caller that named no version cannot be told the comparison failed" —
            // the remedies differ (send the field vs change the version) and §4.7 exists
            // so the code selects the remedy. The vocabulary is §8.4's protocol version
            // identifiers, today the single entity-core/1.0.
            //
            // ORDERED LAST AMONG THE NEGOTIATED FIELDS, DELIBERATELY. §4.5 states no
            // precedence between the three, so a hello disjoint in more than one
            // dimension may be refused on any of them — but the choice is OBSERVABLE,
            // and the reference peer refuses key_types first. Checking protocols first
            // is equally spec-legal and makes AGILITY-UNKNOWN-1 answer
            // incompatible_protocol, because that probe's own hello carries protocols
            // ["entity-core/v7"] — a spec-line name, not a §8.4 identifier (F56).
            let protos: Vec<&str> = params
                .as_ref()
                .and_then(|p| p.field("protocols"))
                .and_then(|v| match v {
                    Value::Array(arr) => Some(
                        arr.iter()
                            .filter_map(|it| match it {
                                Value::Text(s) => Some(s.as_str()),
                                _ => None,
                            })
                            .collect(),
                    ),
                    _ => None,
                })
                .unwrap_or_default();
            if protos.is_empty() {
                return err_out(
                    400,
                    "invalid_request",
                    Some("hello: protocols absent or empty"),
                );
            }
            if !protos.contains(&"entity-core/1.0") {
                return err_out(400, "incompatible_protocol", None);
            }
            if let Some(params) = &params {
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
                // RT-6 (§4.6, 0.8.1): a replayed authenticate re-presents the consumed
                // single-use nonce. The anti-replay property is the MUST and the
                // mechanism (established-state tracking) is impl-defined, but the STATUS
                // is pinned to 401 invalid_nonce — a 409 under-signals the replay.
                return err_out(401, "invalid_nonce", None);
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
        // §4.7 row 10 (0.8.2.4): on the CONNECT handler an unknown operation is
        // 400 invalid_request, not the 501 every other handler answers. The table
        // separates a STATE conflict from an UNKNOWN operation because they select
        // different remedies — "an unknown connect operation is not out of order at
        // all; it exists in no state", so connection_sequence_error would point the
        // caller at its ORDERING when the defect is its OPERATION NAME. Row 10 is
        // scoped "in any state", so this arm covers pre-handshake AND established;
        // the genuine sequence cases are refused above, with 409.
        //
        // SCOPED TO THIS HANDLER DELIBERATELY. The generic registered-handler rule
        // (§3.3's 501 row, §6.2) is a different contract and is separately gated;
        // moving the shared 501 would trade one green check for another.
        err_out(
            400,
            "invalid_request",
            Some(&format!("connect: unknown operation {op}")),
        )
    }

    /// The `ttl_ms` of the policy entry that ceilings THIS caller (§6.2 CAP-5), via the
    /// same dual-form lookup the §4.4 authenticate path uses (hex → Base58 → `default`).
    ///
    /// This is the term that makes policy withdrawal bounded on the `request` path: the
    /// entry's `ttl_ms` is the withdrawal latency for tokens already issued.
    fn policy_ttl_ms(&self, grantee_hash: &[u8]) -> Option<u64> {
        let base = format!("/{}/system/capability/policy/", self.local_peer);
        let entry = self
            .store
            .get_at(&format!("{base}{}", hex(grantee_hash)))
            .or_else(|| {
                let peer = self.store.get_by_hash(grantee_hash)?;
                let pk = peer.bytes_field("public_key")?;
                let pid = identity::peer_id_of_pubkey(pk);
                self.store.get_at(&format!("{base}{pid}"))
            })
            .or_else(|| self.store.get_at(&format!("{base}default")))?;
        entry.uint_field("ttl_ms")
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

    /// The §6.8a execution context for a §6.10 tree-change event, built from what this
    /// dispatch holds (SYSTEM-COMPOSITION §1.4 inventory).
    ///
    /// WHY IT EXISTS. `TreeChangeEvent` had no context field, so every tree-change event
    /// reached a consumer contextless — and that is not a neutral absence.
    /// `EXTENSION-HISTORY` §2.1 defines the AUTONOMOUS case exactly, so a contextless
    /// event is indistinguishable from an autonomous write and a conforming recorder
    /// attributes a REMOTE caller's write to the local peer. §7.2 calls `capability` the
    /// answer to "under what authority?", and the answer was always "its own". Routed by
    /// `entity-system-generator` (H8); the four `history` oracle checks over these fields
    /// are PRESENCE checks, so a peer scores on them either way.
    ///
    /// Slots a core request does not carry are READ FROM THE WIRE and left `None`, never
    /// invented.
    pub(crate) fn exec_context(&self, exec: &Entity, handler_pattern: &str) -> ExecContext {
        // The handler's own grant — the second authority a write runs under, distinct
        // from the caller's. Bound at bootstrap/registration.
        let handler_grant = self
            .store
            .get_at(&format!(
                "/{}/system/capability/grants/{}",
                self.local_peer, handler_pattern
            ))
            .map(|e| e.hash.clone());
        ExecContext {
            request_id: exec.text_field("request_id").unwrap_or("").to_string(),
            handler_pattern: handler_pattern.to_string(),
            operation: exec.text_field("operation").unwrap_or("").to_string(),
            author: exec.bytes_field("author").map(|b| b.to_vec()),
            caller_capability: exec.bytes_field("capability").map(|b| b.to_vec()),
            handler_grant,
            chain_id: exec.text_field("chain_id").map(str::to_string),
            parent_chain_id: exec.text_field("parent_chain_id").map(str::to_string),
            cascade_depth: exec.uint_field("cascade_depth"),
        }
    }

    /// The `system/tree` handler (§6.3).
    ///
    /// RESOLVE THE OPERATION FIRST; only then run the §3.3 resource ladder. The `match op`
    /// below is what makes that true, and it is the shape RULE G asks for: a handler that
    /// validates the resource first answers a RESOURCE fault for an unknown-OPERATION
    /// request, so `system/tree:bogusop` with no resource reports `ambiguous_resource`
    /// where §3.3 pins `501 unsupported_operation`.
    fn tree_handler(
        &self,
        exec: &Entity,
        caller_cap: Option<&Entity>,
        pattern: &str,
    ) -> Outcome {
        let op = exec.text_field("operation").unwrap_or("");
        match op {
            "get" => {
                // §3.3's ladder runs on the EFFECTIVE list (0.8.2.20), never on
                // `resource.targets`: a handler that counts the effective list and then
                // indexes `targets[0]` has implemented the arithmetic completely and is
                // still reading a path no authorization covered.
                let (eff, has_resource) = cap::effective_targets(&self.local_peer, exec);
                if !has_resource {
                    // THE TWO EMPTIES ARE DISTINCT HERE, AND THE OPERATION'S OWN
                    // SPECIFICATION IS WHAT SAYS SO. §3.3's "an empty effective list IS
                    // the absent case" is scoped "for an operation that REQUIRES a
                    // resource" (0.8.2.24, N7); `get` does not. For a resource-OPTIONAL
                    // operation 0.8.2.25 (N10) decides the present-but-empty case by
                    // whether the absent case is WIDER than the request — BROAD-RESULT
                    // refuses it, OPTIONAL-FILTER answers it empty — and requires the
                    // operation to declare which it is.
                    //
                    // EXTENSION-TREE §2.2a (v4.11) is that declaration: `get` is
                    // resource-OPTIONAL and BROAD-RESULT, absent-case answer "the root
                    // listing", self-excluded case "400 path_required". Both arms are
                    // pinned by text and neither is this peer's choice.
                    return self.build_listing(
                        &format!("/{}/", self.local_peer),
                        caller_cap,
                        pattern,
                    );
                }
                if eff.is_empty() {
                    // The self-excluded request: `resource` PRESENT, every target carved
                    // out by the caller's own exclude. Serving it the absent case
                    // "answers a request for one excluded path with a listing of the
                    // tree" (EXTENSION-TREE §2.2a) — the root listing is wider than what
                    // was asked for, which is what BROAD-RESULT means.
                    return err_out(
                        400,
                        "path_required",
                        Some("tree: effective target list is empty"),
                    );
                }
                if eff.len() > 1 {
                    return err_out(
                        400,
                        "ambiguous_resource",
                        Some("tree: more than one effective target"),
                    );
                }
                let target = eff.into_iter().next().unwrap_or_default();
                if !path_flex_ok(&target) {
                    return err_out(400, "invalid_path", Some(&target));
                }
                if target.is_empty() || target.ends_with('/') {
                    return self.build_listing(
                        &cap::canonicalize(&self.local_peer, &target),
                        caller_cap,
                        pattern,
                    );
                }
                if is_pattern_path(&target) {
                    return err_out(400, "malformed_resource", Some(&target));
                }
                let path = cap::canonicalize(&self.local_peer, &target);
                // §6.3: the handler MUST verify the CALLER's capability covers the path it
                // is about to read. NOT a secondary check — the dispatch-level check never
                // saw this path if the caller excluded it.
                if let Some(cc) = caller_cap {
                    if !cap::check_path_permission(
                        "get",
                        &path,
                        cc,
                        pattern,
                        &self.local_peer,
                    ) {
                        return err_out(403, "capability_denied", Some(&path));
                    }
                }
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
                // Same ladder as `get`, with the two empties COLLAPSED rather than split:
                // EXTENSION-TREE §2.2a (v4.11) declares `put` resource-REQUIRED, so §3.3's
                // "an empty effective list IS the absent case" applies in its unscoped form
                // and both empties answer `path_required`. That is the same table `get`'s
                // branch cites, read one row down.
                //
                // Note the code change 0.8.2.20 forced: this branch answered
                // `ambiguous_resource` for a MISSING target, which 0.8.2.20 names as the
                // exact inversion it forbids ("answering ambiguous_resource for an absent
                // resource inverts them"). The remedies differ — *supply a resource* is not
                // *disambiguate your request* — and the code is what selects between them.
                let (eff, has_resource) = cap::effective_targets(&self.local_peer, exec);
                if !has_resource || eff.is_empty() {
                    return err_out(
                        400,
                        "path_required",
                        Some("tree: put requires a resource target"),
                    );
                }
                if eff.len() > 1 {
                    return err_out(
                        400,
                        "ambiguous_resource",
                        Some("tree: more than one effective target"),
                    );
                }
                let target = eff.into_iter().next().unwrap_or_default();
                if !path_flex_ok(&target) {
                    return err_out(400, "invalid_path", Some(&target));
                }
                if is_pattern_path(&target) {
                    return err_out(400, "malformed_resource", Some(&target));
                }
                let path = cap::canonicalize(&self.local_peer, &target);
                if let Some(cc) = caller_cap {
                    if !cap::check_path_permission(
                        "put",
                        &path,
                        cc,
                        pattern,
                        &self.local_peer,
                    ) {
                        return err_out(403, "capability_denied", Some(&path));
                    }
                }
                let params = exec.entity_field("params");
                let entity = params.as_ref().and_then(|p| p.field("entity")).cloned();
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
                    Some(raw) => match admit_put(&raw) {
                        Ok(e) => {
                            self.store.bind_with_context(
                                &path,
                                &e,
                                Some(self.exec_context(exec, "system/tree")),
                            );
                            ok(Entity::make("system/hash", model::bytes(&e.hash)))
                        }
                        Err(refusal) => refusal,
                    },
                    None => err_out(400, "unexpected_params", Some("put: missing entity")),
                }
            }
            _ => err_out(501, "unsupported_operation", Some(op)),
        }
    }

    /// Render a directory listing, FILTERED per §6.3 (0.8.2.21/.22).
    ///
    /// *"When any handler returns a multi-entry result whose entries are tree paths, each
    /// entry MUST be individually checked using `check_path_permission`. Entries for which
    /// `check_path_permission` returns DENY MUST be omitted. The result's `count` field
    /// MUST reflect the filtered entry count, not the source tree's total count."*
    ///
    /// This is the read path at its highest volume and it is the reason 0.8.2.21 refused
    /// to carve reads out of the caller-specified-path rule: an unfiltered listing
    /// discloses the EXISTENCE of every binding under a prefix to a caller whose
    /// capability covers none of them.
    ///
    /// The DIRECTORY itself is deliberately NOT checked — §6.3 makes each ENTRY the
    /// subject, and testing the prefix would deny a listing to a caller whose grant covers
    /// children but not the node above them, which is the ordinary shape of a narrowed
    /// grant.
    ///
    /// An UNAUTHENTICATED context (`caller_cap == None`) is not filtered: the filter's
    /// subject is "the caller's verified capability", and where there is none there is no
    /// caller to narrow. That is the bootstrap/internal path.
    fn build_listing(
        &self,
        path: &str,
        caller_cap: Option<&Entity>,
        pattern: &str,
    ) -> Outcome {
        let entries = self.store.listing(path);
        let mut entry_pairs: Vec<(Key, Value)> = vec![];
        let mut emitted: u64 = 0;
        let dir = if path.ends_with('/') {
            path.to_string()
        } else {
            format!("{path}/")
        };
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
            // §6.3's per-entry check (0.8.2.21/.22).
            if let Some(cc) = caller_cap {
                let child = format!("{dir}{}", le.seg);
                if !cap::check_path_permission("get", &child, cc, pattern, &self.local_peer) {
                    continue;
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
                self.mint_bounded(
                    caller_cap,
                    req_grants(params.as_ref()),
                    &grantee,
                    None,
                    params.as_ref(),
                )
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
                        self.mint_bounded(
                            caller_cap,
                            req_grants(params.as_ref()),
                            a,
                            Some(&parent),
                            params.as_ref(),
                        )
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
        params: Option<&Entity>,
    ) -> Outcome {
        let bounded = match caller_cap {
            Some(cc) => cap::requested_grants_within(&self.local_peer, &req_grants, cc),
            None => false,
        };
        if !bounded {
            return err_out(403, "scope_exceeds_authority", None);
        }
        // §6.2 CAP-5 / §5.6 MIN_DEFINED. `request` mints a ROOT token (parent: null), so
        // §5.6's parent-child attenuation rule never reaches it — without this bound,
        // temporal attenuation is the one dimension a requester can escape.
        //
        //   expires_at = MIN_DEFINED(
        //       caller_capability.expires_at,      ; ABSOLUTE — enters directly
        //       created_at + policy_entry.ttl_ms,  ; DURATION — converted first
        //       created_at + request.ttl_ms)       ; DURATION — converted first
        //
        // Term SHAPE is the trap: mixing a duration in unconverted yields a timestamp
        // near the epoch and clamps every token to already-expired. The disposition is a
        // CLAMP, never a rejection — an over-long request from a bounded caller mints at
        // 200 with the clamped value; rejecting it is explicitly non-conformant.
        let created_at = now_ms();
        let expires_at = min_defined([
            caller_cap.and_then(|cc| cc.uint_field("expires_at")),
            duration_term(created_at, self.policy_ttl_ms(grantee_hash)),
            duration_term(created_at, params.and_then(|p| p.uint_field("ttl_ms"))),
        ]);
        let minted = mint_token_at(
            &self.identity,
            grantee_hash,
            parent,
            req_grants,
            created_at,
            expires_at,
        );
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
            "register" => self.wire_register(exec),
            "unregister" => self.wire_unregister(exec),
            op => err_out(501, "unsupported_operation", Some(op)),
        }
    }

    fn wire_register(&self, exec: &Entity) -> Outcome {
        let pattern = match register_pattern(exec) {
            Ok(p) => p,
            Err(o) => return o,
        };
        if is_reserved_system_pattern(&pattern) {
            return err_out(
                403,
                "forbidden_pattern",
                Some(&format!(
                    // ASCII-ONLY: this string is CBOR-text-encoded and put on the wire.
                    // The section sign stays in comments (ratified discipline; two peers
                    // in this cohort have been killed at runtime by a non-ASCII byte in
                    // an encoded string, on two unrelated compilers).
                    "section 6.2: user-installed handlers MUST NOT register at system/* paths: {pattern}"
                )),
            );
        }
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

        // The tree is the source of truth: a wire registration at a pattern that had a
        // native body replaces that handler, exactly as it replaces an entity-native one.
        self.native_handlers.write().unwrap().remove(&pattern);
        let token = self.bind_handler_entities(
            &pattern,
            &name,
            operations,
            expression_path.as_deref(),
            internal_scope.as_ref(),
            req.field("types"),
            grant_scope,
        );

        let result = Entity::make(
            "system/handler/register-result",
            Value::Map(vec![
                (Key::Text("pattern".into()), model::text(&pattern)),
                (Key::Text("grant".into()), token.data.clone()),
            ]),
        );
        ok(result)
    }

    fn wire_unregister(&self, exec: &Entity) -> Outcome {
        let pattern = match register_pattern(exec) {
            Ok(p) => p,
            Err(o) => return o,
        };
        self.native_handlers.write().unwrap().remove(&pattern);
        self.unbind_handler_entities(&pattern);
        ok(wire::empty_params())
    }

    // ── entity-native handler dispatch (§6.13(a)) ───────────────────────────────

    fn entity_native_dispatch(&self, handler_entity: &Entity, ctx: &HandlerContext<'_>) -> Outcome {
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
        // H7 — the installed evaluator takes the fallback arm, AFTER the built-in floor,
        // so a peer with none installed is byte-identical to the peer before the seam.
        // It discriminates on the body, never on a status: `None` is "not mine".
        if let Some(evaluator) = self.expression_evaluator() {
            let request = ExpressionRequest {
                expression_path: &expr_path,
                expression: &expr,
                handler_entity,
            };
            match catch_unwind(AssertUnwindSafe(|| evaluator.evaluate(&request, ctx))) {
                Ok(Some(result)) => return result,
                Ok(None) => {}
                Err(_) => {
                    return err_out(500, "internal_error", Some("expression evaluator panicked"))
                }
            }
        }
        err_out(501, "unsupported_expression", Some(&expr.typ))
    }

    // ── §7a conformance handlers ────────────────────────────────────────────────

    fn conformance_handler(
        &self,
        conn: &mut Conn,
        env: &Envelope,
        exec: &Entity,
        stripped: &str,
    ) -> Outcome {
        match stripped {
            "system/validate/echo" => self.echo_handler(exec),
            // §1.4 PD-2 needs the OWNING handler's peer-relative pattern (Dimension 1
            // is matched peer-relative) and the parent envelope (the §7a.2a bundle
            // base). Both are already in hand here, so they are CARRIED.
            "system/validate/dispatch-outbound" => {
                self.dispatch_outbound_handler(conn, env, exec, stripped)
            }
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
    fn dispatch_outbound_handler(
        &self,
        conn: &mut Conn,
        env: &Envelope,
        exec: &Entity,
        handler_pattern: &str,
    ) -> Outcome {
        let out_fn = match &conn.outbound {
            Some(f) => f.clone(),
            None => {
                return err_out(
                    503,
                    "no_outbound_seam",
                    // ASCII-only wire-visible string (see the forbidden_pattern site).
                    Some("dispatch-outbound requires a live section 6.11 reentry connection"),
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
        // GUIDE-CONFORMANCE §7a.1: PLURAL carriers [0.8.2.19]. Arrays, and the
        // single-granter case is an array of ONE. They were singular, which made §1.4's
        // multi-signature-root rule ungateable on the wire: driving it needs two
        // granter identities and two signatures, and a single-credential carrier
        // cannot express that input.
        //
        // TRANSITIONAL: the SINGULAR spellings are still accepted, as a list of one,
        // because THE RENAME IS NOT INDEPENDENT OF THE ORACLE PIN. The pinned oracle is
        // what all 46 tracked reports are measured against and it sends the SINGULAR
        // names; a plural-only peer reads the triple as absent there, takes the ambient
        // arm and refuses — measured on the `go` vanguard as 2 of 778 severities moving
        // PASS -> FAIL. Accepting both keeps the cohort 0-FAIL at BOTH check sets.
        // REMOVE THIS FALLBACK AT THE ORACLE RE-PIN, and not before: the exit condition
        // is that `tools/oracle-pin.env`'s `ref` names an oracle whose dispatch-outbound
        // probe sends the plural carriers.
        let entity_list = |key: &str| -> Option<Vec<Entity>> {
            match params.field(key) {
                // An array whose members do not all decode is a MALFORMED carrier and
                // is None, never a silently shorter list — the all-or-none test below
                // would otherwise read a partial credential as a complete one.
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|v| model::entity_of_cbor(v).ok())
                    .collect::<Option<Vec<Entity>>>(),
                _ => None,
            }
        };
        let cap_e = params.entity_field("reentry_capability");
        let granters = entity_list("reentry_granters")
            .or_else(|| params.entity_field("reentry_granter").map(|g| vec![g]));
        let cap_sigs = entity_list("reentry_cap_signatures")
            .or_else(|| params.entity_field("reentry_cap_signature").map(|c| vec![c]));
        // The triple is ALL-OR-NONE (§7a.1): all three present selects the PRESENTED
        // arm, all three absent selects the AMBIENT arm, and a PARTIAL set is 400
        // invalid_params — a partial credential is malformed, not ambient. An empty
        // array is partial, not present: it carries no credential.
        let n_present = [
            cap_e.is_some(),
            granters.as_ref().is_some_and(|v| !v.is_empty()),
            cap_sigs.as_ref().is_some_and(|v| !v.is_empty()),
        ]
        .iter()
        .filter(|b| **b)
        .count();
        if n_present != 0 && n_present != 3 {
            return err_out(
                400,
                "invalid_params",
                Some("dispatch-outbound reentry authority is all-or-none"),
            );
        }
        let has_cred = n_present == 3;
        let cred = if has_cred { cap_e } else { None };
        let granters = if has_cred { granters.unwrap_or_default() } else { vec![] };
        let cap_sigs = if has_cred { cap_sigs.unwrap_or_default() } else { vec![] };

        // §7a.1: the `value` field IS the outbound params entity data — pass it
        // through (re-wrapping double-wraps and breaks echo's result.value).
        let inner = Entity::make("primitive/any", value);

        // `target` arrives as any of §1.4's three spellings and the validator sends the
        // SCHEMED ABSOLUTE form. Both the handler-pattern dimension and the resource
        // target want the PEER-RELATIVE path — §1.4's PD-2 block says so for Dimension
        // 1, and a resource target carrying a scheme is not a path at all.
        let rel_target = cap::peer_relative_of(&target);
        let resource = Value::Map(vec![(
            Key::Text("targets".into()),
            Value::Array(vec![model::text(&format!("system/handler/{rel_target}"))]),
        )]);

        // §7a.2a: the presented arm verifies against a BUNDLE MERGED FROM THE PARENT
        // ENVELOPE'S `included`. The credential, its granters and its signatures arrive
        // NESTED IN PARAMS (ratified shape (a), in-band), so they are not in `env` and
        // a verifier handed that alone cannot resolve a single link — every credential
        // then reads as invalid and the legitimate reentry is refused.
        // `included` is a BTreeMap keyed by content-hash BYTES, so the merge is an
        // insert per entity — and the key MUST be the entity's own hash, or the entry
        // is invisible to the resolver and the credential reads as unresolvable.
        let mut bundle_included = env.included.clone();
        if has_cred {
            for e in cred
                .iter()
                .cloned()
                .chain(granters.iter().cloned())
                .chain(cap_sigs.iter().cloned())
            {
                bundle_included.insert(e.hash.clone(), e);
            }
        }
        let bundle = Envelope {
            root: env.root.clone(),
            included: bundle_included,
        };

        // §1.4: target_peer = extract_peer(uri, local_peer_id). The validator sends the
        // absolute form, so the URI names the target. Where the uri is PEER-RELATIVE
        // there is no peer in it and the §6.11 seam's destination is the connection's
        // remote, so that is the fallback — without it Dimension 4 passes vacuously.
        let uri_peer = cap::extract_peer(&self.local_peer, &target).to_string();
        let target_peer = if uri_peer == self.local_peer {
            conn.hello_peer_id.clone().unwrap_or(uri_peer)
        } else {
            uri_peer
        };

        // §1.4 PD-2: check_permission runs BEFORE the sub-dispatch leaves the peer, all
        // four dimensions, on THIS handler's own grant — with a target-minted credential
        // relaxing Dimension 4 and nothing else. Consulting only the presented
        // credential here is the §6.8 confused-deputy bypass.
        let own_grant = match self
            .store
            .get_at(&cap::grant_path_for(&self.local_peer, handler_pattern))
        {
            Some(g) => g,
            // §6.8: a handler with no valid grant does not run. Fail closed rather than
            // falling back to the credential, which is the substitution §6.8 forbids.
            None => return err_out(403, "capability_denied", Some("no handler grant")),
        };
        if !cap::check_outbound_sub_dispatch(
            &bundle,
            &self.store,
            &self.local_peer,
            &target_peer,
            &rel_target,
            &operation,
            &own_grant,
            &resource,
            cred.as_ref(),
        ) {
            // §7a.1a: the surfaced code is the AUTHORIZATION domain's code. A generic
            // transport- or gateway-class code would launder an authorization verdict
            // into a route fault, and the ambient and presented branches would then
            // disagree about what the same gate decided.
            return err_out(
                403,
                "capability_denied",
                Some("outbound sub-dispatch not authorized by the handler grant"),
            );
        }

        conn.out_counter += 1;
        let rid = format!("ro-{}", conn.out_counter);
        // The AMBIENT arm carries no credential, so the EXECUTE carries no `capability`
        // field. An empty hash would NOT do — that is a present field resolving to
        // nothing, which §5.2 reads as an unresolvable capability rather than as its
        // absence.
        let cap_hash = cred.as_ref().map(|c| c.hash.clone());
        let req_exec = wire::make_execute(wire::ExecuteFields {
            request_id: &rid,
            uri: &target,
            operation: &operation,
            params: inner,
            resource: Some(resource),
            author: Some(&self.identity.identity_hash),
            capability: cap_hash.as_deref(),
        });
        let exec_sig = self.identity.sign_entity(&req_exec);
        // Every granter and every signature goes into `included` because §5.5's chain
        // walk resolves them BY HASH out of that map — a granter left out is a link the
        // verifier cannot reach, which fails closed and reads as the peer refusing the
        // credential form rather than as a carrier we truncated.
        let mut carried: Vec<Entity> = Vec::new();
        if let Some(c) = cred {
            carried.push(c);
            carried.extend(granters);
            carried.extend(cap_sigs);
        }
        carried.push(exec_sig);
        let req_env = Envelope::with_included(req_exec, carried);
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

/// A handler's OWN grant (§6.8) — the authority it spends when it dispatches onward,
/// as distinct from any capability a caller presents. §6.8 row 1: an access in service
/// of a caller's request needs the caller's verified capability AND this grant, and
/// BOTH must pass.
///
/// NARROW BY DESIGN for `dispatch-outbound`, and the narrowness is what makes the
/// intersection MEASURABLE. GUIDE-CONFORMANCE §7a.1 makes it a scaffold-contract
/// requirement: with a wide grant, consulting it and skipping it give the same answer
/// on every input, so the confused-deputy discriminator cannot fire and a bypass reads
/// as conformant. Every other bootstrap handler keeps the empty list.
pub(crate) fn own_grants_for(pattern: &str) -> Vec<Value> {
    if pattern != "system/validate/dispatch-outbound" {
        return vec![];
    }
    let scope = |v: &str| {
        model::map(vec![("include", Value::Array(vec![model::text(v)]))])
    };
    vec![model::map(vec![
        ("handlers", scope("system/validate/echo")),
        ("operations", scope("echo")),
        ("resources", scope("system/handler/system/validate/echo")),
    ])]
}

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

/// A §5.4 PATTERN rather than a concrete path. A resource-requiring operation takes a
/// CONCRETE path (0.8.2.20), and a trailing `/` is a listing request rather than a
/// pattern — only a `*` makes it one.
fn is_pattern_path(t: &str) -> bool {
    t.contains('*')
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

/// Run an installed body, answering a panic with `500 internal_error` (§4.9(c)): the
/// body is third-party code on the dispatch path and must not take the connection —
/// or the connection's mutex — down with it.
fn guarded<F: FnOnce() -> Outcome>(f: F) -> Outcome {
    catch_unwind(AssertUnwindSafe(f))
        .unwrap_or_else(|_| err_out(500, "internal_error", Some("handler panicked")))
}

/// A concrete peer-relative handler pattern: non-empty segments, no `.`/`..`, no
/// wildcard, no NUL, not absolute.
fn is_concrete_pattern(pattern: &str) -> bool {
    !pattern.is_empty()
        && !pattern.starts_with('/')
        && !pattern.contains('\0')
        && pattern
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != ".." && !seg.contains('*'))
}

/// §6.2: user-installed handlers MUST NOT register at system/* paths.
fn is_reserved_system_pattern(pattern: &str) -> bool {
    pattern == "system" || pattern.starts_with("system/")
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
        let hello = |params: Entity| {
            wire::make_execute(wire::ExecuteFields {
                request_id: "r1",
                uri: "system/protocol/connect",
                operation: "hello",
                params,
                resource: None,
                author: None,
                capability: None,
            })
        };
        // The ACCEPT direction, and it is the one that validates the FIXTURE: a hello
        // MUST carry `protocols` (§4.5 — Required, no default), so this params entity
        // is what a well-formed hello looks like and every deny case below differs
        // from it in exactly one field.
        let mut conn = Conn::new();
        let good = Entity::make(
            "primitive/any",
            model::map(vec![("protocols", model::text_array(&["entity-core/1.0"]))]),
        );
        let env = Envelope::new(hello(good.clone()));
        let resp = p.dispatch(&mut conn, &env).unwrap();
        assert_eq!(resp.root.uint_field("status"), Some(200));
        assert!(conn.issued_nonce.is_some());

        // §4.7 out-of-order / 0.8.2.8 half-open: the connection above is now half-open
        // (nonce issued, not established), so a SECOND hello is 409 — the guard that
        // `established` alone cannot reach.
        let env = Envelope::new(hello(good));
        let resp = p.dispatch(&mut conn, &env).unwrap();
        assert_eq!(resp.root.uint_field("status"), Some(409));

        // §4.5 / §4.7 row 1: absent `protocols` is a malformed hello (400
        // invalid_request), NOT a failed comparison (400 incompatible_protocol) —
        // the two select different remedies, so the codes are asserted separately.
        let mut conn = Conn::new();
        let env = Envelope::new(hello(wire::empty_params()));
        let resp = p.dispatch(&mut conn, &env).unwrap();
        assert_eq!(resp.root.uint_field("status"), Some(400));
        assert_eq!(
            resp.root
                .entity_field("result")
                .and_then(|r| r.text_field("code").map(String::from)),
            Some("invalid_request".to_string())
        );
        assert!(conn.issued_nonce.is_none());

        let mut conn = Conn::new();
        let disjoint = Entity::make(
            "primitive/any",
            model::map(vec![("protocols", model::text_array(&["entity-core/9.9"]))]),
        );
        let env = Envelope::new(hello(disjoint));
        let resp = p.dispatch(&mut conn, &env).unwrap();
        assert_eq!(resp.root.uint_field("status"), Some(400));
        assert_eq!(
            resp.root
                .entity_field("result")
                .and_then(|r| r.text_field("code").map(String::from)),
            Some("incompatible_protocol".to_string())
        );
    }

    /// §4.7 row 10 (0.8.2.4): an unknown operation on the CONNECT handler is
    /// 400 invalid_request, and the differential is the point — the same unknown
    /// operation on any OTHER registered handler stays 501 unsupported_operation
    /// (§3.3's 501 row). A peer can satisfy row 10 by making every unknown
    /// operation 400, which trades one contract for another and looks like a fix.
    #[test]
    fn connect_unknown_operation_is_400_and_others_stay_501() {
        let p = Peer::create(CreateOptions {
            seed: [7u8; 32],
            ..Default::default()
        });
        let unknown = |uri: &str| {
            wire::make_execute(wire::ExecuteFields {
                request_id: "r1",
                uri,
                operation: "no_such_operation",
                params: wire::empty_params(),
                resource: None,
                author: None,
                capability: None,
            })
        };
        let code = |o: &Outcome| o.result.text_field("code").map(String::from);

        let mut conn = Conn::new();
        let env = Envelope::new(unknown("system/protocol/connect"));
        let out = p.connect_handler(&mut conn, &env.root, &env);
        assert_eq!(out.status, 400);
        assert_eq!(code(&out), Some("invalid_request".to_string()));

        // The differential. Same unknown operation, a registered NON-connect handler:
        // still 501. Measured together the trade is visible; measured apart it is not.
        let out = p.tree_handler(&unknown("system/tree"), None, "system/tree");
        assert_eq!(out.status, 501);
        assert_eq!(code(&out), Some("unsupported_operation".to_string()));
        let out = p.capability_handler(&unknown("system/capability"), None);
        assert_eq!(out.status, 501);
        assert_eq!(code(&out), Some("unsupported_operation".to_string()));
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
        let out1 = p.build_listing(&format!("{base}/"), None, "system/tree");
        assert_eq!(out1.result.uint_field("count"), Some(2));
        let marker = Entity::make("system/deletion-marker", Value::Map(vec![]));
        p.store.bind(&format!("{base}/target"), &marker);
        let out2 = p.build_listing(&format!("{base}/"), None, "system/tree");
        assert_eq!(out2.result.uint_field("count"), Some(1));
    }

    // ── §3.3's effective-targets ladder + §6.3's listing filter ────────────────

    fn out_code(o: &Outcome) -> Option<&str> {
        o.result.text_field("code")
    }

    fn tree_exec(op: &str, resource: Option<Value>) -> Entity {
        let mut pairs = vec![
            (Key::Text("request_id".into()), Value::Text("t1".into())),
            (Key::Text("uri".into()), Value::Text("system/tree".into())),
            (Key::Text("operation".into()), Value::Text(op.into())),
        ];
        if let Some(r) = resource {
            pairs.push((Key::Text("resource".into()), r));
        }
        Entity::make("system/protocol/execute", Value::Map(pairs))
    }

    fn resource(targets: &[&str], exclude: &[&str]) -> Value {
        let arr = |v: &[&str]| Value::Array(v.iter().map(|s| model::text(s)).collect());
        let mut pairs = vec![(Key::Text("targets".into()), arr(targets))];
        if !exclude.is_empty() {
            pairs.push((Key::Text("exclude".into()), arr(exclude)));
        }
        Value::Map(pairs)
    }

    /// A token granting `get`/`put` on `system/tree` for exactly `resources`.
    fn narrow_token(resources: &[&str]) -> Entity {
        let scope = |v: &[&str]| {
            model::map(vec![(
                "include",
                Value::Array(v.iter().map(|s| model::text(s)).collect()),
            )])
        };
        Entity::make(
            "system/capability/token",
            model::map(vec![(
                "grants",
                Value::Array(vec![model::map(vec![
                    ("handlers", scope(&["system/tree"])),
                    ("operations", scope(&["get", "put"])),
                    ("resources", scope(resources)),
                ])]),
            )]),
        )
    }

    /// §3.3's ladder (0.8.2.20, refined at .24/.25) runs on the EFFECTIVE list, never on
    /// `resource.targets`. Each row names the disposition the revision pins; the two
    /// EMPTIES are deliberately different for `get` (EXTENSION-TREE §2.2a v4.11 declares
    /// it resource-OPTIONAL and BROAD-RESULT) and deliberately the same for `put`
    /// (resource-REQUIRED).
    #[test]
    fn tree_ladder_dispositions() {
        let p = Peer::create(CreateOptions {
            seed: [11u8; 32],
            open_grants: true,
            ..Default::default()
        });
        let run = |op: &str, r: Option<Value>| p.tree_handler(&tree_exec(op, r), None, "system/tree");

        // get, ABSENT resource -> the root listing (§2.2a's absent-case answer).
        let out = run("get", None);
        assert_eq!(out.status, 200);
        assert_eq!(out.result.typ, "system/tree/listing");

        // get, PRESENT and self-excluded -> 400 path_required. Serving this the absent
        // case would answer a request for one excluded path with a listing of the tree.
        let out = run("get", Some(resource(&["app/a"], &["app/a"])));
        assert_eq!((out.status, out_code(&out)), (400, Some("path_required")));

        // get, two survivors -> 400 ambiguous_resource. A peer indexing targets[0]
        // answers 200 and cannot tell the caller it ignored the second.
        let out = run("get", Some(resource(&["app/a", "app/b"], &[])));
        assert_eq!((out.status, out_code(&out)), (400, Some("ambiguous_resource")));

        // get, a PATTERN subject -> 400 malformed_resource. A resource-requiring
        // operation takes a CONCRETE path; without this the pattern is looked up as a
        // literal and answers 404, which names the wrong fault.
        let out = run("get", Some(resource(&["system/type/*"], &[])));
        assert_eq!((out.status, out_code(&out)), (400, Some("malformed_resource")));

        // put, ABSENT resource -> 400 path_required, NOT ambiguous_resource. 0.8.2.20
        // names that inversion outright: *supply a resource* is not *disambiguate your
        // request*, and the code is what selects the remedy.
        let out = run("put", None);
        assert_eq!((out.status, out_code(&out)), (400, Some("path_required")));
        // put, self-excluded: the same answer, because §2.2a declares put
        // resource-REQUIRED and §3.3's "an empty effective list IS the absent case"
        // applies in its unscoped form.
        let out = run("put", Some(resource(&["app/a"], &["app/a"])));
        assert_eq!((out.status, out_code(&out)), (400, Some("path_required")));
        let out = run("put", Some(resource(&["app/a", "app/b"], &[])));
        assert_eq!((out.status, out_code(&out)), (400, Some("ambiguous_resource")));

        // RULE G control: the OPERATION resolves first. An unknown op with no resource
        // answers the OPERATION fault, never the resource one — a handler that validates
        // the resource first answers `ambiguous_resource`/`path_required` here.
        let out = run("bogusop", None);
        assert_eq!((out.status, out_code(&out)), (501, Some("unsupported_operation")));
    }

    /// THE SELECTION, which the arithmetic alone does not give you: with
    /// `targets:[a,b] exclude:[a]` the effective set is `{b}`, size 1, so the COUNT rule
    /// says proceed — and a raw `targets[0]` selector proceeds on `a`. Both targets are
    /// bound, so a 200 naming `a` is a selection defect and nothing else.
    #[test]
    fn tree_get_selects_from_the_effective_set_never_targets_0() {
        let p = Peer::create(CreateOptions {
            seed: [12u8; 32],
            open_grants: true,
            ..Default::default()
        });
        let a = Entity::make("system/test-a", Value::Map(vec![]));
        let b = Entity::make("system/test-b", Value::Map(vec![]));
        p.store.bind(&format!("/{}/app/a", p.local_peer), &a);
        p.store.bind(&format!("/{}/app/b", p.local_peer), &b);
        let out = p.tree_handler(
            &tree_exec("get", Some(resource(&["app/a", "app/b"], &["app/a"]))),
            None,
            "system/tree",
        );
        assert_eq!(out.status, 200);
        assert_eq!(
            out.result.typ, "system/test-b",
            "the subject is SELECTED from the effective set; targets[0] would answer test-a"
        );
    }

    /// §6.3's handler-level path check (0.8.2.20): *"not a secondary check ... the sole
    /// enforcement wherever the subject is derived after dispatch"*. A caller whose
    /// capability does not cover the path is refused HERE even though the dispatch-level
    /// check never saw it.
    #[test]
    fn tree_get_refuses_a_path_the_callers_capability_does_not_cover() {
        let p = Peer::create(CreateOptions {
            seed: [13u8; 32],
            open_grants: true,
            ..Default::default()
        });
        let a = Entity::make("system/test-a", Value::Map(vec![]));
        p.store.bind(&format!("/{}/app/a", p.local_peer), &a);
        p.store.bind(&format!("/{}/app/b", p.local_peer), &a);
        let cap = narrow_token(&["app/a"]);
        // The CONTROL: the one resource the grant covers is served, so a refusal below is
        // about coverage rather than about the grant being unreadable.
        let out = p.tree_handler(
            &tree_exec("get", Some(resource(&["app/a"], &[]))),
            Some(&cap),
            "system/tree",
        );
        assert_eq!(out.status, 200, "the covered path must still be served");
        let out = p.tree_handler(
            &tree_exec("get", Some(resource(&["app/b"], &[]))),
            Some(&cap),
            "system/tree",
        );
        assert_eq!((out.status, out_code(&out)), (403, Some("capability_denied")));
    }

    /// §6.3's listing filter (0.8.2.21/.22): *"each entry MUST be individually checked
    /// using check_path_permission. Entries for which check_path_permission returns DENY
    /// MUST be omitted. The result's `count` field MUST reflect the filtered entry count,
    /// not the source tree's total count."*
    #[test]
    fn listing_omits_entries_the_callers_capability_excludes() {
        let p = Peer::create(CreateOptions {
            seed: [14u8; 32],
            open_grants: true,
            ..Default::default()
        });
        let e = Entity::make("system/test", Value::Map(vec![]));
        let base = format!("/{}/app", p.local_peer);
        p.store.bind(&format!("{base}/a"), &e);
        p.store.bind(&format!("{base}/b"), &e);

        // CONTROL: unfiltered, the listing names BOTH. Without it "b is absent" below is
        // the trivial truth and measures nothing.
        let out = p.build_listing(&format!("{base}/"), None, "system/tree");
        assert_eq!(out.result.uint_field("count"), Some(2));

        let cap = narrow_token(&["app/a"]);
        let out = p.build_listing(&format!("{base}/"), Some(&cap), "system/tree");
        assert_eq!(
            out.result.uint_field("count"),
            Some(1),
            "`count` MUST follow the FILTERED total, not the source tree's"
        );
        let entries = out.result.field("entries").expect("entries");
        assert!(model::map_get(entries, "a").is_some(), "the covered entry survives");
        assert!(
            model::map_get(entries, "b").is_none(),
            "an entry the caller's own capability excludes MUST be omitted"
        );
    }
}
