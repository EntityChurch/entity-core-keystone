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
            "system/tree" => self.tree_handler(exec),
            "system/capability" => self.capability_handler(exec, caller_cap),
            "system/handler" => self.handlers_handler(exec),
            "system/type" => err_out(501, "unsupported_operation", exec.text_field("operation")),
            _ => {
                if self.conformance && stripped.starts_with("system/validate/") {
                    return self.conformance_handler(conn, exec, &stripped);
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
                    "§6.2: user-installed handlers MUST NOT register at system/* paths: {pattern}"
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
        let out = p.tree_handler(&unknown("system/tree"));
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
        let out1 = p.build_listing(&format!("{base}/"));
        assert_eq!(out1.result.uint_field("count"), Some(2));
        let marker = Entity::make("system/deletion-marker", Value::Map(vec![]));
        p.store.bind(&format!("{base}/target"), &marker);
        let out2 = p.build_listing(&format!("{base}/"));
        assert_eq!(out2.result.uint_field("count"), Some(1));
    }
}
