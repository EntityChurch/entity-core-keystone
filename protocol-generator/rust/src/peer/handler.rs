//! The extension-host surface (keystone host contract H1, H3, H6, H7, H8 — see
//! `docs/spec/SPEC-KEYSTONE-PEER.md`): what a third party holding a constructed
//! [`Peer`] uses to install a language-native handler body, install an evaluator for
//! entity-native bodies, and dispatch from inside a handler.
//!
//! Nothing here is wire-observable and nothing here may move a `--profile core`
//! number. Two orderings make that true, and both are asserted by tests:
//!
//! - **Native bodies are consulted only for a pattern that is not a built-in.** The
//!   four MUST handlers and the §7a conformance handlers answer first, and registration
//!   refuses any pattern a handler is already bound at, so no installed body can own a
//!   check the peer is measured on.
//!
//! Registration does NOT refuse `system/*`. §6.2's reservation was withdrawn at 0.8.2.13
//! (installation at a `system/*` path is authorized like any other), and `SDK-OPERATIONS`
//! v1.12 names this exact copy as the defect: that refusal belongs to the wire dispatch
//! operation, and copying it into `register_handler` makes installing a standard
//! extension (`system/content`, `system/compute`) impossible. The wire op on this peer
//! still refuses, deliberately, because the pinned oracle still gates it (F61).
//! - **An installed [`ExpressionEvaluator`] takes the fallback arm (H7).** The
//!   built-in `compute/literal` path answers first; the evaluator only sees bodies the
//!   peer would otherwise refuse with `501 unsupported_expression`.
//!
//! # Where the container is read
//!
//! `Peer::route` in `core.rs` — the §6.6 walk resolves the pattern from the
//! `system/handler` entity bound in the tree, and the native container is consulted
//! for that resolved pattern before the entity-native body. Registration binds the
//! same entities the wire `system/handler:register` op binds, so a natively installed
//! handler and a wire-registered one produce the same peer (H1, last paragraph).

use std::sync::Arc;

use crate::value::{Key, Value};

use super::core::{Conn, Peer};
use super::model::{self, Entity, Envelope};
use super::store::ExecContext;
use super::wire;

/// The outcome of a handler operation (§3.3): a status, the result entity, and the
/// protocol entities to bundle into the response envelope's `included` map (§3.1).
#[derive(Clone, Debug, PartialEq)]
pub struct HandlerResult {
    pub status: u64,
    pub result: Entity,
    pub included: Vec<Entity>,
}

impl HandlerResult {
    /// `200` with `result` and nothing included.
    pub fn ok(result: Entity) -> HandlerResult {
        HandlerResult {
            status: 200,
            result,
            included: vec![],
        }
    }

    /// `200` with `result` plus entities for the envelope's `included` map.
    pub fn ok_with(result: Entity, included: Vec<Entity>) -> HandlerResult {
        HandlerResult {
            status: 200,
            result,
            included,
        }
    }

    /// An error outcome carrying a `system/protocol/error` result (§3.3).
    pub fn error(status: u64, code: &str, message: Option<&str>) -> HandlerResult {
        HandlerResult {
            status,
            result: wire::error_result(code, message),
            included: vec![],
        }
    }
}

/// One operation's declared shape (§3.7 `system/handler/operation-spec`). Both types
/// are optional in the spec; publishing them is what lets tooling derive op shapes
/// without per-extension knowledge, so the in-process surface carries them exactly as
/// the wire register op's manifest does.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationSpec {
    pub name: String,
    pub input_type: Option<String>,
    pub output_type: Option<String>,
}

impl OperationSpec {
    /// An operation declared by name alone (renders as an empty `operation-spec`).
    pub fn named(name: &str) -> OperationSpec {
        OperationSpec {
            name: name.to_string(),
            input_type: None,
            output_type: None,
        }
    }

    /// An operation with its §3.7 input and output type names.
    pub fn typed(name: &str, input_type: &str, output_type: &str) -> OperationSpec {
        OperationSpec {
            name: name.to_string(),
            input_type: Some(input_type.to_string()),
            output_type: Some(output_type.to_string()),
        }
    }

    pub(crate) fn operations_value(specs: &[OperationSpec]) -> Value {
        Value::Map(
            specs
                .iter()
                .map(|s| {
                    let mut fields = vec![];
                    if let Some(t) = &s.input_type {
                        fields.push((Key::Text("input_type".into()), model::text(t)));
                    }
                    if let Some(t) = &s.output_type {
                        fields.push((Key::Text("output_type".into()), model::text(t)));
                    }
                    (Key::Text(s.name.clone()), Value::Map(fields))
                })
                .collect(),
        )
    }
}

/// A language-native handler body (§6.1), installed with [`Peer::register_handler`].
///
/// `handle` runs on the dispatching connection's thread, after §5.2 verification and
/// the dispatch-time `check_permission` have allowed the request. A panic is caught
/// and answered `500 internal_error` (§4.9(c) deliver-or-signal): an installed body is
/// third-party code on the dispatch path and must not take the connection down.
pub trait Handler: Send + Sync {
    /// Peer-relative pattern the handler is installed at, e.g. `app/content`.
    fn pattern(&self) -> &str;
    /// Human-readable name, published on the interface entity (§3.7).
    fn name(&self) -> &str;
    /// Operations published on the interface entity (§3.7).
    fn operations(&self) -> Vec<OperationSpec>;
    /// The handler's own grant scope (§6.8) — the authority it holds independently of
    /// any caller. Empty is valid and is the default: a pure-functional handler acts
    /// under the caller's capability only.
    fn grants(&self) -> Vec<Value> {
        Vec::new()
    }
    /// Serve one EXECUTE.
    fn handle(&self, ctx: &HandlerContext<'_>) -> HandlerResult;
}

type HandleFn = dyn Fn(&HandlerContext<'_>) -> HandlerResult + Send + Sync;

/// A [`Handler`] assembled from a closure, for bodies that need no type of their own.
pub struct FnHandler {
    pattern: String,
    name: String,
    operations: Vec<OperationSpec>,
    grants: Vec<Value>,
    body: Box<HandleFn>,
}

impl FnHandler {
    pub fn new<F>(pattern: &str, name: &str, operations: Vec<OperationSpec>, body: F) -> FnHandler
    where
        F: Fn(&HandlerContext<'_>) -> HandlerResult + Send + Sync + 'static,
    {
        FnHandler {
            pattern: pattern.to_string(),
            name: name.to_string(),
            operations,
            grants: Vec::new(),
            body: Box::new(body),
        }
    }

    /// Give the handler its own grant scope (§6.8).
    pub fn with_grants(mut self, grants: Vec<Value>) -> FnHandler {
        self.grants = grants;
        self
    }
}

impl Handler for FnHandler {
    fn pattern(&self) -> &str {
        &self.pattern
    }
    fn name(&self) -> &str {
        &self.name
    }
    fn operations(&self) -> Vec<OperationSpec> {
        self.operations.clone()
    }
    fn grants(&self) -> Vec<Value> {
        self.grants.clone()
    }
    fn handle(&self, ctx: &HandlerContext<'_>) -> HandlerResult {
        (self.body)(ctx)
    }
}

/// Why [`Peer::register_handler`] refused an installation. The registration surface
/// owns this refusal (H3); reaching the container any other way is the defect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RegisterError {
    /// The pattern is empty, absolute, or carries an empty / `.` / `..` / wildcard
    /// segment. A handler pattern is a concrete peer-relative path.
    InvalidPattern(String),
    /// A handler — native or wire-registered — already resolves at this pattern.
    /// Unregister it first; silently replacing a live handler is not an install.
    AlreadyRegistered(String),
}

impl std::fmt::Display for RegisterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RegisterError::InvalidPattern(p) => write!(f, "invalid handler pattern '{p}'"),
            RegisterError::AlreadyRegistered(p) => {
                write!(f, "a handler is already registered at '{p}'")
            }
        }
    }
}

impl std::error::Error for RegisterError {}

/// The body an entity-native handler was registered with (§6.13(a)), handed to an
/// installed [`ExpressionEvaluator`].
pub struct ExpressionRequest<'a> {
    /// Absolute canonical path the handler's `expression_path` resolved to.
    pub expression_path: &'a str,
    /// The entity bound at that path — the handler's body.
    pub expression: &'a Entity,
    /// The `system/handler` entity that named the body.
    pub handler_entity: &'a Entity,
}

/// The evaluator seam for entity-native handler bodies (H7; §9.4 leaves the mechanism
/// impl-private, so what is contracted is that a mechanism exists).
///
/// Consulted only for a body the built-in `compute/literal` path does not answer.
/// Return `None` for a body this evaluator does not recognise — the peer then answers
/// its own `501 unsupported_expression`, so evaluators compose rather than having to
/// claim every shape. A panic is answered `500 internal_error`.
pub trait ExpressionEvaluator: Send + Sync {
    fn evaluate(&self, request: &ExpressionRequest<'_>, ctx: &HandlerContext<'_>)
        -> Option<HandlerResult>;
}

/// An in-process EXECUTE issued from inside a handler with
/// [`HandlerContext::dispatch_execute`].
#[derive(Clone, Debug)]
pub struct LocalExecute {
    /// A local URI: peer-relative (`system/tree`), absolute (`/{local}/…`) or
    /// `entity://{local}/…`. A foreign namespace is refused — that is the §6.13(b)
    /// outbound seam's job, and it runs under different authority.
    pub uri: String,
    pub operation: String,
    pub params: Entity,
    /// The §3.2 `resource` target. `None` sends no resource: a sub-dispatch inherits
    /// nothing from the parent request's resource.
    pub resource: Option<Value>,
    /// The capability the sub-dispatch is authorized under. `None` means the caller's
    /// verified capability. See [`HandlerContext::dispatch_execute`] for which
    /// capabilities are admissible.
    pub capability: Option<Entity>,
}

impl LocalExecute {
    pub fn new(uri: &str, operation: &str, params: Entity) -> LocalExecute {
        LocalExecute {
            uri: uri.to_string(),
            operation: operation.to_string(),
            params,
            resource: None,
            capability: None,
        }
    }

    /// Set the §3.2 resource to a single target path.
    pub fn with_target(mut self, target: &str) -> LocalExecute {
        self.resource = Some(Value::Map(vec![(
            Key::Text("targets".into()),
            Value::Array(vec![model::text(target)]),
        )]));
        self
    }

    pub fn with_resource(mut self, resource: Value) -> LocalExecute {
        self.resource = Some(resource);
        self
    }

    pub fn with_capability(mut self, capability: Entity) -> LocalExecute {
        self.capability = Some(capability);
        self
    }
}

/// Per-request context handed to a [`Handler`] or an [`ExpressionEvaluator`]
/// (§6.5 step 7, §6.8).
pub struct HandlerContext<'a> {
    pub(crate) peer: &'a Peer,
    pub(crate) envelope: &'a Envelope,
    pub(crate) execute: &'a Entity,
    pub(crate) pattern: String,
    pub(crate) suffix: String,
    pub(crate) caller_capability: Option<&'a Entity>,
    pub(crate) handler_grant: Option<Entity>,
    pub(crate) conn: &'a Conn,
    pub(crate) depth: u32,
}

impl<'a> HandlerContext<'a> {
    /// The peer serving this request.
    pub fn peer(&self) -> &Peer {
        self.peer
    }

    /// The local peer id.
    pub fn local_peer(&self) -> &str {
        &self.peer.local_peer
    }

    /// The envelope the request arrived in (for resolving `included`, §3.1). For an
    /// in-process sub-dispatch this is the originating wire envelope.
    pub fn envelope(&self) -> &Envelope {
        self.envelope
    }

    /// The EXECUTE entity being served.
    pub fn execute(&self) -> &Entity {
        self.execute
    }

    pub fn request_id(&self) -> &str {
        self.execute.text_field("request_id").unwrap_or("")
    }

    pub fn operation(&self) -> &str {
        self.execute.text_field("operation").unwrap_or("")
    }

    /// The request's params entity, if it carries one.
    pub fn params(&self) -> Option<Entity> {
        self.execute.entity_field("params")
    }

    /// The §3.2 `resource` target, if present.
    pub fn resource(&self) -> Option<&Value> {
        self.execute.field("resource")
    }

    /// The authenticated author's identity hash.
    pub fn author(&self) -> Option<&[u8]> {
        self.execute.bytes_field("author")
    }

    /// Peer-relative pattern the request resolved to (§6.6).
    pub fn pattern(&self) -> &str {
        &self.pattern
    }

    /// The URI remainder after the pattern, without a leading `/` (§6.4).
    pub fn suffix(&self) -> &str {
        &self.suffix
    }

    /// The capability this request was authorized under.
    pub fn caller_capability(&self) -> Option<&Entity> {
        self.caller_capability
    }

    /// The handler's own grant, bound at registration (§6.8).
    pub fn handler_grant(&self) -> Option<&Entity> {
        self.handler_grant.as_ref()
    }

    /// Current wall-clock time in ms since the epoch — the clock temporal checks use.
    pub fn now_ms(&self) -> u64 {
        super::core::now_ms()
    }

    /// H6 — the frame budget in force for this request's connection, in bytes. A body
    /// whose ideal response would exceed it must return a partial result rather than a
    /// frame the transport will refuse. Read it at response-construction time; a
    /// literal is wrong even when it equals the default.
    pub fn frame_budget(&self) -> usize {
        if self.conn.max_frame_bytes > 0 {
            self.conn.max_frame_bytes
        } else {
            self.peer.max_frame_bytes()
        }
    }

    /// H8 — the §6.8a execution context for a tree write this request causes. Pass it
    /// to `Store::bind_with_context` so an emit consumer sees the caller, not an
    /// autonomous write.
    pub fn exec_context(&self) -> ExecContext {
        self.peer.exec_context(self.execute, &self.pattern)
    }

    /// The §6.13(b) outbound seam: originate an EXECUTE back over the live connection
    /// this request arrived on (§6.11 reentry). `None` without a connection.
    pub fn outbound(&self) -> Option<Arc<super::core::OutboundFn>> {
        self.conn.outbound.clone()
    }

    /// Dispatch an EXECUTE to a LOCAL handler, in-process, through the same §6.6
    /// resolution, §5.2 `check_permission` and body selection a wire EXECUTE takes.
    ///
    /// This is the seam `EXTENSION-COMPUTE` §4.1's `ctx.dispatch_execute` needs for
    /// `compute/apply` handler mode. It is deliberately NOT the outbound seam: it needs
    /// no connection, it does not re-sign under the handler's authority, and it does
    /// not depend on the reader task.
    ///
    /// **Authority.** The capability is a parameter because §4.1's F2 dual check
    /// narrows the caller's grant, and a seam that substituted the handler's own grant
    /// would be the escalation §6.8 forbids. Admissible capabilities are exactly:
    /// the capability this request was authorized under; this handler's own grant; or
    /// a token this peer issued (granter = the local identity, signature verifiable at
    /// the §3.5 pointer), unexpired and unrevoked. Anything else — including a token
    /// some other peer granted that this request did not present — answers
    /// `403 capability_denied`. The signature check on the EXECUTE itself is skipped:
    /// the author is the originating request's, already authenticated.
    ///
    /// **Bounds.** Re-entrant depth is capped at [`MAX_LOCAL_DISPATCH_DEPTH`]; past it
    /// the answer is `429 bounds_exceeded`. A foreign namespace or the connect path
    /// answers `400 invalid_request`. Every failure is a status, never a panic.
    pub fn dispatch_execute(&self, request: LocalExecute) -> HandlerResult {
        self.peer.dispatch_local(self, request)
    }
}

/// Maximum nesting of [`HandlerContext::dispatch_execute`] calls within one wire
/// request. An expression may dispatch to a handler whose body is an expression; this
/// is the peer's own bound on that cycle, independent of any extension budget.
pub const MAX_LOCAL_DISPATCH_DEPTH: u32 = 16;
