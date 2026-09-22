//! The keystone host contract on this peer, EXECUTED (docs/spec/SPEC-KEYSTONE-PEER.md).
//!
//! Routed by `entity-system-generator` (their K-9): `rust` could not install a handler
//! at all — the generator's compile-fail arm measured `register_handler` private and no
//! container — which capped `rust × COMPUTE` at about 7 of 128 checks. Every claim below
//! is driven over real loopback TCP from a SECOND peer, because a single-peer harness
//! cannot tell the caller from the local peer (H8) and cannot tell a live index from the
//! `compute/literal` fallback (H1's observation).
//!
//! H1's witness combines a REQUEST field with REGISTRATION-TIME state. No
//! `compute/literal` body can produce it, so a peer with no live container cannot pass
//! on the fallback path.

use std::net::TcpStream;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use entity_core_protocol::peer::capability as cap;
use entity_core_protocol::peer::core::Conn;
use entity_core_protocol::peer::model::{self, hex, Entity, Envelope};
use entity_core_protocol::peer::seed_policy::{self, SeedPolicyEntry};
use entity_core_protocol::peer::transport::{self, Io, Session};
use entity_core_protocol::peer::{
    CreateOptions, ExpressionEvaluator, ExpressionRequest, FnHandler, HandlerContext,
    HandlerResult, LocalExecute, OperationSpec, Peer, PeerConfig, RegisterError, SeedPolicy,
};
use entity_core_protocol::value::{Key, Value};

// ── rig: a responder served over loopback and an authenticated initiator session ──

struct Rig {
    session: Session,
    responder: Arc<Peer>,
    initiator: Arc<Peer>,
    teardown: TcpStream,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Rig {
    fn exec(&mut self, uri: &str, op: &str, params: Entity, resource: Option<Value>) -> Envelope {
        let uri = format!("/{}/{uri}", self.responder.local_peer);
        self.session
            .execute(&uri, op, params, resource)
            .expect("a response (never a silent drop)")
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.teardown.shutdown(std::net::Shutdown::Both);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn connect(responder: Arc<Peer>, initiator_seed: u8) -> Rig {
    let initiator = Arc::new(Peer::create(CreateOptions {
        seed: [initiator_seed; 32],
        ..Default::default()
    }));
    let listener = transport::listen(0).expect("bind responder");
    let port = listener.local_addr().unwrap().port();
    let serving = responder.clone();
    let serve = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            transport::serve_connection(serving, stream);
        }
    });
    let stream = TcpStream::connect(("127.0.0.1", port)).expect("dial");
    transport::set_no_delay(&stream);
    let read_stream = stream.try_clone().unwrap();
    let teardown = stream.try_clone().unwrap();
    let io = Io::new(stream).unwrap();
    let conn = Arc::new(Mutex::new(Conn::new()));
    let (rp, rc, ri) = (initiator.clone(), conn.clone(), io.clone());
    let reader = thread::spawn(move || transport::read_loop(rp, rc, ri, read_stream));
    let session = transport::initiate(initiator.clone(), io, conn).expect("handshake");
    Rig {
        session,
        responder,
        initiator,
        teardown,
        threads: vec![reader, serve],
    }
}

fn peer_with(seed: u8, config: PeerConfig) -> Arc<Peer> {
    Arc::new(Peer::create_with(
        CreateOptions {
            seed: [seed; 32],
            ..Default::default()
        },
        config,
    ))
}

fn other_peer_id(seed: u8) -> String {
    Peer::create(CreateOptions {
        seed: [seed; 32],
        ..Default::default()
    })
    .local_peer
}

fn open_peer(seed: u8) -> Arc<Peer> {
    peer_with(seed, PeerConfig::default().seed_policy(SeedPolicy::debug_open()))
}

fn status(env: &Envelope) -> u64 {
    env.root.uint_field("status").unwrap_or(0)
}

fn code(env: &Envelope) -> String {
    env.root
        .entity_field("result")
        .and_then(|r| r.text_field("code").map(str::to_string))
        .unwrap_or_default()
}

fn result(env: &Envelope) -> Entity {
    env.root.entity_field("result").expect("result entity")
}

fn any(pairs: Vec<(&str, Value)>) -> Entity {
    Entity::make("primitive/any", model::map(pairs))
}

fn target(path: &str) -> Value {
    Value::Map(vec![(
        Key::Text("targets".into()),
        Value::Array(vec![model::text(path)]),
    )])
}

const REG_NONCE: &str = "rs-h1-5e2a";

/// A body whose answer depends on a request field AND registration-time state.
fn witness_handler(pattern: &str, invocations: Arc<AtomicUsize>) -> Arc<FnHandler> {
    let captured = format!("{REG_NONCE}:{pattern}");
    Arc::new(FnHandler::new(
        pattern,
        "witness",
        vec![OperationSpec::typed("echo", "primitive/any", "primitive/any")],
        move |ctx: &HandlerContext<'_>| {
            invocations.fetch_add(1, Ordering::SeqCst);
            let echo = ctx
                .params()
                .and_then(|p| p.text_field("echo").map(str::to_string))
                .unwrap_or_default();
            HandlerResult::ok(any(vec![("witness", model::text(&format!("{captured}:{echo}")))]))
        },
    ))
}

// ── H1 ─────────────────────────────────────────────────────────────────────────

#[test]
fn h1_installed_body_is_reached_from_a_second_peer() {
    let responder = open_peer(31);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rig = connect(responder.clone(), 32);

    // Control A — nothing installed: the pattern does not resolve.
    let before = rig.exec("app/witness", "echo", any(vec![("echo", model::text("x"))]), None);
    assert_eq!((status(&before), code(&before).as_str()), (404, "handler_not_found"));

    responder
        .install_handler(witness_handler("app/witness", calls.clone()))
        .expect("install through the public surface");

    // The measurement: a value no compute/literal body can produce.
    let echo = format!("req-{}", std::process::id());
    let got = rig.exec("app/witness", "echo", any(vec![("echo", model::text(&echo))]), None);
    assert_eq!(status(&got), 200, "installed body not reached: {:?}", got.root);
    assert_eq!(
        result(&got).text_field("witness"),
        Some(format!("{REG_NONCE}:app/witness:{echo}").as_str())
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one invocation, by the dispatch");

    // Installation bound the same dispatch entities the wire register op binds.
    let local = &responder.local_peer;
    let bound = |p: String| responder.store.get_at(&p).map(|e| e.typ);
    assert_eq!(bound(format!("/{local}/app/witness")).as_deref(), Some("system/handler"));
    assert_eq!(
        bound(format!("/{local}/system/handler/app/witness")).as_deref(),
        Some("system/handler/interface")
    );
    let grant = responder
        .store
        .get_at(&format!("/{local}/system/capability/grants/app/witness"))
        .expect("handler grant bound");
    assert!(
        responder
            .store
            .get_at(&format!("/{local}/system/signature/{}", hex(&grant.hash)))
            .is_some(),
        "grant signature bound at the section 3.5 pointer"
    );
    // ...and the interface publishes the operation's types (§3.7).
    let iface = responder
        .store
        .get_at(&format!("/{local}/system/handler/app/witness"))
        .unwrap();
    let ops = iface.field("operations").unwrap();
    let echo_spec = model::map_get(ops, "echo").expect("echo op published");
    assert_eq!(
        model::map_get(echo_spec, "input_type"),
        Some(&model::text("primitive/any"))
    );

    // Control B — uninstalled: back to 404, and the body is not invoked again.
    assert!(responder.unregister_handler("app/witness"));
    let after = rig.exec("app/witness", "echo", any(vec![("echo", model::text("y"))]), None);
    assert_eq!(status(&after), 404);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[test]
fn h1_native_body_writes_carry_the_remote_caller_context() {
    // H8 through an installed body: the context a body passes to the store names the
    // remote caller, not the local peer.
    let responder = open_peer(33);
    let seen: Arc<Mutex<Vec<Option<Vec<u8>>>>> = Arc::new(Mutex::new(vec![]));
    let sink = seen.clone();
    responder.store.register_tree_consumer(move |ev| {
        if ev.path.ends_with("/app/rec/out") {
            sink.lock().unwrap().push(ev.context.as_ref().and_then(|c| c.author.clone()));
        }
    });
    responder
        .install_handler(Arc::new(FnHandler::new(
            "app/rec",
            "rec",
            vec![OperationSpec::named("write")],
            |ctx: &HandlerContext<'_>| {
                let path = format!("/{}/app/rec/out", ctx.local_peer());
                let e = any(vec![("v", Value::UInt(1))]);
                ctx.peer().store.put_entity(&e);
                ctx.peer().store.bind_with_context(&path, &e, Some(ctx.exec_context()));
                HandlerResult::ok(any(vec![]))
            },
        )))
        .unwrap();
    let mut rig = connect(responder.clone(), 34);
    let r = rig.exec("app/rec", "write", any(vec![]), None);
    assert_eq!(status(&r), 200);
    let authors = seen.lock().unwrap().clone();
    assert_eq!(authors.len(), 1);
    assert_eq!(authors[0].as_deref(), Some(rig.initiator.identity.identity_hash.as_slice()));
    assert_ne!(authors[0].as_deref(), Some(responder.identity.identity_hash.as_slice()));
}

#[test]
fn h1_a_panicking_body_is_a_status_and_the_connection_survives() {
    let responder = open_peer(35);
    responder
        .install_handler(Arc::new(FnHandler::new(
            "app/boom",
            "boom",
            vec![OperationSpec::named("go")],
            |_ctx: &HandlerContext<'_>| panic!("third-party body failure"),
        )))
        .unwrap();
    responder
        .install_handler(witness_handler("app/witness", Arc::new(AtomicUsize::new(0))))
        .unwrap();
    let mut rig = connect(responder, 36);
    let r = rig.exec("app/boom", "go", any(vec![]), None);
    assert_eq!((status(&r), code(&r).as_str()), (500, "internal_error"));
    let again = rig.exec("app/witness", "echo", any(vec![("echo", model::text("z"))]), None);
    assert_eq!(status(&again), 200, "the connection must outlive a panicking body");
}

// ── H3 ─────────────────────────────────────────────────────────────────────────

#[test]
fn h3_the_registration_surface_owns_the_refusals() {
    let peer = open_peer(37);
    let h = |p: &str| witness_handler(p, Arc::new(AtomicUsize::new(0)));
    // A built-in is bound, so it cannot be replaced...
    for builtin in ["system/tree", "system/capability", "system/handler", "system/protocol/connect"] {
        assert_eq!(
            peer.install_handler(h(builtin)),
            Err(RegisterError::PatternCollision(builtin.into())),
            "{builtin} must not be replaceable in-process"
        );
    }
    // ...but a standard extension's own namespace is installable: §6.2's reservation was
    // withdrawn at 0.8.2.13, and refusing here would make CONTENT/COMPUTE uninstallable.
    peer.install_handler(h("system/content")).expect("system/content is installable");
    for bad in ["", "/abs/path", "app//x", "app/*", "app/../x"] {
        assert!(
            matches!(peer.install_handler(h(bad)), Err(RegisterError::InvalidHandlerSpec(_))),
            "{bad:?} must be refused"
        );
    }
    peer.install_handler(h("app/one")).unwrap();
    assert_eq!(
        peer.install_handler(h("app/one")),
        Err(RegisterError::PatternCollision("app/one".into()))
    );
    assert!(!peer.unregister_handler("app/never"), "nothing installed there");
}

#[test]
fn h3_a_wire_registered_pattern_is_not_silently_replaced() {
    let responder = open_peer(38);
    let mut rig = connect(responder.clone(), 39);
    let req = Entity::make(
        "system/handler/register-request",
        model::map(vec![("manifest", model::map(vec![("name", model::text("wired"))]))]),
    );
    let r = rig.exec("system/handler", "register", req, Some(target("system/handler/app/wired")));
    assert_eq!(status(&r), 200, "{:?}", r.root);
    assert_eq!(
        responder.install_handler(witness_handler("app/wired", Arc::new(AtomicUsize::new(0)))),
        Err(RegisterError::PatternCollision("app/wired".into()))
    );
    // And the reverse: a wire unregister removes a native body with its entities.
    responder
        .install_handler(witness_handler("app/native", Arc::new(AtomicUsize::new(0))))
        .unwrap();
    let u = rig.exec(
        "system/handler",
        "unregister",
        any(vec![]),
        Some(target("system/handler/app/native")),
    );
    assert_eq!(status(&u), 200);
    assert!(!responder.has_native_handler("app/native"));
    let gone = rig.exec("app/native", "echo", any(vec![]), None);
    assert_eq!(status(&gone), 404);
}

// ── H6 ─────────────────────────────────────────────────────────────────────────

fn budget_reader() -> Arc<FnHandler> {
    Arc::new(FnHandler::new(
        "app/budget",
        "budget",
        vec![OperationSpec::named("read")],
        |ctx: &HandlerContext<'_>| {
            HandlerResult::ok(any(vec![("budget", Value::UInt(ctx.frame_budget() as u64))]))
        },
    ))
}

#[test]
fn h6_a_body_reads_the_configured_budget_by_value() {
    const CONFIGURED: usize = 3_145_749;
    let configured = peer_with(
        40,
        PeerConfig::default()
            .seed_policy(SeedPolicy::debug_open())
            .max_frame_bytes(CONFIGURED),
    );
    configured.install_handler(budget_reader()).unwrap();
    let mut rig = connect(configured, 41);
    let r = rig.exec("app/budget", "read", any(vec![]), None);
    assert_eq!(result(&r).uint_field("budget"), Some(CONFIGURED as u64));

    // The negative arm: an unconfigured peer reads the 16 MiB default, so the value
    // above is the configuration arriving and not a constant that happens to match.
    let default = open_peer(42);
    default.install_handler(budget_reader()).unwrap();
    let mut rig2 = connect(default, 43);
    let d = rig2.exec("app/budget", "read", any(vec![]), None);
    assert_eq!(result(&d).uint_field("budget"), Some(16 * 1024 * 1024));
}

#[test]
fn h6_the_configured_budget_is_the_one_enforced() {
    // A frame over the configured budget is refused at the length prefix, which ends
    // the connection (§4.10(a)): the handshake frames fit, a 64 KiB put does not.
    let small = peer_with(
        44,
        PeerConfig::default()
            .seed_policy(SeedPolicy::debug_open())
            .max_frame_bytes(16 * 1024),
    );
    let mut rig = connect(small, 45);
    let big = any(vec![("blob", Value::Bytes(vec![7u8; 64 * 1024]))]);
    let params = Entity::make("system/tree/put-request", model::map(vec![("entity", big.to_cbor())]));
    let path = format!("/{}/app/big", rig.responder.local_peer);
    let uri = format!("/{}/system/tree", rig.responder.local_peer);
    assert!(
        rig.session.execute(&uri, "put", params, Some(target(&path))).is_none(),
        "an over-budget frame must not be served"
    );
}

// ── H7 ─────────────────────────────────────────────────────────────────────────

struct Doubler {
    calls: Arc<AtomicUsize>,
}

impl ExpressionEvaluator for Doubler {
    fn evaluate(&self, req: &ExpressionRequest<'_>, ctx: &HandlerContext<'_>) -> Option<HandlerResult> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if req.expression.typ != "test/double" {
            return None; // not mine — the peer's own 501 stands
        }
        let n = req.expression.uint_field("n")?;
        let bump = ctx.params().and_then(|p| p.uint_field("bump")).unwrap_or(0);
        Some(HandlerResult::ok(any(vec![("value", Value::UInt(n * 2 + bump))])))
    }
}

fn wire_register_entity_native(rig: &mut Rig, pattern: &str, body_path: &str, body: &Entity) {
    let put = Entity::make("system/tree/put-request", model::map(vec![("entity", body.to_cbor())]));
    let r = rig.exec("system/tree", "put", put, Some(target(body_path)));
    assert_eq!(status(&r), 200, "body put: {:?}", r.root);
    let req = Entity::make(
        "system/handler/register-request",
        model::map(vec![(
            "manifest",
            model::map(vec![
                ("name", model::text(pattern)),
                ("expression_path", model::text(body_path)),
            ]),
        )]),
    );
    let r = rig.exec(
        "system/handler",
        "register",
        req,
        Some(target(&format!("system/handler/{pattern}"))),
    );
    assert_eq!(status(&r), 200, "register: {:?}", r.root);
}

#[test]
fn h7_the_built_in_floor_answers_first_and_the_evaluator_takes_the_fallback() {
    let responder = open_peer(46);
    let calls = Arc::new(AtomicUsize::new(0));
    let mut rig = connect(responder.clone(), 47);

    let literal = Entity::make("compute/literal", model::map(vec![("value", Value::UInt(50))]));
    wire_register_entity_native(&mut rig, "app/lit", "app/bodies/lit", &literal);
    let double = Entity::make("test/double", model::map(vec![("n", Value::UInt(21))]));
    wire_register_entity_native(&mut rig, "app/dbl", "app/bodies/dbl", &double);
    let other = Entity::make("test/other", model::map(vec![]));
    wire_register_entity_native(&mut rig, "app/oth", "app/bodies/oth", &other);

    // Uninstalled: literal evaluates, everything else is the peer's 501.
    let lit0 = rig.exec("app/lit", "run", any(vec![]), None);
    assert_eq!(result(&lit0).field("value"), Some(&Value::UInt(50)));
    let dbl0 = rig.exec("app/dbl", "run", any(vec![]), None);
    assert_eq!((status(&dbl0), code(&dbl0).as_str()), (501, "unsupported_expression"));

    responder.set_expression_evaluator(Some(Arc::new(Doubler { calls: calls.clone() })));

    // The floor still wins, and the evaluator is never asked about a literal.
    let lit1 = rig.exec("app/lit", "run", any(vec![]), None);
    assert_eq!((status(&lit1), result(&lit1)), (status(&lit0), result(&lit0)));
    assert_eq!(calls.load(Ordering::SeqCst), 0, "the evaluator preempted compute/literal");

    // The fallback arm, with a request field folded in.
    let dbl1 = rig.exec("app/dbl", "run", any(vec![("bump", Value::UInt(1))]), None);
    assert_eq!(status(&dbl1), 200);
    assert_eq!(result(&dbl1).field("value"), Some(&Value::UInt(43)));

    // Declined: the peer's 501 stands, discriminated on the body, not the status.
    let oth = rig.exec("app/oth", "run", any(vec![]), None);
    assert_eq!((status(&oth), code(&oth).as_str()), (501, "unsupported_expression"));
    assert_eq!(calls.load(Ordering::SeqCst), 2);

    responder.set_expression_evaluator(None);
    let dbl2 = rig.exec("app/dbl", "run", any(vec![]), None);
    assert_eq!(status(&dbl2), 501, "clearing the evaluator restores the floor");
}

// ── H9 ─────────────────────────────────────────────────────────────────────────

#[test]
fn h9_path_permission_one_accept_and_a_deny_per_dimension() {
    let local = Peer::create(CreateOptions {
        seed: [48u8; 32],
        ..Default::default()
    })
    .local_peer;
    let token = Entity::make(
        "system/capability/token",
        model::map(vec![(
            "grants",
            Value::Array(vec![seed_policy::grant(&["app/content"], &["app/data/*"], &["get"], None)]),
        )]),
    );
    let ok = |op: &str, path: &str, handler: &str| {
        cap::check_path_permission(op, path, &token, handler, &local)
    };
    // The accept case validates the fixture.
    assert!(ok("get", "app/data/x", "app/content"), "accept");
    assert!(ok("get", &format!("/{local}/app/data/x"), "app/content"), "accept, absolute");
    assert!(!ok("get", "app/data/x", "app/other"), "deny: handlers");
    assert!(!ok("put", "app/data/x", "app/content"), "deny: operations");
    assert!(!ok("get", "app/secret/x", "app/content"), "deny: resources");
    // No granter frame: a bare pattern never reaches a foreign namespace.
    let foreign = format!("/{}/app/data/x", other_peer_id(49));
    assert!(!ok("get", &foreign, "app/content"), "deny: foreign namespace");
}

// ── local dispatch (their K-5) ───────────────────────────────────────────────────

fn tree_put_handler(capability_from: fn(&HandlerContext<'_>) -> Option<Entity>) -> Arc<FnHandler> {
    Arc::new(FnHandler::new(
        "app/apply",
        "apply",
        vec![OperationSpec::named("store")],
        move |ctx: &HandlerContext<'_>| {
            let body = any(vec![("v", Value::UInt(7))]);
            let put = Entity::make(
                "system/tree/put-request",
                model::map(vec![("entity", Value::Map(vec![
                    (Key::Text("type".into()), model::text(&body.typ)),
                    (Key::Text("data".into()), body.data.clone()),
                    (Key::Text("content_hash".into()), Value::Bytes(body.hash.clone())),
                ]))]),
            );
            let mut req = LocalExecute::new("system/tree", "put", put).with_target("app/out/x");
            if let Some(c) = capability_from(ctx) {
                req = req.with_capability(c);
            }
            let r = ctx.dispatch_execute(req);
            HandlerResult::ok(any(vec![
                ("status", Value::UInt(r.status)),
                ("code", model::text(r.result.text_field("code").unwrap_or(""))),
            ]))
        },
    ))
}

fn inner(env: &Envelope) -> (u64, String) {
    let r = result(env);
    (
        r.uint_field("status").unwrap_or(0),
        r.text_field("code").unwrap_or("").to_string(),
    )
}

#[test]
fn local_dispatch_runs_the_normal_path_under_the_callers_capability() {
    let responder = open_peer(50);
    let seen: Arc<Mutex<Vec<Option<Vec<u8>>>>> = Arc::new(Mutex::new(vec![]));
    let sink = seen.clone();
    responder.store.register_tree_consumer(move |ev| {
        if ev.path.ends_with("/app/out/x") {
            sink.lock().unwrap().push(ev.context.as_ref().and_then(|c| c.author.clone()));
        }
    });
    responder.install_handler(tree_put_handler(|_| None)).unwrap();
    let mut rig = connect(responder.clone(), 51);
    let r = rig.exec("app/apply", "store", any(vec![]), None);
    assert_eq!(status(&r), 200);
    assert_eq!(inner(&r), (200, String::new()), "the in-process put must succeed");
    assert!(responder
        .store
        .get_at(&format!("/{}/app/out/x", responder.local_peer))
        .is_some());
    // The write the sub-dispatch caused is attributed to the ORIGINATING caller.
    let authors = seen.lock().unwrap().clone();
    assert_eq!(authors, vec![Some(rig.initiator.identity.identity_hash.clone())]);
}

#[test]
fn local_dispatch_does_not_escalate_past_the_callers_grant() {
    // The caller may reach app/apply but holds no tree:put. The handler's sub-dispatch
    // runs under the caller's capability, so it is refused — the §6.8 rule that a
    // handler cannot launder the caller into authority the caller lacks.
    let named = |peer: &Peer| SeedPolicyEntry {
        key: hex(&peer.identity.identity_hash),
        grants: vec![seed_policy::grant(&["app/apply"], &["*"], &["store"], None)],
    };
    let initiator_identity = Peer::create(CreateOptions {
        seed: [53u8; 32],
        ..Default::default()
    });
    let policy = SeedPolicy::of(seed_policy::discovery_floor(), vec![named(&initiator_identity)]);
    let responder = peer_with(52, PeerConfig::default().seed_policy(policy));
    responder.install_handler(tree_put_handler(|_| None)).unwrap();
    let mut rig = connect(responder.clone(), 53);
    let r = rig.exec("app/apply", "store", any(vec![]), None);
    assert_eq!(status(&r), 200, "the caller may reach the handler: {:?}", r.root);
    assert_eq!(inner(&r), (403, "capability_denied".into()));
    assert!(responder
        .store
        .get_at(&format!("/{}/app/out/x", responder.local_peer))
        .is_none());
}

#[test]
fn local_dispatch_refuses_a_capability_the_request_did_not_carry() {
    // A token some OTHER peer granted, never presented on this request, is not
    // authority here — even though its grants would cover the put.
    let responder = open_peer(54);
    responder
        .install_handler(tree_put_handler(|_ctx| {
            let other = Peer::create(CreateOptions {
                seed: [99u8; 32],
                ..Default::default()
            });
            Some(Entity::make(
                "system/capability/token",
                model::map(vec![
                    ("granter", model::bytes(&other.identity.identity_hash)),
                    ("grants", Value::Array(seed_policy::open_grants())),
                ]),
            ))
        }))
        .unwrap();
    let mut rig = connect(responder.clone(), 55);
    let r = rig.exec("app/apply", "store", any(vec![]), None);
    assert_eq!(inner(&r), (403, "capability_denied".into()));
}

#[test]
fn local_dispatch_bounds_depth_and_refuses_foreign_and_connect() {
    let responder = open_peer(56);
    let depth_seen = Arc::new(AtomicUsize::new(0));
    let d = depth_seen.clone();
    responder
        .install_handler(Arc::new(FnHandler::new(
            "app/loop",
            "loop",
            vec![OperationSpec::named("go")],
            move |ctx: &HandlerContext<'_>| {
                d.fetch_add(1, Ordering::SeqCst);
                ctx.dispatch_execute(LocalExecute::new("app/loop", "go", any(vec![])))
            },
        )))
        .unwrap();
    let foreign_tree = format!("/{}/system/tree", other_peer_id(58));
    responder
        .install_handler(Arc::new(FnHandler::new(
            "app/edges",
            "edges",
            vec![OperationSpec::named("go")],
            move |ctx: &HandlerContext<'_>| {
                let f = ctx.dispatch_execute(LocalExecute::new(&foreign_tree, "get", any(vec![])));
                let c = ctx.dispatch_execute(LocalExecute::new(
                    "system/protocol/connect",
                    "hello",
                    any(vec![]),
                ));
                HandlerResult::ok(any(vec![
                    ("foreign", Value::UInt(f.status)),
                    ("connect", Value::UInt(c.status)),
                ]))
            },
        )))
        .unwrap();
    let mut rig = connect(responder, 57);
    let r = rig.exec("app/loop", "go", any(vec![]), None);
    assert_eq!((status(&r), code(&r).as_str()), (429, "bounds_exceeded"));
    // The wire call is depth 0; sixteen nested dispatches are admitted, the 17th refused.
    assert_eq!(depth_seen.load(Ordering::SeqCst), 17);

    let e = rig.exec("app/edges", "go", any(vec![]), None);
    assert_eq!(result(&e).uint_field("foreign"), Some(400));
    assert_eq!(result(&e).uint_field("connect"), Some(400));
}

// ── seed policy as a value (their K-7) ────────────────────────────────────────────

#[test]
fn a_policy_between_the_floor_and_open_is_enforced_per_identity() {
    let named_seed = 61u8;
    let named = Peer::create(CreateOptions {
        seed: [named_seed; 32],
        ..Default::default()
    });
    let policy = SeedPolicy::of(
        seed_policy::discovery_floor(),
        vec![SeedPolicyEntry {
            key: hex(&named.identity.identity_hash),
            grants: vec![seed_policy::grant(&["app/witness"], &["*"], &["echo"], None)],
        }],
    );
    let responder = peer_with(60, PeerConfig::default().seed_policy(policy));
    responder
        .install_handler(witness_handler("app/witness", Arc::new(AtomicUsize::new(0))))
        .unwrap();
    let p = |e: &str| any(vec![("echo", model::text(e))]);

    let mut named_rig = connect(responder.clone(), named_seed);
    assert_eq!(status(&named_rig.exec("app/witness", "echo", p("n"), None)), 200);
    // The same identity is still inside its narrow grant, not open.
    let wider = named_rig.exec("system/tree", "get", any(vec![]), Some(target("app/witness")));
    assert_eq!(status(&wider), 403, "a named narrow grant must not be wide");

    let mut other_rig = connect(responder.clone(), 62);
    let denied = other_rig.exec("app/witness", "echo", p("o"), None);
    assert_eq!((status(&denied), code(&denied).as_str()), (403, "capability_denied"));
}

#[test]
fn open_grants_still_selects_the_degenerate_policy() {
    // The deprecated switch keeps working and routes through the same mechanism.
    let peer = Peer::create(CreateOptions {
        seed: [63u8; 32],
        open_grants: true,
        ..Default::default()
    });
    assert_eq!(peer.seed_policy(), &SeedPolicy::debug_open());
    // A declared policy wins over the switch.
    let declared = Peer::create_with(
        CreateOptions {
            seed: [63u8; 32],
            open_grants: true,
            ..Default::default()
        },
        PeerConfig::default().seed_policy(SeedPolicy::standard()),
    );
    assert_eq!(declared.seed_policy(), &SeedPolicy::standard());
}

// ── the host binary's --seed-policy (their K-6) ──────────────────────────────────

fn run_host(args: &[&str]) -> (Option<String>, String, Option<i32>) {
    use std::io::{BufRead, BufReader, Read};
    use std::process::{Command, Stdio};
    let mut child = Command::new(env!("CARGO_BIN_EXE_entity-peer-host"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn host");
    let mut line = String::new();
    let listening = BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .ok()
        .filter(|n| *n > 0)
        .map(|_| line.clone());
    let _ = child.kill();
    let status = child.wait().ok().and_then(|s| s.code());
    let mut err = String::new();
    let _ = child.stderr.take().unwrap().read_to_string(&mut err);
    (listening, err, status)
}

#[test]
fn host_binary_accepts_a_seed_policy_file_and_refuses_a_bad_one() {
    let examples = concat!(env!("CARGO_MANIFEST_DIR"), "/../shared/seed-policy/examples");
    let (listening, err, _) =
        run_host(&["--port", "0", "--seed-policy", &format!("{examples}/default-floor.json")]);
    let line = listening.expect(&format!("no readiness record; stderr: {err}"));
    assert!(line.starts_with("LISTENING {"), "{line}");
    // The policy in force is reported in the readiness record (run.ready / run.posture),
    // by the digest of the file's bytes.
    assert!(line.contains("\"posture\":\"file\""), "{line}");
    let digest = {
        use sha2::{Digest, Sha256};
        let bytes = std::fs::read(format!("{examples}/default-floor.json")).unwrap();
        Sha256::digest(&bytes).iter().map(|b| format!("{b:02x}")).collect::<String>()
    };
    assert!(line.contains(&format!("\"posture_digest\":\"{digest}\"")), "{line}");

    let (listening, err, _) = run_host(&[
        "--port",
        "0",
        "--debug-open-grants",
        "--seed-policy",
        &format!("{examples}/debug-open.json"),
    ]);
    assert!(listening.is_some());
    assert!(err.contains("IGNORED"), "both flags: the declared policy wins, said aloud: {err}");

    let bad = std::env::temp_dir().join(format!("bad-policy-{}.json", std::process::id()));
    std::fs::write(&bad, r#"{"version":1,"entries":[{"grantee":"self","grants":[]}]}"#).unwrap();
    let (listening, err, code) = run_host(&["--port", "0", "--seed-policy", bad.to_str().unwrap()]);
    let _ = std::fs::remove_file(&bad);
    assert!(listening.is_none(), "a refused policy must not start a peer");
    assert_eq!(code, Some(2));
    assert!(err.contains("self"), "{err}");
}
