//! H8 — the §6.10 tree-change event carries the §6.8a execution context.
//!
//! Routed by `entity-system-generator` out of building `EXTENSION-HISTORY` v1.7, and
//! it is a missing VALUE rather than a missing type: `TreeChangeEvent` carried four
//! fields and no context at all, so every event reached a consumer contextless.
//!
//! That is not a neutral absence, which is why the assertion below is on `author`
//! specifically rather than on "a context is present". `EXTENSION-HISTORY` §2.1
//! defines the AUTONOMOUS case exactly — author is the local peer's identity hash —
//! so a contextless event is INDISTINGUISHABLE from an autonomous write, and a
//! conforming recorder fills in the autonomous reading and attributes a REMOTE
//! caller's write to the local peer. §7.2 calls `capability` the answer to "under
//! what authority?", and the answer was always "its own".
//!
//! **The two-peer setup is the control.** A single-peer test passes against the
//! fabricated autonomous value, because there the caller and the local peer are the
//! same identity. The `history` oracle's four context checks are PRESENCE checks over
//! values the extension itself supplies, so a peer scores 33/34 either way — nothing
//! that exists today can see this.

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;

use entity_core_protocol::peer::core::Conn;
use entity_core_protocol::peer::model::{self, Entity};
use entity_core_protocol::peer::store::ExecContext;
use entity_core_protocol::peer::transport::{self, Io};
use entity_core_protocol::peer::{CreateOptions, Peer};
use entity_core_protocol::value::{Key, Value};

fn target(path: &str) -> Value {
    Value::Map(vec![(
        Key::Text("targets".into()),
        Value::Array(vec![Value::Text(path.into())]),
    )])
}

/// Drive a real remote `system/tree:put` and return the contexts it delivered.
fn remote_put() -> (Vec<Option<ExecContext>>, Vec<u8>, Vec<u8>) {
    let responder = Arc::new(Peer::create(CreateOptions {
        seed: [11u8; 32],
        open_grants: true,
        conformance: true,
    }));
    let initiator = Arc::new(Peer::create(CreateOptions {
        seed: [12u8; 32],
        ..Default::default()
    }));
    let remote = responder.local_peer.clone();
    let path = format!("/{remote}/app/h8/probe");

    let seen: Arc<Mutex<Vec<Option<ExecContext>>>> = Arc::new(Mutex::new(Vec::new()));
    {
        let sink = seen.clone();
        let want = path.clone();
        responder.store.register_tree_consumer(move |ev| {
            if ev.path == want {
                sink.lock().unwrap().push(ev.context.clone());
            }
        });
    }

    let listener = transport::listen(0).expect("bind responder");
    let bound_port = listener.local_addr().unwrap().port();
    let resp_for_serve = responder.clone();
    let serve = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            transport::serve_connection(resp_for_serve, stream);
        }
    });

    let stream = TcpStream::connect(("127.0.0.1", bound_port)).expect("dial responder");
    transport::set_no_delay(&stream);
    let read_stream = stream.try_clone().expect("clone read half");
    let teardown_stream = stream.try_clone().expect("clone teardown half");
    let io = Io::new(stream).expect("io");
    let conn = Arc::new(Mutex::new(Conn::new()));
    let reader_peer = initiator.clone();
    let reader_conn = conn.clone();
    let reader_io = io.clone();
    let reader = thread::spawn(move || {
        transport::read_loop(reader_peer, reader_conn, reader_io, read_stream);
    });

    let mut session =
        transport::initiate(initiator.clone(), io.clone(), conn.clone()).expect("handshake");

    let body = Entity::make("primitive/any", model::map(vec![("v", Value::UInt(1))]));
    let params = Entity::make(
        "system/tree/put-request",
        model::map(vec![("entity", body.to_cbor())]),
    );
    let uri = format!("/{remote}/system/tree");
    let resp = session
        .execute(&uri, "put", params, Some(target(&path)))
        .expect("put response");
    assert_eq!(
        resp.root.uint_field("status"),
        Some(200),
        "tree:put must be accepted for this measurement to mean anything"
    );

    let _ = teardown_stream.shutdown(std::net::Shutdown::Both);
    let _ = reader.join();
    let _ = serve.join();

    let contexts = seen.lock().unwrap().clone();
    (
        contexts,
        initiator.identity.identity_hash.clone(),
        responder.identity.identity_hash.clone(),
    )
}

#[test]
fn h8_remote_put_attributes_the_remote_caller() {
    let (contexts, caller_hash, local_hash) = remote_put();
    assert!(
        !contexts.is_empty(),
        "the tree:put fired no tree-change event at the target path"
    );
    let ctx = contexts[0]
        .as_ref()
        .expect("tree-change event carried no context (the H8 defect)");

    // The load-bearing assertion. Before the fix this field did not exist, and a
    // recorder filling it from §2.1's autonomous rule writes the LOCAL hash here.
    assert_eq!(
        ctx.author.as_deref(),
        Some(caller_hash.as_slice()),
        "author must be the REMOTE caller's identity"
    );
    assert_ne!(
        ctx.author.as_deref(),
        Some(local_hash.as_slice()),
        "author is the local peer's own hash — the autonomous-fallback reading, not the caller"
    );

    // "Under what authority?" (§7.2) — both authorities the write ran under.
    assert!(ctx.caller_capability.is_some(), "no caller_capability");
    assert!(ctx.handler_grant.is_some(), "no handler_grant");
    assert_eq!(ctx.handler_pattern, "system/tree");
    assert_eq!(ctx.operation, "put");
    assert!(!ctx.request_id.is_empty(), "no request_id");

    // Slots a core request does not carry read as absent, not as invented values.
    assert!(ctx.chain_id.is_none());
    assert!(ctx.parent_chain_id.is_none());
    assert!(ctx.cascade_depth.is_none());
}

/// The other half, and a real case rather than symmetry: a peer's OWN writes are
/// autonomous and must stay distinguishable. Fabricating a context here would be the
/// same defect in the opposite direction — a recorder could no longer tell a peer's
/// self-seeding from a remote write.
#[test]
fn h8_control_autonomous_write_carries_no_context() {
    let peer = Peer::create(CreateOptions {
        seed: [13u8; 32],
        ..Default::default()
    });
    let seen: Arc<Mutex<Vec<Option<ExecContext>>>> = Arc::new(Mutex::new(Vec::new()));
    let sink = seen.clone();
    let path = format!("/{}/app/h8/autonomous", peer.local_peer);
    let want = path.clone();
    peer.store.register_tree_consumer(move |ev| {
        if ev.path == want {
            sink.lock().unwrap().push(ev.context.clone());
        }
    });

    let e = Entity::make("primitive/any", model::map(vec![("v", Value::UInt(2))]));
    peer.store.bind(&path, &e);
    peer.store.unbind(&path);

    let got = seen.lock().unwrap().clone();
    assert_eq!(got.len(), 2, "expected one created + one deleted event");
    assert!(
        got.iter().all(|c| c.is_none()),
        "an autonomous write carried a caller context; autonomous and dispatched writes \
         are no longer distinguishable"
    );
}
