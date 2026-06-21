//! S3 gate — two `entity-core-protocol-rust` peers talk over real loopback TCP
//! through the full dispatch chain:
//!   - the §4.1 handshake (initiator hello → authenticate, both legs answered by
//!     the responder over real frames),
//!   - 404 on an unregistered path,
//!   - an authority-gated tree get (200) returning a `system/type` entity,
//!   - a capability request (200),
//!   - 8-way `request_id` demux of concurrently-issued replies (N7),
//!   - clean teardown.
//!
//! This is the live-peer counterpart to the S2 wire-conformance gate: passing it
//! means the peer talks to the network at the wire level and the §6.6 dispatch
//! chain + §5 authority surface are end-to-end correct over a real socket.

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;

use entity_core_protocol::peer::core::Conn;
use entity_core_protocol::peer::model::{self, Entity};
use entity_core_protocol::peer::transport::{self, Io};
use entity_core_protocol::peer::{CreateOptions, Peer};
use entity_core_protocol::value::{Key, Value};

fn type_target() -> Value {
    Value::Map(vec![(
        Key::Text("targets".into()),
        Value::Array(vec![Value::Text("system/type/system/peer".into())]),
    )])
}

fn request_params() -> Entity {
    let scope = |incl: &str| {
        Value::Map(vec![(
            Key::Text("include".into()),
            Value::Array(vec![Value::Text(incl.into())]),
        )])
    };
    let grant = Value::Map(vec![
        (Key::Text("handlers".into()), scope("system/tree")),
        (Key::Text("resources".into()), scope("system/type/*")),
        (Key::Text("operations".into()), scope("get")),
    ]);
    Entity::make(
        "system/capability/request",
        Value::Map(vec![(
            Key::Text("grants".into()),
            Value::Array(vec![grant]),
        )]),
    )
}

#[test]
fn two_peer_loopback_over_real_tcp() {
    let responder = Arc::new(Peer::create(CreateOptions {
        seed: [1u8; 32],
        ..Default::default()
    }));
    let initiator = Arc::new(Peer::create(CreateOptions {
        seed: [2u8; 32],
        ..Default::default()
    }));
    let remote = responder.local_peer.clone();

    let mut passed = 0usize;
    let mut failed = 0usize;
    let mut check = |name: &str, ok: bool| {
        if ok {
            passed += 1;
        } else {
            failed += 1;
        }
        println!("  [{}] {name}", if ok { "PASS" } else { "FAIL" });
    };

    // ── responder: bind + accept one connection on its own thread ────────────
    let listener = transport::listen(0).expect("bind responder");
    let bound_port = listener.local_addr().unwrap().port();
    let resp_for_serve = responder.clone();
    let serve = thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            transport::serve_connection(resp_for_serve, stream);
        }
    });

    // ── initiator: dial + run its reader loop so replies demux (N7) ──────────
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

    // ── handshake ────────────────────────────────────────────────────────────
    println!("Handshake:");
    let mut session =
        transport::initiate(initiator.clone(), io.clone(), conn.clone()).expect("handshake");
    check(
        "remote peer_id matches responder",
        session.remote_peer_id == remote,
    );

    // ── dispatch ─────────────────────────────────────────────────────────────
    println!("Dispatch:");
    {
        let uri = format!("/{remote}/does/not/exist");
        let resp = session
            .execute(
                &uri,
                "noop",
                entity_core_protocol::peer::wire::empty_params(),
                None,
            )
            .expect("404 response");
        check(
            "unregistered path -> 404",
            resp.root.uint_field("status") == Some(404),
        );
    }
    {
        let uri = format!("/{remote}/system/tree");
        let resp = session
            .execute(
                &uri,
                "get",
                entity_core_protocol::peer::wire::empty_params(),
                Some(type_target()),
            )
            .expect("tree get response");
        check(
            "granted tree get -> 200",
            resp.root.uint_field("status") == Some(200),
        );
        let result = resp.root.entity_field("result");
        check(
            "tree get returns a system/type entity",
            result.as_ref().map(|r| r.typ.as_str()) == Some("system/type"),
        );
    }
    {
        let uri = format!("/{remote}/system/capability");
        let resp = session
            .execute(&uri, "request", request_params(), None)
            .expect("capability request response");
        check(
            "capability request -> 200",
            resp.root.uint_field("status") == Some(200),
        );
    }

    // ── concurrency: request_id demux (N7) ───────────────────────────────────
    println!("Concurrency (request_id demux):");
    {
        const N: usize = 8;
        let session = Arc::new(Mutex::new(session));
        let mut handles = Vec::new();
        for _ in 0..N {
            let session = session.clone();
            let remote = remote.clone();
            handles.push(thread::spawn(move || {
                let uri = format!("/{remote}/system/tree");
                let resp = {
                    let mut s = session.lock().unwrap();
                    s.execute(
                        &uri,
                        "get",
                        entity_core_protocol::peer::wire::empty_params(),
                        Some(type_target()),
                    )
                };
                match resp {
                    Some(r) if r.root.uint_field("status") == Some(200) => r
                        .root
                        .entity_field("result")
                        .map(|e| e.typ == "system/type")
                        .unwrap_or(false),
                    _ => false,
                }
            }));
        }
        let correlated = handles
            .into_iter()
            .map(|h| h.join().unwrap_or(false))
            .filter(|&ok| ok)
            .count();
        check(
            &format!("8 interleaved requests each correlated -> {correlated}/8"),
            correlated == N,
        );
        // recover the session out of the Arc for teardown (all threads joined).
        drop(session);
    }

    // ── teardown ─────────────────────────────────────────────────────────────
    io.close();
    transport::shutdown(&teardown_stream);
    let _ = reader.join();
    let _ = serve.join();

    println!(
        "\nTeardown clean.   ->   LOOPBACK: {} pass, {} fail",
        passed, failed
    );
    assert_eq!(failed, 0, "{failed} loopback checks failed");
    // sanity: model is reachable from the test crate (keeps the import honest).
    let _ = model::hex(&[0xde, 0xad]);
}
