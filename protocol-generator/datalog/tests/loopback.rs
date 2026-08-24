//! S3 smoke gate (in-tree, deterministic) — two `entity-core-protocol-datalog` peers
//! talk over real loopback TCP through the full dispatch chain + the Ascent authority
//! interior:
//!   - the §4.1 handshake BOTH legs (initiator hello → authenticate, answered by the
//!     responder over real frames),
//!   - an AUTHORIZED EXECUTE (the seed cap flows through `authority::authorize` →
//!     ALLOW) to an unregistered path → 404 (the §6.6 Ascent longest-prefix resolver
//!     finds no handler),
//!   - 8-way `request_id` demux of concurrently-issued replies (N7 / §6.11),
//!   - clean teardown.
//!
//! This proves the peer talks to the network at the wire level in BOTH roles and that
//! the authored §5/§6.6 rules are load-bearing end-to-end over a socket. The
//! cross-impl interop leg (dialing the Go `entity-peer`) lives in `run-s3.sh`.

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;

use entity_core_protocol_datalog::dispatch::{Conn, CreateOptions, Peer};
use entity_core_protocol_datalog::host::{self, Io};
use entity_core_protocol_datalog::model::Envelope;

fn spawn_responder(seed: [u8; 32]) -> (u16, Arc<Peer>) {
    let peer = Arc::new(Peer::create(CreateOptions {
        seed,
        open_grants: true,
        conformance: true,
    }));
    let listener = host::listen(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let p = peer.clone();
    thread::spawn(move || {
        for stream in listener.incoming() {
            match stream {
                Ok(s) => {
                    let p = p.clone();
                    thread::spawn(move || host::serve_connection(p, s));
                }
                Err(_) => break,
            }
        }
    });
    (port, peer)
}

#[test]
fn two_peer_loopback_over_real_tcp() {
    // Responder (open seed policy so the seed cap AUTHORIZES → 404 is reachable).
    let (port, _responder) = spawn_responder([1u8; 32]);

    // Initiator dials over real TCP.
    let initiator = Arc::new(Peer::create(CreateOptions {
        seed: [2u8; 32],
        ..Default::default()
    }));
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    host::set_no_delay(&stream);
    let read_stream = stream.try_clone().unwrap();
    let io = Io::new(stream).unwrap();
    let conn = Arc::new(Mutex::new(Conn::new()));

    // reader loop for the initiator side (routes responses by request_id).
    {
        let peer = initiator.clone();
        let conn = conn.clone();
        let io = io.clone();
        thread::spawn(move || host::read_loop(peer, conn, io, read_stream));
    }

    // §4.1 handshake — BOTH legs (hello + authenticate) answered by the responder.
    let mut session = host::initiate(initiator.clone(), io.clone(), conn.clone())
        .expect("handshake (hello + authenticate) must succeed");

    // AUTHORIZED EXECUTE to an unregistered path → 404 (authority ALLOWs, resolver
    // finds no handler). Proves the §5.2 verdict + §6.6 resolution end-to-end.
    let resp = session
        .execute(
            "system/nonexistent/handler",
            "get",
            host::empty_params(),
            None,
        )
        .expect("reply must arrive");
    assert_eq!(
        resp.root.uint_field("status"),
        Some(404),
        "authorized request to unregistered path must be 404 (not 403/401)"
    );

    // N7 — 8-way concurrent request_id demux over the SAME connection. Replies may
    // arrive out of order; each thread must receive the reply for ITS request_id.
    let session = Arc::new(session);
    let mut handles = Vec::new();
    for i in 0..8u32 {
        let session = session.clone();
        handles.push(thread::spawn(move || {
            let rid = format!("demux-{i}");
            let env: Envelope = session.build_execute(
                &rid,
                "system/nonexistent/handler",
                "get",
                host::empty_params(),
                None,
            );
            let reply = session.io().outbound(env).expect("demux reply");
            let got = reply
                .root
                .text_field("request_id")
                .unwrap_or("")
                .to_string();
            assert_eq!(got, rid, "reply correlated to the wrong request_id");
            reply.root.uint_field("status").unwrap_or(0)
        }));
    }
    for h in handles {
        assert_eq!(h.join().unwrap(), 404);
    }

    // teardown.
    io.close();
}
