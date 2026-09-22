//! Keystone peer contract — the requirements the shared wire driver cannot observe, as local
//! tests. Test names carry the requirement prefix (`embed_create__`, `context_authority_chain__`);
//! `tools/peer-contract/report.py` counts them by that prefix, so a renamed test stops counting
//! rather than silently counting for something else.

// The requirement-prefix names use a double underscore on purpose (report.py matches it).
#![allow(non_snake_case)]

use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::thread;

use entity_core_protocol::peer::capability;
use entity_core_protocol::peer::core::Conn;
use entity_core_protocol::peer::model::{self, hex, Entity};
use entity_core_protocol::peer::transport::{self, Io};
use entity_core_protocol::peer::{
    CreateOptions, HandlerContext, HandlerResult, HandlerSpec, OperationSpec, Peer, PeerConfig,
    SeedPolicy,
};
use entity_core_protocol::value::Value;

fn peer(seed: u8) -> Arc<Peer> {
    Arc::new(Peer::create_with(
        CreateOptions { seed: [seed; 32], ..Default::default() },
        PeerConfig::default().seed_policy(SeedPolicy::debug_open()),
    ))
}

fn any(pairs: Vec<(&str, Value)>) -> Entity {
    Entity::make("primitive/any", model::map(pairs))
}

#[test]
fn embed_create__two_peers_in_one_process_and_a_listenerless_peer() {
    // SDK-OPERATIONS §8.1: multi-peer in one process (MUST) and a peer with no listener (MUST).
    // Neither peer below ever binds a socket.
    let a = peer(0x51);
    let b = peer(0x52);
    assert_ne!(a.local_peer, b.local_peer, "independent identities");
    let ha = a
        .register_handler(
            HandlerSpec::new("app/only-on-a", "a").operation(OperationSpec::named("go")),
            |_ctx: &HandlerContext<'_>| HandlerResult::ok(any(vec![])),
        )
        .unwrap();
    let path = |p: &Peer| format!("/{}/app/only-on-a", p.local_peer);
    assert!(a.store.get_at(&path(&a)).is_some(), "installed on a");
    assert!(b.store.get_at(&path(&b)).is_none(), "b has its own store and handlers");
    assert!(!b.has_native_handler("app/only-on-a"));
    // Closing a's handle touches a only.
    assert!(ha.close());
    assert!(a.store.get_at(&path(&a)).is_none());
}

/// Serve one connection from `responder`, authenticate `initiator`, and return the session.
fn session(responder: Arc<Peer>, initiator: Arc<Peer>) -> (transport::Session, Vec<thread::JoinHandle<()>>, TcpStream) {
    let listener = transport::listen(0).unwrap();
    let port = listener.local_addr().unwrap().port();
    let serving = responder.clone();
    let serve = thread::spawn(move || {
        if let Ok((s, _)) = listener.accept() {
            transport::serve_connection(serving, s);
        }
    });
    let stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
    let read = stream.try_clone().unwrap();
    let teardown = stream.try_clone().unwrap();
    let io = Io::new(stream).unwrap();
    let conn = Arc::new(Mutex::new(Conn::new()));
    let (p, c, i) = (initiator.clone(), conn.clone(), io.clone());
    let reader = thread::spawn(move || transport::read_loop(p, c, i, read));
    let s = transport::initiate(initiator, io, conn).expect("handshake");
    (s, vec![serve, reader], teardown)
}

#[test]
fn context_authority_chain__in_chain_accepts_and_not_in_chain_denies() {
    // SDK-OPERATIONS §11.3 SEC-3. The caller's session capability is granted BY the responder TO
    // the caller: the responder is in its authority chain, the caller (as granter) is not.
    let responder = peer(0x53);
    let initiator = peer(0x54);
    let seen: Arc<Mutex<Option<(bool, bool)>>> = Arc::new(Mutex::new(None));
    let sink = seen.clone();
    let local_identity = responder.identity.identity_hash.clone();
    responder
        .register_handler(
            HandlerSpec::new("app/chain", "chain").operation(OperationSpec::named("ask")),
            move |ctx: &HandlerContext<'_>| {
                let cap = ctx.caller_capability().expect("a verified capability").hash.clone();
                // deny: the author is not a granter anywhere in this chain.
                let author_in = ctx.identity_in_authority_chain(&cap);
                // accept: the responder granted it.
                let local_in = capability::identity_in_authority_chain(
                    ctx.envelope(), &ctx.peer().store, ctx.local_peer(), &cap, &local_identity,
                );
                *sink.lock().unwrap() = Some((author_in, local_in));
                HandlerResult::ok(any(vec![]))
            },
        )
        .unwrap()
        .detach();
    let (mut s, threads, teardown) = session(responder.clone(), initiator);
    let uri = format!("/{}/app/chain", responder.local_peer);
    let r = s.execute(&uri, "ask", any(vec![]), None).expect("response");
    assert_eq!(r.root.uint_field("status"), Some(200), "{:?}", r.root);
    assert_eq!(*seen.lock().unwrap(), Some((false, true)));
    // An unresolvable hash is never "in chain".
    assert!(!capability::identity_in_authority_chain(
        &r, &responder.store, &responder.local_peer, &[0u8; 33], &responder.identity.identity_hash
    ));
    let _ = hex(&[]);
    let _ = teardown.shutdown(std::net::Shutdown::Both);
    for t in threads {
        let _ = t.join();
    }
}
