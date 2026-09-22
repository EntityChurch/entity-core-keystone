//! RT-13b §4.1 Class R — a >=2-writer test asserting FRAME-BOUNDARY INTEGRITY of
//! the emitted stream, not demux timing (protocol-generator/shared/
//! diagnostics/rt13-write-concurrency-classes.md). The gap this closes: the ground-up Rust
//! peer's own multiplex test exercises the write path but asserts response
//! routing, not that concurrent writers never interleave two frames' bytes on
//! the wire — a property `write_stream`'s `Mutex` (super::Io) is supposed to
//! guarantee and which this test would catch a regression in.
//!
//! Run under a race/UB detector: `RUSTFLAGS=-Zsanitizer=thread cargo +nightly test
//! -Z build-std --target x86_64-unknown-linux-gnu transport::tests -- --test-threads=1`
//! (TSan) or `cargo +nightly miri test transport::tests` (Miri) per the profile's
//! documented Class R detector. A plain `cargo test` also runs it (std::sync::Mutex
//! is always race-safe; the sanitizer's job is proving no OTHER shared-state UB
//! sneaks in around it).

use std::net::{TcpListener, TcpStream};
use std::thread;

use super::Io;
use crate::peer::model::{envelope_of_frame, Envelope};
use crate::peer::wire::{empty_params, make_response, read_frame};

#[test]
fn concurrent_writers_frame_boundary_integrity() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");

    let writer_side = thread::spawn(move || TcpStream::connect(addr).expect("connect"));
    let (server_conn, _) = listener.accept().expect("accept");
    let client_conn = writer_side.join().expect("connect thread");

    let io = Io::new(client_conn).expect("Io::new");

    const N: usize = 16;
    let writers: Vec<_> = (0..N)
        .map(|i| {
            let io = io.clone();
            thread::spawn(move || {
                let request_id = format!("rq-{:04}", i);
                let env = Envelope::new(make_response(&request_id, i as u64, &empty_params()));
                io.write_framed(&env).expect("write_framed");
            })
        })
        .collect();

    // Single reader, sequential. Every frame it decodes must be EXACTLY what one
    // writer sent: a torn/interleaved write would either fail to decode as CBOR
    // or decode into a request_id/status pair no writer ever produced together
    // (evidence of byte-splicing across two concurrent frames).
    let mut server_conn = server_conn;
    let mut seen = std::collections::HashSet::with_capacity(N);
    for i in 0..N {
        let payload = read_frame(&mut server_conn)
            .unwrap_or_else(|e| panic!("read_frame({}): {:?}", i, e));
        let env: Envelope = envelope_of_frame(&payload).unwrap_or_else(|e| {
            panic!(
                "frame {} failed to decode as a well-formed envelope (byte-spliced across concurrent writers?): {:?}",
                i, e
            )
        });
        let request_id = env
            .root
            .text_field("request_id")
            .unwrap_or_else(|| panic!("frame {} decoded but has no request_id field (corrupted envelope)", i))
            .to_string();
        let status = env.root.uint_field("status").unwrap_or_else(|| {
            panic!(
                "frame {} (request_id={}) decoded but has no status field (corrupted envelope)",
                i, request_id
            )
        });
        let want_idx: usize = request_id
            .strip_prefix("rq-")
            .and_then(|s| s.parse().ok())
            .unwrap_or_else(|| panic!("frame {}: unparseable request_id {:?} (bytes from a different frame spliced in?)", i, request_id));
        assert_eq!(
            want_idx as u64, status,
            "frame {}: request_id {:?} paired with status={}, want {} — this is exactly the corruption shape a torn concurrent write produces (one frame's header/id with another's body)",
            i, request_id, status, want_idx
        );
        assert!(
            seen.insert(request_id.clone()),
            "request_id {:?} delivered twice — a write was duplicated or a frame boundary was misread",
            request_id
        );
    }

    for w in writers {
        w.join().expect("writer thread");
    }
    assert_eq!(seen.len(), N);
}

// ── §4.11 pre-admission refusals (0.8.2.25) — over a real socket ──────────────
//
// The CLASSIFICATION half is pinned in `peer::wire::tests`. This is the OBLIGATION half,
// and it is the one that was broken: *"A peer that refuses a frame pre-admission MUST put
// a coded EXECUTE_RESPONSE on the wire [MUST]"*. §4.9(c)'s deliver-or-signal rule is
// scoped to *"every request the peer ADMITS"* and reaches none of these, which is why
// §4.11 exists — and BOTH of the non-conformant behaviours it names separately were
// present here: the oversize/truncated arms ended the read loop with NO frame (a bare
// close, indistinguishable from a network fault), and the un-salvageable decode arm wrote
// nothing at all (the silent drop, *"the weaker of the two precisely because nothing
// surfaces it"*).
//
// Driven over a socket rather than against the classifier, because a mapping that is
// correct and never reached is exactly the never-executed-guard shape.

use crate::peer::core::{CreateOptions, Peer};
use crate::peer::model::Entity;
use crate::peer::wire::write_frame;
use crate::value::{Key, Value};
use std::io::Write as _;
use std::sync::Arc;
use std::time::Duration;

/// Serve one connection on a background thread; return a client stream talking to it.
fn serve_one(seed: u8) -> TcpStream {
    let peer = Arc::new(Peer::create(CreateOptions {
        seed: [seed; 32],
        open_grants: true,
        conformance: false,
    }));
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let addr = listener.local_addr().expect("addr");
    thread::spawn(move || {
        if let Ok((s, _)) = listener.accept() {
            super::serve_connection(peer, s);
        }
    });
    let client = TcpStream::connect(addr).expect("connect");
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("read timeout");
    client
}

/// Read one response frame and return `(status, code, request_id)`.
fn read_refusal(stream: &mut TcpStream) -> (u64, String, String) {
    let payload = read_frame(stream).expect("a coded EXECUTE_RESPONSE, not silence or a bare close");
    let env = envelope_of_frame(&payload).expect("the refusal frame must itself decode");
    assert_eq!(
        env.root.typ, "system/protocol/execute/response",
        "§4.11 requires a coded EXECUTE_RESPONSE"
    );
    let status = env.root.uint_field("status").expect("status");
    let result = env.root.entity_field("result").expect("a result entity");
    let code = result.text_field("code").unwrap_or("").to_string();
    let rid = env.root.text_field("request_id").unwrap_or("").to_string();
    (status, code, rid)
}

/// An oversize length prefix — §4.10(a), mood raised to MUST at 0.8.2.25 (N14). The body
/// is never drained, so the framing is lost and the peer closes afterwards; the close is
/// now IN ADDITION TO the frame rather than instead of it.
#[test]
fn oversize_prefix_is_answered_413_before_it_closes() {
    let mut c = serve_one(0x41);
    // 32 MiB declared, nothing sent. The bound is read from the prefix, so no body needs
    // to exist for the refusal to fire — that is the whole point of checking it there.
    c.write_all(&0x0200_0000u32.to_be_bytes()).expect("write prefix");
    c.flush().expect("flush");
    let (status, code, rid) = read_refusal(&mut c);
    assert_eq!((status, code.as_str()), (413, "payload_too_large"));
    // §4.11's best-effort uncorrelated form: there is no request_id to recover from a
    // frame whose body never arrived, and guessing one would correlate the refusal to
    // somebody else's in-flight request.
    assert_eq!(rid, "", "an unrecoverable id yields the uncorrelated best-effort frame");
}

/// A length prefix that declares more than is sent — §4.11's framing arm, "a length prefix
/// that never completes" -> `400 invalid_request`. The CONTROL for this is
/// `clean_close_is_not_a_refusal` below: both end the stream, and only one is owed a frame.
#[test]
fn truncated_frame_is_answered_400_invalid_request() {
    let mut c = serve_one(0x42);
    c.write_all(&[0x00, 0x00, 0x10, 0x00]).expect("prefix");
    c.write_all(&[0xa1]).expect("one body byte");
    c.flush().expect("flush");
    let _ = c.shutdown(std::net::Shutdown::Write);
    let (status, code, _) = read_refusal(&mut c);
    assert_eq!((status, code.as_str()), (400, "invalid_request"));
}

/// THE CONTROL. A clean EOF at a frame boundary is an ordinary hangup, NOT a refusal, and
/// is owed nothing. Without this row every assertion above is satisfied by a peer that
/// answers 400 to everyone who hangs up, which would be a new defect rather than a fix.
#[test]
fn clean_close_is_not_a_refusal() {
    let mut c = serve_one(0x43);
    let _ = c.shutdown(std::net::Shutdown::Write);
    c.set_read_timeout(Some(Duration::from_millis(400))).expect("timeout");
    let mut buf = [0u8; 1];
    use std::io::Read as _;
    match c.read(&mut buf) {
        Ok(0) => {}                       // peer closed without writing: correct
        Err(_) => {}                      // timed out with nothing written: also correct
        Ok(n) => panic!("a clean close was answered with {n} byte(s); it is not a refusal"),
    }
}

/// A mis-keyed `included` entry — §5.2a (0.8.2.24 N4/N5) pins `400 hash_mismatch` here and
/// rules `400 non_canonical_ecf` NON-CONFORMANT. This peer answered `non_canonical_ecf`
/// for every decode-boundary cause until now. The frame is COMPLETE, so the peer answers
/// and KEEPS SERVING; the correlated id proves the salvage path ran.
#[test]
fn miskeyed_included_is_answered_400_hash_mismatch_and_the_connection_survives() {
    let mut c = serve_one(0x44);
    let good = Entity::make("primitive/any", Value::Map(vec![]));
    let root = Entity::make(
        "system/protocol/execute",
        Value::Map(vec![
            (Key::Text("request_id".into()), Value::Text("mk-1".into())),
            (Key::Text("uri".into()), Value::Text("system/tree".into())),
            (Key::Text("operation".into()), Value::Text("get".into())),
        ]),
    );
    let frame = crate::cbor::encode(&Value::Map(vec![
        (Key::Text("root".into()), root.to_cbor()),
        (
            Key::Text("included".into()),
            Value::Map(vec![(Key::Bytes(vec![0x11; 33]), good.to_cbor())]),
        ),
    ]));
    write_frame(&mut c, &frame).expect("write");
    let (status, code, rid) = read_refusal(&mut c);
    assert_eq!((status, code.as_str()), (400, "hash_mismatch"));
    assert_eq!(rid, "mk-1", "a complete frame's request_id is recoverable, so the refusal correlates");

    // AND THE CONNECTION KEEPS SERVING. A decode refusal on a complete frame does not
    // desynchronize the stream, so answering it and closing would be the cascade this
    // cohort has recorded twice. Send the same bad frame again and expect a second answer.
    write_frame(&mut c, &frame).expect("second write on the same connection");
    let (status2, code2, _) = read_refusal(&mut c);
    assert_eq!((status2, code2.as_str()), (400, "hash_mismatch"));
}

/// §6.5's "Other type?" arm as rewritten at 0.8.2.25 (N12/N17): "400 invalid_request,
/// coded frame; MAY then close. NOT a bare close." §3.3 previously read "the connection
/// MUST be closed", assigning no code and requiring no frame; this peer did something
/// weaker still and wrote NOTHING while leaving the connection open — the silent drop.
/// §9.1's floor row that mandated the bare close was REPLACED at the same revision (N18).
#[test]
fn non_execute_root_is_answered_400_invalid_request() {
    let mut c = serve_one(0x45);
    let root = Entity::make(
        "primitive/any",
        Value::Map(vec![(Key::Text("request_id".into()), Value::Text("x-1".into()))]),
    );
    write_frame(&mut c, &Envelope::new(root).encode()).expect("write");
    let (status, code, rid) = read_refusal(&mut c);
    assert_eq!((status, code.as_str()), (400, "invalid_request"));
    // Correlated where the id is recoverable; the uncorrelated frame is the FALLBACK, not
    // the default.
    assert_eq!(rid, "x-1");
}
