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
