//! entity-peer-wasm — the WebAssembly transport seam for the generated Rust peer.
//!
//! This is the ONLY substrate-specific code in the wasm peer. The entire protocol
//! payload — codec, identity, §5 authorization, the §6 dispatch chain, the §9.5 type
//! floor — is the UNMODIFIED `entity_core_protocol` library (path dep on ../rust),
//! cross-compiled to `wasm32-wasip1`. Here we only replace `peer::transport` (which is
//! `std::thread` + `std::net`, neither of which functions on wasip1) with a single-
//! threaded poll loop over WasmEdge sockets.
//!
//! ## Concurrency model — the seam absorbs the substrate difference
//!
//! The native peer runs one reader thread per connection and blocks an outbound-reentry
//! (§7a `dispatch-outbound`) on a condvar while the reader keeps routing. wasm has no
//! threads, so this seam does the same work on ONE thread:
//!   - a `poll()` readiness loop multiplexes the listener + every live connection;
//!   - §7a same-connection reentry (the outbound EXECUTE rides back down the SAME inbound
//!     fd — the wasm-wat/asm finding) collapses the "suspend / pump / resume" to a
//!     synchronous [`pump_outbound`]: send the outbound frame, then pump THIS fd until the
//!     correlated response arrives. Inbound requests that arrive mid-pump are DEFERRED and
//!     drained by the main loop afterward — serializing exactly like the native per-conn
//!     mutex, with no reentrant `&mut Conn` borrow.
//!
//! Crucially, `Peer::dispatch` and every handler are called UNCHANGED: the reentry seam is
//! an `Arc<OutboundFn>` the handler clones out of `Conn` before invoking, so the closure
//! captures only this seam's socket state — never `Conn`. The interior is identical on
//! threads and on one poll loop; only this file differs. That IS the transportable-layer
//! thesis: swap ~one host file, carry the whole protocol.

use std::collections::{HashMap, VecDeque};
use std::io::{ErrorKind, Read, Write};
use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};

use entity_core_protocol::peer::core::OutboundFn;
use entity_core_protocol::peer::model::{self, Envelope};
use entity_core_protocol::peer::wire;
use entity_core_protocol::peer::{Conn, CreateOptions, Peer};
use entity_core_protocol::Value;

use wasmedge_wasi_socket::poll::{poll, EventType, Subscription};
use wasmedge_wasi_socket::{TcpListener, TcpStream};

/// The cohort conformance seed (0x11×32) — yields the same peer_id the Go `entity-peer
/// --name conformance` produces, so the oracle's expected identity matches. `--name` is
/// accepted-and-ignored (identity is fixed here, matching the wasm-wat peer's convention).
const SEED: [u8; 32] = [0x11u8; 32];
const DEFAULT_PORT: u16 = 7777;

const RESPONSE_TYPE: &str = "system/protocol/execute/response";

/// Per-connection socket-side state — everything the reentry seam touches, kept OUT of
/// `Conn` so the `OutboundFn` closure can capture it (`Send + Sync`) without borrowing the
/// `Conn` that `dispatch` holds `&mut`.
struct ConnIo {
    stream: TcpStream,
    /// Bytes read off the wire but not yet framed (§1.6 length-prefix reassembly).
    rbuf: Vec<u8>,
    /// Inbound EXECUTEs that arrived while a `pump_outbound` was awaiting a reply — drained
    /// by the main loop after the in-flight dispatch completes (serialization discipline).
    deferred: VecDeque<Envelope>,
    /// EXECUTE_RESPONSEs read ahead of the pump waiting for them (keyed by request_id).
    pending: HashMap<String, Envelope>,
}

impl ConnIo {
    fn new(stream: TcpStream) -> Arc<Mutex<ConnIo>> {
        Arc::new(Mutex::new(ConnIo {
            stream,
            rbuf: Vec::new(),
            deferred: VecDeque::new(),
            pending: HashMap::new(),
        }))
    }
}

/// Write one §1.6 frame as a SINGLE contiguous buffer (`[4-byte BE len][payload]`) in one
/// `write_all`. This is load-bearing on connection churn: `wire::write_frame` issues the
/// length prefix and the body as two separate sends, which lets Nagle hold the body until
/// the prefix is ACKed — a ~40–200 ms delayed-ACK stall on every cold round trip that
/// dominated §6.11 t2_2 latency (the hand-authored WAT peer hit + fixed the identical bug;
/// see host.wat `on_readable`). Combining them so the body rides with the prefix defeats it.
fn write_frame_oneshot(stream: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    stream.write_all(&framed)?;
    stream.flush()
}

/// Pull one complete §1.6 frame (`[4-byte BE len][payload]`) out of `rbuf`.
/// `Some(Ok(_))` → a frame; `Some(Err(()))` → over the §4.10(a) 16 MiB cap (caller closes
/// the connection, mirroring the native `read_frame` behavior); `None` → need more bytes.
fn extract_frame(rbuf: &mut Vec<u8>) -> Option<Result<Vec<u8>, ()>> {
    if rbuf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]) as usize;
    if len > wire::MAX_FRAME {
        return Some(Err(()));
    }
    if rbuf.len() < 4 + len {
        return None;
    }
    let frame = rbuf[4..4 + len].to_vec();
    rbuf.drain(0..4 + len);
    Some(Ok(frame))
}

/// Drain all currently-available bytes from a non-blocking socket into `rbuf`.
/// Returns `false` if the peer closed (EOF) or errored.
fn fill_rbuf(io: &Arc<Mutex<ConnIo>>) -> bool {
    let mut g = io.lock().unwrap();
    let mut tmp = [0u8; 65536];
    loop {
        match g.stream.read(&mut tmp) {
            Ok(0) => return false, // EOF
            Ok(n) => {
                g.rbuf.extend_from_slice(&tmp[..n]);
                if n < tmp.len() {
                    return true; // socket drained for now
                }
            }
            Err(ref e) if e.kind() == ErrorKind::WouldBlock => return true,
            Err(ref e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return false,
        }
    }
}

/// Block THIS fd until one full frame is available; used by the reentry pump. Returns the
/// framed payload, or `None` on close/over-cap.
fn read_one_frame_blocking(io: &Arc<Mutex<ConnIo>>) -> Option<Vec<u8>> {
    loop {
        // Already buffered?
        {
            let mut g = io.lock().unwrap();
            match extract_frame(&mut g.rbuf) {
                Some(Ok(f)) => return Some(f),
                Some(Err(())) => return None,
                None => {}
            }
        }
        // Wait for readability on just this fd (blocking poll), then drain.
        let fd = io.lock().unwrap().stream.as_raw_fd();
        let subs = [Subscription::IO {
            userdata: 0,
            fd,
            read_event: true,
            write_event: false,
        }];
        match poll(&subs) {
            Ok(events) => {
                if events.iter().any(|e| matches!(e.event_type, EventType::Error(_))) {
                    return None;
                }
            }
            Err(_) => return None,
        }
        if !fill_rbuf(io) {
            return None;
        }
    }
}

/// Answer a frame the strict decoder rejected with `400 non_canonical_ecf` (§6.3),
/// recovering ONLY the `request_id` so the sender can correlate the refusal.
///
/// THE PARENT CRATE HAS ANSWERED THIS SINCE AUGUST AND THIS SEAM DID NOT, which is the
/// whole lesson: the §6.3 sweep landed in `peer/transport.rs`'s read loop, and a thin
/// transport seam that reimplements the read loop does NOT inherit a read-loop fix by
/// depending on the crate. Measured on the wire 2026-09-14: this peer answered nothing to
/// a mis-keyed `included` entry — `Err(_) => continue` refuses the frame (correct) and
/// satisfies only the first half of §6.3's sentence, leaving the sender blocked until its
/// own timeout, so a refusal is indistinguishable from a dead peer. §4.9(c)
/// deliver-or-signal says the same from the other direction.
///
/// The frame stays rejected: nothing is built from it and nothing is stored — the salvage
/// decode exists solely to read back the correlation key. If even the request_id is
/// unrecoverable there is nobody to answer, which is the one case where silence is all
/// that is available.
fn reject_non_canonical(io: &Arc<Mutex<ConnIo>>, payload: &[u8]) {
    let Ok(v) = entity_core_protocol::cbor::decode_salvage(payload) else {
        return;
    };
    let request_id = match model::map_get(&v, "root")
        .and_then(|root| model::map_get(root, "data"))
        .and_then(|data| model::map_get(data, "request_id"))
    {
        Some(Value::Text(s)) => s.clone(),
        _ => return, // no correlatable request_id — nothing to answer
    };
    let result = wire::error_result(
        "non_canonical_ecf",
        Some("frame is not canonical ECF (section 6.3): CBOR tags are forbidden anywhere in an entity"),
    );
    let resp = wire::response_envelope(&request_id, 400, &result);
    let mut g = io.lock().unwrap();
    let _ = write_frame_oneshot(&mut g.stream, &resp.encode());
}

/// The §7a / §6.11 outbound-reentry hook, single-threaded. Sends `req` down the inbound fd
/// and pumps that fd until the correlated EXECUTE_RESPONSE returns. Inbound requests seen
/// mid-pump are deferred; unrelated responses are stashed for an outer pump.
fn pump_outbound(io: &Arc<Mutex<ConnIo>>, req: Envelope) -> Option<Envelope> {
    let rid = req.root.text_field("request_id").unwrap_or("").to_string();
    {
        let mut g = io.lock().unwrap();
        if write_frame_oneshot(&mut g.stream, &req.encode()).is_err() {
            return None;
        }
        if let Some(env) = g.pending.remove(&rid) {
            return Some(env);
        }
    }
    loop {
        let frame = read_one_frame_blocking(io)?;
        let env = match model::envelope_of_frame(&frame) {
            Ok(e) => e,
            Err(_) => {
                reject_non_canonical(io, &frame); // §6.3: a refusal is a STATUS, not silence
                continue;
            }
        };
        if env.root.typ == RESPONSE_TYPE {
            let erid = env.root.text_field("request_id").unwrap_or("").to_string();
            if erid == rid {
                return Some(env);
            }
            io.lock().unwrap().pending.insert(erid, env);
        } else {
            io.lock().unwrap().deferred.push_back(env);
        }
    }
}

/// Bind the reentry seam, dispatch one inbound EXECUTE against the UNMODIFIED interior, and
/// write the response frame. The `OutboundFn` closure captures only `io` (Send + Sync),
/// never `conn` — so there is no reentrant `&mut Conn` conflict.
fn dispatch_one(peer: &Arc<Peer>, io: &Arc<Mutex<ConnIo>>, conn: &mut Conn, env: Envelope) {
    let io_seam = io.clone();
    let outbound: Arc<OutboundFn> = Arc::new(move |req: Envelope| pump_outbound(&io_seam, req));
    conn.outbound = Some(outbound);
    let resp = peer.dispatch(conn, &env);
    conn.outbound = None;
    if let Some(r) = resp {
        let mut g = io.lock().unwrap();
        let _ = write_frame_oneshot(&mut g.stream, &r.encode());
    }
}

/// Service a readable connection: drain the socket, then process every complete frame plus
/// any requests deferred by a reentry pump. Returns `false` if the connection should close.
fn service_readable(peer: &Arc<Peer>, io: &Arc<Mutex<ConnIo>>, conn: &mut Conn) -> bool {
    if !fill_rbuf(io) {
        return false;
    }
    loop {
        // Next unit of work: a freshly-framed message, else a deferred request.
        let env = {
            let mut g = io.lock().unwrap();
            match extract_frame(&mut g.rbuf) {
                Some(Err(())) => return false, // over-cap → close (native parity)
                Some(Ok(frame)) => {
                    drop(g);
                    match model::envelope_of_frame(&frame) {
                        Ok(e) => e,
                        Err(_) => {
                            // §6.3: a refusal is a STATUS, not silence. The lock is
                            // already released above, so answering here cannot deadlock.
                            reject_non_canonical(io, &frame);
                            continue;
                        }
                    }
                }
                None => match g.deferred.pop_front() {
                    Some(e) => e,
                    None => return true, // nothing left
                },
            }
        };
        if env.root.typ == RESPONSE_TYPE {
            // A response with no active pump — stash (a late reply) or drop.
            let rid = env.root.text_field("request_id").unwrap_or("").to_string();
            io.lock().unwrap().pending.insert(rid, env);
        } else {
            dispatch_one(peer, io, conn, env);
        }
    }
}

fn main() {
    let mut open_grants = false;
    let mut conformance = false;
    let mut port = DEFAULT_PORT;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--debug-open-grants" => open_grants = true,
            "--validate" => conformance = true,
            "--port" => port = args.next().and_then(|v| v.parse().ok()).unwrap_or(DEFAULT_PORT),
            "--name" => {
                let _ = args.next();
            } // identity is the fixed conformance seed; ignore
            _ => {}
        }
    }

    let peer = Arc::new(Peer::create(CreateOptions {
        seed: SEED,
        open_grants,
        conformance,
    }));

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let listener = TcpListener::bind(addr, true).expect("bind 127.0.0.1");

    // The run-s4 harness waits for a line starting with LISTENING.
    println!("LISTENING 127.0.0.1:{port} open_grants={open_grants} validate={conformance}");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    // (userdata, socket-state, protocol-state). userdata 0 is reserved for the listener.
    let mut conns: Vec<(u64, Arc<Mutex<ConnIo>>, Conn)> = Vec::new();
    let mut next_id: u64 = 1;

    loop {
        let mut subs = Vec::with_capacity(conns.len() + 1);
        subs.push(Subscription::IO {
            userdata: 0,
            fd: listener.as_raw_fd(),
            read_event: true,
            write_event: false,
        });
        for (id, io, _) in &conns {
            let fd = io.lock().unwrap().stream.as_raw_fd();
            subs.push(Subscription::IO {
                userdata: *id,
                fd,
                read_event: true,
                write_event: false,
            });
        }

        let events = match poll(&subs) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let mut to_close: Vec<u64> = Vec::new();
        for ev in events {
            if ev.userdata == 0 {
                // Accept every pending connection (edge-triggered readiness).
                loop {
                    match listener.accept(true) {
                        Ok((stream, _peer)) => {
                            let _: &TcpStream = &stream;
                            conns.push((next_id, ConnIo::new(stream), Conn::new()));
                            next_id += 1;
                        }
                        Err(_) => break, // WouldBlock / transient
                    }
                }
            } else if let Some(pos) = conns.iter().position(|(id, _, _)| *id == ev.userdata) {
                if matches!(ev.event_type, EventType::Error(_)) {
                    to_close.push(ev.userdata);
                    continue;
                }
                let (id, io, conn) = &mut conns[pos];
                let id = *id;
                if !service_readable(&peer, io, conn) {
                    to_close.push(id);
                }
            }
        }

        if !to_close.is_empty() {
            conns.retain(|(id, _, _)| !to_close.contains(id));
        }
    }
}
