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
/// `Some(Ok(_))` → a frame; `Some(Err(e))` → a pre-admission REFUSAL owed a coded frame
/// (§4.11); `None` → need more bytes.
///
/// THE ERROR CARRIES ITS CAUSE (0.8.2.25, RULE C/D). It used to be `Err(())` — a bare
/// "close the connection, mirroring the native `read_frame` behavior" — and both halves of
/// that comment stopped being true at .25: §4.11 makes the coded frame MANDATORY, and the
/// native read loop it mirrors now emits one. A unit type cannot say WHICH code is owed,
/// and §4.11's whole point is that *"the frame obligation belongs to the class; the CODE
/// belongs to the cause"*. Reusing the parent crate's `WireError` rather than minting a
/// local enum is what lets `wire::pre_admission_refusal` be the single table for both
/// read loops.
fn extract_frame(rbuf: &mut Vec<u8>) -> Option<Result<Vec<u8>, wire::WireError>> {
    if rbuf.len() < 4 {
        return None;
    }
    let len = u32::from_be_bytes([rbuf[0], rbuf[1], rbuf[2], rbuf[3]]) as usize;
    if len > wire::MAX_FRAME {
        return Some(Err(wire::WireError::PayloadTooLarge));
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
                Some(Err(e)) => {
                    // §4.11 reaches the REENTRY pump too, and this arm is the reason the
                    // refusal helper takes `io` rather than living in the service loop: a
                    // frame refused while we are waiting for a correlated response is still
                    // a frame refused pre-admission, and dropping it here would answer the
                    // outbound caller with a hang. The lock is released first — the helper
                    // takes it — so this cannot deadlock.
                    drop(g);
                    let (status, code, message) = wire::pre_admission_refusal(&e);
                    refuse_pre_admission(io, "", status, code, message);
                    return None;
                }
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

/// Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
/// refused BEFORE it becomes an admitted request.
///
/// *"A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
/// wire `[MUST]` — correlated by request_id where the id is available, and otherwise as a
/// best-effort coded frame carrying no correlation."* §4.9(c)'s deliver-or-signal rule is
/// scoped to *"every request the peer ADMITS"* and therefore reaches none of these, which
/// is why §4.11 exists.
///
/// THE PARENT CRATE HAS ANSWERED THIS SINCE AUGUST AND THIS SEAM DID NOT, which is the
/// whole lesson and it has now cost the same peer twice: the §6.3 sweep landed in
/// `peer/transport.rs`'s read loop, and a thin transport seam that reimplements the read
/// loop does NOT inherit a read-loop fix by depending on the crate. The §6.3 half was
/// closed here on 2026-09-14; the .25 half — the CODE belonging to the cause, and the two
/// FRAMING arms that used to close with no frame at all — is this change, and rebuilding
/// against a swept parent propagated neither.
///
/// AN EMPTY `request_id` IS THE BEST-EFFORT FORM, NOT A BUG. The previous version returned
/// early when nothing was salvageable, on the reading that *"there is nobody to answer"*.
/// §4.11 rules otherwise and is right to: an uncorrelated coded frame still tells the
/// sender its frame was REFUSED rather than lost, which is the distinction a silent drop
/// destroys.
fn refuse_pre_admission(
    io: &Arc<Mutex<ConnIo>>,
    request_id: &str,
    status: u64,
    code: &str,
    message: &str,
) {
    let result = wire::error_result(code, Some(message));
    let resp = wire::response_envelope(request_id, status, &result);
    let mut g = io.lock().unwrap();
    let _ = write_frame_oneshot(&mut g.stream, &resp.encode());
}

/// Recover ONLY the `request_id` from a frame the strict decoder rejected, so the refusal
/// can be delivered CORRELATED rather than as §4.11's uncorrelated best-effort frame.
/// `""` when nothing is recoverable.
///
/// The frame stays rejected: nothing is built from it, nothing is stored, and a tag is
/// never interpreted — the salvage decode exists solely to read back the correlation key.
fn salvage_request_id(payload: &[u8]) -> String {
    let Ok(v) = entity_core_protocol::cbor::decode_salvage(payload) else {
        return String::new();
    };
    match model::map_get(&v, "root")
        .and_then(|root| model::map_get(root, "data"))
        .and_then(|data| model::map_get(data, "request_id"))
    {
        Some(Value::Text(s)) => s.clone(),
        _ => String::new(),
    }
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
            Err(err) => {
                // THE SECOND SITE FOR ONE REFUSAL, and it must say the same thing as the
                // service loop's. This peer has TWO read loops — the poll-driven service
                // loop and this synchronous reentry pump — because wasip1 has no threads,
                // so every transport rule lands twice here and a rule applied once is a
                // rule the wire can observe half of, depending only on whether a handler
                // happened to be mid-outbound when the bad frame arrived.
                let (status, code, message) = wire::decode_refusal(&err);
                refuse_pre_admission(io, &salvage_request_id(&frame), status, code, message);
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
        // A CLEAN CLOSE AT A FRAME BOUNDARY AND A STREAM THAT ENDED MID-FRAME ARE
        // DIFFERENT EVENTS, AND ONLY THE FRAME BOUNDARY KNOWS WHICH (§4.11, N14). The
        // first is an ordinary hangup, owed nothing — there is no refusal and nobody to
        // answer. The second is a TRUNCATED frame, which §4.11's framing arm names
        // explicitly ("a length prefix that never completes") and answers `400
        // invalid_request`. `fill_rbuf` collapses them into one `false`, exactly as
        // `io::ReadFull` collapses EOF and UnexpectedEOF in the native peer, so the
        // discriminator has to be made HERE: bytes still buffered mean a frame was
        // begun and never finished.
        //
        // The write will usually fail — the socket is half-closed — and that is fine and
        // is why the result is discarded: the obligation is to EMIT, and a peer whose
        // stream layer has already ended the write side has satisfied it as far as the
        // runtime allows. (On a managed runtime that half is a defaulted socket option
        // rather than a line of code; on wasip1 sockets it is the ordinary FIN.)
        let partial = !io.lock().unwrap().rbuf.is_empty();
        if partial {
            let (status, code, message) = wire::pre_admission_refusal(&wire::WireError::Truncated);
            refuse_pre_admission(io, "", status, code, message);
        }
        return false;
    }
    loop {
        // Next unit of work: a freshly-framed message, else a deferred request.
        let env = {
            let mut g = io.lock().unwrap();
            match extract_frame(&mut g.rbuf) {
                Some(Err(e)) => {
                    // OVER-CAP: the coded frame goes out and THEN the connection closes.
                    // This used to be a bare `return false` — a close with no frame, which
                    // §4.11 names as one of its two separately-non-conformant behaviours
                    // and which is indistinguishable from a network fault (§4.6). The body
                    // was never drained so the framing is lost and closing is still the
                    // only sound choice; §4.11 makes it a choice IN ADDITION to answering
                    // rather than INSTEAD of it. (§4.10(a)'s "SHOULD ... and otherwise MAY
                    // close after a best-effort coded frame" became a MUST at N14, because
                    // the condition is detected at the LENGTH PREFIX with the connection
                    // intact and nothing spent.)
                    drop(g);
                    let (status, code, message) = wire::pre_admission_refusal(&e);
                    refuse_pre_admission(io, "", status, code, message);
                    return false;
                }
                Some(Ok(frame)) => {
                    drop(g);
                    match model::envelope_of_frame(&frame) {
                        Ok(e) => e,
                        Err(err) => {
                            // A COMPLETE frame the decoder refused: the framing is intact,
                            // so answer and KEEP SERVING. The lock is already released
                            // above, so answering here cannot deadlock.
                            //
                            // THE CODE IS THE CAUSE'S (§4.11, §5.2a). This answered
                            // `non_canonical_ecf` for every cause until 0.8.2.24/.25 pinned
                            // them apart, and `wire::decode_refusal` is the parent crate's
                            // single table for both read loops rather than a second copy
                            // that can drift.
                            let (status, code, message) = wire::decode_refusal(&err);
                            refuse_pre_admission(io, &salvage_request_id(&frame), status, code, message);
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
