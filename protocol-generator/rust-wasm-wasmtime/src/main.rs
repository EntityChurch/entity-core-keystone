//! entity-peer-wasm-wasmtime — the WebAssembly transport seam for the generated Rust
//! peer, targeting WASMTIME's standard wasip1 runtime (for Cranelift AOT).
//!
//! This is the ONLY substrate-specific code in the peer. The entire protocol payload —
//! codec, identity, §5 authorization, the §6 dispatch chain, the §9.5 type floor — is
//! the UNMODIFIED `entity_core_protocol` library (path dep on ../rust), cross-compiled
//! to `wasm32-wasip1` — byte-identical to what ../rust-wasm compiles. Only this file
//! differs from ../rust-wasm, and only in its socket layer:
//!
//!   ../rust-wasm (WasmEdge): the guest SELF-BINDS via WasmEdge's non-standard sock_*
//!       extension (sock_open/bind/listen) through the `wasmedge_wasi_socket` crate.
//!   this crate  (wasmtime) : the HOST preopens the listener — run as
//!       `wasmtime run -S preview2=n -S tcplisten=127.0.0.1:PORT peer.wasm` — and the
//!       guest receives it as a preopened fd, then accepts with the STANDARD wasip1
//!       `sock_accept`. recv/send are `fd_read`/`fd_write`, readiness is `poll_oneoff`.
//!       No self-bind primitive is used; every import is standard wasi-snapshot-preview1
//!       (the `wasi` crate), which is what makes it wasmtime-portable and AOT-compilable.
//!
//! ## Concurrency model — identical to ../rust-wasm (the seam absorbs the difference)
//!
//! No threads on wasip1, so ONE poll loop multiplexes the listener + every live conn.
//! §7a same-connection reentry (the outbound EXECUTE rides back down the SAME inbound fd)
//! collapses "suspend / pump / resume" to a synchronous [`pump_outbound`]. This logic —
//! framing, the reentrant pump, deferred-inbound serialization, single-send framing — is
//! PORTED VERBATIM from ../rust-wasm/src/main.rs; only [`sock`] (the fd primitives)
//! changed. `Peer::dispatch` and every handler are called UNCHANGED.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use entity_core_protocol::peer::core::OutboundFn;
use entity_core_protocol::peer::model::{self, Envelope};
use entity_core_protocol::peer::wire;
use entity_core_protocol::peer::{Conn, CreateOptions, Peer};
use entity_core_protocol::Value;

/// The cohort conformance seed (0x11×32) — yields the same peer_id the Go `entity-peer
/// --name conformance` produces, so the oracle's expected identity matches. `--name` is
/// accepted-and-ignored (identity is fixed here, matching ../rust-wasm's convention).
const SEED: [u8; 32] = [0x11u8; 32];
const DEFAULT_PORT: u16 = 7777;

const RESPONSE_TYPE: &str = "system/protocol/execute/response";

/// The wasip1 socket primitives — the substrate seam. Everything wasmtime-specific lives
/// here; the framing/dispatch logic above it is byte-for-byte the WasmEdge peer's. All
/// calls go through the standard `wasi` snapshot-preview1 bindings (no WasmEdge sock_*).
mod sock {
    pub type Fd = wasi::Fd;

    /// Outcome of a non-blocking read.
    pub enum Rd {
        Data(usize),
        WouldBlock,
        Eof,
        Err,
    }

    /// Locate the host-preopened listening socket. With `-S tcplisten`, wasmtime hands the
    /// listener to the guest as a preopened fd after stdio (0,1,2) and any `--dir`
    /// preopens. We scan fds 3.. for the first STREAM socket (robust against extra
    /// preopens); if the runtime doesn't report the filetype, fall back to the
    /// conventional listenfd (fd 3).
    pub fn find_listener() -> Fd {
        for fd in 3u32..64 {
            match unsafe { wasi::fd_fdstat_get(fd) } {
                Ok(st) if st.fs_filetype == wasi::FILETYPE_SOCKET_STREAM => return fd,
                Ok(_) => continue,
                Err(_) => continue,
            }
        }
        3
    }

    pub fn set_nonblock(fd: Fd) -> Result<(), wasi::Errno> {
        unsafe { wasi::fd_fdstat_set_flags(fd, wasi::FDFLAGS_NONBLOCK) }
    }

    /// Accept one pending connection as a non-blocking socket. `None` = nothing pending
    /// (AGAIN) or a transient error; the caller stops the accept drain.
    pub fn accept(listener: Fd) -> Option<Fd> {
        match unsafe { wasi::sock_accept(listener, wasi::FDFLAGS_NONBLOCK) } {
            Ok(fd) => Some(fd),
            Err(_) => None,
        }
    }

    pub fn read(fd: Fd, buf: &mut [u8]) -> Rd {
        let iov = wasi::Iovec { buf: buf.as_mut_ptr(), buf_len: buf.len() };
        match unsafe { wasi::fd_read(fd, &[iov]) } {
            Ok(0) => Rd::Eof,
            Ok(n) => Rd::Data(n),
            Err(e) if e == wasi::ERRNO_AGAIN || e == wasi::ERRNO_INTR => Rd::WouldBlock,
            Err(_) => Rd::Err,
        }
    }

    /// Write the whole buffer, waiting for write-readiness on partial/AGAIN. `Err(())` on
    /// a closed/errored socket.
    pub fn write_all(fd: Fd, mut data: &[u8]) -> Result<(), ()> {
        while !data.is_empty() {
            let ciov = wasi::Ciovec { buf: data.as_ptr(), buf_len: data.len() };
            match unsafe { wasi::fd_write(fd, &[ciov]) } {
                Ok(0) => return Err(()),
                Ok(n) => data = &data[n..],
                Err(e) if e == wasi::ERRNO_AGAIN || e == wasi::ERRNO_INTR => {
                    if !poll_one(fd, false) {
                        return Err(());
                    }
                }
                Err(_) => return Err(()),
            }
        }
        Ok(())
    }

    /// Block on a single fd for read- (or write-) readiness. `false` on hangup/error.
    pub fn poll_one(fd: Fd, read: bool) -> bool {
        let sub = wasi::Subscription {
            userdata: 0,
            u: wasi::SubscriptionU {
                tag: if read {
                    wasi::EVENTTYPE_FD_READ.raw()
                } else {
                    wasi::EVENTTYPE_FD_WRITE.raw()
                },
                u: wasi::SubscriptionUU {
                    fd_read: wasi::SubscriptionFdReadwrite { file_descriptor: fd },
                },
            },
        };
        let mut ev = std::mem::MaybeUninit::<wasi::Event>::uninit();
        match unsafe { wasi::poll_oneoff(&sub, ev.as_mut_ptr(), 1) } {
            Ok(n) if n >= 1 => {
                let ev = unsafe { ev.assume_init() };
                ev.error == wasi::ERRNO_SUCCESS
            }
            _ => false,
        }
    }

    /// Readable event on this poll wakeup, tagged by the caller's userdata. `hangup` marks
    /// a peer close/error so the caller can reap the connection.
    pub struct Ready {
        pub userdata: u64,
        pub hangup: bool,
    }

    /// Wait for read-readiness across (userdata, fd) pairs. Returns the ready set.
    pub fn poll_read(fds: &[(u64, Fd)]) -> Vec<Ready> {
        let subs: Vec<wasi::Subscription> = fds
            .iter()
            .map(|(ud, fd)| wasi::Subscription {
                userdata: *ud,
                u: wasi::SubscriptionU {
                    tag: wasi::EVENTTYPE_FD_READ.raw(),
                    u: wasi::SubscriptionUU {
                        fd_read: wasi::SubscriptionFdReadwrite { file_descriptor: *fd },
                    },
                },
            })
            .collect();
        let mut out: Vec<wasi::Event> = Vec::with_capacity(subs.len());
        let n = match unsafe { wasi::poll_oneoff(subs.as_ptr(), out.as_mut_ptr(), subs.len()) } {
            Ok(n) => n,
            Err(_) => return Vec::new(),
        };
        unsafe { out.set_len(n) };
        out.into_iter()
            .map(|ev| Ready {
                userdata: ev.userdata,
                hangup: ev.error != wasi::ERRNO_SUCCESS
                    || (ev.fd_readwrite.flags & wasi::EVENTRWFLAGS_FD_READWRITE_HANGUP) != 0,
            })
            .collect()
    }

    pub fn close(fd: Fd) {
        let _ = unsafe { wasi::fd_close(fd) };
    }
}

/// Per-connection socket-side state — everything the reentry seam touches, kept OUT of
/// `Conn` so the `OutboundFn` closure can capture it (`Send + Sync`) without borrowing the
/// `Conn` that `dispatch` holds `&mut`. Identical to ../rust-wasm except `fd` replaces the
/// WasmEdge `TcpStream`.
struct ConnIo {
    fd: sock::Fd,
    /// Bytes read off the wire but not yet framed (§1.6 length-prefix reassembly).
    rbuf: Vec<u8>,
    /// Inbound EXECUTEs that arrived while a `pump_outbound` was awaiting a reply — drained
    /// by the main loop after the in-flight dispatch completes (serialization discipline).
    deferred: VecDeque<Envelope>,
    /// EXECUTE_RESPONSEs read ahead of the pump waiting for them (keyed by request_id).
    pending: HashMap<String, Envelope>,
}

impl ConnIo {
    fn new(fd: sock::Fd) -> Arc<Mutex<ConnIo>> {
        Arc::new(Mutex::new(ConnIo {
            fd,
            rbuf: Vec::new(),
            deferred: VecDeque::new(),
            pending: HashMap::new(),
        }))
    }
}

/// Write one §1.6 frame as a SINGLE contiguous buffer (`[4-byte BE len][payload]`) in one
/// `write_all`. Load-bearing on connection churn: two separate sends (length prefix, then
/// body) let Nagle hold the body until the prefix is ACKed — a ~40–200 ms delayed-ACK
/// stall on every cold round trip that dominated §6.11 t2_2 latency (the WAT + WasmEdge
/// peers both hit and fixed the identical bug). One buffer defeats it.
fn write_frame_oneshot(fd: sock::Fd, payload: &[u8]) -> Result<(), ()> {
    let mut framed = Vec::with_capacity(4 + payload.len());
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    sock::write_all(fd, &framed)
}

/// Pull one complete §1.6 frame (`[4-byte BE len][payload]`) out of `rbuf`.
/// `Some(Ok(_))` → a frame; `Some(Err(e))` → a pre-admission REFUSAL owed a coded frame
/// (§4.11); `None` → need more bytes.
///
/// THE ERROR CARRIES ITS CAUSE (0.8.2.25, RULE C/D). It used to be `Err(())` — a bare
/// "close the connection, native parity" — and both halves of that comment stopped being
/// true at .25: §4.11 makes the coded frame MANDATORY, and the native read loop it mirrors
/// now emits one. A unit type cannot say WHICH code is owed, and §4.11's whole point is
/// that *"the frame obligation belongs to the class; the CODE belongs to the cause"*.
/// Reusing the parent crate's `WireError` rather than minting a local enum is what lets
/// `wire::pre_admission_refusal` be the single table for every read loop in the cohort.
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
        let fd = g.fd;
        match sock::read(fd, &mut tmp) {
            sock::Rd::Eof => return false,
            sock::Rd::Data(n) => {
                g.rbuf.extend_from_slice(&tmp[..n]);
                if n < tmp.len() {
                    return true; // socket drained for now
                }
            }
            sock::Rd::WouldBlock => return true,
            sock::Rd::Err => return false,
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
                    // §4.11 reaches the REENTRY pump too: a frame refused while we are
                    // waiting for a correlated response is still a frame refused
                    // pre-admission, and dropping it here answers the outbound caller with
                    // a hang. The lock is released first — the helper takes it.
                    drop(g);
                    let (status, code, message) = wire::pre_admission_refusal(&e);
                    refuse_pre_admission(io, "", status, code, message);
                    return None;
                }
                None => {}
            }
        }
        // Wait for readability on just this fd (blocking poll), then drain.
        let fd = io.lock().unwrap().fd;
        if !sock::poll_one(fd, true) {
            return None;
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
/// scoped to *"every request the peer ADMITS"* and therefore reaches none of these.
///
/// THE PARENT CRATE HAS ANSWERED THIS SINCE AUGUST AND THIS SEAM DID NOT, which is the
/// whole lesson and it has now cost this peer twice: a thin transport seam that
/// reimplements the read loop does NOT inherit a read-loop fix by depending on the crate.
/// The §6.3 half was closed here on 2026-09-14; the .25 half — the CODE belonging to the
/// cause, and the two FRAMING arms that used to close with no frame at all — is this
/// change, and rebuilding against a swept parent propagated NEITHER. Measured before and
/// after on the wire (`tools/pa-probe`): 4 of 6 arms owed → 0.
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
    let fd = io.lock().unwrap().fd;
    let _ = write_frame_oneshot(fd, &resp.encode());
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
        let fd = g.fd;
        if write_frame_oneshot(fd, &req.encode()).is_err() {
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
        let g = io.lock().unwrap();
        let _ = write_frame_oneshot(g.fd, &r.encode());
    }
}

/// Service a readable connection: drain the socket, then process every complete frame plus
/// any requests deferred by a reentry pump. Returns `false` if the connection should close.
fn service_readable(peer: &Arc<Peer>, io: &Arc<Mutex<ConnIo>>, conn: &mut Conn) -> bool {
    if !fill_rbuf(io) {
        // A CLEAN CLOSE AT A FRAME BOUNDARY AND A STREAM THAT ENDED MID-FRAME ARE
        // DIFFERENT EVENTS, AND ONLY THE FRAME BOUNDARY KNOWS WHICH (§4.11, N14). The
        // first is an ordinary hangup, owed nothing. The second is a TRUNCATED frame,
        // which §4.11's framing arm names explicitly ("a length prefix that never
        // completes") and answers `400 invalid_request`. `fill_rbuf` collapses them into
        // one `false`, so the discriminator is made HERE: bytes still buffered mean a
        // frame was begun and never finished.
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
                    // §4.11 names as one of its two separately-non-conformant behaviours.
                    // The body was never drained so the framing is lost and closing is
                    // still the only sound choice; §4.11 makes it a choice IN ADDITION to
                    // answering rather than INSTEAD of it.
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
                            // THE CODE IS THE CAUSE'S (§4.11, §5.2a) — this answered
                            // `non_canonical_ecf` for every cause until 0.8.2.24/.25.
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

    // The listener is HOST-preopened (wasmtime `-S tcplisten`); the guest never binds.
    let listener = sock::find_listener();
    sock::set_nonblock(listener).expect("set listener nonblocking");

    // The run-s4 harness waits for a line starting with LISTENING.
    println!("LISTENING 127.0.0.1:{port} open_grants={open_grants} validate={conformance} (preopened fd {listener})");
    use std::io::Write as _;
    let _ = std::io::stdout().flush();

    // (userdata, socket-state, protocol-state). userdata 0 is reserved for the listener.
    let mut conns: Vec<(u64, Arc<Mutex<ConnIo>>, Conn)> = Vec::new();
    let mut next_id: u64 = 1;

    loop {
        let mut fds: Vec<(u64, sock::Fd)> = Vec::with_capacity(conns.len() + 1);
        fds.push((0, listener));
        for (id, io, _) in &conns {
            fds.push((*id, io.lock().unwrap().fd));
        }

        let ready = sock::poll_read(&fds);

        let mut to_close: Vec<u64> = Vec::new();
        for ev in ready {
            if ev.userdata == 0 {
                // Accept every pending connection (drain until AGAIN).
                while let Some(fd) = sock::accept(listener) {
                    conns.push((next_id, ConnIo::new(fd), Conn::new()));
                    next_id += 1;
                }
            } else if let Some(pos) = conns.iter().position(|(id, _, _)| *id == ev.userdata) {
                if ev.hangup {
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
            for (id, io, _) in &conns {
                if to_close.contains(id) {
                    sock::close(io.lock().unwrap().fd);
                }
            }
            conns.retain(|(id, _, _)| !to_close.contains(id));
        }
    }
}
