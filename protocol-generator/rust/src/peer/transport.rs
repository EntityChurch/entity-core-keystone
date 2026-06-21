//! Transport (L4) — TCP listener + dialer + per-connection serve loop on
//! `std::thread` (the profile's `[concurrency].style = threaded`; no tokio).
//!
//! Concurrency model (§6.11 / N6 / N7):
//!   - One READER thread per connection demuxes inbound frames (§6.11). An
//!     EXECUTE_RESPONSE is routed to the awaiting outbound caller by request_id; an
//!     inbound EXECUTE is dispatched on its OWN thread (§4.8) so a handler that
//!     originates an outbound EXECUTE (§6.13(b)) and awaits its reply does NOT
//!     block the reader — the reader keeps reading and routes the reply back.
//!   - Writes (responses + outbound requests share the stream) are serialized by a
//!     `Mutex` over the write half.
//!   - A pending-request table (request_id → slot + condvar) is the §6.11 demux.
//!     Connection close broadcasts all waiters so a never-arriving reply unblocks.
//!
//! §7b: `set_nodelay(true)` on every accepted/dialed connection (Nagle + delayed-ACK
//! on small handshake frames was the cohort throughput killer). Thread-per-conn means
//! there is no bounded cooperative pool to starve (the Swift trap does not apply), and
//! the store lock is never held across I/O (§4.8 discipline, enforced in [`super::store`]).

use std::collections::HashMap;
use std::io::Write;
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::value::Value;

use super::core::{Conn, OutboundFn, Peer};
use super::identity::Identity;
use super::model::{self, Entity, Envelope};
use super::wire::{self, WireError};

/// A pending-outbound slot: filled by the reader when the correlated reply arrives.
struct PendingSlot {
    response: Mutex<Option<Envelope>>,
    cond: Condvar,
    done: Mutex<bool>,
}

impl PendingSlot {
    fn new() -> PendingSlot {
        PendingSlot {
            response: Mutex::new(None),
            cond: Condvar::new(),
            done: Mutex::new(false),
        }
    }
}

/// Per-connection IO state: the shared stream (write half mutex-guarded), and the
/// §6.11 pending-response demux table.
pub struct Io {
    /// Write half — a cloned TcpStream handle, serialized by `write_lock`.
    write_stream: Mutex<TcpStream>,
    pending: Mutex<HashMap<String, Arc<PendingSlot>>>,
    closed: Mutex<bool>,
}

impl Io {
    pub fn new(stream: TcpStream) -> std::io::Result<Arc<Io>> {
        let write_stream = stream.try_clone()?;
        Ok(Arc::new(Io {
            write_stream: Mutex::new(write_stream),
            pending: Mutex::new(HashMap::new()),
            closed: Mutex::new(false),
        }))
    }

    /// Serialized framed write (responses + outbound requests share the stream).
    pub fn write_framed(&self, env: &Envelope) -> Result<(), WireError> {
        let payload = env.encode();
        let mut s = self.write_stream.lock().unwrap();
        wire::write_frame(&mut *s, &payload)
    }

    /// Route an inbound EXECUTE_RESPONSE to its awaiting outbound caller (§6.11).
    fn route_response(&self, env: Envelope) {
        let request_id = env.root.text_field("request_id").unwrap_or("").to_string();
        let slot = {
            let pending = self.pending.lock().unwrap();
            pending.get(&request_id).cloned()
        };
        if let Some(slot) = slot {
            *slot.response.lock().unwrap() = Some(env);
            *slot.done.lock().unwrap() = true;
            slot.cond.notify_all();
        }
        // unmatched response → dropped (deliver-or-signal, never crash; §4.9).
    }

    /// §6.13(b) outbound: send a request envelope, await its correlated reply.
    pub fn outbound(&self, request: Envelope) -> Option<Envelope> {
        let request_id = request
            .root
            .text_field("request_id")
            .unwrap_or("")
            .to_string();
        let slot = Arc::new(PendingSlot::new());
        {
            let mut pending = self.pending.lock().unwrap();
            if *self.closed.lock().unwrap() {
                return None;
            }
            pending.insert(request_id.clone(), slot.clone());
        }
        if self.write_framed(&request).is_err() {
            self.pending.lock().unwrap().remove(&request_id);
            return None;
        }
        // wait until the reader fills the slot or the connection closes.
        let mut done = slot.done.lock().unwrap();
        while !*done && !*self.closed.lock().unwrap() {
            let (g, timeout) = slot
                .cond
                .wait_timeout(done, std::time::Duration::from_millis(200))
                .unwrap();
            done = g;
            if timeout.timed_out() && *self.closed.lock().unwrap() {
                break;
            }
        }
        drop(done);
        self.pending.lock().unwrap().remove(&request_id);
        let mut guard = slot.response.lock().unwrap();
        guard.take()
    }

    /// Wake every pending outbound waiter on connection close.
    pub fn close(&self) {
        *self.closed.lock().unwrap() = true;
        let pending = self.pending.lock().unwrap();
        for slot in pending.values() {
            slot.cond.notify_all();
        }
    }
}

/// Disable Nagle on a connection (§7b). Best-effort.
pub fn set_no_delay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}

/// Bind a loopback TCP listener on `port` (0 = auto-assign).
pub fn listen(port: u16) -> std::io::Result<TcpListener> {
    let listener = TcpListener::bind(("127.0.0.1", port))?;
    Ok(listener)
}

// ── reader loop (§6.11 demux) ────────────────────────────────────────────────

/// The reader loop: EXECUTE_RESPONSE → route; EXECUTE → dispatch on its own
/// thread. Runs until the connection closes / a frame ends it. `read_stream` is a
/// dedicated read-half clone so reads never contend with the write mutex.
pub fn read_loop(peer: Arc<Peer>, conn: Arc<Mutex<Conn>>, io: Arc<Io>, mut read_stream: TcpStream) {
    // Closed / PayloadTooLarge / Io ends the loop.
    while let Ok(payload) = wire::read_frame(&mut read_stream) {
        let env = match model::envelope_of_frame(&payload) {
            Ok(e) => e,
            Err(_) => continue, // malformed → drop, keep reading
        };
        if env.root.typ == "system/protocol/execute/response" {
            io.route_response(env);
        } else {
            // dispatch on its own thread (§4.8); the reader keeps reading + routing
            // §6.11 reentry responses meanwhile.
            let peer = peer.clone();
            let conn = conn.clone();
            let io = io.clone();
            thread::spawn(move || {
                dispatch_one(peer, conn, io, env);
            });
        }
    }
    io.close();
}

fn dispatch_one(peer: Arc<Peer>, conn: Arc<Mutex<Conn>>, io: Arc<Io>, env: Envelope) {
    // Bind the §6.11 reentry seam so a §7a dispatch-outbound handler can originate.
    let io_for_seam = io.clone();
    let outbound: Arc<OutboundFn> = Arc::new(move |req: Envelope| io_for_seam.outbound(req));

    let resp = {
        let mut c = conn.lock().unwrap();
        c.outbound = Some(outbound);
        let r = peer.dispatch(&mut c, &env);
        c.outbound = None; // detach the seam after dispatch
        r
    };
    if let Some(r) = resp {
        let _ = io.write_framed(&r);
    }
}

/// Serve one accepted connection to completion on the calling thread (the
/// responder side spawns this per accept).
pub fn serve_connection(peer: Arc<Peer>, stream: TcpStream) {
    set_no_delay(&stream);
    let read_stream = match stream.try_clone() {
        Ok(s) => s,
        Err(_) => return,
    };
    let io = match Io::new(stream) {
        Ok(io) => io,
        Err(_) => return,
    };
    let conn = Arc::new(Mutex::new(Conn::new()));
    read_loop(peer, conn, io, read_stream);
}

// ── initiator handshake (§4.1) + authenticated session ─────────────────────────

/// An authenticated session over an established connection (§4.4 / §5.8). Owns the
/// capability chain entities it re-presents on every request.
pub struct Session {
    io: Arc<Io>,
    local: Arc<Peer>,
    pub remote_peer_id: String,
    capability: Entity,
    granter_peer: Entity,
    cap_signature: Entity,
    req_counter: u32,
}

impl Session {
    /// Build, sign, and send an authenticated EXECUTE; await the correlated reply
    /// (§5.8 chain inclusion). Returns the response envelope.
    pub fn execute(
        &mut self,
        uri: &str,
        operation: &str,
        params: Entity,
        resource: Option<Value>,
    ) -> Option<Envelope> {
        self.req_counter += 1;
        let rid = format!("req-{}", self.req_counter);
        let exec = wire::make_execute(wire::ExecuteFields {
            request_id: &rid,
            uri,
            operation,
            params,
            resource,
            author: Some(&self.local.identity.identity_hash),
            capability: Some(&self.capability.hash),
        });
        let exec_sig = self.local.identity.sign_entity(&exec);
        let env = Envelope::with_included(
            exec,
            vec![
                self.capability.clone(),
                self.granter_peer.clone(),
                self.local.identity.peer_entity.clone(),
                self.cap_signature.clone(),
                exec_sig,
            ],
        );
        self.io.outbound(env)
    }
}

/// Initiator handshake (§4.1): hello → authenticate, returning a [`Session`].
pub fn initiate(local: Arc<Peer>, io: Arc<Io>, conn: Arc<Mutex<Conn>>) -> Option<Session> {
    // 1. hello
    let r1 = send_connect(&io, &conn, "hello", wire::empty_params(), vec![])?;
    if r1.root.uint_field("status") != Some(200) {
        return None;
    }
    let remote_hello = r1.root.entity_field("result")?;
    let remote_peer_id = remote_hello.text_field("peer_id")?.to_string();
    let remote_nonce = remote_hello.bytes_field("nonce")?.to_vec();

    // 2. authenticate
    authenticate(local, io, conn, &remote_nonce, &remote_peer_id)
}

fn authenticate(
    local: Arc<Peer>,
    io: Arc<Io>,
    conn: Arc<Mutex<Conn>>,
    remote_nonce: &[u8],
    remote_peer_id: &str,
) -> Option<Session> {
    let id: &Identity = &local.identity;
    let auth = Entity::make(
        "system/protocol/connect/authenticate",
        model::map(vec![
            ("peer_id", model::text(&id.peer_id)),
            ("public_key", model::bytes(&id.public_key)),
            ("key_type", model::text("ed25519")),
            ("nonce", model::bytes(remote_nonce)),
        ]),
    );
    let auth_sig = id.sign_entity(&auth);
    let included = vec![id.peer_entity.clone(), auth_sig];
    let response = send_connect(&io, &conn, "authenticate", auth, included)?;
    if response.root.uint_field("status") != Some(200) {
        return None;
    }
    let grant = response.root.entity_field("result")?;
    let token_hash = grant.bytes_field("token")?.to_vec();
    let token = response.included_get(&token_hash)?.clone();
    let granter_h = token.bytes_field("granter")?.to_vec();
    let granter_peer = response.included_get(&granter_h)?.clone();
    let cap_sig = find_signature(&response, &token.hash)?;

    Some(Session {
        io,
        local: local.clone(),
        remote_peer_id: remote_peer_id.to_string(),
        capability: token,
        granter_peer,
        cap_signature: cap_sig,
        req_counter: 0,
    })
}

/// A connect-path EXECUTE carries no author/capability (§4.2 pre-authorization).
fn send_connect(
    io: &Arc<Io>,
    conn: &Arc<Mutex<Conn>>,
    operation: &str,
    params: Entity,
    included: Vec<Entity>,
) -> Option<Envelope> {
    let rid = {
        let mut c = conn.lock().unwrap();
        c.out_counter += 1;
        format!("h-{}", c.out_counter)
    };
    let exec = wire::make_execute(wire::ExecuteFields {
        request_id: &rid,
        uri: "system/protocol/connect",
        operation,
        params,
        resource: None,
        author: None,
        capability: None,
    });
    let env = Envelope::with_included(exec, included);
    io.outbound(env)
}

fn find_signature(env: &Envelope, target: &[u8]) -> Option<Entity> {
    env.included.values().find_map(|e| {
        if e.typ == "system/signature" && e.bytes_field("target") == Some(target) {
            Some(e.clone())
        } else {
            None
        }
    })
}

/// Helper: flush + shutdown a stream so a parked reader returns (teardown).
pub fn shutdown(stream: &TcpStream) {
    let _ = (&mut &*stream).flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}
