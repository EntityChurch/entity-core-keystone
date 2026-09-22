//! host.rs — the byte-pump (L4): TCP listener + dialer, §1.6 framing with the
//! §4.10 resource bounds, the §6.11 reentrant `request_id` demux, and the §4.1
//! initiator handshake. Datalog never touches a socket (profile `[host] owns`).
//!
//! Concurrency (§6.11 / N6 / N7): one READER thread per connection demuxes inbound
//! frames — an EXECUTE_RESPONSE routes to the awaiting outbound caller by
//! request_id; an inbound EXECUTE dispatches on its OWN thread (§4.8) so a handler
//! that originates outbound (§6.13(b)) does not block the reader. Writes are
//! serialized by a mutex over the write half. §4.8 store-race safety is structural
//! (the `RwLock` store; the profile's chosen §7b idiom). `set_nodelay(true)` on
//! every stream (§7b). §4.9 resilience: the per-request dispatch is wrapped so a
//! host ROOT error (a panic at the boundary) becomes a 500, never a dropped
//! connection (the cohort rule — Oz A-OZ-005, Smalltalk A-ST-016).

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Condvar, Mutex};
use std::thread;

use crate::cbor_host::{self, Key, Value};
use crate::dispatch::{Conn, OutboundFn, Peer};
use crate::identity::Identity;
use crate::model::{self, Entity, Envelope};

/// §1.6 SHOULD bound / §4.10(a) recommended default — 16 MiB max inbound payload.
pub const MAX_FRAME: usize = 16 * 1024 * 1024;

#[derive(Debug)]
pub enum WireError {
    Closed,
    /// Length prefix exceeded [`MAX_FRAME`] → `413 payload_too_large`.
    PayloadTooLarge,
    Io(std::io::Error),
}
impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8]) -> Result<(), WireError> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) => return Err(WireError::Closed),
            Ok(n) => off += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(WireError::Io(e)),
        }
    }
    Ok(())
}

/// Read one length-prefixed frame. §4.10(a): the bound is checked on the length
/// prefix BEFORE the body is buffered (reject over-limit without reading it).
pub fn read_frame(stream: &mut impl Read) -> Result<Vec<u8>, WireError> {
    let mut hdr = [0u8; 4];
    read_exact(stream, &mut hdr)?;
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_FRAME {
        return Err(WireError::PayloadTooLarge);
    }
    let mut payload = vec![0u8; len];
    read_exact(stream, &mut payload)?;
    Ok(payload)
}

pub fn write_frame(stream: &mut impl Write, payload: &[u8]) -> Result<(), WireError> {
    stream.write_all(&(payload.len() as u32).to_be_bytes())?;
    stream.write_all(payload)?;
    stream.flush()?;
    Ok(())
}

// ── EXECUTE / EXECUTE_RESPONSE builders (§3.2 / §3.3) ──────────────────────────

pub struct ExecuteFields<'a> {
    pub request_id: &'a str,
    pub uri: &'a str,
    pub operation: &'a str,
    pub params: Entity,
    pub resource: Option<Value>,
    pub author: Option<&'a [u8]>,
    pub capability: Option<&'a [u8]>,
}

pub fn make_execute(f: ExecuteFields) -> Entity {
    let mut pairs: Vec<(Key, Value)> = vec![
        (
            Key::Text("request_id".into()),
            cbor_host::text(f.request_id),
        ),
        (Key::Text("uri".into()), cbor_host::text(f.uri)),
        (Key::Text("operation".into()), cbor_host::text(f.operation)),
        (Key::Text("params".into()), f.params.to_cbor()),
    ];
    if let Some(a) = f.author {
        pairs.push((Key::Text("author".into()), cbor_host::bytes(a)));
    }
    if let Some(c) = f.capability {
        pairs.push((Key::Text("capability".into()), cbor_host::bytes(c)));
    }
    if let Some(r) = f.resource {
        pairs.push((Key::Text("resource".into()), r));
    }
    Entity::make("system/protocol/execute", Value::Map(pairs))
}

pub fn empty_params() -> Entity {
    Entity::make("primitive/any", Value::Map(vec![]))
}

// ── per-connection IO (§6.11 demux) ────────────────────────────────────────────

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

pub struct Io {
    write_stream: Mutex<TcpStream>,
    pending: Mutex<HashMap<String, Arc<PendingSlot>>>,
    closed: Mutex<bool>,
}

impl Io {
    pub fn new(stream: TcpStream) -> std::io::Result<Arc<Io>> {
        Ok(Arc::new(Io {
            write_stream: Mutex::new(stream.try_clone()?),
            pending: Mutex::new(HashMap::new()),
            closed: Mutex::new(false),
        }))
    }
    pub fn write_framed(&self, env: &Envelope) -> Result<(), WireError> {
        let payload = env.encode();
        let mut s = self.write_stream.lock().unwrap();
        write_frame(&mut *s, &payload)
    }
    fn route_response(&self, env: Envelope) {
        let rid = env.root.text_field("request_id").unwrap_or("").to_string();
        let slot = self.pending.lock().unwrap().get(&rid).cloned();
        if let Some(slot) = slot {
            *slot.response.lock().unwrap() = Some(env);
            *slot.done.lock().unwrap() = true;
            slot.cond.notify_all();
        }
        // unmatched response → dropped (deliver-or-signal, never crash; §4.9).
    }
    /// §6.13(b) outbound: send a request, await its correlated reply.
    pub fn outbound(&self, request: Envelope) -> Option<Envelope> {
        let rid = request
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
            pending.insert(rid.clone(), slot.clone());
        }
        if self.write_framed(&request).is_err() {
            self.pending.lock().unwrap().remove(&rid);
            return None;
        }
        let mut done = slot.done.lock().unwrap();
        while !*done && !*self.closed.lock().unwrap() {
            let (g, t) = slot
                .cond
                .wait_timeout(done, std::time::Duration::from_millis(200))
                .unwrap();
            done = g;
            if t.timed_out() && *self.closed.lock().unwrap() {
                break;
            }
        }
        drop(done);
        self.pending.lock().unwrap().remove(&rid);
        let taken = slot.response.lock().unwrap().take();
        taken
    }
    pub fn close(&self) {
        *self.closed.lock().unwrap() = true;
        for slot in self.pending.lock().unwrap().values() {
            slot.cond.notify_all();
        }
    }
}

pub fn set_no_delay(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
}
pub fn listen(port: u16) -> std::io::Result<TcpListener> {
    TcpListener::bind(("127.0.0.1", port))
}

// ── reader loop (§6.11 demux) ──────────────────────────────────────────────────

pub fn read_loop(peer: Arc<Peer>, conn: Arc<Mutex<Conn>>, io: Arc<Io>, mut read_stream: TcpStream) {
    while let Ok(payload) = read_frame(&mut read_stream) {
        let env = match model::envelope_of_frame(&payload) {
            Ok(e) => e,
            Err(_) => {
                // §6.3: "Rejection returns `400 non_canonical_ecf`" — the frame is refused
                // (correct) and that refusal MUST be a STATUS, not silence. Dropping it
                // satisfies only the first half of the sentence and leaves the sender
                // blocked until its own timeout, so a refusal is indistinguishable from a
                // dead peer; §4.9(c) deliver-or-signal says the same from the other
                // direction. Answer, then keep reading.
                reject_non_canonical(&io, &payload);
                continue;
            }
        };
        if env.root.typ == "system/protocol/execute/response" {
            io.route_response(env);
        } else {
            let peer = peer.clone();
            let conn = conn.clone();
            let io = io.clone();
            thread::spawn(move || dispatch_one(peer, conn, io, env));
        }
    }
    io.close();
}

fn dispatch_one(peer: Arc<Peer>, conn: Arc<Mutex<Conn>>, io: Arc<Io>, env: Envelope) {
    let io_seam = io.clone();
    let outbound: Arc<OutboundFn> = Arc::new(move |req: Envelope| io_seam.outbound(req));
    let request_id = env.root.text_field("request_id").unwrap_or("").to_string();

    // §4.9(c) resilience: catch the host ROOT error class (a panic at the request
    // boundary) → 500, never a dropped connection (cohort rule).
    let resp = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let mut c = conn.lock().unwrap();
        c.outbound = Some(outbound);
        let r = peer.dispatch(&mut c, &env);
        c.outbound = None;
        r
    }));
    match resp {
        Ok(Some(r)) => {
            let _ = io.write_framed(&r);
        }
        Ok(None) => {} // non-EXECUTE root → ignored (§3.3)
        Err(_) => {
            // deliver-or-signal: a 500 rather than a silent hang.
            let err = Entity::make(
                "system/protocol/error",
                cbor_host::map(vec![("code", cbor_host::text("internal_error"))]),
            );
            let resp = Envelope::new(response_entity(&request_id, 500, &err));
            let _ = io.write_framed(&resp);
        }
    }
}

/// Answer a frame the strict decoder rejected with `400 non_canonical_ecf` (§6.3),
/// recovering ONLY the `request_id` so the sender can correlate the refusal.
///
/// The frame stays rejected: nothing is built from it, nothing is stored, and the tag is
/// never interpreted — the salvage decode exists solely to read back the correlation key.
/// The envelope and entity-wrapper shapes are fixed maps with no legal tag position, so a
/// frame whose ONLY defect is a tag inside some entity's `data` still has a structurally
/// sound root, which is exactly the case worth recovering. If even the request_id is
/// unrecoverable there is nobody to answer, so the frame is dropped: the one case where
/// silence is all that is available.
fn reject_non_canonical(io: &Arc<Io>, payload: &[u8]) {
    let Ok(v) = cbor_host::decode_salvage(payload) else {
        return;
    };
    let request_id = match cbor_host::map_get(&v, "root")
        .and_then(|root| cbor_host::map_get(root, "data"))
        .and_then(|data| cbor_host::map_get(data, "request_id"))
    {
        Some(Value::Text(s)) => s.clone(),
        _ => return, // no correlatable request_id — nothing to answer
    };
    let err = Entity::make(
        "system/protocol/error",
        cbor_host::map(vec![
            ("code", cbor_host::text("non_canonical_ecf")),
            (
                "message",
                cbor_host::text(
                    "frame is not canonical ECF (section 6.3): CBOR tags are forbidden anywhere in an entity",
                ),
            ),
        ]),
    );
    let resp = Envelope::new(response_entity(&request_id, 400, &err));
    let _ = io.write_framed(&resp);
}

fn response_entity(request_id: &str, status: u64, result: &Entity) -> Entity {
    Entity::make(
        "system/protocol/execute/response",
        Value::Map(vec![
            (Key::Text("request_id".into()), cbor_host::text(request_id)),
            (Key::Text("status".into()), Value::UInt(status)),
            (Key::Text("result".into()), result.to_cbor()),
        ]),
    )
}

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
    /// The shared connection IO (for concurrent, out-of-order demux exercises — N7).
    pub fn io(&self) -> Arc<Io> {
        self.io.clone()
    }

    /// Build + sign an authenticated EXECUTE envelope WITHOUT sending it (§5.8 chain
    /// re-inclusion). Callers send it via [`Io::outbound`] — used by the demux test
    /// to issue many requests concurrently on one connection.
    pub fn build_execute(
        &self,
        rid: &str,
        uri: &str,
        operation: &str,
        params: Entity,
        resource: Option<Value>,
    ) -> Envelope {
        let exec = make_execute(ExecuteFields {
            request_id: rid,
            uri,
            operation,
            params,
            resource,
            author: Some(&self.local.identity.identity_hash),
            capability: Some(&self.capability.hash),
        });
        let exec_sig = self.local.identity.sign_entity(&exec);
        Envelope::with_included(
            exec,
            vec![
                self.capability.clone(),
                self.granter_peer.clone(),
                self.local.identity.peer_entity.clone(),
                self.cap_signature.clone(),
                exec_sig,
            ],
        )
    }

    /// Build, sign, and send an authenticated EXECUTE; await the correlated reply.
    pub fn execute(
        &mut self,
        uri: &str,
        operation: &str,
        params: Entity,
        resource: Option<Value>,
    ) -> Option<Envelope> {
        self.req_counter += 1;
        let rid = format!("req-{}", self.req_counter);
        let env = self.build_execute(&rid, uri, operation, params, resource);
        self.io.outbound(env)
    }
}

pub fn initiate(local: Arc<Peer>, io: Arc<Io>, conn: Arc<Mutex<Conn>>) -> Option<Session> {
    // §4.5 makes `protocols` Required with NO default, so a hello that omits it is a
    // MALFORMED hello and a conforming responder answers 400 invalid_request. This
    // dialer sent `empty_params()` and it worked only because no peer enforced the
    // rule — the moment the responder side landed, the peer could not complete a
    // handshake with itself. THE ORACLE CANNOT SEE THIS: it is always the client, and
    // its origination check reuses the INBOUND connection rather than making us dial;
    // the only thing that catches it is this peer's own two-peer loopback test.
    let hello_params = Entity::make(
        "primitive/any",
        cbor_host::map(vec![
            ("peer_id", cbor_host::text(&local.local_peer)),
            ("protocols", cbor_host::text_array(&["entity-core/1.0"])),
            ("hash_formats", cbor_host::text_array(&["ecfv1-sha256"])),
            ("key_types", cbor_host::text_array(&["ed25519"])),
        ]),
    );
    let r1 = send_connect(&io, &conn, "hello", hello_params, vec![])?;
    if r1.root.uint_field("status") != Some(200) {
        return None;
    }
    let remote_hello = r1.root.entity_field("result")?;
    let remote_peer_id = remote_hello.text_field("peer_id")?.to_string();
    let remote_nonce = remote_hello.bytes_field("nonce")?.to_vec();
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
        cbor_host::map(vec![
            ("peer_id", cbor_host::text(&id.peer_id)),
            ("public_key", cbor_host::bytes(&id.public_key)),
            ("key_type", cbor_host::text("ed25519")),
            ("nonce", cbor_host::bytes(remote_nonce)),
        ]),
    );
    let auth_sig = id.sign_entity(&auth);
    let response = send_connect(
        &io,
        &conn,
        "authenticate",
        auth,
        vec![id.peer_entity.clone(), auth_sig],
    )?;
    if response.root.uint_field("status") != Some(200) {
        return None;
    }
    let grant = response.root.entity_field("result")?;
    let token_hash = grant.bytes_field("token")?.to_vec();
    let token = response.included_get(&token_hash)?.clone();
    let granter_h = token.bytes_field("granter")?.to_vec();
    let granter_peer = response.included_get(&granter_h)?.clone();
    let cap_sig = response.included.values().find_map(|e| {
        if e.typ == "system/signature" && e.bytes_field("target") == Some(token.hash.as_slice()) {
            Some(e.clone())
        } else {
            None
        }
    })?;
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
    let exec = make_execute(ExecuteFields {
        request_id: &rid,
        uri: "system/protocol/connect",
        operation,
        params,
        resource: None,
        author: None,
        capability: None,
    });
    io.outbound(Envelope::with_included(exec, included))
}

pub fn shutdown(stream: &TcpStream) {
    let _ = (&mut &*stream).flush();
    let _ = stream.shutdown(std::net::Shutdown::Both);
}
