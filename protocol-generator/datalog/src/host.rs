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
    /// A frame that never completed: a PARTIAL length prefix, or a prefix declaring N
    /// bytes followed by fewer. §4.11's framing arm names this input explicitly — "un-
    /// parseable, truncated or non-canonical CBOR, or a length prefix that never
    /// completes" — and answers `400 invalid_request`.
    ///
    /// IT IS A SEPARATE VALUE FROM [`WireError::Closed`] BECAUSE THE TWO ARE DIFFERENT
    /// EVENTS AND A NAIVE read-exact COLLAPSES THEM. A clean EOF at a frame boundary is
    /// an ordinary close and is owed nothing; a stream that ends MID-FRAME is a REFUSAL
    /// and is owed a coded frame. The distinction can only be made here, where the frame
    /// boundary is known.
    Truncated,
    Io(std::io::Error),
}
impl From<std::io::Error> for WireError {
    fn from(e: std::io::Error) -> Self {
        WireError::Io(e)
    }
}

/// Fill `buf`. A zero-byte read at offset 0 is an ordinary close; at any later offset it
/// is a TRUNCATION (§4.11).
fn read_exact(stream: &mut impl Read, buf: &mut [u8]) -> Result<(), WireError> {
    let mut off = 0;
    while off < buf.len() {
        match stream.read(&mut buf[off..]) {
            Ok(0) if off == 0 => return Err(WireError::Closed),
            Ok(0) => return Err(WireError::Truncated),
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
    // A body that starts at offset 0 and never arrives is still a TRUNCATION, not a
    // close: the prefix already committed the sender to `len` bytes. read_exact cannot
    // know that, so the mapping is made here, at the site that read the prefix.
    match read_exact(stream, &mut payload) {
        Ok(()) => Ok(payload),
        Err(WireError::Closed) => Err(WireError::Truncated),
        Err(e) => Err(e),
    }
}

/// The (status, code) §4.11 (0.8.2.25) assigns a pre-admission refusal's CAUSE.
///
/// "A peer that refuses a frame pre-admission MUST put a coded EXECUTE_RESPONSE on the
/// wire [MUST]" — and "the frame obligation belongs to the CLASS; the CODE belongs to the
/// CAUSE [MUST]". A single code for the whole class answers an honest caller under the
/// wrong reason and sends them to the wrong layer.
///
///   envelope over the configured max     413 payload_too_large   (§4.10(a), N14)
///   resolution integrity (mis-keyed)     400 hash_mismatch       (§5.2a, §1.8)
///   framing / never becomes an Envelope  400 invalid_request     (§4.7, §4.11)
///   root is neither EXECUTE nor
///     EXECUTE_RESPONSE                   400 invalid_request     (§3.3, §4.11 — raised
///                                                                 in dispatch, not here)
///
/// THE CBOR TAG-POLICY ARM KEEPS `non_canonical_ecf` AND THAT IS DELIBERATE. §4.11 rules
/// that code non-conformant "on the framing arm" and gives its reason in the same
/// sentence: ENTITY-CBOR-ENCODING §5.4 "defines that code for CBOR tag-policy violations
/// specifically", which that document still MUSTs at decode time. The two texts are only
/// compatible if the tag case is not read as part of the framing arm, even though
/// §4.11's row says "non-canonical CBOR" and a tagged frame is literally that. Taken as
/// the reading that keeps BOTH MUSTs satisfiable and preserves the behaviour the
/// `tag_reject` vectors were written against.
fn refusal_of_model_error(e: &model::ModelError) -> (u64, &'static str) {
    match e {
        // §5.2a (0.8.2.24 N4/N5, 0.8.2.25 N16): "A peer that refuses at the decode
        // boundary MUST answer `400 hash_mismatch` [MUST] … `400 non_canonical_ecf` is
        // NOT conformant here [MUST]." A mis-keyed `included` entry carries no tag and
        // its encoding IS canonical — what is false is the claim the KEY makes. This
        // answered `non_canonical_ecf` for every cause until 0.8.2.24/.25 pinned them
        // apart; the code selects the caller's remedy, so a code that is merely in the
        // right family is still wrong.
        model::ModelError::IncludedKeyMismatch | model::ModelError::ContentHashMismatch => {
            (400, "hash_mismatch")
        }
        model::ModelError::Codec(cbor_host::DecodeError::TagRejected) => (400, "non_canonical_ecf"),
        _ => (400, "invalid_request"),
    }
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
    loop {
        let payload = match read_frame(&mut read_stream) {
            Ok(p) => p,
            Err(e) => {
                // §4.11: the two REFUSABLE framing arms are owed a coded frame; an
                // ordinary close is not a refusal of anything and there is nobody left to
                // answer. The stream is desynchronized on both refusable arms — an
                // oversize body was never drained, a truncated one never arrived — so the
                // frame goes out and THEN the loop ends. §4.11 makes the frame mandatory
                // and leaves the close to us; closing is the only sound choice once the
                // framing is lost, and it is a choice rather than an alternative to
                // answering. Closing with NO coded frame is one of the two behaviours
                // §4.11 names non-conformant, and this loop used to do exactly that.
                match e {
                    WireError::PayloadTooLarge => {
                        refuse_pre_admission(&io, "", 413, "payload_too_large")
                    }
                    WireError::Truncated => refuse_pre_admission(&io, "", 400, "invalid_request"),
                    WireError::Closed | WireError::Io(_) => {}
                }
                break;
            }
        };
        let env = match model::envelope_of_frame(&payload) {
            Ok(e) => e,
            Err(err) => {
                // A COMPLETE frame the decoder refused. The framing is intact, so we
                // answer and KEEP SERVING. Dropping it satisfies only the first half of
                // §6.3's "Rejection returns `400 …`" sentence and leaves the sender
                // blocked until its own §6.11(c) deadline, making a refusal
                // indistinguishable from a dead peer; §4.9(c)'s deliver-or-signal says
                // the same from the other direction, and §4.11 makes it explicit for the
                // pre-admission class. THE CODE IS THE CAUSE'S.
                let (status, code) = refusal_of_model_error(&err);
                // An unrecoverable request_id yields the UNCORRELATED best-effort frame
                // §4.11 prescribes, never silence: "correlated by request_id where
                // available, otherwise a best-effort coded frame carrying no
                // correlation." Returning here was the OTHER non-conformant behaviour —
                // "the weaker of the two precisely because nothing surfaces it."
                let rid = salvage_request_id(&payload).unwrap_or_default();
                refuse_pre_admission(&io, &rid, status, code);
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
        Ok(None) => {
            // ROOT IS NEITHER EXECUTE NOR EXECUTE_RESPONSE. This used to be IGNORED —
            // §4.11's silent-drop arm, "the weaker of the two precisely because nothing
            // surfaces it". 0.8.2.25 (N12/N17) WITHDREW the old §3.3 rule "the connection
            // MUST be closed" here and §6.5's dispatch-chain pseudocode changed
            // `Other type? -> Invalid. Close connection.` to a coded refusal; §9.1's
            // floor row that mandated the close was REPLACED (N18). Answer 400
            // invalid_request and keep the connection: closing would cost every ADMITTED
            // in-flight request its response, and §4.11 leaves the close to us.
            //
            // `request_id` is read from the root's data where it exists and is empty
            // otherwise — §4.11's best-effort uncorrelated form.
            refuse_pre_admission(&io, &request_id, 400, "invalid_request");
        }
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

/// Recover ONLY the `request_id` from a frame the strict decoder rejected, so the
/// rejection can be delivered as a CORRELATED response rather than as the uncorrelated
/// best-effort frame §4.11 falls back to.
///
/// The frame stays rejected: nothing else is read out of it, no entity is built, nothing
/// is stored, and an offending tag is never interpreted. The envelope and entity-wrapper
/// shapes are fixed maps with no legal tag position (§6.3), so a frame whose ONLY defect
/// is a tag inside some entity's `data` still has a structurally sound root — which is
/// exactly the case this recovers.
pub fn salvage_request_id(payload: &[u8]) -> Option<String> {
    let v = cbor_host::decode_salvage(payload).ok()?;
    match cbor_host::map_get(&v, "root")
        .and_then(|root| cbor_host::map_get(root, "data"))
        .and_then(|data| cbor_host::map_get(data, "request_id"))
    {
        Some(Value::Text(s)) => Some(s.clone()),
        _ => None,
    }
}

/// Put the coded EXECUTE_RESPONSE §4.11 (0.8.2.25) requires on the wire for a frame
/// refused BEFORE it becomes an admitted request.
///
/// §4.9(c)'s deliver-or-signal rule is scoped to "every request the peer ADMITS" and
/// therefore reaches NONE of these, which is why §4.11 exists. The two non-conformant
/// behaviours it names are SEPARATE failures and this peer had one of each: DROPPING the
/// frame (every decode refusal whose request_id could not be salvaged, plus every framing
/// fault), and CLOSING with no coded frame (the oversize and truncated arms, which
/// returned straight out of the read loop). A bare close is indistinguishable from a
/// network fault (§4.6), and on a multiplexed connection it destroys unrelated ADMITTED
/// requests.
///
/// An empty `request_id` IS the best-effort form, not a bug: it is what the section
/// prescribes where no id can be recovered.
pub fn refuse_pre_admission(io: &Arc<Io>, request_id: &str, status: u64, code: &str) {
    let err = Entity::make(
        "system/protocol/error",
        cbor_host::map(vec![("code", cbor_host::text(code))]),
    );
    let resp = Envelope::new(response_entity(request_id, status, &err));
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

// ─────────────────────────────────────────────────────────────────────────────
// §4.11 pre-admission refusals (0.8.2.25) and §5.2a's decode-boundary code.
//
// The RUNTIME half — that a refusal actually reaches the socket — is not testable
// here and is driven over a real connection by the §4.11 wire driver; what IS
// testable here is the MAPPING, which §4.11 states as its own [MUST] ("the frame
// obligation belongs to the class; the CODE belongs to the cause"), and the
// truncation/close discrimination that decides whether a frame is owed at all.
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod pre_admission {
    use super::*;
    use crate::cbor_host::DecodeError;
    use crate::model::ModelError;

    /// A clean EOF at a frame boundary is an ORDINARY CLOSE and is owed nothing.
    #[test]
    fn a_clean_eof_at_a_frame_boundary_is_not_a_refusal() {
        let mut src: &[u8] = &[];
        assert!(matches!(read_frame(&mut src), Err(WireError::Closed)));
    }

    /// A stream that ends MID-FRAME is a REFUSAL and is owed a coded frame. A naive
    /// read-exact collapses this into the case above, and the collapse is invisible
    /// in the body arm — which is why the PREFIX arm is asserted separately.
    #[test]
    fn a_partial_length_prefix_is_a_truncation_not_a_close() {
        let mut src: &[u8] = &[0x00, 0x00];
        assert!(matches!(read_frame(&mut src), Err(WireError::Truncated)));
    }

    #[test]
    fn a_declared_body_that_never_arrives_is_a_truncation() {
        // Prefix declares 0x1000 bytes; three arrive, then EOF. The body read starts at
        // offset 0, so the mapping has to be made where the prefix was read.
        let mut src: &[u8] = &[0x00, 0x00, 0x10, 0x00, 0xA1, 0x64, 0x72];
        assert!(matches!(read_frame(&mut src), Err(WireError::Truncated)));
        let mut src: &[u8] = &[0x00, 0x00, 0x10, 0x00];
        assert!(matches!(read_frame(&mut src), Err(WireError::Truncated)));
    }

    #[test]
    fn an_oversize_prefix_is_refused_before_the_body_is_buffered() {
        // §4.10(a): the bound is checked on the PREFIX. The stream carries no body at
        // all, so reaching PayloadTooLarge proves nothing was buffered.
        let mut src: &[u8] = &[0xFF, 0xFF, 0xFF, 0xFF];
        assert!(matches!(
            read_frame(&mut src),
            Err(WireError::PayloadTooLarge)
        ));
    }

    #[test]
    fn a_zero_length_frame_is_complete_and_reaches_the_decoder() {
        // A COMPLETE frame, not a truncated one — so it is owed the DECODER's refusal
        // (400 invalid_request), not the framing arm's.
        let mut src: &[u8] = &[0x00, 0x00, 0x00, 0x00];
        assert_eq!(read_frame(&mut src).unwrap(), Vec::<u8>::new());
        let err = crate::model::envelope_of_frame(&[]).unwrap_err();
        assert_eq!(refusal_of_model_error(&err), (400, "invalid_request"));
    }

    /// §5.2a (0.8.2.24 N4/N5, 0.8.2.25 N16): a mis-keyed `included` entry is
    /// `400 hash_mismatch` [MUST], and `400 non_canonical_ecf` is NOT conformant here.
    /// The mis-keyed entry carries no tag and its encoding IS canonical.
    #[test]
    fn the_code_belongs_to_the_cause() {
        assert_eq!(
            refusal_of_model_error(&ModelError::IncludedKeyMismatch),
            (400, "hash_mismatch")
        );
        assert_eq!(
            refusal_of_model_error(&ModelError::ContentHashMismatch),
            (400, "hash_mismatch")
        );
        // THE DIFFERENTIAL: the tag arm must answer a DIFFERENT code, or the peer is
        // not classifying, it is just refusing. ENTITY-CBOR-ENCODING §5.4 defines
        // `non_canonical_ecf` for tag-policy violations SPECIFICALLY.
        assert_eq!(
            refusal_of_model_error(&ModelError::Codec(DecodeError::TagRejected)),
            (400, "non_canonical_ecf")
        );
        for e in [
            ModelError::BadEntity,
            ModelError::Codec(DecodeError::Malformed),
            ModelError::Codec(DecodeError::Truncated),
            ModelError::Codec(DecodeError::TrailingData),
            ModelError::Codec(DecodeError::IndefiniteLength),
        ] {
            assert_eq!(
                refusal_of_model_error(&e),
                (400, "invalid_request"),
                "{e:?}"
            );
        }
    }

    /// A mis-keyed `included` entry really does reach that arm through the decoder,
    /// rather than the mapping being asserted against a value nothing produces.
    #[test]
    fn a_miskeyed_included_entry_reaches_the_hash_mismatch_arm() {
        let e = Entity::make("primitive/any", cbor_host::map(vec![]));
        let env = Value::Map(vec![
            (Key::Text("root".into()), e.to_cbor()),
            (
                Key::Text("included".into()),
                Value::Map(vec![(Key::Bytes(vec![0u8; 33]), e.to_cbor())]),
            ),
        ]);
        let err = crate::model::envelope_of_frame(&cbor_host::encode(&env)).unwrap_err();
        assert!(matches!(err, ModelError::IncludedKeyMismatch));
        assert_eq!(refusal_of_model_error(&err), (400, "hash_mismatch"));
        // CONTROL — the SAME entity filed under its own hash decodes cleanly, which is
        // what says the assertion above is about the KEY and not about the fixture.
        let env = Value::Map(vec![
            (Key::Text("root".into()), e.to_cbor()),
            (
                Key::Text("included".into()),
                Value::Map(vec![(Key::Bytes(e.hash.clone()), e.to_cbor())]),
            ),
        ]);
        assert!(crate::model::envelope_of_frame(&cbor_host::encode(&env)).is_ok());
    }

    /// The correlation key is recoverable from a frame the STRICT decoder refused —
    /// that is what makes the refusal correlated rather than best-effort.
    #[test]
    fn the_request_id_is_salvageable_from_a_tagged_frame() {
        // {"root": {"data": <tag(0) 0>, "type": "..."}} is refused strictly and the
        // root is still structurally sound, so a request_id beside the tag survives.
        let inner = Value::Map(vec![(
            Key::Text("request_id".into()),
            cbor_host::text("r9"),
        )]);
        let root = Value::Map(vec![
            (Key::Text("data".into()), inner),
            (
                Key::Text("type".into()),
                cbor_host::text("system/protocol/execute"),
            ),
        ]);
        let env = Value::Map(vec![(Key::Text("root".into()), root)]);
        let bytes = cbor_host::encode(&env);
        assert_eq!(salvage_request_id(&bytes).as_deref(), Some("r9"));
        // And an unrecoverable id yields None, which the read loop turns into §4.11's
        // UNCORRELATED best-effort frame rather than into silence.
        assert_eq!(salvage_request_id(&[0xFF, 0xFF, 0xFF]), None);
    }
}
