//! entity-core-protocol-rust — standalone peer host.
//!
//! The runnable target for S4 conformance: boots a single `Peer` listener on a TCP
//! port and blocks until killed, so an external oracle (entity-core-go
//! `validate-peer`) can drive the live wire surface against it.
//!
//! ```text
//!   --port N             listen port (default 7777; 0 = auto-assign)
//!   --name NAME          load a persistent Ed25519 identity from
//!                        ~/.entity/peers/NAME/keypair — an entity-core PEM whose
//!                        body is base64(32-byte seed) between BEGIN/END ENTITY
//!                        PRIVATE KEY lines (the Go entity-peer --name / peer-manager
//!                        convention). Without --name a random seed is used.
//!   --validate           register the §7a system/validate/* conformance handlers
//!                        (OFF by default — dispatch-outbound is a standing dialer).
//!   --debug-open-grants  the degenerate `default → *` seed policy (deprecated;
//!                        routed through the real §6.9a mechanism, not a fork).
//!   --help               print usage and exit.
//! ```
//!
//! Binds loopback (127.0.0.1); run the validator in the same namespace. A single
//! `LISTENING …` line goes to stdout once bound — a run script waits for it.

use std::process::exit;
use std::sync::Arc;

use entity_core_protocol::peer::transport;
use entity_core_protocol::peer::{CreateOptions, Peer};

fn main() {
    let mut port: u16 = 7777;
    let mut open_grants = false;
    let mut validate = false;
    let mut seed = random_seed();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                let v = args
                    .next()
                    .unwrap_or_else(|| die("--port requires an integer"));
                port = v.parse().unwrap_or_else(|_| die("bad --port value"));
            }
            "--name" => {
                let name = args
                    .next()
                    .unwrap_or_else(|| die("--name requires a value"));
                seed = load_seed_from_name(&name);
            }
            "--validate" => validate = true,
            "--debug-open-grants" => open_grants = true,
            "-h" | "--help" => {
                println!(
                    "usage: entity-peer-host [--port N] [--name NAME] [--validate] [--debug-open-grants]"
                );
                return;
            }
            other => die(&format!("unknown argument '{other}'")),
        }
    }

    let peer = Arc::new(Peer::create(CreateOptions {
        seed,
        open_grants,
        conformance: validate,
    }));

    let listener = transport::listen(port).unwrap_or_else(|e| die(&format!("listen failed: {e}")));
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    println!(
        "LISTENING 127.0.0.1:{bound} peer_id={} open_grants={open_grants} validate={validate}",
        peer.local_peer
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();

    // accept loop — each connection served on its own thread (§4.8).
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let peer = peer.clone();
                std::thread::spawn(move || transport::serve_connection(peer, s));
            }
            Err(_) => break,
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2);
}

/// A random 32-byte seed (no persistent --name). Reads /dev/urandom directly to
/// avoid a rand/getrandom crate (dep-minimization).
fn random_seed() -> [u8; 32] {
    use std::io::Read;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    // last-resort fallback (a fresh ephemeral identity per run).
    use sha2::{Digest, Sha256};
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    buf.copy_from_slice(&Sha256::digest(t.to_le_bytes()));
    buf
}

/// Load the 32-byte Ed25519 seed from `~/.entity/peers/NAME/keypair` (the Go
/// entity-peer --name / peer-manager convention): a PEM whose body is base64(seed)
/// between BEGIN/END ENTITY PRIVATE KEY lines. Missing/malformed → stderr + exit(2).
fn load_seed_from_name(name: &str) -> [u8; 32] {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let path = format!("{home}/.entity/peers/{name}/keypair");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| die(&format!("--name {name}: cannot read {path}: {e}")));

    // Concatenate the base64 body (every line not starting with '-').
    let body: String = data
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .collect();

    let decoded = base64_decode(&body)
        .unwrap_or_else(|| die(&format!("--name {name}: malformed base64 keypair")));
    if decoded.len() != 32 {
        die(&format!(
            "--name {name}: expected a 32-byte seed, got {} bytes",
            decoded.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded);
    seed
}

/// Minimal standard-alphabet base64 decoder (hand-rolled, dep-minimization — the
/// `base64` crate is not in the closure). Tolerates `=` padding + whitespace.
fn base64_decode(s: &str) -> Option<Vec<u8>> {
    fn val(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }
    let mut acc: u32 = 0;
    let mut nbits = 0u32;
    let mut out = Vec::new();
    for &c in s.as_bytes() {
        if c == b'=' || c.is_ascii_whitespace() {
            continue;
        }
        let v = val(c)? as u32;
        acc = (acc << 6) | v;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}
