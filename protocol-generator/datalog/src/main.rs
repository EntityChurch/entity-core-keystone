//! entity-core-protocol-datalog — the runnable peer host.
//!
//! Boots a single Datalog peer listener on a TCP port and blocks until killed, so an
//! external oracle (entity-core-go `validate-peer`) or a reference `entity-peer` can
//! drive the live wire surface. The §5/§6.6 authority interior it enforces is the
//! `authority.rs` Ascent program; this binary is the byte-pump shell around it.
//!
//! ```text
//!   --port N             listen port (default 7737; 0 = auto-assign)
//!   --name NAME          load a persistent Ed25519 identity from
//!                        ~/.entity/peers/NAME/keypair (entity-core PEM = base64 of a
//!                        32-byte seed) — the Go entity-peer / peer-manager convention.
//!   --validate           register the §7a system/validate/* conformance handlers
//!                        (OFF by default — dispatch-outbound is a standing dialer).
//!   --debug-open-grants  the degenerate `default → *` seed policy (deprecated).
//! ```

use std::process::exit;
use std::sync::Arc;

use entity_core_protocol_datalog::dispatch::{CreateOptions, Peer};
use entity_core_protocol_datalog::host;

fn main() {
    let mut port: u16 = 7737;
    let mut open_grants = false;
    let mut validate = false;
    let mut seed = random_seed();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => {
                port = args
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or_else(|| die("bad/missing --port"));
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
                println!("usage: entity-peer-datalog [--port N] [--name NAME] [--validate] [--debug-open-grants]");
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
    let listener = host::listen(port).unwrap_or_else(|e| die(&format!("listen failed: {e}")));
    let bound = listener.local_addr().map(|a| a.port()).unwrap_or(port);
    println!(
        "LISTENING 127.0.0.1:{bound} peer_id={} open_grants={open_grants} validate={validate}",
        peer.local_peer
    );
    use std::io::Write;
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let peer = peer.clone();
                std::thread::spawn(move || host::serve_connection(peer, s));
            }
            Err(_) => break,
        }
    }
}

fn die(msg: &str) -> ! {
    eprintln!("error: {msg}");
    exit(2);
}

fn random_seed() -> [u8; 32] {
    use std::io::Read;
    let mut buf = [0u8; 32];
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(&mut buf).is_ok() {
            return buf;
        }
    }
    let t = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    entity_core_protocol_datalog::codec_ffi::sha256(&t.to_le_bytes()).unwrap_or([0u8; 32])
}

fn load_seed_from_name(name: &str) -> [u8; 32] {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let path = format!("{home}/.entity/peers/{name}/keypair");
    let data = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| die(&format!("--name {name}: cannot read {path}: {e}")));
    let body: String = data
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .collect();
    let decoded =
        base64_decode(&body).unwrap_or_else(|| die(&format!("--name {name}: malformed base64")));
    if decoded.len() != 32 {
        die(&format!(
            "--name {name}: expected 32-byte seed, got {}",
            decoded.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded);
    seed
}

/// Minimal standard-alphabet base64 (dep-minimization; no crate).
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
        acc = (acc << 6) | val(c)? as u32;
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
        }
    }
    Some(out)
}
