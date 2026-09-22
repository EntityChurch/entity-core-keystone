//! The peer's own host, as a library function (keystone peer contract `embed.host_main`,
//! `run.*`).
//!
//! `entity-peer-host` is `run_host(argv, |_| Ok(()))` and nothing else. A composed peer —
//! an extension installed into this peer by someone else's program — is
//! `run_host(argv, |peer| { install … })`, so the bare host and a composed host parse the
//! same flags, provision the same identity, apply the same seed policy, emit the same
//! readiness record and serve with the same loop. That is what lets a differential run
//! *one* variable: both arms run this function, and only the callback differs.
//!
//! # Flags (`run.cli`)
//!
//! ```text
//!   --port N              listen port (default 7777; 0 = auto-assign)
//!   --bind ADDR           listen address (default 127.0.0.1). `0.0.0.0` makes the peer
//!                         reachable from outside its own network namespace (`run.serve`).
//!   --name NAME           persistent identity from ~/.entity/peers/NAME/keypair
//!                         (`run.identity`); without it a random identity is used
//!   --validate            install the §7a system/validate/* conformance handlers
//!   --seed-policy PATH    the §6.9a seed policy in keystone's file format (`run.posture`)
//!   --max-frame-bytes N   the inbound frame budget in bytes (`run.limits`)
//!   --ready-file PATH     also write the readiness record, as JSON, to PATH (`run.ready`)
//!   --debug-open-grants   DEPRECATED — the degenerate `default -> *` policy; ignored when
//!                         --seed-policy is given
//!   --help                usage, exit 0
//! ```
//!
//! An unknown flag, a missing value or an unreadable policy exits `2` with a message on
//! stderr, before anything listens.
//!
//! # The readiness record (`run.ready`)
//!
//! Exactly one stdout line, emitted once the listener is bound and after `configure` has
//! returned:
//!
//! ```text
//! LISTENING {"record":"keystone-peer-ready/1","transport":"tcp","addr":"127.0.0.1:7777",…}
//! ```
//!
//! The line starts with `LISTENING ` so every existing harness that waits on `^LISTENING`
//! keeps working; the rest of the line is the JSON object, which is byte-identical to what
//! `--ready-file` writes. Fields: `record`, `transport`, `addr`, `peer_id`,
//! `posture` (`standard` | `debug-open` | `file`), `posture_digest` (sha256 hex of the
//! policy file's bytes, or the posture name when there is no file), `limits`
//! (`max_frame_bytes`, `max_chain_depth`), `validate`.
//!
//! # Stop (`run.stop`)
//!
//! This crate forbids `unsafe`, and std Rust has no signal handling without it, so SIGTERM
//! terminates the process by signal rather than returning `0`. What the contract measures
//! is the property that has actually broken harnesses here — **the listening socket is
//! released promptly after the signal** — and that holds, because the kernel closes the
//! process's descriptors on exit.

use std::io::Write;
use std::net::TcpListener;
use std::sync::Arc;

use sha2::{Digest, Sha256};

use super::capability::MAX_CHAIN_DEPTH;
use super::core::{CreateOptions, Peer, PeerConfig};
use super::seed_policy::SeedPolicy;
use super::transport;

/// The readiness record's version tag. Bump when a field changes meaning.
pub const READY_RECORD: &str = "keystone-peer-ready/1";

/// Parsed host flags. Public so a composing program can inspect what `run_host` will do,
/// but the supported entry point is [`run_host`].
#[derive(Clone, Debug)]
pub struct HostArgs {
    pub port: u16,
    pub bind: String,
    pub name: Option<String>,
    pub validate: bool,
    pub seed_policy_path: Option<String>,
    pub open_grants: bool,
    pub max_frame_bytes: Option<usize>,
    pub ready_file: Option<String>,
    pub help: bool,
}

impl Default for HostArgs {
    fn default() -> Self {
        HostArgs {
            port: 7777,
            bind: "127.0.0.1".to_string(),
            name: None,
            validate: false,
            seed_policy_path: None,
            open_grants: false,
            max_frame_bytes: None,
            ready_file: None,
            help: false,
        }
    }
}

/// The usage line for the bare host. A composed host prints the same flags under its own program
/// name ([`usage`]).
pub const USAGE: &str = "usage: entity-peer-host [--port N] [--bind ADDR] [--name NAME] [--validate] \
[--seed-policy PATH] [--max-frame-bytes N] [--ready-file PATH] [--debug-open-grants]";

/// The usage line under the running program's own name (`argv[0]`'s file name), so a composed
/// host built on [`run_host`] does not introduce itself as `entity-peer-host`.
pub fn usage() -> String {
    let program = std::env::args_os()
        .next()
        .and_then(|a| std::path::Path::new(&a).file_name().map(|n| n.to_string_lossy().into_owned()))
        .unwrap_or_else(|| "entity-peer-host".to_string());
    USAGE.replacen("entity-peer-host", &program, 1)
}

/// The readiness record's own fields. A composing program's extra fields may not reuse them: the
/// record is one JSON object, and a second `peer_id` is a record two parsers read two ways.
pub const READY_RECORD_FIELDS: [&str; 8] =
    ["record", "transport", "addr", "peer_id", "posture", "posture_digest", "limits", "validate"];

/// Parse host flags (`run.cli`). The program name must NOT be included.
pub fn parse_args<I: IntoIterator<Item = String>>(argv: I) -> Result<HostArgs, String> {
    let mut a = HostArgs::default();
    let mut it = argv.into_iter();
    fn value(it: &mut impl Iterator<Item = String>, flag: &str) -> Result<String, String> {
        it.next().ok_or_else(|| format!("{flag} requires a value"))
    }
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--port" => {
                a.port = value(&mut it, "--port")?
                    .parse()
                    .map_err(|_| "bad --port value".to_string())?
            }
            "--bind" => a.bind = value(&mut it, "--bind")?,
            "--name" => a.name = Some(value(&mut it, "--name")?),
            "--validate" => a.validate = true,
            "--seed-policy" => a.seed_policy_path = Some(value(&mut it, "--seed-policy")?),
            "--max-frame-bytes" => {
                let n: usize = value(&mut it, "--max-frame-bytes")?
                    .parse()
                    .map_err(|_| "bad --max-frame-bytes value".to_string())?;
                if n == 0 {
                    return Err("--max-frame-bytes must be positive".to_string());
                }
                a.max_frame_bytes = Some(n);
            }
            "--ready-file" => a.ready_file = Some(value(&mut it, "--ready-file")?),
            "--debug-open-grants" => a.open_grants = true,
            "-h" | "--help" => a.help = true,
            other => return Err(format!("unknown argument '{other}'")),
        }
    }
    Ok(a)
}

/// Run the peer's host: parse `argv` (without the program name), build the peer, hand it
/// to `configure` BEFORE listening, emit the readiness record, and serve until the process
/// is killed. Returns an exit code only when it cannot start — `2` for a usage or
/// configuration error, `1` when the listener cannot be bound or `configure` refuses.
///
/// `configure` is where a composing program installs handlers, consumers, types and an
/// evaluator. Returning `Err` aborts startup with the message on stderr, before anything
/// is reachable.
///
/// **Keep what `configure` installs.** A [`super::HandlerHandle`] unregisters its handler when it
/// is dropped, and a named binding (`let _h = peer.register_handler(…)?;`) is dropped when the
/// closure returns — before the peer listens — so the handler is gone by the time anyone can reach
/// it. `#[must_use]` does not catch a named binding. Call `.detach()` for a peer-lifetime install,
/// or move the handle somewhere that outlives the closure.
pub fn run_host<I, F>(argv: I, configure: F) -> i32
where
    I: IntoIterator<Item = String>,
    F: FnOnce(&Arc<Peer>) -> Result<(), String>,
{
    run_host_with(argv, &[], configure)
}

/// [`run_host`] with extra top-level fields for the readiness record, each a key and a
/// value that is ALREADY valid JSON (`"\"text\""`, `{…}`, `true`). A composing program uses
/// it to announce what it is — the keystone contract host adds `contract_host`.
pub fn run_host_with<I, F>(argv: I, extra_record_fields: &[(&str, String)], configure: F) -> i32
where
    I: IntoIterator<Item = String>,
    F: FnOnce(&Arc<Peer>) -> Result<(), String>,
{
    run_host_announcing(argv, extra_record_fields, |peer| configure(peer).map(|()| Vec::new()))
}

/// [`run_host_with`] whose `configure` also returns record fields, for what a composition can
/// only know AFTER installing — what it read back off the peer, not what it meant to install.
/// The returned fields follow `extra_record_fields` in the record. Every value must be valid
/// JSON (integers only: the peer's JSON reader refuses floats), and no key may repeat another or name one of [`READY_RECORD_FIELDS`]; either refuses
/// startup with exit `1` before anything listens.
pub fn run_host_announcing<I, F>(argv: I, extra_record_fields: &[(&str, String)], configure: F) -> i32
where
    I: IntoIterator<Item = String>,
    F: FnOnce(&Arc<Peer>) -> Result<Vec<(String, String)>, String>,
{
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("{}", usage());
            return 2;
        }
    };
    if args.help {
        println!("{}", usage());
        return 0;
    }

    let seed = match &args.name {
        Some(name) => match load_named_seed(name) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("error: {e}");
                return 2;
            }
        },
        None => random_seed(),
    };

    let mut config = PeerConfig::default();
    let (posture, posture_digest) = match &args.seed_policy_path {
        Some(path) => {
            let bytes = match std::fs::read(path) {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("error: --seed-policy: cannot read {path}: {e}");
                    return 2;
                }
            };
            let text = match String::from_utf8(bytes.clone()) {
                Ok(t) => t,
                Err(_) => {
                    eprintln!("error: --seed-policy: {path} is not UTF-8");
                    return 2;
                }
            };
            match SeedPolicy::from_json(&text) {
                Ok(p) => config = config.seed_policy(p),
                Err(e) => {
                    eprintln!("error: --seed-policy: {e}");
                    return 2;
                }
            }
            if args.open_grants {
                eprintln!("warning: --debug-open-grants is DEPRECATED and is IGNORED because --seed-policy was given (a declared policy wins)");
            }
            ("file", hex(&Sha256::digest(&bytes)))
        }
        None if args.open_grants => {
            eprintln!("warning: --debug-open-grants is DEPRECATED (v7.74 section 6.9a) - prefer --seed-policy PATH");
            ("debug-open", "debug-open".to_string())
        }
        None => ("standard", "standard".to_string()),
    };
    if let Some(n) = args.max_frame_bytes {
        config = config.max_frame_bytes(n);
    }

    let peer = Arc::new(Peer::create_with(
        CreateOptions {
            seed,
            open_grants: args.open_grants && args.seed_policy_path.is_none(),
            conformance: args.validate,
        },
        config,
    ));

    let announced = match configure(&peer) {
        Ok(fields) => fields,
        Err(e) => {
            eprintln!("error: configure refused: {e}");
            return 1;
        }
    };
    let mut extra: Vec<(String, String)> =
        extra_record_fields.iter().map(|(k, v)| (k.to_string(), v.clone())).collect();
    extra.extend(announced);
    if let Err(e) = check_extra_record_fields(&extra) {
        eprintln!("error: readiness record: {e}");
        return 1;
    }

    let listener = match TcpListener::bind((args.bind.as_str(), args.port)) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("error: listen on {}:{} failed: {e}", args.bind, args.port);
            return 1;
        }
    };
    let addr = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| format!("{}:{}", args.bind, args.port));

    let mut record = ready_record(&peer, &addr, posture, &posture_digest, args.validate);
    if !extra.is_empty() {
        record.pop(); // the closing brace
        for (k, v) in &extra {
            record.push_str(&format!(",\"{}\":{v}", json_escape(k)));
        }
        record.push('}');
    }
    if let Some(path) = &args.ready_file {
        if let Err(e) = std::fs::write(path, format!("{record}\n")) {
            eprintln!("error: --ready-file {path}: {e}");
            return 1;
        }
    }
    println!("LISTENING {record}");
    let _ = std::io::stdout().flush();

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let peer = peer.clone();
                std::thread::spawn(move || transport::serve_connection(peer, s));
            }
            // A transient accept error must not end the accept loop (AGENTS.md: a peer
            // that stops LISTENING while alive reads as a crash).
            Err(_) => continue,
        }
    }
    0
}

/// Refuse extra record fields that would make the record ambiguous or not JSON.
pub fn check_extra_record_fields(fields: &[(String, String)]) -> Result<(), String> {
    let mut seen: Vec<&str> = Vec::new();
    for (k, v) in fields {
        if READY_RECORD_FIELDS.contains(&k.as_str()) {
            return Err(format!("extra field '{k}' is one of the record's own fields"));
        }
        if seen.contains(&k.as_str()) {
            return Err(format!("extra field '{k}' is given twice"));
        }
        seen.push(k);
        super::json::parse(v).map_err(|e| format!("extra field '{k}' is not valid JSON ({e})"))?;
    }
    Ok(())
}

/// The readiness record as a single-line JSON object.
pub fn ready_record(peer: &Peer, addr: &str, posture: &str, posture_digest: &str, validate: bool) -> String {
    format!(
        "{{\"record\":\"{READY_RECORD}\",\"transport\":\"tcp\",\"addr\":\"{}\",\"peer_id\":\"{}\",\"posture\":\"{}\",\"posture_digest\":\"{}\",\"limits\":{{\"max_frame_bytes\":{},\"max_chain_depth\":{}}},\"validate\":{}}}",
        json_escape(addr),
        json_escape(&peer.local_peer),
        json_escape(posture),
        json_escape(posture_digest),
        peer.max_frame_bytes(),
        MAX_CHAIN_DEPTH,
        validate
    )
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// A random 32-byte seed read from /dev/urandom (no rand crate — dep-minimization).
pub fn random_seed() -> [u8; 32] {
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
    buf.copy_from_slice(&Sha256::digest(t.to_le_bytes()));
    buf
}

/// Load the 32-byte Ed25519 seed from `~/.entity/peers/NAME/keypair` (`run.identity`): an
/// entity-core PEM whose body is base64(seed) between BEGIN/END ENTITY PRIVATE KEY lines.
pub fn load_named_seed(name: &str) -> Result<[u8; 32], String> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
    let path = format!("{home}/.entity/peers/{name}/keypair");
    let data = std::fs::read_to_string(&path)
        .map_err(|e| format!("--name {name}: cannot read {path}: {e}"))?;
    let body: String = data
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('-'))
        .collect();
    let decoded =
        base64_decode(&body).ok_or_else(|| format!("--name {name}: malformed base64 keypair"))?;
    if decoded.len() != 32 {
        return Err(format!(
            "--name {name}: expected a 32-byte seed, got {} bytes",
            decoded.len()
        ));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded);
    Ok(seed)
}

/// Standard-alphabet base64 decoder; tolerates `=` padding and whitespace.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
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
        acc = (acc << 6) | u32::from(val(c)?);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((acc >> nbits) as u8);
            acc &= (1 << nbits) - 1;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn run_cli_unknown_flag_is_refused() {
        assert!(parse_args(args(&["--bogus"])).is_err());
        assert!(parse_args(args(&["--port"])).is_err());
        assert!(parse_args(args(&["--max-frame-bytes", "0"])).is_err());
    }

    #[test]
    fn run_cli_every_flag_parses() {
        let a = parse_args(args(&[
            "--port", "0", "--bind", "0.0.0.0", "--name", "n", "--validate", "--seed-policy",
            "p.json", "--max-frame-bytes", "4096", "--ready-file", "r.json",
        ]))
        .unwrap();
        assert_eq!(a.port, 0);
        assert_eq!(a.bind, "0.0.0.0");
        assert_eq!(a.name.as_deref(), Some("n"));
        assert!(a.validate);
        assert_eq!(a.seed_policy_path.as_deref(), Some("p.json"));
        assert_eq!(a.max_frame_bytes, Some(4096));
        assert_eq!(a.ready_file.as_deref(), Some("r.json"));
    }

    #[test]
    fn base64_round_trips_the_cohort_seed() {
        let s = base64_decode("ERERERERERERERERERERERERERERERERERERERERERE=").unwrap();
        assert_eq!(s, vec![0x11; 32]);
    }
}

#[cfg(test)]
mod record_field_tests {
    use super::*;

    fn f(k: &str, v: &str) -> (String, String) {
        (k.to_string(), v.to_string())
    }

    #[test]
    fn extra_record_fields_refuse_ambiguity_and_non_json() {
        assert!(check_extra_record_fields(&[f("composed", "{\"extensions\":[\"COMPUTE\"]}"), f("n", "3")]).is_ok());
        assert!(check_extra_record_fields(&[f("peer_id", "\"x\"")]).is_err(), "a record field");
        assert!(check_extra_record_fields(&[f("a", "1"), f("a", "2")]).is_err(), "a repeated key");
        assert!(check_extra_record_fields(&[f("a", "not json")]).is_err(), "not JSON");
    }

    #[test]
    fn usage_keeps_the_flag_list() {
        let u = usage();
        assert!(u.starts_with("usage: ") && u.ends_with(USAGE.trim_start_matches("usage: entity-peer-host")));
    }
}
