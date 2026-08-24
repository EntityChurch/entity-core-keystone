// GO-gate self-test for the Datalog peer (protocol-generator/datalog/).
//
// Proves — headless, in the capped container — the three things S1 must establish
// before S2/S3 authoring is worth starting:
//
//   1. DATALOG ENGINE: Ascent (bottom-up, semi-naive, set-oriented, terminating)
//      evaluates a RECURSIVE rule to fixpoint. The rule authored here IS the §5.5
//      delegation shape the peer's authority interior will use:
//          authorized(A,B) <-- granted(A,B).
//          authorized(A,C) <-- granted(A,B), authorized(B,C).
//      i.e. the transitive delegation closure — the SecPAL/Binder trust-management
//      pattern. Proves the recursive delegation-rule mechanism works in-process.
//
//   2. FFI SEAM: reach libentitycore_codec and run an ec_sha256 known-answer test
//      (SHA-256("abc") = ba7816bf…015ad). Proves the seam links + calls — the peer's
//      canonical CBOR / Ed25519 / SHA all cross this exact boundary.
//
//   3. TRANSPORT: an 8-bit-clean TCP echo including 0x00 and 0xFF. Proves the host
//      moves framed binary CBOR byte-faithfully (the transport is host-owned; Datalog
//      never touches a socket).
//
// Exit 0 iff all three pass; any failure is FATAL (nonzero) so the image build fails.

use ascent::ascent;
use std::collections::BTreeSet;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::raw::c_char;
use std::thread;

// --- FFI seam: only ec_sha256 + provenance needed for the KAT. -----------------
extern "C" {
    fn ec_sha256(data_ptr: *const u8, data_len: usize, out_ptr: *mut u8) -> i32;
    fn ec_impl_info() -> *const c_char;
}

// --- Leg 1: the §5.5 recursive delegation closure as genuine bottom-up Datalog. -
ascent! {
    // Direct grant edge: `granter` delegated authority to `grantee`.
    relation granted(u32, u32);
    // Derived transitive delegation closure — computed bottom-up to fixpoint.
    relation authorized(u32, u32);

    authorized(a, b) <-- granted(a, b);
    authorized(a, c) <-- granted(a, b), authorized(b, c);
}

fn check_datalog() -> Result<(), String> {
    let mut prog = AscentProgram::default();
    // Delegation chain 1->2->3->4 plus an isolated edge 10->11.
    prog.granted = vec![(1, 2), (2, 3), (3, 4), (10, 11)];
    prog.run();

    let got: BTreeSet<(u32, u32)> = prog.authorized.iter().copied().collect();
    let expect: BTreeSet<(u32, u32)> = [
        (1, 2), (1, 3), (1, 4), // 1 reaches 2,3,4 transitively
        (2, 3), (2, 4),
        (3, 4),
        (10, 11), // isolated edge — closure does NOT invent cross-links
    ]
    .into_iter()
    .collect();

    if got == expect {
        println!(
            "  [1/3] DATALOG OK: recursive delegation closure -> fixpoint ({} tuples, incl. 1->4 depth-3)",
            got.len()
        );
        Ok(())
    } else {
        Err(format!(
            "datalog closure wrong: got {:?} expected {:?}",
            got, expect
        ))
    }
}

// --- Leg 2: FFI seam KAT via libentitycore_codec. ------------------------------
fn check_ffi_sha256() -> Result<(), String> {
    let msg = b"abc";
    let mut digest = [0u8; 32];
    let rc = unsafe { ec_sha256(msg.as_ptr(), msg.len(), digest.as_mut_ptr()) };
    if rc != 0 {
        return Err(format!("ec_sha256 returned {rc}"));
    }
    // SHA-256("abc") known-answer (NIST).
    let expect: [u8; 32] = [
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
        0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
        0x15, 0xad,
    ];
    if digest != expect {
        return Err(format!("ec_sha256(\"abc\") mismatch: got {digest:02x?}"));
    }
    let info = unsafe {
        let p = ec_impl_info();
        if p.is_null() {
            "<null>".to_string()
        } else {
            std::ffi::CStr::from_ptr(p).to_string_lossy().into_owned()
        }
    };
    println!("  [2/3] FFI SEAM OK: ec_sha256(\"abc\") KAT byte-exact; provenance = {info}");
    Ok(())
}

// --- Leg 3: 8-bit-clean TCP echo incl. 0x00 / 0xFF. ----------------------------
fn check_socket() -> Result<(), String> {
    let listener = TcpListener::bind("127.0.0.1:0").map_err(|e| format!("bind: {e}"))?;
    let addr = listener.local_addr().map_err(|e| format!("addr: {e}"))?;

    // Payload deliberately spans the full byte range including the two edge bytes.
    let payload: Vec<u8> = vec![0x00, 0x01, 0x0a, 0x7f, 0x80, 0xc0, 0xfe, 0xff, 0x00, 0xff];
    let expect = payload.clone();

    let server = thread::spawn(move || -> std::io::Result<()> {
        let (mut sock, _) = listener.accept()?;
        let mut buf = vec![0u8; 64];
        let n = sock.read(&mut buf)?;
        sock.write_all(&buf[..n])?;
        Ok(())
    });

    let mut client = TcpStream::connect(addr).map_err(|e| format!("connect: {e}"))?;
    client
        .write_all(&payload)
        .map_err(|e| format!("write: {e}"))?;
    let mut back = vec![0u8; 64];
    let n = client.read(&mut back).map_err(|e| format!("read: {e}"))?;
    back.truncate(n);
    server
        .join()
        .map_err(|_| "server thread panicked".to_string())?
        .map_err(|e| format!("server io: {e}"))?;

    if back == expect {
        println!("  [3/3] TRANSPORT OK: TCP echo 8-bit-clean ({} bytes incl. 0x00/0xFF)", n);
        Ok(())
    } else {
        Err(format!("echo mismatch: sent {expect:02x?} got {back:02x?}"))
    }
}

fn main() {
    println!("== Datalog peer GO-gate (Rust host + Ascent + libentitycore_codec) ==");
    let mut failed = false;
    for (name, res) in [
        ("datalog", check_datalog()),
        ("ffi", check_ffi_sha256()),
        ("socket", check_socket()),
    ] {
        if let Err(e) = res {
            eprintln!("  FATAL [{name}]: {e}");
            failed = true;
        }
    }
    if failed {
        eprintln!("GO-GATE: NO-GO");
        std::process::exit(1);
    }
    println!("GO-GATE OK: embedded bottom-up Datalog + FFI codec seam + 8-bit-clean transport");
}
