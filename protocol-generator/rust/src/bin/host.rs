//! entity-core-protocol-rust — standalone peer host.
//!
//! The runnable target for S4 conformance, and nothing but the library's own host:
//! `run_host(argv, no-op)`. Flags, identity, seed policy, the readiness record and the
//! accept loop all live in [`entity_core_protocol::peer::host`], so a composed peer —
//! someone else's program installing an extension — runs exactly this `main` with an
//! install callback, and the bare and composed arms of a differential cannot drift.
//! See that module for the flag list and the readiness record.

fn main() {
    let code = entity_core_protocol::peer::host::run_host(std::env::args().skip(1), |_| Ok(()));
    std::process::exit(code);
}
