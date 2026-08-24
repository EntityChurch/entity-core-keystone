# Changelog — entity-core-protocol-datalog

## v0.1.0-pre (2026-07-16)

Initial core peer — **tracks ENTITY-CORE-PROTOCOL v0.8.0 / V8** (Layers 0–4).
The cohort's **authority-as-query spec-discovery probe** (deductive-logic /
query-native paradigm; peer target `datalog`). Provided, cohort-consistent — **not**
independent convergence (shared generation lineage + shared FFI codec, ADR-0012).

### Pins
- **Spec:** ENTITY-CORE-PROTOCOL **v0.8.0 / V8** (`spec-data/v0.8.0`; core wire
  byte-unchanged across V7→V8, proven byte-identical at S2 — A-DL-003 closed).
- **Engine:** `ascent = "=0.8.0"` (crates.io newest, 2025-03-02; `default-features=false`
  drops `par` — the host serializes requests, so the serial engine is smaller +
  deterministic). Full transitive closure frozen in `Cargo.lock`.
- **Host:** Rust 1.96.1 (fedora:43 `updates` distro build, pinned-for-repro).
- **Codec / crypto:** FFI over `libentitycore_codec` — **C-ABI 1.1**
  (`ec_abi_version`; `ffi-generator/c-abi/spec/`), libsodium 1.0.22. Canonical CBOR +
  Ed25519 + Ed448 + SHA-256/384 + peer-id base58 all cross the C-ABI; the host makes
  the `extern "C"` calls and the Ascent layer never touches a byte.

### Authority interior (S3 — the probe artifact, `src/authority.rs`)
- **§5.2 verdict** as a derived `allow(c)` fact; **fail-closed is structural** (absence
  of an `allow` tuple = denial — the closed-world assumption) (A-DL-010).
- **§5.5 delegation** as a two-rule transitive closure to least fixpoint (the
  SecPAL/Binder trust-management shape) (A-DL-010).
- **§5.5a** within-grant conjunction as a 5-way join on the grant index (the
  "one grant, not four" invariant falls out structurally); the glob *decision* is a
  host-asserted fact (A-DL-011).
- **§3.6 K-of-N multisig** as a counting aggregate over `distinct_signer` (A-DL-012).
- **§6.6 handler resolution** as longest-prefix via stratified negation (A-DL-014).
- §6.5 dispatch sequencing, the §4 handshake state machine, temporal comparison,
  framing/crypto/store correctly **leak to the Rust host** — the seam split, itself the
  headline finding (A-DL-013).

### Peer surface (S4 — host seam, `src/dispatch.rs` + `src/types.rs`)
- §9.5 **53-type Core Type Floor** served at `system/type/<name>`, rendered natively
  (A-DL-015); handler register/unregister; capability `configure` + zero-token revoke
  reject; §3.9 tree CAS + §1.4 path validity (→ 400) + deletion-marker listing filter;
  §6.11 `dispatch-outbound` reentry; §4.5 negotiation + §4.7 key_type rejects.
- **The wrapper-guard held:** completing the surface added **zero** imperative
  allow/deny — the §5.2 verdict still derives end-to-end from the `ascent!` rules.

### Conformance (S4)
- `validate-peer --profile core` → **`Result: PASS` — 682 · 0F @ `cc1970f`**
  (292 P / 294 W / 0 F / 96 S; `core_gate_fingerprint 8261a033…`).
- origination-core **3/3**; **live 2-of-3 multisig accept** (the Ascent K-of-N
  aggregate) + the `k_of_n_2_of_3_accept_path` / `k_of_n_duplicate_signer_does_not_inflate`
  unit tests (the accept path the rejection-only oracle category can't cover — A-DL-006).
- Wire corpus **71/71** byte-identical. 29 lib unit tests + loopback + Go-interop GREEN;
  `cargo clippy -D warnings` + `cargo fmt --check` clean.
- Oracle **not rebuilt here** — the overseer's fresh `cc1970f` binaries (fingerprint
  reproduced) are the gate; go HEAD moved past `cc1970f` on NETWORK work and re-pinning
  is a policy-§4 decision, not an S4/S5 step.

### Publishing
- `0.1.0-pre`. Registry publish (crates.io) **deferred** like the cohort (probe tier,
  `publish = false`). Ship from source via `cargo build --release`. Promotion to
  `0.1.0` is not proposed — the probe's value is the finding + the readable
  trust-management reference, not a deployment.
