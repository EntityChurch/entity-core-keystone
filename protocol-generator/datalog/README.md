# entity-core-protocol-datalog

A core **entity-core protocol** peer (V8 / v0.8.0, Layers 0–4) whose **§5/§6.6
authority interior is authored as genuine bottom-up Datalog rules** — the embedded
**Ascent** engine (0.8.0) on a **Rust** seam host over `libentitycore_codec`.
Peer target `datalog`; the cohort's **authority-as-query paradigm probe**
(deductive-logic / query-native half; SQL is the set-oriented-query other half).

> **Status: exploratory spec-discovery probe (Tier: probe, ‡ seam-hybrid).** Not a
> deployable-tier peer, and **not** independent convergence — it shares the cohort's
> generation lineage and the same FFI codec `.so`, so its green gate is
> *cohort-consistent*, not an independent second implementation (ADR-0012). The
> payoff is the **finding**, not a deployment: the §5/§6.6 decision surface **is a
> monotone deductive system**, and the seam split (which half of the protocol is
> deductive vs. stateful-sequential) is the co-equal deliverable
> (`../../research/evaluations/authority-as-query.md`).

## The probe — the authority interior IS a query

Trust-management logics (SecPAL, Binder, DKAL) are literally Datalog dialects, so the
§5 authorization model should be a natural fit. It is. `src/authority.rs` authors the
decision surface as two `ascent!` blocks — real, legible rules that **drive the verdict
end-to-end** (the wrapper-guard held through S4: completing the handler surface added
**zero** imperative allow/deny to the host):

- **§5.2 verdict — a derived fact.** `allow(c)` is a derived relation over
  `verified_signer` / `authorized` / `scope_ok` / temporal facts. **Fail-closed is
  structural**: the *absence* of an `allow` tuple **is** the denial — the closed-world
  assumption, where an imperative peer encodes fail-closed as an explicit final
  `return Deny` fallthrough a refactor can silently drop (A-DL-010).
- **§5.5 delegation — a recursive rule to least fixpoint.** The transitive delegation
  closure is two rules (`confers(c) <-- verified_root(c)` /
  `confers(c) <-- verified_link(c,p), confers(p)`) — the SecPAL/Binder shape. What
  imperative peers walk with a loop + depth counter + per-link state is the spec's
  implicit recursion made explicit.
- **§5.5a within-grant conjunction — a 5-way join.** The string-glob *decision*
  (prefix + the `"*"`/`"/*/*"` dual form) is a host-asserted fact; the *conjunction*
  ("all four dims covered by ONE grant, not four different grants") falls out of the
  join on the grant index for free — the rule cannot express it wrong (A-DL-011).
- **§3.6 K-of-N multisig — a counting aggregate.** `quorum_met(c) <-- threshold(c,k),
  agg n = count() in distinct_signer(c,_), if n >= k` — not a host loop. (Caveat:
  set-distinctness is a property of the *fixpoint*, not of externally-loaded EDB — a
  one-line copy-rule moves signer facts into the IDB where set semantics apply, or a
  duplicate signature silently inflates the count; A-DL-012.)
- **§6.6 handler resolution — longest-prefix as stratified negation.**
  `resolved(p) <-- candidate(p,_), !longer_exists(p)` — the backward tree-walk as "the
  maximal prefix," on the canvas, not buried in a host `resolve()` (A-DL-014).

**The seam** is drawn only at what Datalog genuinely can't do: the Rust host owns
sockets, §1.6 framing, canonical CBOR + Ed25519/Ed448 + SHA (all across the C-ABI),
§7b store mutation, the §4 handshake state machine, and §6.5 dispatch sequencing — and
it **verifies signatures first, then asserts `verified_signer(_)` facts**. Ascent never
touches a byte or a key. That the entire S4 growth was host-seam and the deductive
interior needed **zero** additions confirms the seam split at the live-peer bar
(A-DL-013).

This makes the peer a **readable reference for the logic-programming /
trust-management community**: the authority logic they know from the literature,
rendered against a real protocol's conformance gate.

## Architecture

| Concern | Where | Module |
|---|---|---|
| **Authority interior** (§5.2/§5.5/§5.5a/§3.6/§6.6) — the probe artifact | Ascent rules | `src/authority.rs` |
| Codec / crypto seam (canonical CBOR, Ed25519/Ed448, SHA, peer-id) | C-ABI FFI | `src/codec_ffi.rs`, `src/cbor_host.rs` |
| TCP + §1.6 framing + connection lifecycle + fact assertion | Rust host | `src/host.rs` |
| §6.5 op-switch + dispatch sequencing + handler bodies | Rust host | `src/dispatch.rs` |
| §7b store (§4.8), identity, model, §9.5 type floor | Rust host | `src/store.rs`, `src/identity.rs`, `src/model.rs`, `src/types.rs` |

`libentitycore_codec` is the language-agnostic C-ABI (`ec_*`, ABI 1.1) — the same
shared codec the pd/oz/io seam-hybrid peers consume. Datalog holds no bytes and does no
crypto; the readable fields (paths, scopes, small ints, status codes) are real facts,
the opaque values (sigs, hashes, keys) ride as host handles.

## Build & run (container-bound)

Everything runs inside `containers/datalog-toolchain/` (Rust 1.96.1 + Ascent 0.8.0 +
`libentitycore_codec` built from source + the baked GO-gate self-test), capped and
offline:

```sh
./run-s2.sh                 # S2: wire corpus 71/71 byte-identical (via the C-ABI codec)
./run-s3.sh                 # S3: loopback + Go-interop smoke (drives authorize() live)
./run-s4.sh                 # S4: validate-peer --profile core (the live gate)
./run-s4.sh -category multisig       # a single oracle category
./run-origination-core.sh   # §10.2 origination-core (Datalog A-role, Go B-role) 3/3
```

**Build note (A-DL-009):** on an SELinux-enforcing host the run scripts set
`CARGO_TARGET_DIR` to a **container-local** named volume (off the `:Z`-relabelled bind
mount) — `ld` otherwise denies writing Ascent's proc-macro dylib onto the relabelled
mount. `Cargo.lock` still persists back to the host.

Peer startup convention:

```sh
cargo run --release --bin entity-peer-datalog -- --port <p> --name <NAME> [--validate]
```

`--name NAME` loads the persistent Ed25519 identity from
`~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed).
`--validate` enables the `system/validate/*` conformance handlers (off by default).

## Conformance

`validate-peer --profile core` → **`Result: PASS` — 682 · 0F @ `cc1970f`**
(292 P / 294 W / 0 F / 96 S; `core_gate_fingerprint 8261a033…`). Plus origination-core
**3/3**, a **live 2-of-3 multisig accept** (the Ascent K-of-N aggregate, not a host
loop), and the **71/71** byte-identical wire corpus. The 294 warns are all
`type_system` non-floor vocabulary (matched-if-present under `--profile core`); the 96
skips are extension-only categories the §9.0 profile carve-out auto-allowlists (no
masked failure). Full P/W/F/S per category: `status/CONFORMANCE-REPORT.md`
(raw oracle JSON: `status/CONFORMANCE-REPORT.json`).

> **Conformance badge:** `--profile core` **682·0F (Result: PASS)** @ `cc1970f` —
> see [`status/CONFORMANCE-REPORT.md`](status/CONFORMANCE-REPORT.md).

The type floor is served as fetchable `system/type/<name>` entities, rendered
**natively** from the peer's own model (`src/types.rs`) with the Go-rendered vectors as
the drift target — the type registry is published *data*, orthogonal to the authority
interior (A-DL-015).

## License

Apache-2.0 (`LICENSE`). Ascent is MIT/Apache-2.0 dual.
