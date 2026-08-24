# entity-core-protocol-datalog — Profile Rationale

The audit trail for every major S1 choice. Companion to `../profile.toml`. This peer is
a **QUERY-NATIVE spec-discovery probe**: the deliverable is co-equally a green gate and
the **seam-split finding** (how much of the §5/§6.6 authority interior stays expressible
as bottom-up Datalog rules vs. leaks to the host). One paragraph per choice.

## Engine — embedded Ascent, NOT batch Soufflé, NOT CozoDB (the S1 discrepancy, resolved)

The handoff §Feasibility floated **Soufflé / CozoDB / Nemo** (batch bottom-up); the
deep-dive (`research/evaluations/declarative-query-viability.md` §Datalog runtime options)
instead recommended a **Rust host + Ascent (or Datafrog)**. S1 weighed embedded vs. batch
with real evidence (the GO-gate build below) and chose **embedded Ascent in a Rust host**:

- **Genuine bottom-up, set-oriented, terminating Datalog.** Ascent is semi-naive
  fixpoint evaluation over relations-as-sets — the SecPAL/Binder trust-management shape,
  and the hard requirement of this probe. The GO-gate proved a recursive
  `authorized(A,C) <-- granted(A,B), authorized(B,C)` rule evaluating to least fixpoint
  in-process. This is emphatically NOT Prolog-in-Datalog (see §Distinctness).
- **Embedded beats batch on the per-request tax.** Soufflé compiles Datalog→C++ and runs
  **batch** (facts in → fixpoint → relations out); as a per-request authority engine it
  imposes a process-spawn or persistent-harness tax on every request. Ascent is an
  **in-process Rust macro** — each request asserts its facts and runs a fixpoint with no
  spawn. For a request/response peer that is the decisive difference.
- **Rust is the cleanest possible host.** Rust already carries the ecosystem's codec/
  crypto/socket story (`containers/rust-toolchain`, the FFI codec). The peer host owns
  sockets + §1.6 framing + the `libentitycore_codec` FFI + fact assertion; Ascent owns
  the authority logic. Same crate, one compile, no IPC — the seam is the smallest of any
  candidate. Datafrog (also Rust, used by Polonius) was rejected because it is a low-level
  *iteration library* where the "rules" are hand-written join loops — that fails the
  wrapper-guard legibility bar (the rules must READ as rules). CozoDB was rejected as a
  whole embedded DB engine with its own CozoScript dialect and a heavier seam than a
  macro. Nemo (existential rules) is heavier than the monotone Datalog this needs.

## Host language — Rust

The host is a **byte-pump + FFI seam + fact-asserter**: it verifies crypto, asserts the
established facts INTO the Ascent program, runs the fixpoint, and emits the response frame
from the derived verdict. Rust gives it `std::net` sockets, a clean `extern "C"` FFI to
`libentitycore_codec`, `Result<T,E>` for the resilience frame (§4.9(c) → 500 on the host
root error class — the Oz A-OZ-005 / Smalltalk A-ST-016 cohort rule), and — critically —
Ascent compiles as a macro *inside the same crate*, so the authored rules and the seam
share one build with zero glue. Pinned to fedora:43 `updates` **rust/cargo 1.96.1-1.fc43**
(reviewed distro channel → pin-for-repro; the sibling rust-toolchain's 1.96.0-1.fc43 has
aged out of the repos, `updates` now serves 1.96.1 — re-pinned deliberately per S11).

## Seam boundary — FFI codec (host) vs. authored rules (Datalog)

Drawn exactly where the substrate genuinely can't reach, per the wrapper-guard:

- **HOST (the seam):** the TCP socket, the §1.6 frame assembler, canonical CBOR +
  Ed25519/Ed448 + SHA via `libentitycore_codec` (the GO-gate `ec_sha256` KAT proved the
  seam links + calls), §7b store-safety, §6.11 demux, and the §4 connection-lifecycle
  state machine. Crucially, **the host verifies signatures FIRST, then asserts
  `verified_signer(Author)`** — Datalog never touches a key or a byte. Opaque values
  (sigs, hashes, keys) ride as host-owned handles keyed by an id interned into the fact
  space; readable fields (paths, scopes, timestamps, counts, status codes) are real facts.
- **AUTHORED (Datalog rules — the probe artifact, `src/authority.rs`):** §5.2 verdict as
  a derivable fact (fail-closed = no derived `allow(_)` — the deductive analogue of
  fail-closed), §5.5 delegation as the recursive transitive closure, §5.5a scope match as
  a rule (with a host-asserted glob fact where the atom model can't glob), §3.6 K-of-N as
  a counting aggregate over distinct `verified_signer` facts, and §6.6 handler resolution
  as a visible longest-prefix (max-prefix-length aggregate) selection — NOT a hidden host
  `resolve()`. The S3 agent authors these and fills in the `[expressibility]` section as
  observed-vs-expected; the shapes are committed in the profile so they cannot be quietly
  folded into a host call (the FLOW-DESIGN wrapper-guard — a single collapsed dispatch hid
  real conformance bugs in Node-RED #31 and TurboWarp #32).

## Number-model tax location — host

The uint64 wire head-form lives entirely in the host/codec seam (the host owns the bytes;
`libentitycore_codec` does canonical ECF). Datalog facts carry only *small readable* ints
— chain depth (§9.1 floor), K-of-N counts, status codes — that fit trivially, so there is
**no integer head-form trap in the rule layer** (contrast the fixed-width-int peers that
carry the head form + `[2⁶³,2⁶⁴−1]` self-test). This is a consequence of the seam split:
wire integers are a codec concern, and the codec is host-side.

## Distinctness from the Prolog peer (protocol-generator/prolog/) — load-bearing

If this collapsed into Prolog's model the finding would be a re-run, not new. Ascent is
provably distinct on all three axes: **evaluation** — bottom-up semi-naive fixpoint
(facts → derive all consequences) vs. Prolog's top-down SLD resolution (goal → resolve
backward); **semantics** — set-oriented relations (no duplicates, no tuple ordering, no
answer-order dependence) vs. Prolog's ordered clause DB + first-solution/backtracking;
**control** — no cut, no backtracking, no negation-as-failure hazard, no clause-order
sensitivity, terminating by construction on a finite EDB vs. Prolog's cut/backtracking +
possible non-termination. The delegation closure is expressed the SecPAL/Binder way (a
monotone recursive rule to least fixpoint) — the trust-management-literature shape, a
distinct data point from Prolog's SLD walk. (A-DL-002.)

## GO-gate evidence (real build, capped container, 2026-07-16)

Built `containers/datalog-toolchain/` via `make datalog-toolchain` (PODMAN_BUILD_CAPS:
`--memory=4g --memory-swap=4g`). The baked build-time self-test
(`gogate/` + `gogate-selftest.sh`) ran in the REAL peer substrate (Rust + Ascent +
`libentitycore_codec`) and passed all three legs — this is why GO is evidenced, not
asserted from desk reasoning:

```
[1/3] DATALOG OK: recursive delegation closure -> fixpoint (7 tuples, incl. 1->4 depth-3)
[2/3] FFI SEAM OK: ec_sha256("abc") KAT byte-exact; provenance = c 0.1.0 / ecf-c-abi 1.1
                   / spec-data v7.71 / libsodium 1.0.22 (+ hand-rolled sha384; ed448 ...)
[3/3] TRANSPORT OK: TCP echo 8-bit-clean (10 bytes incl. 0x00/0xFF)
GO-GATE OK
```

## Pins (S11)

- **ascent 0.8.0** — crates.io newest, published **2025-03-02** (~16 months old at
  authoring 2026-07-16), far over the ≥30-day supply-chain floor. Fetched by cargo at
  build; the full transitive closure (`ascent_base`, `ascent_macro`, `syn`, `petgraph`,
  `hashbrown`, `indexmap`, `ahash`, `itertools`, `boxcar`, …) all compiled clean and gets
  pinned in the generated `Cargo.lock` at S2. `default-features = false` drops `par`
  (rayon/dashmap/once_cell): the host serializes requests, so the serial engine is smaller
  and deterministic.
- **rust/cargo 1.96.1-1.fc43** — fedora:43 `updates` distro build (reviewed channel →
  pin-for-repro).
- **libsodium 1.0.22-1.fc43** (static) — image-provided; the C-ABI codec statically +
  privately links it (verified in the GO-gate provenance string).

## Note — codec provenance version skew (non-blocking, A-DL-003)

The in-repo `entity-core-codec-ffi-c` builds a `libentitycore_codec.so` whose
`ec_impl_info()` reports `spec-data v7.71`, while this peer targets `v0.8.0` (V8). Per
AGENTS.md the **core wire is byte-unchanged across the V7→V8 cutover**, so the codec is
correct for the core surface; logged as a version-skew note for S2 to confirm (rebuild the
codec if a v0.8.0-stamped C-ABI build lands), not a blocker.
