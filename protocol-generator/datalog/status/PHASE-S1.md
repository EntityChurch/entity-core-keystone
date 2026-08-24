# entity-core-protocol-datalog — Phase S1 (Profile) Summary

**QUERY-NATIVE spec-discovery probe** (deductive-logic / bottom-up Datalog — the
trust-management-logic home turf; frontier bet alongside SQL) · **probe tier (‡,
seam-hybrid)** · started + completed 2026-07-16 · **Verdict: GO** (build-verified).

## What this S1 is (and is not)

A **SPEC-discovery probe, not a substrate probe**. The deliverable is co-equally (a) a
path to a green gate and (b) the **seam-split finding**: how much of the §5/§6.6 authority
interior stays expressible as genuine bottom-up Datalog RULES vs. leaks to the host seam.
Authorization/delegation IS a trust-management logic (SecPAL/Binder/DKAL are Datalog
dialects), so the §5.5 delegation-chain-as-recursive-rule should be a natural fit — the
probe measures exactly how natural, and where it stops. The **wrapper-guard** is the
central discipline: the authority interior must be authored as legible rules, not folded
behind one host call with the engine as decoration.

## GO-gate — RESOLVED: **GO** (2026-07-16, build-verified in the capped container)

Built `containers/datalog-toolchain/` via `make datalog-toolchain` (PODMAN_BUILD_CAPS
`--memory=4g --memory-swap=4g`). The baked build-time self-test (`gogate/` +
`gogate-selftest.sh`) ran in the **real peer substrate** (Rust host + Ascent engine +
`libentitycore_codec`) — GO is evidenced, not desk-reasoned. All three legs green:

| Gate leg | Result |
|---|---|
| 1. Embedded Datalog boots headless + evaluates a RECURSIVE rule to fixpoint | **PASS** — Ascent 0.8.0 `authorized(A,C) <-- granted(A,B), authorized(B,C)` → least fixpoint, 7 tuples incl. the depth-3 `1->4` transitive link. Proves the §5.5 recursive delegation mechanism. |
| 2. Host seam reaches `libentitycore_codec` (ec_sha256 KAT) | **PASS** — `ec_sha256("abc")` byte-exact vs. the NIST known answer; provenance `c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 / libsodium 1.0.22`. Proves the FFI seam links + calls. |
| 3. Socket 8-bit-clean echo incl. 0x00 / 0xFF | **PASS** — TCP echo returned all 10 bytes byte-identical (spanning 0x00…0xFF). Proves host-owned binary transport for framed CBOR. |

Embedded-vs-batch was decided WITH this evidence: the Rust+Ascent macro compiled the full
ascent closure in 8.6s and ran the fixpoint in-process — no per-request spawn, confirming
the embedded path the batch engines (Soufflé) would have taxed.

## Runtime decision (the S1 discrepancy, resolved)

The handoff §Feasibility suggested batch **Soufflé/CozoDB/Nemo**; the deep-dive recommended
**Rust + Ascent embedded**. Chosen: **embedded Ascent 0.8.0 in a Rust host.** Rationale in
`arch/PROFILE-RATIONALE.md §engine`:

| Candidate | Verdict |
|---|---|
| **Ascent (embedded, Rust)** | **CHOSEN** — genuine bottom-up/set-oriented/terminating; in-process (no spawn); Rust owns codec/crypto/socket → cleanest seam; rules stay legible (wrapper-guard). |
| Soufflé (batch, →C++) | Rejected — bottom-up ✓ but **batch**: per-request process-spawn / persistent-harness tax on a request/response peer. |
| CozoDB (embedded, Rust) | Rejected — whole embedded DB engine + CozoScript dialect; heavier seam than a macro. |
| Datafrog (Rust) | Rejected — low-level iteration library; "rules" are hand-written join loops → **fails the wrapper-guard legibility bar**. |
| Nemo | Rejected — existential-rule engine, heavier than the monotone Datalog this needs. |

## Decisions (all in profile.toml + arch/PROFILE-RATIONALE.md)

| Surface | Decision | Note |
|---|---|---|
| Engine | **Ascent 0.8.0**, embedded, `default-features=false` (serial) | 2025-03-02, ~16mo → S11-clean; `par` dropped (host serializes) |
| Host | **Rust 1.96.1-1.fc43** | fedora:43 `updates` (sibling's 1.96.0 aged out — re-pinned) |
| Codec/crypto | **FFI** over `libentitycore_codec` | the seam half; canonical CBOR + Ed25519/Ed448 + SHA delegated |
| Number-model tax | **host** | wire uint64 head-form is codec-side; rule-layer facts carry only small readable ints — no head-form trap |
| Authority interior | **authored as rules** | §5.2 verdict / §5.5 recursive delegation / §5.5a scope / §3.6 K-of-N / §6.6 resolution — legible, not folded |
| Seam boundary | host = sockets/framing/crypto/store/handshake; Datalog = the verdict logic | host establishes facts (verified_signer), Datalog derives allow |
| Concurrency | **host-owned** (Datalog stateless-fixpoint) | NOT a new §7b shape — documented, not a finding (per handoff) |
| Error model | verdict-fact (fail-closed = no derived allow) + host Result → 500 | §4.9(c) resilience frame catches host ROOT error class (cohort rule) |
| Distinctness | bottom-up/set-oriented/terminating vs. Prolog SLD | load-bearing (A-DL-002) |
| Tier / publish | **probe (‡)** / `0.1.0-pre` deferred | seam-hybrid, not a deployable independent peer |

## Container

`containers/datalog-toolchain/Containerfile` **authored AND built** (GO-gate green). Builds
`libentitycore_codec` from the in-repo C source (static libsodium 1.0.22), fetches Ascent
0.8.0, compiles the GO-gate crate, and runs the three-leg self-test FATAL-on-failure. Pins:
ascent 0.8.0 (registry, ≥30d), rust/cargo 1.96.1-1.fc43 (distro pin-for-repro), libsodium
1.0.22-1.fc43. Auto-discovered by the Makefile (`make datalog-toolchain`) with the caps.

## Ambiguity log

7 entries (A-DL-001..007). **No blocking-severity items.** Headline:
- **A-DL-001** — the engine decision (embedded Ascent), build-verified.
- **A-DL-002** — distinctness from Prolog (the finding depends on it).
- **A-DL-004/007** — the EXPECTED seam split (scope-match may need a host glob fact;
  §6.5 dispatch + §4 handshake leak to host) — the payoff findings the S3 agent confirms.
- **A-DL-003** — codec provenance v7.71 vs. target v0.8.0 (core-wire-unchanged; S2 verify).
- **A-DL-006** — mandatory K-of-N accept-path unit test (rejection-only oracle category).

## Exit criteria

profile.toml fully populated (no TBD-blocking; only `repository_url` empty, TBD-on-first-
publish — same as the other probe peers) · `arch/PROFILE-RATIONALE.md` written (one
paragraph per major choice + the GO-gate evidence) · container **authored and BUILT**
with a green three-leg GO-gate · ambiguity log has no blocking-severity items · the
new-for-this-probe `[expressibility]` section stubbed for S3. **S1 PASS — GO.**

## What S2/S3 need to know going in

1. **S2 (codec/seam):** the codec is FFI-delegated — author `src/codec_ffi.rs` as the
   `extern "C"` bindings to `libentitycore_codec` (the GO-gate already proved ec_sha256;
   extend to encode/decode/sign/verify/peerid). Confirm A-DL-003 (codec pin) + generate +
   commit `Cargo.lock` (full ascent transitive pin). No native CBOR to hand-roll — that is
   the whole point of the seam.
2. **S3 (the heart — author the authority interior):** author `src/authority.rs` as the
   `ascent! { ... }` rules for §5.2 verdict / §5.5 recursive delegation / §5.5a scope /
   §3.6 K-of-N / §6.6 resolution — **legible rules, under the wrapper-guard**. Fill in the
   profile `[expressibility]` section observed-vs-expected and log each finding to the
   ambiguity log AS YOU AUTHOR — the seam split is the deliverable. Host establishes facts
   (verified_signer, now, scope_covers); Datalog derives allow. Pre-resolve A-PD-016
   (ms-precision mints) + A-PD-017 (seed dual-form `["*","/*/*"]`) + frame-cap + the
   resilience frame → 500 + the K-of-N accept-path test.
3. **S4 gate:** `validate-peer --profile core` = 682·0F Result: PASS @ cc1970f +
   origination-core 3/3 + a genuine 2-of-3 multisig accept path + the 71-vector wire
   corpus. **REBUILD the oracle from entity-core-go HEAD** (`CGO_ENABLED=0 GOWORK=off`) —
   never trust a vendored stale validate-peer; verify new vectors compiled.
