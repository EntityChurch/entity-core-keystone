# Changelog — entity-core-protocol-odin

All notable changes to this peer. Spec-version tracked literally per the keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note:** Odin has no package manager and no version grammar to satisfy — there is
> nothing analogous to a `Cargo.toml`/`package.json` version field to carry `0.1.0-pre`. The
> marker lives here + in README.md only. `make dist` stamps the tarball name from `VERSION`
> (default `0.1.0-pre`).

## [0.1.0-pre]

**Tracks Entity Core v0.8.0 (V8)** spec-data (`protocol-generator/shared/spec-data/v0.8.0/`);
**codec corpus v0.8.0**. The core wire contract is byte-unchanged across the V7→V8 cutover.
Oracle pin: **`entity-core-go @cc1970f`**.

First release line. **The cohort's data-oriented / no-exceptions / no-package-manager probe**
(Odin `dev-2026-06:285f6d8`: fixed-width ints, manual `context`-allocator memory, value-return
error handling). Derived spec-first from the pinned v0.8.0 (V8) snapshot with a **native
pure-Odin crypto floor** — `core:crypto/ed25519` + `core:crypto/sha2`, FFI-free — and a
hand-rolled canonical CBOR byte-layer. Not yet published — parked at `-pre`, registry-publish
deferred like the rest of the cohort (OCaml / Elixir / CL / Forth / Rexx), pending architecture
v0.1 sign-off + a first external Odin consumer (the S5 promotion gate).

The probe's payoff is **generator robustness on a fresh syntax / packaging / error-idiom shape**
(no-exceptions value-return errors, no-GC context allocators, no package manager) plus a
**native pure-Odin crypto corroboration** (a fresh independent RFC-8032 re-derivation of the
same Ed25519 signatures). Per ADR-0012 a green verdict is **cohort-consistent, not independent
convergence** — the oracle + type vectors are the Go author's artifacts.

### Conformance
- `validate-peer --profile core`: **Result: PASS** — **682 total · 292P / 294W / 0F / 96S**
  (all 96 skips are §9.0 auto-allowlisted extension carve-outs; 0 fail-counting), oracle
  `entity-core-go @cc1970f` (core-gate fingerprint `8261a033…`, vectors confirmed compiled).
  Every live core-profile category is 0-FAIL. The 3 warns are benign (non-floor extension types
  a core peer correctly omits; §4.10(c) r3_connection_flood admission SHOULD; the validator's
  own cleanup step) — none mask a failure.
- Codec (S2): **71/71** byte-identical to `conformance-vectors-v1` — pure-Odin canonical ECF;
  content_hash + signature legs use native `core:crypto/{sha2,ed25519}`. Fixed-width u64
  `[2^63, 2^64-1]` boundary head-form self-test. Leak-clean under `mem.Tracking_Allocator`.
- §9.5 53-type floor: **53/53** byte-identical (render-from-model, asserted equal to the Go
  reference — not ingested).
- S3: two-peer loopback smoke **7/7** (in-process raw-thread transport + real loopback TCP),
  leak-clean.
- multisig: genuine 2-of-3 M3+M4+M6 with a positive accept-path
  (`multisig_k_of_n_accept_and_deny_flips`) — proves the primitive is implemented, not just
  fail-closed.

### Added
- **Pure-Odin canonical CBOR / ECF byte-layer** (`src/cbor.odin`, `varint.odin`, `base58.odin`,
  `peer_id.odin`, `hash.odin`, `signature.odin`, `model.odin`): shortest-float ladder
  (f16/f32/f64, f16 leg + shortest-form ladder hand-rolled), recursive major-type-6 tag reject
  at every node, length-then-lex key sort, minimal-head re-validation, dup-key / UTF-8 /
  trailing-byte reject, N4 entity byte-fidelity, Base58 via byte-wise long division (no bignum).
- **Native pure-Odin crypto floor** (`src/signature.odin`, `src/hash.odin`): Ed25519
  sign/verify/seed→pubkey (`core:crypto/ed25519`, RFC 8032) + SHA-256/384/512
  (`core:crypto/sha2`) — source-verified FFI-free. Gated by two independent KATs beyond the
  corpus (all-zero-seed corpus signature + RFC 8032 §7.1 vector 1).
- **Raw-thread transport + peer machinery** (`src/store.odin`, `entity.odin`, `wire.odin`,
  `identity.odin`, `capability.odin`, `type_defs.odin`, `peer.odin`, `transport.odin`): §6.5/§6.6
  dispatch, §5 capability chain-walk + authz trichotomy + §3.6 multisig, Mutex-guarded §4.8
  store, §1.6 length framing + §4.10(a)/(b) floor, §6.11 request_id reentry demux
  (`{request_id → waiter}` + `sync.Cond`), §9.5 53-type render-from-model floor.
- §7a conformance handlers (`--validate`): `system/validate/echo`,
  `system/validate/dispatch-outbound`.
- `host/host.odin` host driver: `bin/entity-core-peer --port`, `--name` (Ed25519 identity from
  `~/.entity/peers/NAME/keypair`), `--validate`, `--debug-open-grants`. Prints `LISTENING <port>`.
- **`make dist`** source-tarball packaging (`make build`/`test`/`clean` container wrappers).

### Known limitations / honest notes
- **Ed448 / crypto-agility higher bar deferred** (cohort-wide): the Ed25519 + SHA-256/384 floor
  is byte-proven; `core:crypto` has no Ed448 signature scheme (verified absent). The future
  path is hybrid-FFI via `libentitycore_codec` (`ec_ed448_*`) bound with `foreign import` as an
  opt-in sub-package — a documented non-v0.1 item, not a gap (A-ODIN-002).
- **The native crypto floor is unaudited by design** (A-ODIN-004): `core:crypto` self-declares
  no independent third-party review and assumes 64-bit — an operator note, oracle-gated by the
  KATs, with a libsodium `foreign import` drop-in available if an audited floor is required.
- The compiled binaries (`bin/entity-core-peer`, `bin/smoke`), the C-ABI oracle ELFs
  (`output/s4-oracles/`), and `dist/` are gitignored build outputs — sources + run scripts are
  committed.
- No package registry / no version-grammar field (see the version note).

### Spec items surfaced (logged in status/SPEC-AMBIGUITY-LOG.md)
All 11 items **A-ODIN-001..011** are resolved at their stage or research-owned
(generator-robustness); **none are open spec findings**. On the current saturated wire surface
the data-oriented / no-exceptions probe surfaced no fresh spec-precision issue — clean
corroboration end to end, the answer the profile was built to get. Durable cross-peer lessons
banked: A-ODIN-009 (a raw-thread store must pin ONE allocator, not the calling thread's context,
or it double-frees at destroy), A-ODIN-010 (Odin slice compound literals rendered in place —
stack-temp lifetime trap). **Owner: operator/research** (no arch escalation outstanding).
