# Changelog — entity-core-protocol-go

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

## [0.1.0-pre]

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.75. Codec corpus v0.8.0 (byte-identical
across the v7.56→v7.71 window — the ECF corpus did not change; A-GO-005).**

First release line. **Clean-room Go peer**, derived from the V7 spec + the keystone
`shared/lifecycle` contracts + the cohort's language-neutral sibling profiles — and,
critically, **NOT** from `entity-core-go` (the oracle's own source). Go *is* the reference
oracle's language; this peer's value is being an independent reimplementation that
byte-agrees with the oracle. Not yet published — parked at `-pre` pending architecture v0.1
sign-off + first external consumer (S5 promotion gate). Distribution is a git tag consumers
`go get` by module path + checksum (no central registry).

### Toolchain pins (S11)
- **Go 1.25.10** — from `containers/go/Containerfile` (fedora `golang-1.25.10`, dnf/distro
  channel — a reviewed channel, so the ≥30-day age floor relaxes to "pin exactly for repro").
  Satisfies `entity-core-go`'s declared `go 1.25.0` minimum. `crypto/ed25519` + `crypto/sha256`
  + `crypto/sha512` are stdlib and pinned by the toolchain.
- **Zero third-party modules** — the whole peer is stdlib-only; `go.sum` is empty. The single
  pin is the Go toolchain version.

### Conformance
- `validate-peer --profile core` (oracle `entity-core-go` `75c532e`): **PASS** — 653 / 291P /
  268W / **0F** / 94skip (machine-verified `summary.failed == 0`; 0 FAIL-severity records).
  An independent stdlib-only Go peer reaches the same 0-FAIL fixed point as the Go oracle and
  the cross-language cohort.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first run, 0 codec fixes.
- §9.5 53-type registry: 53/53 byte-identical (`TestCoreTypeRegistryByteIdentical`,
  render-from-model through the peer's own codec), first run.
- origination-core: 3/3 PASS (`reference_connect`, `reference_ready`,
  `dispatch_outbound_reentry` over real two-peer TCP, §6.11 reentry).
- S3 loopback smoke: 11/11 (incl. 8-way concurrent `request_id` demux). `go build` / `go vet`
  / `gofmt -l` clean.

### Added
- Hand-rolled canonical-CBOR (ECF) codec (`internal/cbor`): f16 ⊂ f32 ⊂ f64 shortest-float
  minimization (enforced on encode AND decode), length-then-lex map-key sort on encoded key
  bytes, definite lengths, no-duplicate-keys, recursive major-type-6 tag rejection on decode
  → `400 non_canonical_ecf`. LEB128 varints (`internal/varint`) + Base58 (`internal/base58`),
  both hand-rolled (neither in stdlib).
- CBOR head-form integer carrier over native `uint64`/`int64` — full §3.2 0..2⁶⁴−1 / −1..−2⁶⁴
  range with no BigInt and no 63-bit trap (A-GO-003).
- Ed25519 identity, deterministic signatures (`crypto/ed25519`); SHA-256 (`crypto/sha256`),
  SHA-384 agility hashing (`crypto/sha512`). Canonical identity-multihash peer_id
  (`hash_type=0x00`, §1.5; lowercase `%02x` hex tree-paths).
- Handshake, dispatch, capability authorization with chain attenuation; the §9.5 53-type
  registry (render-from-model, 53/53 byte-identical); CORE-TREE get/put/CAS/delete; the §10.1
  register-then-dispatch round-trip; the §7a `system/validate/*` opt-in conformance handlers.
- Error model: explicit `(T, error)` returns; sentinel + typed errors wrapped with `%w`,
  discriminated via `errors.Is` / `errors.As` (never string-match); typed error → status code
  (400/401/403/413) at the dispatcher boundary. `panic` only for unreachable invariants;
  `recover` at goroutine boundaries so one bad connection never crashes the peer (§4.9).
- Concurrency: goroutines + channels; one reader goroutine per connection; `request_id` →
  channel demux; `sync.RWMutex`-guarded store (race-safe from S3 — the Zig/CL store-race
  lesson, pre-resolved); `SetNoDelay(true)` on every connection (§7b throughput floor);
  `context.Context` threads cancellation/deadlines (§6.11).

### Known limitations
- **Ed448 / crypto-agility higher bar unsupported** — Go's stdlib has no Ed448 and
  `golang.org/x/crypto` has none either; no audited pure-Go Ed448 in a reviewed channel exists
  (no BouncyCastle-equivalent). A-GO-002, mirroring Zig A-ZIG-002 / OCaml A-OC-002. Planned:
  hybrid native-Ed25519 + FFI-Ed448 via cgo (consume `libentitycore_codec` for the Ed448 family
  only) when agility enters scope. Does NOT affect the ECF/Ed25519 conformance floor.
- `go test -race` did not complete in-env (the cgo race-detector build stalled on host go 1.24
  and in-container past timeout) — **non-gating**: store safety is structural (`sync.RWMutex`)
  and exercised live by the oracle's `concurrency` category (5/5 PASS, incl. the §7b T2.1
  sustained-load store-race probe). See [`status/PHASE-S4.md`](status/PHASE-S4.md).
- Public API surface is documented (README §Use, godoc), not yet frozen with an explicit
  semver lock — deferred to publish-prep / first external consumer.

### Spec items surfaced (routed to architecture)
- **A-GO-006** §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403)
  request-time boundary. Implemented as a 4-way verdict (401 authn-fail / 403 authz-deny /
  401 unresolvable-grantee / 400 chain-depth). The **notable independent signal**: a clean-room
  Go peer, built from the spec NOT the oracle, lands on the SAME trichotomy the spec-first cohort
  hit (Zig A-ZIG-006 / OCaml A-OC-008 / arch F20) — now 5+ independent peers converge. Records
  the Go peer's corroboration so the convergence count is visible; not a new ask.
- **A-GO-007** the live `--profile core` total at `75c532e` is 653, not the docs' 576 — the
  delta is entirely non-failing newer-category skips + a wider `type_system` probe (vector/total
  reproducibility note to keystone; not a blocker — the binary gate is `failed == 0`).
- A-GO-001 (codec library rejected for hand-roll), A-GO-003 (`nint` carrier), A-GO-004
  (module-path placeholder), A-GO-005 (corpus version skew) — local/informational, owner-routed.
