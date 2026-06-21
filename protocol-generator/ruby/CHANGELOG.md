# Changelog — entity-core-protocol-ruby

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version-spelling note (the Ruby analogue of Common Lisp's A-CL-010).** The cohort release
> line is written `0.1.0-pre` in prose. RubyGems, however, treats a literal `-` in a version
> string as a `.pre.` separator, so `Gem::Version.new("0.1.0-pre")` canonicalizes to the
> malformed `0.1.0.pre.pre`. The RubyGems-idiomatic pre-release spelling is **dot-separated
> `0.1.0.pre`** (canonicalizes to itself; `.prerelease?` is true) — so the gem coordinate is
> `0.1.0.pre` while the CHANGELOG/README carry the cohort `0.1.0-pre` label. Verified in-container
> (Ruby 3.4.4 / RubyGems 3.6.7). See `status/SPEC-AMBIGUITY-LOG.md` A-RUBY-010.

## [0.1.0-pre] (gem coordinate `0.1.0.pre`)

**Tracks V7 ENTITY-CORE-PROTOCOL-V7 spec-data v7.75** (the COMPLETE ratified snapshot — the
register/outbound/emit §6.13 peer surface, §6.9a owner-cap, §7a conformance handlers AND the
§4.8 store-safety / §4.9 resilience / §4.10 resource_bounds substrate floor are all present as
ratified text, so this peer carries no snapshot-lag caveat). Codec corpus byte-identical
v7.73→v7.75 (SHA-verified in the spec-data MANIFEST).

First release line. Peer #12 (Ruby / MRI-CRuby), the **first dynamic / duck-typed / scripting
peer** and the **10th byte-compatible core impl** (after the Go/Rust/Python reference trio +
C#/TS/OCaml/Elixir/Common-Lisp/Zig/Swift/Haskell/Java), derived **spec-first** (no
sibling-language source). Not yet published — parked at `0.1.0-pre` pending architecture v0.1
sign-off + first external consumer (S5 promotion gate).

### Conformance
- `validate-peer --profile core`: **PASS** — 653 total / 291P / 268W / **0F** / 94S
  (machine-verified `summary.failed == 0`), oracle `entity-core-go @75c532e`. All 16 core
  categories 0-FAIL. (The 653 total vs the v7.75 8-peer-rerun's 576 is purely later-oracle
  extension categories — `relay`/`discovery`/`registry`/`published_root` — that auto-skip under
  `--profile core`; the FAIL gate and every core category are unchanged.)
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`, first full run, 0 codec fixes.
- origination-core: 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam cross-impl wire-proven).
- §9.5 53-type registry: 53/53 byte-identical (render-from-shapes; content_hash recomputed by the
  Ruby codec and asserted equal to the Go reference @75c532e, not ingested).
- `rake test`: 32 runs / 66 assertions / 0 failures (ECF 69/69 + agility 35/35 + smoke 11/11).

### Added
- Hand-rolled canonical-CBOR (ECF) codec: f16⊂f32⊂f64 float minimization (`Array#pack` has no
  half-float code, so f16 is assembled from the binary64 bits — A-RUBY-006), length-then-lex
  map-key sort on encoded key bytes, recursive major-type-6 tag rejection on decode, full
  0..2⁶⁴−1 head-form integer range. Ruby's **arbitrary-precision `Integer`** carries the full u64
  range with **no native-int trap** (the BEAM result, replicated — no `ulong`/int63/`bigint`
  workaround). Hand-rolled base58 (Bitcoin alphabet) + multicodec LEB128 varint (neither warranted
  a gem). Wire bytes are **ASCII-8BIT** (`String#b`) throughout — never UTF-8 for the codec core.
- **Ed25519 AND Ed448 sign/verify + SHA-256/384 native via stdlib `openssl`** (OpenSSL 3.x
  backend bundled with Ruby 3.4) — zero-dependency core, **no FFI, no libsodium/RbNaCl**. The
  generic PKey EdDSA surface (`OpenSSL::PKey.new_raw_private_key(alg, seed)` /
  `sign(nil, msg)` / `verify(nil, sig, msg)` / `raw_{private,public}_key`) reaches BOTH curve
  families — the **third native-full-agility substrate** after Elixir (`:crypto`) and Haskell
  (crypton), and the first via OpenSSL stdlib (A-RUBY-002, A-RUBY-003; byte-verified vs the
  v7.67 agility pins). Deterministic RFC-8032 signing → cross-impl signature byte-equality.
- §1.5 canonical-form peer_id construction (`hash_type=0x00` identity-multihash, digest = raw
  pubkey for ≤32 B keys), following the §1.5 v7.65 table — **not** the stale §7.4 SHA-256
  pseudocode. Lowercase hex everywhere (dodges the A-CL-009 uppercase address-space-path trap).
- §1.1 entity `data` modeled as an **arbitrary ECF value, not a `Hash`** — duck-typing makes this
  natural (`data` is "whatever ECF value"); corroborates A-JAVA-010 on a dynamically-typed peer.
- §4.1 handshake (three-check PoP), §6.5/§6.6 `send`-reflection dispatch ladder, capability
  authorization with chain attenuation + §5.7 delegation caveats + the §4.10(b) max-chain-depth
  (64) pre-check returning **400 `chain_depth_exceeded`**, type registry (53/53), in-memory
  address-space store with §3.9 CAS, §9.5a CORE-TREE get/put/CAS/delete + listing-omit deletion
  markers, the §6.13 register / §PR-8 granter frame / §6.9a owner-cap / §7a conformance surface.
- §4.10 resource_bounds: 413 `payload_too_large` (16 MiB) + 400 `chain_depth_exceeded`;
  connection-admission is the §4.10(c) SHOULD / external-layer carve-out (WARN, not a core MUST).
- §5.2 / §5.2a request verification as a three-way verdict
  (ALLOW / unauthenticated→401 / authenticated-but-unauthorized→403 / unresolvable-identity→401).
- Error model: a `StandardError`-rooted `EntityCore::Error` exception lattice (`CodecError`,
  `ProtocolError`, `TransportError`, …) — the dynamic-language exception idiom. Protocol status is
  carried as a **value record, never across an exception** (the cohort's status-as-value invariant).
- Concurrency (the GVL seam, A-RUBY-004): **thread-per-connection** under MRI's Global VM Lock —
  one reader `Thread` per socket, one `Thread` per inbound EXECUTE, a `pending {request_id =>
  Waiter}` map + `ConditionVariable` for the §6.11 reentrant demux, a per-connection write `Mutex`,
  `TCP_NODELAY` on every socket. The GVL is released on blocking IO, so the IO-bound peer is
  genuinely concurrent; the GVL does **not** make compound read-then-write atomic, so the §3.9 CAS
  store is an explicit `Mutex`-guarded critical section (proven by a 64-thread one-winner race).
  Ractors (true-parallel, share-nothing) declined as the wrong tool at core; noted as the
  parallelism escape hatch.

### Known limitations
- **RubyGems publishing deferred** — operator action after arch v0.1 sign-off. The gem id
  `entity_core_protocol` (snake_case, no redundant `_ruby` suffix; A-RUBY-005) must be confirmed
  non-squatted at first publish; fall back to `entity_core_protocol_ruby` if taken.
- Crypto-agility **full MATRIX** (the M2/M3/M6 cross-product corpus) is a cohort-wide deferral; the
  primitives (Ed448 + SHA-384) AND the M2/M3/M6 `root_cap` cap-token shapes are S2-byte-proven
  (A-RUBY-007), but the full agility matrix harness is not wired.
- Public API surface is documented (README §Use, the `EntityCore::*` tiers), not yet frozen with an
  explicit semver lock — Ruby has no module-private keyword, so freezing is a documentation +
  test-relocation pass deferred to publish-prep / first external consumer (the OCaml `.mli` / Zig
  `root.zig` / CL export-tier analogue).
- The suite's vendored codec corpus is `v7.71` (no `v7.75/` test-vector snapshot ships); the ECF +
  agility encodings are byte-identical v7.73→v7.75 (SHA-verified in the MANIFEST), and the live
  `--profile core` run is the version-authoritative superset, so the codec axis is wire-stable
  (A-RUBY-009). A `repository_url` is TBD until first publish.

### Toolchain pins (S11)
- **Ruby 3.4.4 (MRI/CRuby)** with the **bundled openssl gem 3.x** (OpenSSL 3.x backend; provides
  Ed25519 + Ed448 + SHA-2). Floor is Ruby `>= 3.2` (`Data.define` + openssl ≥ 3.0).
- **Minitest 5.25 + Rake 13.2** — dev-only DEFAULT gems (ship with Ruby), declared in the Gemfile;
  resolved from the system gem set with no network fetch (pull-once-then-offline posture). The core
  peer has **ZERO runtime gem dependencies**.

### Spec items surfaced (routed to architecture / operator)
- **No NEW spec-level defect.** The well is dry: Ruby reads the COMPLETE v7.75 snapshot and
  **corroborated** the inherited cohort findings (peer-id §1.5, 401/403 §5.2a, §4.10
  resource_bounds, A-JAVA-010 data-shape, the §7a conformance framing) **live against the oracle**
  rather than re-litigating them. The contribution is **idiom breadth + convergence evidence**
  (first scripting peer; native-full-agility on a 3rd substrate; the 12th-arrival `send`-reflection
  dispatch; arbitrary-precision-Integer int story) — not a new finding.
- **A-RUBY-010** RubyGems treats `-pre` as `.pre.pre`; the idiomatic spelling is dotted `0.1.0.pre`
  — packaging note (operator), the Ruby analogue of the CL A-CL-010 ASDF wrinkle. NEW (packaging).
- **A-RUBY-002 / -003 / -006 / -007 / -008** (RESOLVED) — Ed448 native / openssl raw-key API /
  f16-from-bits / root_cap cap-token shape / full 53-type floor.
- **A-RUBY-005** RubyGems id confirm-non-squatted — operator (S5 registry step).
- **A-RUBY-009** absent v7.75 test-vector snapshot + the deferred-gate-count note — research/operator
  (non-blocking; codec is wire-stable v7.73→v7.75, the live run closes the version question).
