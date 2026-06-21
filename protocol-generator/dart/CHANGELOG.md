# Changelog — entity-core-protocol-dart

All notable changes to this peer. Spec-version tracked literally per keystone lifecycle
(S5 §Version-pin). Format loosely follows Keep a Changelog.

> **Version note.** pub.dev uses SemVer directly, so `0.1.0-pre` is carried in the `pubspec.yaml`
> `version:` field as the SemVer pre-release form — no doc-only split like the CMake (`project VERSION`
> dotted-numeric) / ASDF (Common Lisp) peers needed. The release line is `0.1.0-pre`.

## [0.1.0-pre]

**Tracks ENTITY-CORE-PROTOCOL-V7 spec-data v7.75**, certified against the **v7.77** cohort oracle
(`e8524ed`; the core floor is byte-unchanged v7.75 → v7.77 — the v7.77 delta is entirely extension +
the V8-naming kebab fold, which this peer already satisfies). Codec corpus v0.8.0
(ENTITY-CBOR-ENCODING byte-identical v7.71 → v7.75, no wire change).

First release line. The Dart 3 **REACH peer** (Flutter cross-platform / Dart-ecosystem coverage),
derived **fresh** in S1 from the V7 spec as an **independent reader** (hand-rolled pure-Dart ECF codec,
NOT FFI into the sibling C-ABI codec, NOT the `cbor` pub package — A-DART-001) in Dart-native idiom:
sealed-class `Result` error model + exhaustive switch expression, `Future`/`async-await` on the
per-isolate event loop, `BigInt` uint64 head-form carrier (web-safe). Not yet published — parked at
`-pre` pending architecture v0.1 sign-off + first external consumer (S5 promotion gate) AND the pub.dev
verified-publisher-namespace operator step (A-DART-007).

### Conformance
- `validate-peer --profile core`: **PASS** — 665 total / 291P / 279W / **0F** / 95skip
  (machine-verified `summary.failed == 0`), on the **v7.77** oracle `e8524ed` with
  **`core_gate_sha256` matched** (`e09a865f…`) to the committed pin — exactly the cohort floor.
- Codec (S2): 69/69 byte-identical to `conformance-vectors-v1`.
- §9.5 53-type registry: 53/53 byte-identical (peer-side dual + live oracle `type_system_match`).
- §10.1 core-register gate: 10/10 PASS.
- origination-core: **3/3** over real two-peer TCP (`reference_connect` · `reference_ready` ·
  `dispatch_outbound_reentry` — the §6.11 reentry seam cross-impl wire-proven).
- multisig: **11/11** PASS, **0 skip** — genuine §3.6 K-of-N incl `valid_2of3_peer_signed_accepted`
  (the accept-path genuinely runs via the `--name conformance` persistent-identity surface).
- `concurrency` (§7b): 5/5 (4 PASS + 1 informational WARN — no parallel speedup on a single-threaded
  event loop, NOT a §6.11 violation). `resource_bounds` (§4.10): r1 413 / r2 400 PASS, r3 WARN.
- `dart test`: codec 69/69 corpus + Ed25519 KATs + 53-type byte-diff + two-peer loopback smoke +
  dart2js web-truncation proof — 0 failures.

### Added
- Hand-rolled canonical-CBOR (ECF) codec on `Uint8List`/`ByteData`: f16⊂f32⊂f64 float minimization,
  length-first-then-bytewise (CTAP2) map-key ordering, recursive major-type-6 tag rejection at any
  depth, hand-rolled LEB128 + Base58 (neither in the Dart core libs).
- **`BigInt` uint64 head-form carrier** (A-DART-006) — carries the full `0 .. 2⁶⁴−1` range web-safe
  (survives the 53-bit dart2js int truncation) AND native-correct. The headline portability call; the
  web-truncation behavior is locked by a `dart2js`-runtime test (A-DART-013).
- **Ed25519 sign/verify via `cryptography_plus` 2.7.1** (the maintained fork; A-DART-002/012) + the
  §1.5 raw-pubkey; SHA-256 via `package:crypto` 3.0.6 (first-party). Both pure Dart → self-contained on
  every Flutter target (no native lib). Deterministic RFC-8032 signing → cross-impl signature
  byte-equality.
- §1.5 canonical-form peer_id construction (Ed25519 → `hash_type=0x00` raw-pubkey identity-multihash),
  per the §1.5 v7.65 table, NOT the stale §7.4 pseudocode (A-DART-010). Seed-`0x11` peer_id
  byte-identical to the Kotlin / Java / CL peers. Lowercase `%02x` hex.
- §4.1 handshake, §6.5/§6.6 single-dispatch handler ladder, capability authorization with chain
  attenuation + §5.7 delegation caveats, type registry (render-from-model, 53/53), in-memory
  address-space store with CAS, §9.5a CORE-TREE get/put/CAS/delete + listing-omit deletion markers.
- v7.73/v7.74 peer surface: §6.13 register's normative writes, §PR-8 granter frame, §6.9a owner-cap
  bootstrap, §7a conformance handlers (`--validate`, off by default).
- v7.75 non-functional floor: §4.10(a) max-payload → 413, §4.10(b) chain-depth structural pre-check →
  400 (distinct from the 403 authz path), §7b store-safety **structural** via single-threaded
  event-loop confinement (A-DART-005 — no lock needed in-isolate).
- §5.2 request verification as a three-way verdict (ALLOW / AUTHN_FAIL→401 / AUTHZ_DENY→403).
- Error model: Dart-3 **sealed-class `Result`** matched by exhaustive switch expression
  (compiler-enforced; status carried as a value, never across an exception). Distinct from the
  TypeScript peer's exception choice (A-DART-004).
- Concurrency: `Future`/`async-await` on the per-isolate event loop. The transport carries an
  **O(1)-cursor frame reassembler + a connection-set lifecycle + accept backlog** (A-DART-016, the one
  genuine peer bug S4 surfaced and fixed — an I/O-path complexity bug under sustained-load / churn, not
  a spec defect; protocol semantics byte-identical).
- Standard host CLI surface (cohort convention, `bin/peer.dart`): `--name NAME` (load Ed25519 identity
  from `~/.entity/peers/NAME/keypair`), `--port N`, `--validate` (§7a handlers, off by default),
  `--debug-open-grants` (deprecated; degenerate `default→*` seed policy).
- pub.dev packaging (`pubspec.yaml`): `0.1.0-pre`, Apache-2.0, pinned deps, `repository`/`homepage`/
  `topics` metadata; `publish_to: none` parked-state guard. `dart pub publish --dry-run` green.

### Known limitations
- **pub.dev publishing deferred** — requires a verified pub.dev publisher namespace before the first
  `dart pub publish` (A-DART-007). The package is publish-ready; the deploy is an operator action.
- **Ed448 / SHA-384 crypto-agility deferred** (A-DART-003) — no maintained pure-Dart Ed448; an FFI
  route would break pure-Dart self-containment. The v0.1 target is the Ed25519 + SHA-256 §9.1 floor
  (69/69 byte-green). The full agility MATRIX harness is unwired.
- **Web/dart2js `BigInt` cost** — the web-safe uint64 carrier adds `BigInt` arithmetic on the hot
  codec path (overhead for native-VM-only consumers); the reach mandate (Flutter web included) makes
  the web-safe carrier the right floor (A-DART-006).
- Public API surface is documented (README §Use — the two Tier libraries), not yet frozen with an
  explicit visibility lock — deferred to publish-prep / first external consumer.
- The v7.73/v7.74/v7.75 peer-surface behavior is oracle-sourced against the v7.75 spec-data snapshot
  (the v7.76/v7.77 deltas are extension-only; the core floor is byte-unchanged).

### Toolchain pins (S11)
- **Dart SDK 3.11.6** (~45d at authoring → clears the ≥30-day floor; the 3.11
  line is the conservative pick — 3.12.x at ~24d is UNDER the floor and NOT picked). Fetched as the
  dart-lang official release tarball + verified sha256 (reviewed vendor channel; exact pin for repro).
  fedora dnf carries no current Dart SDK → pin-the-tarball (A-DART-011).
- **`cryptography_plus` 2.7.1** (~602d aged; pub.dev-pulled → ≥30-day floor met). The one non-first-
  party crypto runtime dep. Re-pinned 2.7.0 → 2.7.1 at S2 (2.7.0 does not exist on pub.dev — the S1
  sentinel fired; A-DART-012/014).
- **`crypto` 3.0.6** (first-party Dart-team SHA-256; long-stable ≫30d; BSD-3).
- **`package:test` 1.25.15** (first-party test runner; DEV-scope only, never shipped; ≥30-day met).
- Codec / Base58 / varint / conformance harness hand-rolled in-repo (no further registry deps);
  transitive deps locked in the committed `pubspec.lock`.

### Spec items surfaced (routed to architecture)
No NEW spec defect surfaced — corroboration-only, exactly as the reach-peer mandate predicted (the
sealed-Result and wide-integer idioms were saturated by Kotlin / TypeScript). All `A-DART-*` items are
recorded decisions, corroborations, or local resolutions; full text in
`status/SPEC-AMBIGUITY-LOG.md`:
- **A-DART-010** §7.4-vs-§1.5 peer-id form — **corroboration only** (already reconciled in the v7.75
  body; pinned proactively). Earlier surfaced by Zig/OCaml/CL/Java/Kotlin.
- **A-DART-006** uint64 head-form carrier = `BigInt` — the web/dart2js 53-bit-int truncation trap;
  the load-bearing portability decision (corroborates the TypeScript-`bigint` lesson). Local.
- **A-DART-016** (RESOLVED at S4) transport I/O-path complexity bug (O(n²) reassembly + connection
  leak under sustained-load/churn) — local fix; an I/O-path bug, not a spec defect.
- **A-DART-015** (RESOLVED at S4) §6.11 reentry inner-200 is the validator's cross-peer cap, confirmed
  via origination-core `dispatch_outbound_reentry`.
- **A-DART-002 / -003 / -012 / -014** crypto floor (maintained-fork pick) + Ed448 defer + the
  2.7.0→2.7.1 re-pin — recorded decisions / local, no spec change.
- **A-DART-007** pub.dev publisher namespace — packaging note (operator).
- **A-DART-001 / -004 / -005 / -008 / -009 / -011 / -013** recorded decisions (codec strategy / error
  model / async idiom / spec version / §7a-§7b scaffolding / container / dart2js proof) — local, no
  spec change.
