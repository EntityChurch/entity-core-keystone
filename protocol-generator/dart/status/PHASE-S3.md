# entity-core-protocol-dart — Phase S3 (Peer machinery) Summary

**Release "reach" peer** (Dart 3 — Flutter cross-platform / Dart
ecosystem reach; corroboration-only) · **Status: COMPLETE — two-peer loopback 12/12, units
all green (multisig accept-path + type-registry 53/53 + codec 69/69 + selftests), `dart
analyze --fatal-infos` clean, AOT host boots + `--name` keypair load works. No new spec
defect (reach-peer prediction held).**

S3 builds the V7 Layer 1–4 + foundation peer machinery on top of the S2 codec (still 69/69
byte-identical). Native Dart-3 idiom per `profile.toml`: `enum` verdicts matched by
exhaustive `switch`, `final`-field value types with content_hash-based `==`, `Future`/`async`
dispatch + reentry on the single per-isolate event loop, `cryptography_plus` Ed25519 +
`package:crypto` SHA-256. This is an INDEPENDENT Dart reading; the **Kotlin** peer
(sealed-Result + coroutines) was the closest structural analogue and the reference for the
two up-front mandates that made Kotlin 0-fix at S4.

## Result headline

- **Two-peer loopback smoke — 12/12 PASS** (`smoke_test.dart`, real TCP between two Dart
  peers): handshake both legs; unregistered→404; granted tree-get→200 +
  system/handler/interface result; capability request→200; **8/8 request_id demux** (N7);
  register live-hook→200 (not 501); emit hook fires on register's tree writes (§6.13(c));
  §7a echo→200 + verbatim; **§6.11 dispatch-outbound reentry round-trips over the inbound
  connection** (B→A echo, outer 200; inner verdict = A's §5.2 cap check, A-DART-015).
- **Genuine multi-sig K-of-N accept-path — PASS** (`multisig_accept_test.dart`): 2-of-3 →
  ALLOW (M3/M4/M6) + the deny flips the rejection-only oracle cannot cover (below-threshold
  M4, duplicate-sig-no-inflate M4, local-not-in-signers M6, threshold=1 M3, duplicate-signers
  M3, off-root M3) + single-sig superset unregressed.
- **Type-registry — 53/53 PASS** (`type_registry_test.dart`): the full §9.5 core floor renders
  + binds at `system/type/{name}`, each a 33-byte ecfv1-sha256 hash, render deterministic.
- **S2 codec regression — 69/69 byte-identical** + the beyond-corpus selftests — unchanged.
- **`dart analyze --fatal-infos`: No issues found** (lib + bin + test, the linter as a build
  gate). AOT host (`dart compile exe bin/peer.dart`) compiles + boots (`LISTENING <port>` /
  `PEER <id>`); `--name` loads the on-disk PEM keypair from `~/.entity/peers/NAME/keypair`.

## What was built (`protocol-generator/dart/lib/src/peer/` + `bin/`)

| Surface | Files | Notes |
|---|---|---|
| **L1 Identity** | `identity.dart`, (S2 `crypto/ed.dart` / `peer_id.dart`) | §1.5 identity-multihash peer_id from RAW pubkey; `Identity.ofSeed`/`sign` async (Ed25519 is `Future`). system/peer + system/signature integrated with the codec. (No seed→pubkey gap — cryptography_plus gives `rawPublicKeyFromSeed`.) |
| **L2 Interaction** | `wire.dart`, `envelope.dart`, `entity.dart`, `dispatch.dart` | EXECUTE / EXECUTE_RESPONSE only (§3.3); typed builders/parsers; 4-byte-BE length-prefix framing; §6.11 request_id demux; §4.10(a) 16 MiB max-frame reject before body buffer. `included` content_hash-MAP dedup on emit (mirror of A-KT-010). |
| **L3 Capability** | `capability.dart` | §5.2 `verifyRequest` (3-way `enum` verdict), §5.5 chain-walk + sig verify (async), §5.6 attenuation, §5.7 caveats, §5.1 revocation, §PR-8 granter-frame, §4.10(b) `chainExceedsDepth` pre-check (→ 400, distinct from 403). **Genuine §3.6 M3 multi-sig K-of-N** (granter union; M3 structure before sig counting; §5.5 M6 local∈signers + M4 distinct-signer quorum; root-only). |
| **L4 Bootstrap** | `transport.dart` | TCP listener + dialer (`dart:io` async sockets, TCP_NODELAY); §4.8 inbound-concurrent-with-outbound (inbound EXECUTE dispatched without inline await on the same event loop); §6.11 reentrant transport with `Map<String, Completer<Envelope?>>` demux. **No blocking-read trap** — Dart sockets are stream-based, so the §7b "blocking I/O on a cooperative pool" axis simply does not arise. |
| **Foundation** | `store.dart`, `peer.dart`, `core_types.dart` | content store + entity tree (§1.7); §6.10 emit pathway (live with zero consumers); §6.6 handler resolution; `Handler` interface (`async`); the §6.5 dispatch chain; the 53-type §9.5 core floor. Store is SYNC-only → §4.8 atomic by event-loop confinement (no `await` inside a critical section). |
| **Handlers** | `peer.dart` (`_OpsHandler` op-tables) | connect (hello/authenticate), tree (get/put), handler (register/unregister — §6.13(a) live), capability (request/delegate/revoke/configure), type (validate). |
| **§6.9a bootstrap** | `peer.dart` | self-owner cap (detached-sig L0) + default scope-template; authenticate dual-form policy lookup ∪ §4.4 floor; `--debug-open-grants` = degenerate `default→*`. |
| **§7a conformance** | `peer.dart` (`--validate` opt-in, OFF by default) | `system/validate/echo` + `system/validate/dispatch-outbound` (the §6.11 reentry originator). |
| **Host** | `bin/peer.dart` (AOT-compiled for S4) | `--port`/`--seed`/`--name`/`--debug-open-grants`/`--validate`; prints `LISTENING <port>` + `PEER <id>`; `--name` loads the on-disk PEM keypair (multisig accept-path probe). |
| **Barrel** | `lib/entity_core_peer.dart` | the peer surface export (separate from the S2 codec barrel `entity_core_protocol.dart`). |

## The TWO "build it right the first time" mandates — GENUINELY built

1. **§3.6 K-of-N multisig WITH an accept-path test.** `_verifyMultiSigRoot` is a real
   implementation: granter union (single `system/hash` bytes | `{signers, threshold}` map,
   root-only); §3.6 M3 structure (root-only, n≥2, 2≤threshold≤n, distinct signers) BEFORE sig
   counting (precedence 25); then §5.5 M6 (local ∈ signers) + M4 (DISTINCT-signer valid-sig
   count ≥ threshold — the K-of-N replay defense). Single-sig path byte-identical (strict
   superset). The accept-path unit test exercises the ALLOW direction the rejection-only
   `multisig` oracle cannot reach — the genuine cross-impl proof. **PASS.**
2. **§6.11 reentry-capable transport + §7a handlers UP FRONT.** The transport demuxes by
   request_id so an inbound EXECUTE handler can originate an outbound EXECUTE back to the
   caller over the SAME inbound connection. `dispatch-outbound` originates B→A over the
   inbound connection (validator = B-role, NOT a third-peer dial). The smoke round-trips it
   end-to-end (outer 200). This is the from-zero-transport trap (OCaml/COBOL) avoided.

## Idiom notes (Dart-native shapes; how it diverges from Kotlin #closest-analogue)

- **Verdicts/dispatch:** `enum Verdict`/`RequestVerdict` matched by exhaustive `switch` at the
  single dispatch site; handler op-routing is an `_OpsHandler` op→function table (the
  Dart-idiomatic `match op` ladder; absent-key → 501). Failures are VALUES (`Outcome` with a
  status) — the sealed-result error model.
- **Async:** `Future`/`async` on the single per-isolate event loop — `async` handlers + a
  `Map<String, Completer<Envelope?>>` request_id demux + inbound EXECUTE dispatched WITHOUT
  inline await (the §4.8/§6.11 reentry awaits without stalling the reader). NO dedicated reader
  threads needed (vs Kotlin's coroutine + OS-thread split) — `dart:io` sockets are non-blocking
  streams, so the §7b blocking-read rule has nothing to move.
- **Store-safety (§4.8/§7b):** event-loop confinement — every store op is fully synchronous, so
  a read-modify-write never yields; concurrent inbound dispatches interleave only at `await`
  points, never inside a store op. The cleanest §7b point alongside the actor peers; A-C-009 is
  N/A (GC'd + single-threaded per isolate).
- **Value types:** `final`-field classes with content_hash-based `==`/`hashCode` (no `data
  class` keyword); `Entity`/`Identity`/`Envelope`/`Included` defensively copy their `Uint8List`
  (`no_byte_array_aliasing`). Nullability in the type system (`T?`), no `Optional`.
- **Entity construction is SYNC** (content_hash is a pure SHA-256 over the S2 encoder); only
  signing/verifying (Ed25519) are async — the codec surface stays synchronous as the profile
  declares.

## Ambiguities logged (this phase)

`SPEC-AMBIGUITY-LOG.md` — corroboration-only / bookkeeping (no new spec defect, as the
reach-peer mandate predicted):
- **A-DART-014** profile-text crypto pin reconciled 2.7.0 → 2.7.1 (the S2 carry-forward
  discharged; profile text now == lock == pubspec == prefetch).
- **A-DART-015** §6.11 dispatch-outbound smoke inner-verdict is a §5.2 cap check (403 at the
  smoke; S4's validator supplies the cross-peer reentry cap for inner-200 — same scoping as
  the Kotlin A-KT-012).

The S2 carry-forward watches are all DISCHARGED: §4.10(b) chain-depth pre-check (P5); §5.2a
trichotomy (P3); general entity `data` (P4); TCP_NODELAY (P6); event-loop confinement (P6);
the profile 2.7.1 reconciliation.

## What S4 must watch

- **Re-verify §1.5 peer_id construction against the live handshake oracle** — exercised green
  in the loopback (both legs); S4 runs it vs `entity-peer`.
- **The §6.11 `dispatch_outbound_reentry` origination-core gate** — the transport seam is built
  + smoke-proven; S4's validator (B-role) supplies the cross-peer reentry cap for the inner-200
  round-trip (A-DART-015). The from-zero transport trap is avoided.
- **Multi-sig accept-path** — the unit test proves genuine K-of-N; S4's
  `valid_2of3_peer_signed_accepted` runs via `--name` (the host loads the on-disk keypair).
- **§7b `concurrency` + `resource_bounds` gates** — store-safety (event-loop confinement),
  max-payload 413, chain-depth 400 are built in; S4 scores them.
- **AOT exe is the S4 host** — `dart compile exe bin/peer.dart` (per profile [build]); verified
  to boot + bind + load `--name`. S4 should AOT-compile fresh in the run-s4 image.
- **Ed448/SHA-384 agility higher-bar remains deferred** (floor first; A-DART-003).

## Exit criteria

Two-peer loopback **12/12** byte-faithful · multisig accept-path PASS · type-registry 53/53 ·
S2 codec 69/69 unchanged · `dart analyze --fatal-infos` clean · AOT host boots + `--name`
keypair load works · profile 2.7.1 reconciliation done · no blocking ambiguities · no
sacred-tree writes (only `protocol-generator/dart/` in the `lang/dart` worktree). **S3 PASS.**
