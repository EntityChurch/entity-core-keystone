# Phase S5 — Publish (entity-core-protocol-dart)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` (carried directly in `pubspec.yaml` `version:` — pub.dev's
native SemVer pre-release form; no doc-only split). · **Spec basis:** V7 spec-data v7.75, certified
against the v7.77 oracle `e8524ed` (core floor byte-unchanged v7.75 → v7.77); codec corpus v0.8.0.

S5 polishes the S4-conformant Dart 3 **REACH peer** into a *ready-to-publish* artifact.
`/entity-rosetta` never publishes (lifecycle §Publishing) — this phase produces the artifacts + the
runbook; an operator publishes when arch signs off v0.1 AND a pub.dev publisher namespace is verified.
This doc is the release-readiness record + the operator handoff.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 665 / 291P / 279W / **0F** / 95skip, machine-verified `summary.failed == 0` (`status/CONFORMANCE-REPORT.{md,json}`), on the v7.77 oracle `e8524ed` with `core_gate_sha256` matched (`e09a865f…`) — exactly the cohort floor. |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| §10.1 core-register gate | ✅ | 10/10. |
| multisig genuine K-of-N | ✅ | 11/11, 0 skip — `valid_2of3_peer_signed_accepted` genuinely runs via the `--name conformance` persistent-identity surface (not a vacuous skip). |
| concurrency (§7b) + resource_bounds (§4.10) | ✅ | concurrency 5/5 (4 PASS + 1 informational WARN — single-threaded event loop, not a §6.11 violation); resource_bounds r1 413 / r2 400 PASS, r3 WARN (SHOULD). |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors`. |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (peer-side dual + live oracle `type_system_match`). |
| Ed25519 RFC-8032 KAT | ✅ | `cryptography_plus` sign/verify byte-equal; §1.5 raw-pubkey → cohort-canonical seed-`0x11` peer_id `2KHoAk…` (byte-identical to Kotlin/Java/CL). |
| `dart test` clean | ✅ | codec 69/69 + Ed25519 KATs + 53/53 type-diff + two-peer loopback smoke + dart2js web-truncation proof, 0 failures (carried from S2–S4). |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0; holder `Entity Core Protocol contributors` — cohort convention, matches the other peers). pub.dev auto-detects the file. |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, verdict + reproduce + the byte-identity proof; conformance line links `status/CONFORMANCE-REPORT.md`). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.75, certified @ v7.77 e8524ed`. |
| Package metadata (`pubspec.yaml`) | ✅ | `name: entity_core_protocol`, `version: 0.1.0-pre`, description, `environment.sdk: ^3.6.0` (consumer floor; built on pinned 3.11.6), pinned deps (`cryptography_plus: 2.7.1`, `crypto: 3.0.6`, `test: 1.25.15` dev), Apache-2.0, `repository`/`homepage`/`documentation`/`issue_tracker`/`topics`. `publish_to: none` parked-state guard. |
| `pubspec.lock` coherent | ✅ | committed; `dart pub get --offline` matches it exactly (no drift; transitive deps locked). |
| Version pin | ✅ | parked `0.1.0-pre` (cohort norm). pub.dev carries the `-pre` qualifier directly (contrast the CMake/ASDF dotted-numeric peers — no doc-only split). |
| Toolchain pin (S11) | ✅ | Dart SDK **3.11.6** (official tarball, SHA-256-pinned); `cryptography_plus` 2.7.1 / `crypto` 3.0.6 / `test` 1.25.15 all ≥30-day-aged (test dev-scope). Pins mirrored in `containers/dart-toolchain/prefetch/pubspec.yaml`. |
| `dart pub publish --dry-run` | ✅ (offline-validated) | Package validates clean — full file listing + structure + license + version + deps all pass; **0 warnings, 0 errors**. The ONLY non-pass is the final pub.dev existence query (`Got socket error … at https://pub.dev`), which needs network — expected under `--network=none`, documented not run online (§3). |
| Public API surface | ◑ documented | two Tier libraries in README §Use (`entity_core_protocol` Tier 1 codec/crypto, `entity_core_peer` Tier 2 peer); internal `lib/src/...` units may churn without a semver bump. Explicit visibility freeze deferred to publish-prep / first consumer (the Kotlin `@PublishedApi` / OCaml `.mli` analogue). |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; all `A-DART-*` resolved-in-peer / corroboration / operator-owned. **No NEW spec defect** (reach-peer corroboration-only). No new S5 ambiguity (none expected; none arose). |
| **Published to pub.dev / tagged** | ⛔ **deferred** | operator action — requires verified pub.dev publisher namespace (A-DART-007) AND arch v0.1 sign-off (§4). No auto-tag, no push, no deploy. |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not yet met** (no
Dart/Flutter consumer wired). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **pub.dev package** — `entity_core_protocol:0.1.0-pre` (`pubspec.yaml`), pure Dart, two import
  tiers (`entity_core_protocol` codec/crypto; `entity_core_peer` full peer + transport). **Pure-Dart,
  self-contained on every Flutter target (iOS / Android / web / desktop) — no native library to
  ship** (the headline reach value). The **one** non-first-party runtime dependency is
  `cryptography_plus` (pure-Dart Ed25519); `crypto` is first-party Dart-team SHA-256; `test` is
  dev-scope (never shipped). The codec, Base58, LEB128 varint, content-hash, peer-id, dispatch,
  capability authz, type registry, CORE-TREE surface, resource-bounds, and concurrency gate are all
  hand-rolled in `lib/src/`.
- **Crypto: pure-Dart floor, no FFI.** Ed25519 sign/verify + §1.5 raw-pubkey via `cryptography_plus`;
  SHA-256 via `package:crypto`. Ed448 / SHA-384 **agility is deferred** (A-DART-003) — no maintained
  pure-Dart Ed448, and an FFI route would break the pure-Dart self-containment; the v0.1 target is the
  §9.1 floor.
- **`BigInt` uint64 head-form carrier** (A-DART-006) — web-safe (survives the 53-bit dart2js int
  truncation) AND native-correct; the load-bearing portability decision, locked by a dart2js test.
- **Host executable** (`bin/peer.dart`, the S4 conformance driver — `--name`/`--port`/`--validate`/
  `--debug-open-grants`; emits `LISTENING …`). Test/conformance only — not the published library
  surface (it is included in the archive as `bin/` but is a driver, not the API).

---

## 3. Packaging notes specific to Dart

- **Single registry, single manifest.** Dart has one central registry (pub.dev), so packaging is just
  `pubspec.yaml` — no multi-registry recipe set (contrast the C++ peer's CMake-package + vcpkg + conan
  trio). Full details + the operator runbook live in [`../packaging/README.md`](../packaging/README.md).
- **pub.dev carries the `-pre` qualifier directly.** `version: 0.1.0-pre` is the single source of the
  release line — no CMake-`project(VERSION)`-style dotted-numeric split that forced C++ / Common Lisp
  to carry `-pre` in docs only.
- **Two parked-state guards.** `publish_to: none` makes an accidental `dart pub publish` a no-op while
  keeping `dart pub get` / local use working; `version: 0.1.0-pre` marks the pre-release. **`dart pub
  publish --dry-run` ignores `publish_to`** and runs the full pub.dev validation suite anyway — which
  is exactly how the package's well-formedness was proven offline.
- **pub.dev needs a verified publisher namespace (A-DART-007).** Publishing requires claiming a
  verified pub.dev publisher (e.g. `entitycore.org`, via DNS / Google-account ownership) before the
  first `dart pub publish` — a one-time operator action the pipeline cannot perform. The package name
  `entity_core_protocol` is `lowercase_with_underscores` (hyphens not allowed; the keystone peer id
  `entity-core-protocol-dart` maps to it). This is *the* reason the Dart publish is deferred (plus the
  cohort-wide arch v0.1 gate).
- **Consumer SDK floor vs build SDK.** `environment.sdk: ^3.6.0` is the consumer-facing *minimum* (a
  deliberately wide reach floor — Dart-3 sealed classes / patterns / records); the peer is built and
  certified on the pinned **3.11.6** toolchain. A consumer is not pinned to 3.11.
- **`dart pub publish --dry-run` verification.** Ran in the `dart-toolchain` image, `--network=none`,
  against the warm `PUB_CACHE`. The validator listed the archive, checked structure / license /
  version / deps — **0 warnings, 0 errors** — and stopped only at the final pub.dev *existence* query
  (`Got socket error … at https://pub.dev`), which is the one step that needs network. That step is
  documented here rather than run online (lifecycle "offline / sealed" discipline). The
  "newer-versions-available" lines from `dart pub get` are informational, not validation warnings — S11
  deliberately pins aged versions.

---

## 4. Ambiguity-log finalization (owner + escalation status)

All S1–S5 `A-DART-*` items are resolved-in-peer / recorded; **none block release**, and — exactly as
the reach-peer mandate predicted — **no NEW spec defect surfaced** (the sealed-Result idiom was
saturated by Kotlin, the wide-integer-carrier lesson by TypeScript). **No new S5 ambiguity** (none
expected per the prompt; none arose). Full text in `status/SPEC-AMBIGUITY-LOG.md`:

- **A-DART-010** §7.4-vs-§1.5 peer-id form — **corroboration only**, already reconciled in the v7.75
  body; pinned proactively. Earlier surfaced by Zig/OCaml/CL/Java/Kotlin — owner: research.
- **A-DART-006** uint64 head-form carrier = `BigInt` (web/dart2js 53-bit truncation trap) — the
  load-bearing portability decision; corroborates the TypeScript-`bigint` lesson. Owner: operator/research.
- **A-DART-016** (RESOLVED at S4) transport I/O-path complexity bug (O(n²) reassembly + connection
  leak under sustained-load / churn) — local fix; an I/O-path bug, not a spec defect. Owner: operator.
- **A-DART-015** (RESOLVED at S4) §6.11 reentry inner-200 = the validator's cross-peer cap, confirmed
  via origination-core. Owner: operator.
- **A-DART-002 / -003 / -012 / -014** crypto floor (maintained `cryptography_plus` fork) + Ed448 defer
  + the 2.7.0→2.7.1 re-pin (the S1 pin-date sentinel firing) — recorded decisions / local. Owner:
  operator.
- **A-DART-007** pub.dev publisher namespace — owner: operator (S5 registry step).
- **A-DART-001 / -004 / -005 / -008 / -009 / -011 / -013** recorded decisions (codec strategy / error
  model / async idiom / spec version / §7a-§7b scaffolding / container / dart2js proof) — owner:
  operator; local, no spec change.

---

## 5. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar, an external
consumer confirms the peer, AND the pub.dev publisher namespace is verified — full runbook in
[`../packaging/README.md`](../packaging/README.md) §Operator-handoff. In brief:

1. **Decide in-repo vs standalone repo** (S10 lift-out deferred keystone-wide; current default is
   in-repo). Repoint `repository`/`homepage` if standalone.
2. **Claim the pub.dev verified publisher namespace** (A-DART-007) — the gate that cannot be done
   before first deploy. Set `publisher` in `profile.toml [publishing]`.
3. **Settle the public-surface freeze** (§1) — lock the Tier-1/Tier-2 library exports.
4. **Promote version** `0.1.0-pre → 0.1.0` in `pubspec.yaml` + `CHANGELOG.md` once the promotion gate
   (§1) is met.
5. **Remove `publish_to: none`**, set `repository:` to the final home, then `dart pub publish`. **Tag
   the release** at the reviewed commit at this point only (lifecycle §"no auto-tag").
6. **(Optional) Wire CI** to the chosen repo's runner — build + `dart test` + `--profile core`
   (assert `summary.failed == 0`) + origination-core in `dart-toolchain`, `--network=none`. No
   remote/CD attached today by design.
7. **Pin discipline** (S11): Dart SDK 3.11.6 + `cryptography_plus` 2.7.1 + `crypto` 3.0.6 + `test`
   1.25.15 pins stay exact; re-pinning is deliberate + reviewed.

---

## 6. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged to pub.dev —
gated on publisher-namespace verification A-DART-007 + arch v0.1; `0.1.0` promotion pending external
consumer; public-surface freeze pending). Regression GREEN (**S2 69/69 · S4 665 · 291P/279W/0F/95S @
e8524ed · origination 3/3 · §10.1 register 10/10 · multisig 11/11 incl accept-path · concurrency 5/5 ·
resource_bounds GREEN · 53-type 53/53**) — S1–S4 artifacts untouched. `dart pub publish --dry-run`
validates clean offline (0 warn / 0 err; only the network-gated pub.dev existence query unrun, by
sealed-offline discipline). Ambiguity log finalized + owner-routed; **no NEW spec defect**
(corroboration-only, as the reach-peer mandate predicted); no new S5 ambiguity. Only
`protocol-generator/dart/` written (no shared-tracker edits — the orchestrator reconciles
CONFORMANCE-MATRIX / STATUS / RELEASE-READINESS on master). **S5 objective met; the Dart 3 REACH peer
is publish-ready and parked at `0.1.0-pre` pending arch v0.1 sign-off + the pub.dev publisher-namespace
step.**
