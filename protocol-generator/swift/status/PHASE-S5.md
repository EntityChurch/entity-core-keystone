# Phase S5 — Publish (entity-core-protocol-swift)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` · **Spec basis:** V7 spec-data **v7.74** (register /
outbound-closure / emit / peer-owner-cap / §7a conformance handlers / §7b concurrency); codec
corpus v0.8.0.

S5 polishes the S4-conformant peer #7 into a *ready-to-publish* SwiftPM artifact.
`/entity-rosetta` never publishes (lifecycle §Publishing) — this phase produces the artifacts +
the runbook; an operator publishes when arch signs off v0.1. This doc is the release-readiness
record + the operator handoff. Twin of the OCaml/Zig/Elixir `PHASE-S5.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S2 codec green | ✅ | 69/69 byte-identical vs `conformance-vectors-v1`, first run, 0 codec fixes |
| S3 smoke green | ✅ | `swift run smoke` 11/11 (two-peer loopback handshake + dispatch + reentry) |
| S4 `--profile core` green | ✅ | 573 / 288P / 196W / **0F** / 89skip, machine-verified `failed==0` (`status/CONFORMANCE-REPORT.{md,json}`) |
| §10.1 register + §10.2 origination + §7b concurrency gates | ✅ | 10/10 + 3/3 (incl. `dispatch_outbound_reentry` over real TCP) + 5/5 |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1` |
| S7 higher bar (validate-peer core) | ✅ | same fixed point as C#/TS/OCaml/Zig/Elixir/CL, reached spec-first |
| `swift build -c release` (sealed offline) | ✅ | re-run green in-container at S5 (`--network=none`, `Package.resolved` committed); 1 benign warning (swift-asn1 used by no target — the A-SW-005 explicit transitive pin, expected) |
| `swift test` | ✅ | 27/27 (codec 69/69 + 25 selftests + A-SW-009 53-type byte-diff) |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local copy, full text) |
| README + conformance badge | ✅ | `README.md` (install/use, build/test/run-conformance in-container, verdict + reproduce, the A-SW-002 String + §7b notes) |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.74` |
| Package metadata (`Package.swift`) | ✅ | swift-tools-version:6.0; product = `.library("EntityCoreProtocol")` (+ Host/Smoke executables, test/conformance only); swift-crypto `exact: "3.14.0"` + swift-asn1 `exact: "1.7.0"`; `Package.resolved` committed (S11 lockfile) |
| Pinned deps (S11, ≥30d) | ✅ | swift 6.2 (~9mo), swift-crypto 3.14.0 (~10mo), swift-asn1 1.7.0 (~59d, explicit-pinned over the floating 1.7.1 — A-SW-005). No CBOR/Base58/varint deps |
| Public API surface | ◑ documented | the `public` surface (`Peer`/`Server`/`Model`/`CBOR`/`ContentHash`/`Identity`/`SeedPolicy`/…) + README §Install/use Tier-1/Tier-2. Explicit semver freeze deferred to publish-prep / first consumer |
| CI config (Podman, offline) | ◑ authored, not wired | `.github/workflows/swift.yml` — runs build + `swift test` (S2 69/69) + the S4 gate in `swift-toolchain`, `--network=none` where offline. **No remote/CD attached** (operator/arch decides the CI home — §6) |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; every A-SW-* tagged owner + escalation status (§5) |
| `STATUS.md` row (repo root) | ✅ | Swift (peer #7) row added: codec ✅ / peer ✅ / conformance ✅ (573/0F) / S5 publish-ready `0.1.0-pre` |
| **Published / tagged** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6) — no auto-tag, no push, no registry submission |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) ≥1 external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not
yet met** (no Swift consumer wired). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **SwiftPM package** `entity-core-protocol-swift` (`Package.swift`, swift-tools-version:6.0):
  one library product `EntityCoreProtocol` (the consumer surface) + two executable products
  (`entity-peer-swift` = the S4 conformance host; `smoke` = the S3 smoke runner) that are
  **test/conformance artifacts, not library surface**.
- **Library:** module `EntityCoreProtocol`, imported `import EntityCoreProtocol`. Native codec
  (hand-rolled ECF, zero CBOR dep), native crypto via **one** SwiftPM dependency (swift-crypto;
  swift-asn1 is its explicit-pinned transitive). `swift build` runs fully `--network=none` after
  the one-time resolve (`Package.resolved` committed).
- **Host executable** (`Sources/Host`): the S4 conformance driver (`--port`,
  `--seed-policy`, `--owner-identity`, `--debug-open-grants`, `--validate`; emits `LISTENING …`).
  Test/conformance only.

---

## 3. Public API surface (the S5 "settle the surface" decision)

The stable contract is the README §Install/use two-tier table. Swift's access control is
per-declaration `public`/`internal` (`internal` is the default), so the module boundary is
already enforced by the compiler — only `public` declarations are reachable by a consumer. The
remaining publish-prep work is an **audit + freeze** of that `public` surface (confirm no
implementation detail is accidentally `public`; lock the signatures against a first consumer),
which is a mechanical pass best done once the surface is frozen — the honest S5 state for an
all-source-in-repo peer (S10; mirrors the OCaml `.mli`-deferral and Zig `root.zig`-freeze
rationale).

**Tier 1 — Codec island (S7 lower bar; shared-data-library consumers).** `Model.make`,
`CBOR.encode`/`decode`, `ContentHash.contentHash`/`ecfOfEntity`/`sha256`/`sha384`,
`Identity(seed:)` + `sign`/`signatureEntity`, `PeerID`, `Base58`, `Varint`, `CBORValue`,
`CodecError`.

**Tier 2 — Full peer (S7 higher bar).** `Peer(seed:seedPolicy:conformanceHandlers:)` + `dispatch`,
`Server(peer:port:)` + `start`/`port`, `Connection`, `SeedPolicy` (`.standard()`/`.debugOpen()`/
`.of(_:)`), `Capability`, `Store`.

---

## 4. Packaging notes specific to Swift

- **No central binary registry.** SwiftPM resolves dependencies from a git URL + semver tag; the
  Swift Package Index is a *discovery* index over git, not a binary host. "Publishing" = a
  reviewed semver git tag; consumers pin by `url` + `from:`/`exact:` in their own
  `Package.swift`, and `Package.resolved` locks the exact revision. Decentralized + git-tag-pinned
  by design (like crates / Zig). There is no `publish` command to run.
- **`Package.resolved` is the S11 lockfile** — committed, locks swift-crypto + swift-asn1 by exact
  revision. The peer pulls exactly two deps; after the one-time resolve every build is offline.
- **Explicit transitive pin (A-SW-005):** swift-asn1 is pinned `exact: "1.7.0"` to override
  SwiftPM's auto-resolution to 1.7.1 (which breaches the S11 30-day floor). This produces a benign
  `swift-asn1 is not used by any target` build warning — expected; the explicit `.package(...)`
  entry is the pin mechanism, and the dependency is consumed transitively by swift-crypto.
- **Ed448 / crypto-agility higher bar is OUT of S5 core scope** (A-SW-001): swift-crypto /
  BoringSSL omits Ed448 and no audited pure-Swift Ed448 exists. When agility enters scope the
  design is **hybrid** — native Ed25519 (shipped) + FFI Ed448 via `libentitycore_codec` (a C
  system-library target + module map over `entitycore_codec.h`; Swift's first-class C interop
  makes this clean — the resolved OCaml A-OC-002 pattern). That introduces a C-ABI dependency +
  an `ec_abi_version` pin in the manifest (lifecycle §Version-pin, codec_strategy=ffi clause).
  Documented now so the manifest doesn't silently claim agility it doesn't have.
- **Package name vs module name:** the package id is `entity-core-protocol-swift` (the
  human/repo name, hyphenated); the library product + module is `EntityCoreProtocol`
  (UpperCamelCase, imported `import EntityCoreProtocol`). Expected and idiomatic.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S4 A-SW-* items are resolved-in-peer or owner-routed; none block release. Full text in
`status/SPEC-AMBIGUITY-LOG.md`.

| Item | Topic | Owner | Status |
|---|---|---|---|
| **A-SW-001** | Ed448 native gap (crypto-agility higher bar) | research — profile/agility | **deferred** (hybrid-FFI when agility in scope; mirrors OCaml A-OC-002 / Zig A-ZIG-002; does not touch the floor) |
| **A-SW-002** | Swift `String` grapheme/non-Int-index → wire ops on UTF-8 bytes | operator — local | **resolved / informational** (codec discipline; spec unambiguous; reusable grapheme-string generator guidance) |
| **A-SW-003** | CryptoKit unavailable on Linux → swift-crypto | operator — local | resolved (platform fact; settled at S1) |
| **A-SW-004** | XCTest vs swift-testing | operator — local | resolved (XCTest; non-blocking, revisitable) |
| **A-SW-005** | swift-asn1 transitive auto-resolve breaches S11 → explicit older pin | operator — local | **resolved** (explicit `exact: "1.7.0"`; reusable range-resolving-package-manager generator pattern) |
| **A-SW-006** | §7a/§7b conformance scaffolding is GUIDE-carried, not in spec-data | research — track arch open-item | resolved-in-peer (picked up from GUIDE-CONFORMANCE; track whether it folds into the snapshot set) |
| **A-SW-007** ⚑ | §7.3 NORMATIVE `message=content_hash` contradicts Appendix E `signature` vectors (sign ECF preimage) | **architecture** | escalated (corroboration — 7th peer to arrive at the corpus convention; first to surface the §7.3-vs-Appendix-E *text* tension) |
| **A-SW-008** ⚑ | §7.4 NORMATIVE peer-id derivation contradicts §1.5 canonical-form table | **architecture** | escalated (high; **4th-peer corroboration** of OCaml A-OC-007 / Zig A-ZIG-001; validated live) |
| **A-SW-009** | full §9.5 53-type registry render | operator — local | **RESOLVED** at S4 (53/53 byte-identical, offline + live) |
| **A-SW-010** ⚑ | §4.2/§5.1 flat "403" vs §5.2a author-absent(401)/cap-absent(403) | **architecture** | escalated (corroboration of F20 / OCaml A-OC-008; built to §5.2a, green) |
| §7b bounded-pool finding | structured-concurrency cooperative pool hostile to blocking I/O → dedicated OS thread | operator — local | resolved-in-peer (logged in PHASE-S4.md §8; reusable generator guidance for actor/async targets doing raw blocking sockets) |

No item left untagged. The three ⚑ items (A-SW-007/008/010) are spec-text-tension corroborations
routed to architecture as v7.75-candidate spec-refinement findings; the rest are
resolved-in-peer or operator-local.

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an
external consumer confirms the peer:

1. **Decide in-repo vs standalone repo.** Per-language sibling repos are deferred keystone-wide
   (S10); current default is in-repo under `protocol-generator/swift/`. The package lifts out
   cleanly when that day comes (the repo name is already `entity-core-protocol-swift`).
2. **Settle the public-surface freeze** (§3): audit the `public` surface, confirm no
   implementation detail leaks, lock signatures against the first consumer; build-verified in the
   `swift-toolchain` image.
3. **Promote version** `0.1.0-pre → 0.1.0` in `CHANGELOG.md` (there is no `version` field in
   `Package.swift` — the version *is* the git tag) once the promotion gate (§1) is met.
4. **Set `repository_url`** in `profile.toml [publishing]` (currently empty — the per-language
   sibling repo is deferred per S10) + confirm the package id is unclaimed on the Swift Package
   Index (discovery-only; no squatting risk on a binary host since there is none).
5. **Tag the release** at the reviewed commit (only at this point — lifecycle §"no auto-tag").
   For Swift that tag *is* the distribution: consumers add `.package(url: "<repo>", from:
   "0.1.0")` + `Package.resolved` pins the revision. There is no `publish` command to run.
6. **Wire CI** (`.github/workflows/swift.yml`) to the chosen repo's runner, or fold it into the
   keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
7. **Pin discipline** (S11): swift / swift-crypto / swift-asn1 pins stay exact; re-pinning is
   deliberate + reviewed (e.g. when swift-asn1 1.7.1 ages past 30 days, re-apply the rule). The
   committed `Package.resolved` is the lockfile.

---

## 7. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged;
`0.1.0` promotion pending external consumer; public-surface freeze pending) and the CI-not-wired
line (authored, reproducible-offline, no remote by design). Final in-container sanity build green
(`swift build -c release`, `--network=none`, exit 0). Ambiguity log finalized + owner-routed
(every A-SW-* tagged). Operator handoff (§6) prepared. **S5 objective met; the Swift peer #7 is
publish-ready and parked at `0.1.0-pre` pending arch v0.1 sign-off.** This completes the S1→S5
lifecycle for peer #7.
