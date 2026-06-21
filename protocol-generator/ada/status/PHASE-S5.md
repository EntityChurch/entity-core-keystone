# Phase S5 — Publish (entity-core-protocol-ada)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` (in `alire.toml version` directly). · **Spec basis:**
ENTITY-CORE-PROTOCOL-V7 **v7.75** (spec-data/v7.75); codec corpus v0.8.0 (byte-stable v7.71→v7.75).

S5 polishes the S4-conformant peer #10 (the **10th byte-compatible core impl**; sibling of the C
peer) into a *ready-to-publish* artifact. `/entity-rosetta` never publishes (lifecycle §Publishing)
— this phase produces the artifacts + the runbook; an operator publishes when arch signs off v0.1
AND the Alire crate-index submission is made. This doc is the release-readiness record + the operator
handoff. The architecture review + the publishing-options decision surface + the consolidated findings
ledger live in `status/ARCHITECTURE-REVIEW.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **576 / 292P / 195W / 0F / 89skip** at the v7.75 cohort baseline oracle `b30a589`, machine-verified `summary.failed == 0` (`status/CONFORMANCE-REPORT.{md,json}`). `resource_bounds` ACTIVE in core (413/400/WARN); `concurrency` 5/5 (genuinely concurrent). |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first run, 0 codec fixes; + 37/37 Ed25519/SHAKE256 KAT self-tests. |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (`type_system_match`, content_hash equality). |
| S3 two-direction loopback smoke | ✅ | GREEN (Scenario A 5/5 Ada-dials-Go, Scenario B 2/2 Go-dials-Ada); peer_id `2KD6sD8JpEHJ3EaQu2mKCfiQZnkvcDmS8xtvstw9c4dHZm`. |
| §4.8 store-safety | ✅ | Protected-object store — store-race **structurally unrepresentable** (the cleanest §4.8 story in the cohort; the C sibling's heap race A-C-009 cannot occur here by construction). |
| Build clean (warnings + contracts) | ✅ | gprbuild clean under `-gnatwa` (all warnings) + `-gnata` (design-by-contract Pre/Post/Type_Invariant aspects live). |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0 + libsodium ISC third-party notice). |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, verdict + reproduce + the byte-identity proof; conformance line links `status/CONFORMANCE-REPORT.md`). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks ENTITY-CORE-PROTOCOL-V7 v7.75`; native hand-rolled codec + libsodium Interfaces.C + tasks/protected-objects/rendezvous + design-by-contract idiom summary. |
| Package metadata (`alire.toml`) | ✅ | crate `entity_core_protocol:0.1.0-pre`, Apache-2.0, `project-files = ["entity_core_protocol.gpr"]`, **no Alire crate deps** (system libsodium only). Alire `version` carries `-pre` directly (contrast A-CL-010). |
| Toolchain pin (S11) | ✅ | GNAT `gcc-gnat-15.2.1-7.fc43` + `gprbuild-25.0.0-5.fc43` + libsodium `1.0.22-1.fc43` (Fedora 43 distro channel, exact NVR pins by `rpm -q`); GCC 15.2 ≥30-day-aged. No Alire crates. |
| CI config (Podman, offline) | ✅ authored | `.github/workflows/conformance.yml` — Gate 0 gprbuild + Gate 1 run-s2 (69/69) + Gate 2 run-s3 smoke + Gate 3 run-s4 (`summary.failed == 0`) + Gate 4 origination 3/3, all sealed-offline in `ada-toolchain`. Mirrors the Zig/Swift/Haskell cohort pattern. **Not wired to a remote/CD** (cohort-wide — committed for reviewability; the runner home is an arch/operator S10 decision). |
| Public API surface | ◑ documented | `Entity_Core.*` tiers in README §Use (`...Codec.*`/`...Crypto` Tier 1, `...Protocol` Tier 2); internal units may churn without a semver bump. Explicit surface freeze deferred to publish-prep / first consumer (the Java public-surface / OCaml `.mli` analogue). |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-ADA-001/003 ⚑ arch, A-ADA-013 ⚑ mainline/arch, A-ADA-011/010 impl-notes, A-ADA-002/005 deferred (operator), A-ADA-006/004 resolved (§5). |
| **Published to Alire / tagged** | ⛔ **deferred** | operator action — requires an Alire crate-index submission (A-ADA-005) AND arch v0.1 sign-off (§6). No auto-tag, no push, no publish. |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external Ada consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not yet met**
(no Ada consumer wired). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **Alire crate** — `entity_core_protocol:0.1.0-pre` (`alire.toml`), Apache-2.0, built by gprbuild
  against the committed `entity_core_protocol.gpr`. **One runtime dependency:** system libsodium
  (Ed25519 + SHA-256 via the `Interfaces.C` binding, `-lsodium`); CBOR (canonical ECF), Base58, and
  the multicodec LEB128 varint are hand-rolled in `src/`. **No Alire crate dependencies** — the core
  build resolves nothing from a registry; gprbuild builds fully offline against the `.gpr`.
- **Crypto: libsodium-native, the raw-pubkey advantage.** libsodium returns the raw 32-byte public
  key directly, so the §1.5 identity-multihash peer_id needs no point-extraction (contrast the JDK
  EdEC decode, A-JAVA-007). Ed448 + SHA-384 (the agility higher bar) deferred — libsodium has neither
  (A-ADA-002); the §9.1 floor needs only Ed25519 + SHA-256.
- **Concurrency: protected-object store, the structural §4.8 win.** The §4.8 store + tree index are a
  protected object (language-enforced mutual exclusion); one task per connection; the §6.11/N7 demux
  + shared-stream write are protected objects. Store-race structurally unrepresentable; genuinely
  concurrent (5/5 §7b, no-head-of-line + sustained-10000-req PASS together).
- **Host executable** (the S4 conformance driver, `bin/host`: `--port` / `--debug-open-grants` /
  `--validate`; emits a `LISTENING …` readiness line). Test/conformance only — not part of the
  published library surface. Plus `bin/run_conformance`, `bin/run_tests`, `bin/smoke_s3`.

---

## 3. Public API surface (the S5 "settle the surface" decision)

The stable contract is the README §Use two-tier package map — **Tier 1** the codec island
(`Entity_Core.Codec.Cbor` / `.Value` / `.Peer_Id`) + identity/signatures (`Entity_Core.Crypto`) and
**Tier 2** the full peer (`Entity_Core.Protocol`: handshake, dispatch, the protected-object store +
capability surface). Internal units (varint, base58, wire framing, the type-registry render table)
are implementation detail and may churn without a semver bump. An explicit visibility freeze (locking
the public `.ads` specs against churn) is a mechanical publish-prep pass, deferred until the surface
is frozen against a first external consumer — the honest `0.1.0-pre` state for an all-source-in-repo
peer (mirrors the Java public-surface / OCaml `.mli` / Zig `root.zig` deferral). Until then the tiers
are documented in README §Use + here.

---

## 4. Packaging notes specific to Ada

- **Alire's `version` accepts the `-pre` qualifier directly (contrast A-CL-010).** Unlike ASDF's
  dotted-integer-only `:version` (which forced Common Lisp to carry the `-pre` marker in the
  CHANGELOG only), Alire's crate `version` accepts a SemVer-style qualifier, so
  `alire.toml version = "0.1.0-pre"` is idiomatic and the single source of the release line.
- **Alire is a git-repo-indexed registry with a crate-index gate (A-ADA-005).** Unlike Maven Central's
  upload+namespace model, `alr publish` submits a crate manifest (a PR to the `alire-index` repo)
  pointing at a tagged git commit — the submission sets the concrete `origin`/`repository_url`
  (currently empty) and is a one-time operator action that gates the first publish. This is *the*
  reason the Ada publish is deferred (in addition to the cohort-wide arch v0.1 sign-off gate).
- **The core build needs NO Alire at all.** The peer has no Alire crate dependencies (crypto =
  libsodium binding, CBOR/base58/varint hand-rolled), so `gprbuild -P entity_core_protocol.gpr` builds
  fully offline under `--network=none` with no registry resolve — Alire is the *distribution channel
  only* (A-ADA-004). A consumer can `with` the committed `.gpr` directly (vendored/submoduled) and
  never touch Alire. This is the lightest-supply-chain posture in the cohort (with Zig/Elixir/Java).
- **Crypto-agility — floor NATIVE, Ed448/SHA-384 deferred (libsodium gap, A-ADA-002).** libsodium
  closes the §9.1 floor (Ed25519 + SHA-256, 69/69 byte-green) zero-Alire-dep, but has no Ed448 and no
  SHA-384 — the OCaml/Zig company. The agility overlay, when taken, comes via the libentitycore_codec
  C-ABI surface or an OpenSSL curve448 binding (`openssl-devel` is in the base image), NOT libsodium.
  Does NOT affect the §9.1 floor nor the connect-path agility slice. SPARK formal proof is likewise an
  explicit out-of-scope-v0.1 item (the design-by-contract aspects are runtime guards under `-gnata`).
- **The §4.8 store-safety is a language guarantee, not a packaging caveat.** Worth stating for a
  consumer: the protected-object store makes the store-race structurally unrepresentable — the peer
  carries no "remember to hold the lock" contract the consumer or a future maintainer could break.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-ADA-* items are resolved-in-peer and routed; none block release. The arch escalation
bundle (full text in `status/SPEC-AMBIGUITY-LOG.md`; consolidated table in `ARCHITECTURE-REVIEW.md`
Part D):

- **A-ADA-013 ⚑** the cohort oracle is `b30a589`, not `62044c5` (off-by-one-commit) — **owner:
  mainline/arch**. `b30a589` folds `resource_bounds` into `coreProfileCategories` → the real
  576·0F·89S (clean `62044c5` auto-skips it → 574·0F·90S). Verified read-only + live re-run, no
  doctoring, peer not rebuilt. The scorecard label should take the one-commit fix. RESOLVED in-peer.
- **A-ADA-001 ⚑** §7.4-vs-§1.5 peer-id contradiction — **owner: arch** (high; silent-handshake-kill).
  N-th spec-first corroboration (Zig/OCaml/CL/Java/Swift). Resolved via the §1.5 identity-multihash
  form (raw pubkey, `hash_type=0x00`), baked at S1.
- **A-ADA-003 ⚑** hex-case unspecified — **owner: arch** (high; case-sensitive-path 404). Ada hex
  builtins default UPPERCASE (the A-CL-009 trap the CL log named Ada as carrying); pinned proactively
  (custom lowercase nibble→char table).
- **A-ADA-008 ⚑** §5.2 401/403/401-unresolvable trichotomy — **owner: arch** (multi-peer-convergent).
  Pre-resolved + held; mapped from the exception lattice at the dispatcher boundary.
- **A-ADA-011** EXECUTE `params` is an ENTITY wire-form (`params.data.entity`) — **owner: none**
  (implementation note; the biggest S4 fix cluster). §3.x text adequate; the trap is altitude.
- **A-ADA-010** GNAT float-validity over-strictness — **owner: operator** (toolchain note,
  conformance-neutral). `-gnatVa` not used; validity checks scoped-suppressed in the two float-bit
  codec bodies (contract aspects stay live).
- **A-ADA-007** resource_bounds 413/400/WARN — settled in v7.75; pre-resolved + held.
- **A-ADA-002** Ed448/SHA-384 agility defer — **owner: operator** (libsodium gap; non-floor).
- **A-ADA-005** Alire crate publish — **owner: operator** (S5 crate-index submission step).
- **A-ADA-006** task topology (one task per connection) / **A-ADA-004** build tooling (gprbuild +
  hand-rolled runner, no Alire deps) — RESOLVED. **A-ADA-012** grant-list duplication — cosmetic,
  cohort-consistent, non-blocking.

---

## 6. The arch sign-off + oracle-provenance items (the handoff items)

Two items the orchestrator should carry into the merge/handoff decision:

1. **A-ADA-013 — the cohort scorecard's oracle label is off-by-one.** The scorecard labels the v7.75
   oracle `62044c5` and reports 576·0F·89S, but a *clean* `62044c5` build auto-skips `resource_bounds`
   under `--profile core` → 574·0F·90S; the true 576 oracle is the immediate child **`b30a589`**
   (folds `resource_bounds` into `coreProfileCategories`). Ada certified against `b30a589` → the real
   576·0F·89S, verified read-only from oracle source + the live re-run (no doctoring, peer NOT
   rebuilt). **For the merge:** Ada's verdict is **0 FAIL at the correct baseline**, so the merge is
   safe; the scorecard's `62044c5` label should take the one-commit correction to `b30a589`.

2. **Arch v0.1 sign-off + first external consumer gate the publish.** As with every cohort peer, the
   `0.1.0-pre → 0.1.0` promotion needs arch's v0.1 conformance sign-off AND a first external Ada
   consumer confirming the peer; and the `alr publish` crate-index submission (A-ADA-005) is a
   one-time operator action the pipeline cannot take. Both are deliberately deferred.

---

## 7. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar, an external
consumer confirms the peer, AND the Alire crate-index entry is submitted:

1. **Decide in-repo vs standalone repo** (see `ARCHITECTURE-REVIEW.md` §Publishing-options).
   Per-language sibling repos are deferred keystone-wide (S10); current default is in-repo under
   `protocol-generator/ada/`.
2. **Submit the Alire crate-index entry** (A-ADA-005) — a PR to the `alire-index` repo with the crate
   manifest pointing at a tagged commit; this sets the concrete `origin`/`repository_url` (currently
   empty in `alire.toml`). This is the gate that cannot be done before first publish.
3. **Settle the public-surface freeze** (§3): lock the public `Entity_Core.*` `.ads` specs against
   churn (the Tier-1/Tier-2 surface), build-verified in the `ada-toolchain` image.
4. **Promote version** `0.1.0-pre → 0.1.0` in `alire.toml version` + `CHANGELOG.md` once the promotion
   gate (§1) is met. (Alire carries the marker directly — no CL-style doc-only split.)
5. **Set `origin`/`repository_url`** in `alire.toml [origin]` + `profile.toml [publishing]`
   (currently empty; point at the per-language sibling repo if Option 2 is taken).
6. **Publish** — `alr publish` to the Alire community index (or a private index for an internal
   consumer). **Tag the release** at the reviewed commit at this point only (lifecycle §"no auto-tag").
7. **Wire CI** (`.github/workflows/conformance.yml` — gprbuild + run-s2/s3/s4 + origination in
   `ada-toolchain`, `--network=none`, assert `summary.failed == 0`) to the chosen repo's runner, or
   fold into the keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
8. **Pin discipline** (S11): GNAT 15.2.1-7 + gprbuild 25.0.0-5 + libsodium 1.0.22-1 stay exact;
   re-pinning is deliberate + reviewed. **Rebuild the oracle from `b30a589`** (READ-ONLY `git archive`)
   per `CONFORMANCE-REPORT.md` §Oracle-provenance — NOT `62044c5` (A-ADA-013).
9. **Ed448/SHA-384 agility overlay** — when taken, source via the C-ABI surface or an OpenSSL curve448
   binding, NOT libsodium (A-ADA-002). An explicit post-v0.1 item.

---

## 8. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged to Alire —
gated on the crate-index submission A-ADA-005 + arch v0.1; `0.1.0` promotion pending external
consumer; public-surface freeze pending; CI authored-offline but not wired to a remote — by design).
Regression GREEN (**S2 69/69 + 37/37 KAT · S3 GREEN (5/5 + 2/2) · S4 576 · 292P/195W/0F/89S @
`b30a589` · origination 3/3 · 53-type 53/53 · concurrency 5/5 · resource_bounds 413/400/WARN**).
Ambiguity log finalized + owner-routed (A-ADA-001/003/008 ⚑ arch; A-ADA-013 ⚑ mainline/arch;
A-ADA-011/010 impl-notes; A-ADA-002/005 deferred-operator; A-ADA-006/004 resolved). Architecture
review + publishing-options + consolidated findings ledger written (`status/ARCHITECTURE-REVIEW.md`).
The oracle-provenance correction (A-ADA-013) + the arch-sign-off/consumer gate stated for the
orchestrator (§6). Operator handoff (§7) prepared. **S5 objective met; the Ada peer #10 (10th
byte-compatible core impl, the sibling of the C peer) is publish-ready and parked at `0.1.0-pre`
pending arch v0.1 sign-off + the Alire crate-index submission step.**
