# Phase S5 — Publish (entity-core-protocol-haskell)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` · **Spec basis:** V7 spec-data **v7.74** (register /
outbound-closure / emit / peer-owner-cap / §7a conformance handlers head); codec corpus v0.8.0.

S5 polishes the S4-conformant peer #8 into a *ready-to-publish* Hackage artifact.
`/entity-rosetta` never publishes (lifecycle §Publishing) — this phase produces the artifacts +
the runbook; an operator runs `cabal upload` (or tags a source dep) when arch signs off v0.1.
This doc is the release-readiness record + the operator handoff. Twin of the OCaml/Elixir
`PHASE-S5.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S2 codec byte-identical (S7 lower bar) | ✅ | 69/69 vs `conformance-vectors-v1`, first build, 0 codec fixes; full `cabal test conformance` **160 examples / 0 failures** re-run green in-container at S5 |
| S3 smoke (two-peer loopback) | ✅ | `cabal test smoke` **7/7 (10 assertions)** re-run green in-container at S5 |
| S4 `--profile core` green (S7 higher bar) | ✅ | 573 / 289P / 195W / **0F** / 89skip, machine-verified `failed==0` (`status/CONFORMANCE-REPORT.{md,…}`); same fixed point as the cohort, reached spec-first, **0 peer-correctness fixes** |
| §10.1 register + §10.2 origination + §7b gates | ✅ | 10/10 + 3/3 (incl. `dispatch_outbound_reentry` over real TCP) + 5/5 |
| Crypto-agility higher bar | ✅ | Ed448 + SHA-384 **native** via `crypton` (no FFI, no opt-in sub-library — the first native-full-agility peer) |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local copy, cohort-consistent) |
| README + conformance pointer | ✅ | `README.md` (what-it-is, install/use both tiers, codec/crypto/laziness/STM story, build/test in-container, links to CONFORMANCE-REPORT + spec version) |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.74` |
| Package metadata (`.cabal`) | ✅ | `cabal check` **clean — no errors or warnings**; `category`/`synopsis`/`description` set, `CHANGELOG.md`+`README.md` in `extra-doc-files`, `license: Apache-2.0` + `license-file`, `tested-with GHC ==9.8.4` |
| `-Werror` out of the distributed build | ✅ | moved behind the manual `dev` flag (default OFF); `-Wall` stays. Dev/CI loop: `cabal build -f dev` / `cabal test -f dev` (verified green in-container) |
| Pinned deps (S11 lockfile) | ✅ | committed `cabal.project.freeze` (LTS 23.27-derived) pins the full transitive closure; `cabal.project` pins the Hackage `index-state` + `crypton 1.0.4`/`memory`/`basement` constraints |
| Toolchain pin (S11) | ✅ | GHC **9.8.4** + cabal-install **3.14.2.0** (`containers/ghc-toolchain`), both ≥30-day; warm `.cabal-home` store + sealed-offline (`--network=none`) build proven |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; every A-HS-* tagged owner + resolved/deferred/escalated; no NEW spec finding (8th corroboration) |
| Workspace build-state gitignored | ✅ | `.cabal-home/` + `dist-newstyle/` + `.build.sh` confirmed in `.gitignore` (the committed freeze IS tracked) |
| CI config (Podman, offline) | ◑ authored | `.github/workflows/haskell.yml` — runs the in-container build + conformance + smoke sealed-offline, asserts the gates. **No remote/CD attached** (operator/arch decides the CI home — cohort-wide no peer wires one) |
| **Published / tagged** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§4) — no auto-tag, no `cabal upload`, no registry submission |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) ≥1 external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not
yet met** (no Haskell consumer wired). Stays `0.1.0-pre` until then. (The `.cabal` `version:`
field carries `0.1.0.0` for build purposes; the *release line* is `0.1.0-pre`.)

---

## 2. What this peer ships

- **Hackage package:** `entity-core-protocol-haskell` — one library component (`EntityCore.*`),
  plus a `host` executable (the validate-peer target) and `conformance-exe` (the corpus runner).
- **Library surface:** the public modules are re-exported under `EntityCore.*` (Codec, Model,
  ContentHash, PeerId, Identity, Signature, Peer, Transport, SeedPolicy, …). Pure-Haskell, native
  codec, native crypto. **One wire-path Hackage dependency — `crypton`**; CBOR/Base58/varint
  hand-rolled; transport/store on the GHC-boot `network`/`stm`/`containers`/`time` set.
- **`host` executable** (`--port`/`--validate`/`--owner-identity`/`--seed-policy`/
  `--debug-open-grants`; emits `LISTENING …`): the S4 conformance driver. A test/conformance
  artifact, not core library surface (a consumer depends on the library, not the host).

The native-crypto choice means the published package carries the **full crypto-agility higher
bar (Ed448 + SHA-384) with no system-package dependency and no opt-in agility split** — leaner
than the OCaml hybrid (Ed448 in an opt-in C-ABI-linked sub-library). `crypton` *itself* bundles
audited C, vendored and built by cabal — no host `depext`.

---

## 3. Public API surface (the "settle the surface" decision)

The stable contract is the two tiers below; Haddock `@-`comments are authored on the public
modules. Two enforcement mechanisms remain as publish-prep, deliberately deferred (cohort-aligned
with OCaml's `.mli`/odoc deferral and Elixir's `@moduledoc false`/ex_doc deferral):

- **Module-export tightening** — some internal helpers are currently exported for the in-repo test
  modules (S10 library clients reaching `Varint`/`Base58`/`Wire` directly). A hard hide is a
  mechanical pass best done once the surface is frozen and the tests move behind the package
  boundary.
- **Haddock rendering** — `haddock` is a dev-only tool we have not run under the sealed-offline
  zero-extra-dep stance; the doc-comments are authored but not yet rendered. One `cabal haddock`
  at publish-prep renders them.

**Tier 1 — Codec island (S7 lower bar; shared-data-library consumers).** Minimum surface to
encode/verify ECF:

| Module | Stable entry points |
|---|---|
| `EntityCore.Codec` | `encode :: Value -> ByteString`, `decode :: ByteString -> Either CodecError Value` (pure) |
| `EntityCore.Model` | `makeEntity`, field accessors, `entityOfCbor` / `entityToCbor`, envelope helpers |
| `EntityCore.ContentHash` | `contentHash` (`varint(fmt) ++ HASH(ECF{type,data})`) |
| `EntityCore.PeerId` | `derivePeerId`, `formatPeerId`, parse |
| `EntityCore.Identity` | `identityOfSeed`, `peerIdOfPubkey`, `signEntity`, `verifySignature`, `idPeerId` |
| `EntityCore.Signature` | Ed25519 + Ed448 sign/verify (via `crypton`) |

**Tier 2 — Full peer (S7 higher bar).**

| Module | Stable entry points |
|---|---|
| `EntityCore.Peer` | `createPeer :: ByteString -> SeedPolicy -> Bool -> IO Peer`, `outboundDispatch`, dispatch |
| `EntityCore.Transport` | `listenOn`, `acceptLoop`, `serveConnection` |
| `EntityCore.SeedPolicy` | `standardPolicy`, `SeedPolicy(..)` (`SeedPolicyStandard` / `SeedPolicyDebugOpen`) |
| `EntityCore.Store` / `EntityCore.Capability` | STM store + tree; grant/scope + chain verification (mostly internal-driven) |

---

## 4. Packaging notes specific to Haskell / Cabal

- **`cabal check` clean.** All the S2/S3-flagged publish items are addressed: `-Werror` is behind
  the `manual`, default-off `dev` flag (so a downstream GHC bump can't break a consumer's build on
  a new warning, while the generator keeps `-Werror` hygiene via `-f dev`); `category` /
  `synopsis` / `description` are set; `CHANGELOG.md` + `README.md` moved to `extra-doc-files`;
  `license: Apache-2.0` + `license-file: LICENSE`; `tested-with: GHC ==9.8.4`.
- **`homepage` / `bug-reports` deliberately omitted** until the first publish — the per-language
  sibling repo is deferred (S10), so the repository URL is not yet fixed. `cabal check` does *not*
  warn on their absence; they are a publish-time TODO (set in `profile.toml [publishing]` + the
  `.cabal` when the URL is fixed). This is the one genuinely-operator/publish-time item.
- **Offline build (A-HS-005).** A cold-store `cabal build` consults the remote Hackage index;
  the offline recipe is *resolve-once-then-warm-store*: the committed `cabal.project.freeze` +
  pinned `index-state` + a warm `.cabal-home` store → `cabal build --offline` runs fully
  `--network=none`. Re-proven at S5 (the sanity build below).
- **S11 age floor = the snapshot date.** The freeze is derived from Stackage LTS 23.27 (GHC
  9.8.4) — a single dated snapshot pins the whole closure ≥30 days old in one
  build-tested set (no per-dep manual age audit). A-HS-012 carries the one re-pin audit item
  (`network 3.2.8.0`).
- **No CBOR / Base58 / varint dependency** — hand-rolled in-repo (the A-005 native-codec finding).

---

## 5. Sanity build (re-run at S5, sealed-offline, in-container)

```
podman run --rm --network=none \
  -e CABAL_DIR=/work/protocol-generator/haskell/.cabal-home \
  -v "$PWD":/work:Z -w /work/protocol-generator/haskell \
  entity-core-keystone/ghc-toolchain:latest \
  sh -c 'cabal build --offline -f dev && cabal test conformance --offline -f dev && cabal test smoke --offline -f dev'
```

Result: `cabal build -f dev` clean (`-Wall -Werror`); **`cabal test conformance`
160 examples / 0 failures**; **`cabal test smoke` 7/7 (10 assertions) green** over loopback TCP;
**`cabal check` — no errors or warnings.** No regression vs S4. `failed==0` holds.

---

## 6. Ambiguity-log finalization (owner + escalation status)

No NEW spec ambiguity surfaced in S1–S5; Haskell corroborates the cohort's findings from an
8th, pure-functional/lazy idiom peer. None block release. Full detail + rationale in
`status/SPEC-AMBIGUITY-LOG.md`; final tags:

- **A-HS-001** pure `Either CodecError a`; IO exceptions edge-only — operator/local, **resolved**.
- **A-HS-002** lazy-eval / strictness in a byte-exact codec — operator/local, **resolved at S2**
  (purity ⇒ codec laziness-immune; one UTF-8 string-length trap; strictness = space-safety).
- **A-HS-003** STM + green-threads concurrency — operator/local, **resolved** (S3 decision;
  §7b 5/5 structural at S4).
- **A-HS-004** hspec vs tasty/HUnit — operator/local, **resolved** (hspec).
- **A-HS-005** cabal offline mechanics — operator/local, **resolved** (warm-store + freeze +
  pinned index-state; re-proven at S5).
- **A-HS-006** §7a/§7b GUIDE-carried not in spec-data — research/track-arch-open-item,
  **resolved-in-peer** (picked up at S3/S4; same item Swift A-SW-006 flagged).
- **A-HS-007** Ed448 NATIVE (crypton) — research/agility-ledger, **resolved / data point**
  (confirmed live at S4; the first native-full-agility peer).
- **A-HS-008** agility decode-reject codes are a peer/validate policy not codec — operator/local,
  **resolved** (informational; layer placement).
- **A-HS-009** §9.5 53-type render — operator/local, **RESOLVED at S4** (53/53 byte-identical).
- **A-HS-010** entity-native dispatch evaluates minimal `compute/literal` — research/track-arch
  (mirrors A-011/A-OC-010), **recorded** (no longer gate-exercised after the §7a resolution;
  harmless, kept until Go drops it, no flag-day).
- **A-HS-011** `--seed-policy <file>` JSON parse — operator/local, **recorded / deferred**
  (in-code builders are the floor; file-parse is the next increment; cohort-aligned).
- **A-HS-012** transport deps pinned at index-state — operator/S11 re-pin audit, **recorded /
  deferred** (confirm `network 3.2.8.0` clears the 30-day floor at the next deliberate re-pin;
  the index-state already bounds it ≤ the LTS snapshot).

**No `⚑` spec-text-tension item from peer #8** — the peer-id §7.4→§1.5 reconciliation, the §4.6
401/403 boundary, and the §PR-8/§5.5a granter frame all landed consistent with the cohort against
the live oracle (8th independent corroboration, not a discovery).

---

## 7. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an
external consumer confirms the peer:

1. **Set the repository URL** in `profile.toml [publishing].repository_url` + add `homepage:` /
   `bug-reports:` to the `.cabal` (the deferred publish-time item).
2. **Promote the version** `0.1.0-pre → 0.1.0` in `CHANGELOG.md` (and bump the `.cabal` `version:`
   if the publish line warrants) once the promotion gate (§1) is met.
3. **Tighten the public surface** (module exports) + render Haddock (`cabal haddock`, dev-only,
   sealed-offline) — build-verified in the `ghc-toolchain` image.
4. **Dry-run the sdist** in-container, sealed-offline: `cabal sdist` produces the Hackage source
   tarball; `cabal check` (already clean) gates it.
5. **Publish:** `cabal upload --publish dist-newstyle/sdist/*.tar.gz` (and `cabal upload -d` for
   the Haddock docs) — an operator action, reviewed, never automated, never from `/entity-rosetta`.
   Tag the release only at this point (lifecycle §"What you do NOT do": no auto-tag). A source dep
   (git tag) is the alternative for an early consumer before a Hackage release.
6. **Pin discipline on the published manifest** (S11): any dev deps added (haddock/hspec-discover)
   stay exact via the freeze; re-pinning is deliberate + reviewed.

---

## 8. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged;
`0.1.0` promotion pending external consumer; CI workflow authored-not-wired; homepage/bug-reports
URLs pending the publish-time repo URL) and the publish-prep mechanical pass (export-tighten +
Haddock render). `cabal check` is clean. Ambiguity log finalized + owner-routed. Sanity build
re-run green sealed-offline (160/0 conformance + 7/7 smoke). Operator handoff (§7) prepared.
**S5 documentation objective met; the Haskell peer is publish-ready and parked at `0.1.0-pre`
pending arch v0.1 sign-off.** This completes the S1→S5 lifecycle for peer #8.
