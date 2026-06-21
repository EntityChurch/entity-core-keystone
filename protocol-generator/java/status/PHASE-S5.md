# Phase S5 — Publish (entity-core-protocol-java)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` (in `pom.xml <version>` directly). · **Spec basis:**
V7 spec-data v7.72 + the v7.73/v7.74 peer-surface closeout (register/outbound/emit §6.13 + §PR-8
granter frame + §6.9a owner-cap + §7a conformance handlers); codec corpus v0.8.0.

S5 polishes the S4-conformant peer #7 (the **9th byte-compatible core impl**) into a
*ready-to-publish* artifact. `/entity-rosetta` never publishes (lifecycle §Publishing) — this phase
produces the artifacts + the runbook; an operator publishes when arch signs off v0.1 AND the Maven
Central namespace is verified. This doc is the release-readiness record + the operator handoff. The
architecture review + the publishing-options decision surface + the consolidated findings ledger
live in `status/ARCHITECTURE-REVIEW.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 573 / 289P / 195W / **0F** / 89skip, machine-verified `summary.failed == 0` (`status/CONFORMANCE-REPORT.{md,json}`). A clean **superset** of the OCaml/CL 568 fixed point (the +5 is §7b, which gates core at the in-flight oracle HEAD — see §6 / A-JAVA-011). |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| S7 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first run, 0 codec fixes. |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (`TypeRegistryTest` peer-side dual + live oracle `type_system_match`). |
| S3 two-peer loopback smoke | ✅ | 11/11; peer_id byte-identical to the CL peer (seed `0x11` → `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`). |
| Ed25519 + Ed448 RFC-8032 KAT | ✅ | SunEC sign/verify byte-equal pins; hand-rolled SHAKE256 + raw-pubkey derivation KAT-verified (A-JAVA-007); BouncyCastle cross-check byte-equal. |
| `mvn -o -B test` clean | ✅ | 15 tests, 0 failures (codec 69/69 + KATs + 53/53 type-diff + 11/11 smoke). |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0; pom.xml `<licenses>` block). |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, verdict + reproduce + the byte-identity proof). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 v7.72 + v7.73/v7.74 closeout`. |
| Package metadata (`pom.xml`) | ✅ | `org.entitycore:entity-core-protocol:0.1.0-pre`, JDK 21, `<licenses>`/`<developers>`/`<url>`, **zero runtime deps** (JUnit test-scope, BouncyCastle `provided`/test-scope). Maven supports `-pre` directly (contrast A-CL-010). |
| Toolchain pin (S11) | ✅ | Temurin **JDK 21 LTS** (SHA-256-pinned) + Apache **Maven 3.9.9** (SHA-512-pinned, two-mirror-verified); JUnit 5.11.4 / surefire 3.5.2 / BouncyCastle 1.80 all ≥30-day-aged, test/`provided` scope. |
| CI config (Podman, offline) | ◑ runnable, not wired | the build/test/conformance run sealed-offline in `java-toolchain` today (`run-s2/s3/s4.sh`, `run-origination-core.sh`, `mvn -o`). A committed CI *workflow* is deferred **cohort-wide** — no peer has one wired; lands at S10 lift or when arch defines the shared CI home. |
| Public API surface | ◑ documented | package tiers in README §Use (`...codec`/`...crypto` Tier 1, `...peer` Tier 2); internal units may churn without a semver bump. `module-info` / explicit semver freeze deferred to publish-prep / first consumer (the OCaml `.mli` / Zig `root.zig` analogue). |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; A-JAVA-004/009/010/007/011 routed ⚑ to arch (§5 + ARCH-REVIEW Part D). |
| **Published to Maven Central / tagged** | ⛔ **deferred** | operator action — requires verified `org.entitycore` namespace (A-JAVA-005) AND arch v0.1 sign-off (§6). No auto-tag, no push, no deploy. |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not yet met**
(no Java consumer wired). Stays `0.1.0-pre` until then.

---

## 2. What this peer ships

- **Maven artifact** — `org.entitycore:entity-core-protocol:0.1.0-pre` (`pom.xml`), JDK-21,
  `jar` packaging. **Zero runtime dependencies:** Ed25519/Ed448 sign/verify + SHA-256/384 from the
  JDK (SunEC + `MessageDigest`); CBOR (canonical ECF), Base58, the multicodec LEB128 varint, and
  the FIPS-202 SHAKE256 + RFC-8032 raw-pubkey derivation are hand-rolled in `src/main/java`. JUnit 5
  is test-scope; BouncyCastle is `provided`-scope (OPT-IN agility cross-check, never shipped).
- **Crypto: JDK-native, no FFI.** SunEC supplies both curve families' sign/verify natively — the
  first peer whose vendor-curated stdlib closes the agility *signature* bar (company with CL/Elixir;
  contrast OCaml C-ABI, Zig gap). The raw-*public-key* half has a JDK gap (no SHAKE256, no
  seed→public), closed by ~250 lines of hand-rolled, KAT-verified code (A-JAVA-007).
- **Host executable** (the S4 conformance driver, `--port`/`--debug-open-grants`/`--validate`;
  emits `LISTENING …`). Test/conformance only — not part of the published library surface.

---

## 3. Public API surface (the S5 "settle the surface" decision)

The stable contract is the README §Use two-tier package map — **Tier 1** codec island
(`org.entitycore.protocol.codec`) + identity/signatures (`...crypto`) and **Tier 2** full peer
(`...peer`: `Peer`, `Transport`, the store + capability surface). Internal units (varint, base58,
wire framing, the type-registry render table) are implementation detail and may churn without a
semver bump. An explicit `module-info.java` / public-surface freeze is a mechanical publish-prep
pass, deferred until the surface is frozen against a first external consumer — the honest
`0.1.0-pre` state for an all-source-in-repo peer (mirrors the OCaml `.mli` / Zig `root.zig`
deferral). Until then the tiers are documented in README §Use + here.

---

## 4. Packaging notes specific to Java

- **Maven supports the `-pre` qualifier directly (contrast A-CL-010).** Unlike ASDF's
  dotted-integer-only `:version` (which forced Common Lisp to carry the `-pre` marker in the
  CHANGELOG only), Maven's version grammar accepts a SemVer-style qualifier, so `pom.xml
  <version>0.1.0-pre</version>` is idiomatic and the single source of the release line. (The S2
  placeholder was `0.1.0-SNAPSHOT`; SNAPSHOT is Maven's *mutable-dev* channel, not a pre-release
  marker, so S5 set the explicit `0.1.0-pre`.)
- **Maven Central is a real upload registry with a namespace gate (A-JAVA-005).** Unlike Zig/CL
  (decentralized, git-tag/dist-indexed), publishing to Maven Central (Sonatype Central Portal)
  requires the publisher to **verify ownership of the `org.entitycore` reverse-DNS namespace**
  (DNS TXT record / hosting-provider proof) before the first `mvn deploy` — a one-time operator
  action that cannot be done by the pipeline. This is *the* reason the Java publish is deferred (in
  addition to the cohort-wide arch v0.1 sign-off gate).
- **Zero-runtime-dependency posture is a packaging advantage.** A consumer of the published artifact
  inherits *no* transitive runtime deps (BouncyCastle `provided`/test, JUnit test) — lighter than
  C#'s multi-provider graph, comparable to Elixir's zero-Hex posture; the only pin a consumer takes
  on is JDK 21.
- **Crypto-agility — sign/verify NATIVE, raw-pubkey hand-rolled, full MATRIX deferred (cohort-wide).**
  SunEC closes Ed25519 + Ed448 sign/verify zero-dep; the raw-pubkey gap is closed by the hand-rolled
  KAT-verified SHAKE256 + RFC-8032 derivation (A-JAVA-007). The agility *full MATRIX* harness (the
  M2/M3/M6 key-type × hash-format cross-product) is the documented non-v0.1 item — no FFI or second
  provider needed when it lands; only the matrix harness is unwired. Does NOT affect the §9.1 floor
  (Ed25519 + SHA-256, 69/69 byte-green) nor the connect-path agility slice.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-JAVA-* items are resolved-in-peer and routed; none block release. The arch escalation
bundle (full text in `status/SPEC-AMBIGUITY-LOG.md`; consolidated table in `ARCHITECTURE-REVIEW.md`
Part D):

- **A-JAVA-010 ⚑** §1.1 entity `data` is an arbitrary ECF value (not necessarily a map) — **owner:
  arch** (NEW; high-signal interop trap). Map-only model passes S2/S3 then silently 500s on scalar
  data at the §7b gate. Recommend a scalar-data conformance vector + a §1.1 emphasis. Resolved
  locally (generalized `Entity`).
- **A-JAVA-004 ⚑** §7.4-vs-§1.5 peer-id contradiction — **owner: arch** (high; silent-handshake-
  kill). **FOURTH spec-first corroboration** (Zig A-ZIG-001, OCaml A-OC-007, CL A-CL-002, now Java).
  peer_id byte-identical to CL.
- **A-JAVA-009 ⚑** §5.2 401/403 request-time boundary — **owner: arch** (corroborates F20).
  **FIFTH-peer convergence** (OCaml A-OC-008 / Zig A-ZIG-006 / Java). Resolved via 3-way verdict.
- **A-JAVA-007 ⚑** JDK SHAKE256 / seed→public gap for native Ed448 raw-pubkey — **owner:
  arch/research** (NEW crypto-ledger data point). Resolved via hand-rolled KAT-verified primitive.
- **A-JAVA-011 ⚑** §7b gates `--profile core` at oracle HEAD `749e57e` (568→573); §7a
  dispatch-outbound is a generic verbatim relay — **owner: arch/research**. Needs an arch ruling (is
  §7b-gates-core intended for v0.1?) + re-confirm Java's 573·0F when `749e57e` lands on origin/main
  (§6).
- **A-JAVA-001** v7.73/v7.74 spec-data snapshot missing — owner: research/arch (provenance gap; the
  oracle check-set IS at HEAD; corroborates A-CL-001). NON-blocking.
- **A-JAVA-005** Maven Central namespace verification — owner: operator (S5 registry step).
- **A-JAVA-008** (CLOSED — 53/53). **A-JAVA-002/003/006** (RESOLVED — crypto sourcing / concurrency
  / Maven sha512).

---

## 6. The 568→573 §7b-gates-core question + the upstream re-confirm dependency (THE handoff item)

**This is the single most important item for the orchestrator's merge/handoff decision** (full
treatment in `ARCHITECTURE-REVIEW.md` §A.5). Stated plainly:

The canonical `--profile core` gate count moved **568 → 573** between the OCaml/CL builds and this
Java build, and **the reason is not a Java scope difference.** The Go oracle was built from the
mainline's **in-flight committed-but-unpushed HEAD `749e57e`** ("validate-peer/concurrency: keystone
§7b matrix fixes"), **14 commits ahead of origin/main**, and at that HEAD the **§7b concurrency
category runs and *gates* under `--profile core`** — a layered conditional that was a §9.0 drift-list
carve-out (auto-skipped) at the older oracle the OCaml/CL peers ran against. All 5 §7b checks PASS
for Java on virtual threads, so 573 · 289P/195W/**0F**/89S is a clean **superset**, not a regression.

Two things follow, **both needing action before the count is treated as canonical:**

1. **Arch ruling needed: is §7b-gates-core intended for v0.1?** It re-baselines the canonical core
   gate from 568 to 573. If yes, the OCaml/CL/etc. peers should be re-run against the §7b-gating
   oracle to confirm they also reach 573·0F (unverified at the new gate). If §7b is meant to stay a
   §9.0 drift carve-out for v0.1, Java's *canonical* verdict is the 568-subset (also 0F) and the §7b
   superset is forward-looking. **The cohort cannot have a single canonical core count until ruled.**
2. **Re-confirm Java's 573·0F once `749e57e` lands on origin/main.** The +5 §7b PASS depends on the
   Go-side §7b matrix fixes being upstream. The oracle is reproducible-correct at `749e57e` today
   (symbols verified, tree clean at build), but the canonical claim is stable only once that HEAD is
   pushed. **A re-run of `run-s4.sh` against the origin/main oracle is a required post-merge step.**

**For the merge decision:** Java's verdict is **0 FAIL either way** (568-subset or 573-superset), so
the merge is safe on conformance grounds — but **do not stamp 573 as the new canonical cohort core
count** until arch rules §7b-gates-core for v0.1 *and* the oracle HEAD lands upstream and Java
(ideally the cohort) is re-run against it.

---

## 7. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar, an
external consumer confirms the peer, AND the `org.entitycore` namespace is verified:

1. **Decide in-repo vs standalone repo** (see `ARCHITECTURE-REVIEW.md` §Publishing-options).
   Per-language sibling repos are deferred keystone-wide (S10); current default is in-repo under
   `protocol-generator/java/`.
2. **Verify the `org.entitycore` Maven Central namespace** (A-JAVA-005) — DNS TXT record on the
   owned domain or a hosting-provider proof via the Sonatype Central Portal. This is the gate that
   cannot be done before first deploy.
3. **Settle the public-surface freeze** (§3): add a `module-info.java` exporting the locked
   Tier-1/Tier-2 packages, build-verified in the `java-toolchain` image.
4. **Promote version** `0.1.0-pre → 0.1.0` in `pom.xml <version>` + `CHANGELOG.md` once the
   promotion gate (§1) is met. (Maven carries the marker directly — no CL-style doc-only split.)
5. **Set `repository_url`** in `profile.toml [publishing]` + the pom `<url>`/`<scm>` (currently the
   keystone repo / empty; point at the per-language sibling repo if Option 2 is taken).
6. **Deploy** — `mvn -o -B deploy` to a Maven Central staging repo (GPG-signed artifacts), then
   release via the Central Portal. There is no consumer index-submission beyond the deploy. **Tag
   the release** at the reviewed commit at this point only (lifecycle §"no auto-tag").
7. **Wire CI** (`run-s2/s3/s4.sh` + `run-origination-core.sh` + `mvn -o test` in `java-toolchain`,
   `--network=none`, assert `summary.failed == 0`) to the chosen repo's runner, or fold into the
   keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
8. **Pin discipline** (S11): JDK 21 + Maven 3.9.9 + JUnit/surefire/BouncyCastle pins stay exact;
   re-pinning is deliberate + reviewed. **Before promotion, re-confirm the §7b/573·0F gate against
   the origin/main oracle** (§6 / A-JAVA-011).

---

## 8. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged to Maven
Central — gated on namespace verification A-JAVA-005 + arch v0.1; `0.1.0` promotion pending external
consumer; public-surface freeze pending; CI authored-offline but not wired to a remote — by design).
Regression GREEN (**S2 69/69 · S3 11/11 · S4 573 · 289P/195W/0F/89S · origination 3/3 · 53-type
53/53 · `mvn -o test` 15/0**). Ambiguity log finalized + owner-routed (A-JAVA-004/009/010/007/011 ⚑
arch). Architecture review + publishing-options + consolidated findings ledger written
(`status/ARCHITECTURE-REVIEW.md`). The 568→573 §7b-gates-core question + the
re-confirm-when-`749e57e`-lands-upstream dependency stated for the orchestrator (§6). Operator
handoff (§7) prepared. **S5 objective met; the Java peer #7 (9th byte-compatible core impl) is
publish-ready and parked at `0.1.0-pre` pending arch v0.1 sign-off + the Maven Central namespace
step.**
