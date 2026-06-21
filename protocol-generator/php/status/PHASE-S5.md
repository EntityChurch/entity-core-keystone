# Phase S5 — Publish (entity-core-protocol-php)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` (the label in CHANGELOG/README; `composer.json` carries
**no `version`** field — Packagist infers it from the VCS git tag — A-PHP-012). · **Spec basis:** V7
spec-data **v7.75**; codec corpus v0.8.0 (byte-stable v7.71→v7.75). · **Oracle:** the **v7.77** cohort
baseline **`e8524ed`** (go HEAD; core category set byte-unchanged v7.75→v7.77; `core_gate_sha256`
`e09a865f…`, pinned in `tools/oracle-pin.env`).

S5 polishes the S4-conformant PHP peer — a release **"reach"** peer (`research/RELEASE-READINESS.md`
§2 row 2: web-backend ubiquity — WordPress / Laravel / Symfony), the **2nd dynamic / scripting peer**
after Ruby #12, corroboration-only by design (the spec-discovery well is dry; its value is REACH +
exercising the generator against PHP idiom: GMP uint64 carrier / single-thread event loop / `\Exception`
hierarchy / Ed448 gap) — into a *ready-to-publish* artifact. `/entity-rosetta` never publishes
(lifecycle §Publishing); this phase produces the artifacts + the runbook; an operator publishes when
arch signs off v0.1 AND a first external PHP consumer confirms it. This doc is the release-readiness
record + the operator handoff.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **665** / 292P / 278W / **0F** / 95S, machine-verified `summary.failed == 0` @ the v7.77 oracle `e8524ed` (core_gate `e09a865f…` matches the committed pin). (`status/CONFORMANCE-REPORT.json`, `status/PHASE-S4.md`.) |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| multisig (genuine K-of-N) | ✅ | 11/11, 0 skip — incl. `valid_2of3_peer_signed_accepted` PASS (`--name conformance` persistent identity; validator co-signs AS the peer → 200, RUN not SKIP). |
| S2 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, 0 codec fixes. |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (content_hash recomputed by the PHP codec, asserted equal to the Go reference — not ingested). |
| S3 two-peer loopback smoke | ✅ | 12/12 (handshake + dispatch + capability + multi-request_id demux). |
| Ed25519 (floor crypto) | ✅ | ext-sodium (libsodium) `sodium_crypto_sign_*`, deterministic RFC-8032; SHA-256/384 via stdlib `hash()`. Zero Composer/PECL dep, zero FFI. |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0 + libsodium ISC third-party notice). Holder `Entity Core Protocol contributors` (cohort convention). |
| README + conformance status | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, install/consume via Composer, verdict 665·0F + reproduce). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre`, literally **"tracks V7 spec-data v7.75"** (certified @ v7.77 oracle `e8524ed`); the A-PHP-012 version-spelling note carried. |
| Package metadata (`composer.json`) | ✅ | `entity-core/protocol`, PHP `>=8.3`, `ext-sodium` + `ext-gmp` in `require`, PSR-4 `EntityCore\` → `src/`, Apache-2.0, `bin: ["bin/peer"]`, `minimum-stability: dev` + `prefer-stable: true`, **zero runtime Composer deps** (phpunit is `require-dev` only). **`composer validate --strict` passes in-container; `composer install --dry-run --no-dev` confirms the platform reqs are satisfiable offline.** |
| Version-spelling correctness | ✅ | `composer.json` carries **no `version`** — Composer rejects the literal `0.1.0-pre` (`pre` is not a stability keyword), so the version is **VCS-tag-inferred** at publish (A-PHP-012, NEW); validates `--strict` clean. The `0.1.0-pre` label lives in README/CHANGELOG/this doc. |
| Toolchain pin (S11) | ✅ | PHP **8.3** (official `php:8.3-cli-bookworm`) + **ext-sodium** (bundled libsodium) + **ext-gmp** (added) + Composer **2.7** (pinned official layer). Floor PHP `>= 8.3`. PHPUnit 11.2.0 = dev-only Composer dep; **zero runtime Composer deps**. Container build-time assertion gates ext-sodium + GMP>2^63 + SHA-256/384. |
| CI config (Podman, offline) | ◑ runnable, not wired | the build/test/conformance runs sealed-offline in `php-toolchain` today (`run-s2/s3/s4.sh`, `run-origination-core.sh`, `vendor/bin/phpunit`, all `--network=none`). A committed CI *workflow* is deferred **cohort-wide** for the dynamic peers (Ruby ships none either) — lands at S10 lift or when arch defines the shared CI home. |
| Public API surface | ◑ documented | README §Install/consume documents the codec/crypto/peer surface; internal units (`Varint`/`Base58`/`Cbor` framing/type-floor table) + `bin/peer` driver may churn / are not the published library. PHP has no module-private keyword, so an explicit semver freeze is a doc + test-relocation pass deferred to publish-prep / first consumer (the Ruby / OCaml `.mli` / Zig `root.zig` analogue). |
| Ed448 / SHA-384 agility | ◑ deferred | A-PHP-002 — ext-sodium has no Ed448; PHP stdlib has no other EdDSA source. The §9.1 floor (Ed25519 + SHA-256) is fully native + the only path the corpus exercises (69/69). Route when agility lands: hybrid ext-ffi → sibling C-ABI `ec_ed448_*` (OCaml shape), opt-in; SHA-384 already native via `hash()`. Non-v0.1; does not affect the floor. |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; **no ⚑ arch asks** (dry well — corroboration-only); A-PHP-012 (NEW, packaging) + A-PHP-006/002 routed to operator/research. |
| **Published to Packagist / tagged** | ⛔ **deferred** | operator action — requires the `entity-core/protocol` id confirmed non-squatted (A-PHP-006) AND arch v0.1 sign-off (§5). No auto-tag, no push, no `composer publish`. |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external PHP consumer confirms it works — **not yet met** (no PHP consumer wired). Stays `0.1.0-pre`
until then.

---

## 2. What this peer ships

- **Composer package** — `entity-core/protocol` (`composer.json`), PHP `>= 8.3`. **Zero runtime
  Composer dependencies:** Ed25519 sign/verify from **ext-sodium** (bundled libsodium); SHA-256/384
  from the stdlib `hash()`; the uint64 carrier from **ext-gmp**; the canonical-CBOR (ECF) codec,
  Base58, and the multicodec LEB128 varint hand-rolled in `src/`. PHPUnit 11.2.0 is `require-dev`
  only. PSR-4 autoload `EntityCore\` → `src/`; `bin: ["bin/peer"]` exposes the host driver as a
  Composer-installed binary.
- **Crypto: ext-sodium-native, no FFI.** Ed25519 (libsodium) + SHA-256/384 (stdlib) — both ship with
  PHP, so a consumer of the published package inherits **no transitive runtime deps** (the cohort's
  lightest tier, alongside Ruby/Elixir/Haskell/Java/Zig). Ed448/SHA-384-agility deferred (A-PHP-002).
- **Host / oracle driver** (`bin/peer`): the S4 conformance + codec-oracle driver (`--port` / `--name`
  / `--debug-open-grants` / `--validate`; emits `LISTENING …`). Test/conformance tooling — not part of
  the published library surface (the in-repo test clients reference internals by name; freezing is a
  publish-prep pass).

---

## 3. Public API surface (the S5 "settle the surface" decision)

The stable contract is the README §Install/consume surface — the codec/crypto/identity island
(`EntityCore\Cbor`, `PeerId`, the value objects, the `EntityCoreException` lattice) plus the full peer
(`EntityCore\Peer`, `Transport`, store + capability). Internal units (`Varint`, `Base58`, the `Cbor`
framing internals, the type-floor render table) are implementation detail and may churn without a
semver bump; the `bin/peer` driver is test tooling.

**Why the surface is documented, not enforced** (the honest `0.1.0-pre` state, matching Ruby/OCaml/Zig/
CL/Java): PHP has **no module-private keyword** — Composer PSR-4 autoload exposes every `public` class
in the namespace, and `private`/`protected` would have to be applied class-by-class. A hard freeze
(privatizing internals + relocating the in-repo test clients that reference them by name) is build-risky
against the current all-source-in-repo layout and best done once the surface is frozen against a first
external consumer — exactly the Ruby / OCaml `.mli` / Zig `root.zig` deferral. Until then the surface is
documented in README §Install/consume + here.

---

## 4. Packaging notes specific to PHP

- **Composer version-grammar: omit `version`, tag-infer — Composer REJECTS the literal `0.1.0-pre`
  (A-PHP-012, NEW; overturns the S1 A-PHP-006 prediction).** Composer's version grammar recognizes only
  the stability keywords `alpha`/`beta`/`RC`/`dev` (+ `a`/`b`/numeric forms); `pre` is **not** among
  them, so `composer validate` rejects `"version": "0.1.0-pre"` with `Invalid version string
  "0.1.0-pre"` (verified in-container, Composer 2.7 / PHP 8.3 — `0.1.0-pre` REJECT vs
  `0.1.0-alpha1`/`0.1.0-dev`/`0.1.0-RC1`/`0.1.0` all OK). The Composer-idiomatic resolution is to omit
  `version` entirely and let Packagist read the VCS git tag (`0.1.0-pre`/`v0.1.0`) — Composer's own
  documented guidance for VCS-distributed packages, and a tag-less manifest passes `composer validate
  --strict` clean (the "could not detect … version, defaulting to 1.0.0" line is an informational
  notice, not an error). This is the **third** cohort ecosystem whose version grammar disagrees with
  the SemVer-dash (after RubyGems `0.1.0.pre.pre` / CL ASDF dotted-integer), and notably the *inverse*
  of A-PHP-006's "suffix-accepting majority" claim for the `-pre` suffix specifically. **Escalation:
  operator.**
- **Packagist is a VCS-indexed registry (not an upload registry).** Publishing is `composer require` /
  a submit of the public VCS URL on packagist.org + a webhook — closest in shape to RubyGems among the
  cohort but tag-driven rather than artifact-upload. There is no Maven-Central-style reverse-DNS
  namespace gate (A-JAVA-005) — but the **vendor namespace `entity-core` + package `entity-core/protocol`
  must be confirmed non-squatted** before first publish (A-PHP-006; fall back to a different vendor if
  taken). `minimum-stability: dev` + `prefer-stable: true` are retained so the unpromoted pre-release
  installs only under an explicit stability flag (`@dev`/`@alpha`).
- **Zero-runtime-Composer-dependency posture is a packaging advantage.** A consumer of the published
  package inherits *no* transitive runtime deps — crypto/hashing from ext-sodium + stdlib `hash()`, the
  uint64 carrier from ext-gmp (both core PHP extensions, declared as `ext-*` platform requirements, not
  packages), CBOR/base58/varint hand-rolled. The only pins a consumer takes are PHP `>= 8.3` +
  `ext-sodium` + `ext-gmp`.
- **`composer.json` link-metadata deliberately unset.** `homepage`/`support.source` are left unset
  (`repository_url` is TBD until first publish); the operator sets them to the published URLs at publish
  time. (No `gem build`-style homepage warning surfaces because Composer does not validate optional URL
  fields when absent.)
- **Crypto-agility — Ed25519 + SHA-256 NATIVE, Ed448 deferred (A-PHP-002).** ext-sodium closes the §9.1
  floor (69/69 byte-green) but has no Ed448, and PHP's stdlib has no other EdDSA source. When agility
  lands, the dependency-lightest route is hybrid ext-ffi to the sibling C-ABI `ec_ed448_*` (the OCaml
  shape), scoped to an opt-in agility surface so the shipped floor peer stays FFI-free; SHA-384 itself
  is already native via `hash('sha384')`. An explicit non-v0.1 item; does not affect the floor.
- **Single-thread event loop is a packaging non-issue.** No threading extension is required or
  declared (php-cli core only) — the §7b concurrency seam is pure stdlib `stream_*`; `TCP_NODELAY` is a
  best-effort latency tune via ext-sockets when present (A-PHP-010), not a declared dependency.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-PHP-* items are resolved-in-peer or owner-routed; none block release. **There are no ⚑ arch
asks from this peer** — the honest cohort-fit result is a **dry well**: PHP read the complete v7.75
snapshot and *corroborated* the inherited cohort findings live against the oracle rather than surfacing
anything new (full text in `status/SPEC-AMBIGUITY-LOG.md`):

- **A-PHP-012** (NEW, packaging) — Composer rejects `0.1.0-pre` (`pre` is not a stability keyword);
  omit `version`, tag-infer. The PHP analogue of RubyGems A-RUBY-010 / CL A-CL-010, and the inverse of
  the S1 A-PHP-006 "SemVer-dash native" sub-claim. **Owner: operator.**
- **A-PHP-006** Packagist coordinate `entity-core/protocol` confirm-non-squatted — **owner: operator**
  (S5 registry step; fall back to a different vendor if taken).
- **A-PHP-002** Ed448 native gap → defer — **owner: research/agility**, DEFERRED. Does not affect the
  floor.
- **A-PHP-001/-003/-004/-005/-007/-008/-009/-010/-011** (RESOLVED) — native hand-rolled codec / GMP
  uint64 carrier / f16-from-bits / single-thread event loop / ByteString+EcfMap wrappers / PHP-runtime
  float seams / TCP_NODELAY best-effort / PSR-4 handler files — validated end-to-end at S2–S4.

**Corroborated (read as ratified v7.75 text, not re-litigated):** peer-id §1.5 canonical form,
401/403/401 §5.2/§5.2a trichotomy, §4.10 resource_bounds (413 + the 403→400 chain-depth), the
A-JAVA-010 §1.1 arbitrary-ECF-`data` shape, lowercase address-space hex (the A-CL-009 trap). The 2nd
dynamic/scripting peer finding nothing new is further convergence evidence.

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar, an external
consumer confirms the peer, AND the `entity-core/protocol` coordinate is confirmed available:

1. **Decide in-repo vs standalone repo** — per-language sibling repos are deferred keystone-wide (S10);
   current default is in-repo under `protocol-generator/php/`. Packagist needs a public VCS URL.
2. **Confirm the `entity-core/protocol` coordinate is non-squatted** (A-PHP-006) on packagist.org; fall
   back to a different vendor namespace if the `entity-core` vendor is taken.
3. **Settle the public-surface freeze** (§3): apply `private`/`protected` to the internal units and
   relocate the in-repo test clients that reference them, build-verified in the `php-toolchain` image.
4. **Promote version** `0.1.0-pre → 0.1.0` in the CHANGELOG/README labels once the promotion gate (§1)
   is met. The git **tag** is the registry coordinate (A-PHP-012 — `composer.json` stays version-less);
   tag `v0.1.0` at the reviewed commit (lifecycle §"no auto-tag"). A pre-release tag (`0.1.0-pre`) stays
   gated behind the consumer's stability flag.
5. **Set the `composer.json` link-metadata** — `homepage` / `support.source` / `support.issues` to the
   chosen repo's URLs (currently unset), and `repository_url` in `profile.toml [publishing]`.
6. **Publish** — submit the public VCS URL on packagist.org + wire the push webhook; Packagist reads the
   tags. **Tag the release** at the reviewed commit at this point only.
7. **Wire CI** (`run-s2/s3/s4.sh` + `run-origination-core.sh` + `vendor/bin/phpunit` in `php-toolchain`,
   `--network=none`, assert `summary.failed == 0`) to the chosen repo's runner, or fold into the
   keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
8. **Pin discipline** (S11): PHP 8.3 + ext-sodium + ext-gmp + Composer 2.7 + PHPUnit 11.2.0 stay exact;
   re-pinning is deliberate + reviewed. **Re-confirm 665·0F against a clean `e8524ed` oracle**
   (`tools/oracle-pin.env`, `core_gate_sha256` `e09a865f…`) if the oracle is rebuilt.

---

## 7. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged to Packagist
— gated on the coordinate check A-PHP-006 + arch v0.1; `0.1.0` promotion pending external consumer;
public-surface freeze pending; Ed448 agility deferred; CI authored-offline but not wired to a remote —
by design). Regression GREEN (**S2 69/69 · S3 12/12 · S4 665 · 292P/278W/0F/95S @ e8524ed ·
origination 3/3 · multisig 11/11 · 53-type 53/53**). The Composer manifest **validates `--strict`
clean** and **`composer install --dry-run --no-dev` confirms the platform reqs are satisfiable
offline** (zero runtime deps). Ambiguity log finalized + routed — **no ⚑ arch asks** (dry well;
A-PHP-012 NEW packaging + A-PHP-006/002 → operator/research). Operator handoff (§6) prepared. Only
`protocol-generator/php/` was touched; no shared-tracker edits; no sacred-tree writes; oracle not
rebuilt. **S5 objective met; the PHP reach peer (2nd dynamic/scripting peer) is publish-ready and
parked at `0.1.0-pre` pending arch v0.1 sign-off + the Packagist coordinate check. Nothing published.**
