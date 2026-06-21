# Phase S5 — Publish (entity-core-protocol-ruby)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` · **Gem coordinate:** `0.1.0.pre` (RubyGems pre-release
spelling — A-RUBY-010). · **Spec basis:** V7 spec-data **v7.75** (the COMPLETE ratified snapshot — no
snapshot-lag caveat; the §6.13 register / §6.9a owner-cap / §7a peer surface AND the §4.8/§4.9/§4.10
substrate floor are all present as ratified text); codec corpus byte-identical v7.73→v7.75.

S5 polishes the S4-conformant peer #12 — the cohort's **first dynamic / duck-typed / scripting peer**
and the **10th byte-compatible core impl** — into a *ready-to-publish* artifact. `/entity-rosetta`
never publishes (lifecycle §Publishing) — this phase produces the artifacts + the runbook; an
operator publishes when arch signs off v0.1 AND the RubyGems id is confirmed non-squatted. This doc
is the release-readiness record + the operator handoff. The architecture review + the
publishing-options decision surface live in `status/ARCHITECTURE-REVIEW.md`.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | 653 / 291P / 268W / **0F** / 94S, machine-verified `summary.failed == 0` (`status/CONFORMANCE-REPORT.{md,json}`), oracle `entity-core-go @75c532e`. All 16 core categories 0-FAIL. (653 vs the v7.75 8-peer-rerun's 576 = later-oracle extension categories that auto-skip under `--profile core`; FAIL gate + core categories unchanged.) |
| origination-core (reentry) | ✅ | 3/3 over real two-peer TCP (`reference_connect` · `reference_ready` · `dispatch_outbound_reentry`). |
| S2 lower bar (codec byte-identical) | ✅ | 69/69 vs `conformance-vectors-v1`, first full run, 0 codec fixes. **Re-ran GREEN at S5** after packaging (`rake test`). |
| §9.5 53-type floor byte-identical | ✅ | 53/53 (render-from-shapes; content_hash recomputed by the Ruby codec, asserted equal to the Go reference @75c532e — not ingested). |
| S3 two-peer loopback smoke | ✅ | 11/11 (handshake + dispatch + capability + 8-way request_id demux). **Re-ran GREEN at S5.** |
| Ed25519 + Ed448 native (agility primitives) | ✅ | stdlib openssl (OpenSSL 3.x), zero FFI; byte-verified vs the v7.67 pins (Ed448 seed→pubkey / peer_id / content_hash / 114-B sig) (A-RUBY-002/003). |
| `rake test` clean | ✅ | **32 runs / 66 assertions / 0 failures** (ECF 69/69 + agility 35/35 + smoke 11/11), re-run in-container at S5. |
| LICENSE present (Apache-2.0, S9) | ✅ | `LICENSE` (peer-local Apache-2.0; gemspec `spec.license = "Apache-2.0"`). |
| README + conformance badge | ✅ | `README.md` (build/test/run-conformance in-container, idiom story, verdict + reproduce + the byte-identity proof; links `status/CONFORMANCE-REPORT.md`). |
| CHANGELOG (spec-version pinned) | ✅ | `CHANGELOG.md` — `0.1.0-pre tracks V7 spec-data v7.75`; the A-RUBY-010 version-spelling note carried. |
| Package metadata (`gemspec`) | ✅ | `entity_core_protocol` `0.1.0.pre`, Ruby `>= 3.2`, Apache-2.0, **zero runtime deps**, `rubygems_mfa_required`. **`gem build` succeeds + `spec.validate` passes in-container** (only warning: deliberately-unset homepage). |
| Version-spelling correctness | ✅ | `0.1.0.pre` (dotted) verified `prerelease? == true` in-container (Ruby 3.4.4 / RubyGems 3.6.7); the SemVer-dash `0.1.0-pre` would mis-canonicalize to `0.1.0.pre.pre` — A-RUBY-010. |
| Toolchain pin (S11) | ✅ | Ruby **3.4.4 (MRI/CRuby)** + bundled **openssl gem 3.x** (OpenSSL 3.x; Ed25519+Ed448+SHA-2). Floor `>= 3.2`. Minitest 5.25 + Rake 13.2 = dev-only DEFAULT gems (ship with Ruby); **zero runtime gem deps**. |
| CI config (Podman, offline) | ◑ runnable, not wired | the build/test/conformance run sealed-offline in `ruby-toolchain` today (`run-s3/s4.sh`, `run-origination-core.sh`, `bundle exec rake test`, all `--network=none`). A committed CI *workflow* is deferred **cohort-wide** — no peer has one wired; lands at S10 lift or when arch defines the shared CI home. |
| Public API surface | ◑ documented | two tiers in README §Use (Tier 1 model+codec+identity / Tier 2 full peer); internal units (`Varint`/`Base58`/`Wire`/type-floor table) + `exe/` drivers may churn / are not shipped. Ruby has no module-private keyword, so an explicit semver freeze is a doc + test-relocation pass deferred to publish-prep / first consumer (the OCaml `.mli` / Zig `root.zig` / CL export-tier analogue). |
| Ambiguity log finalized (owner + status) | ✅ | `status/SPEC-AMBIGUITY-LOG.md`; **no ⚑ arch asks** (dry well — corroboration-only); A-RUBY-005/009/010 routed to operator/research. |
| **Published to RubyGems / tagged** | ⛔ **deferred** | operator action — requires the `entity_core_protocol` id confirmed non-squatted (A-RUBY-005) AND arch v0.1 sign-off (§5). No auto-tag, no push, no `gem push`. |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and* (b) ≥1
external consumer confirms it works (the C#-class "Avalonia confirms" analogue) — **not yet met** (no
Ruby consumer wired). Stays `0.1.0-pre` / gem coordinate `0.1.0.pre` until then.

---

## 2. What this peer ships

- **RubyGem** — `entity_core_protocol` `0.1.0.pre` (`entity_core_protocol.gemspec`), Ruby `>= 3.2`.
  **Zero runtime gem dependencies:** Ed25519/Ed448 sign/verify + SHA-256/384 from the stdlib
  `openssl` gem (OpenSSL 3.x); the canonical-CBOR (ECF) codec, Base58, and the multicodec LEB128
  varint are hand-rolled in `lib/entity_core/`. Minitest + Rake are dev-only DEFAULT gems (Gemfile,
  not the gemspec). `gem build` produces `entity_core_protocol-0.1.0.pre.gem` (25 files), `spec.files`
  scoped to `lib/**/*.rb` + LICENSE/README/CHANGELOG.
- **Crypto: stdlib-openssl-native, no FFI.** The bundled `openssl` gem (OpenSSL 3.x) supplies BOTH
  curve families' sign/verify natively via one generic PKey surface — the **third native-full-agility
  substrate** (after Elixir `:crypto` and Haskell crypton, and the first via OpenSSL stdlib). No
  libsodium/RbNaCl, no second provider, no C-ABI in the manifest.
- **Host / oracle drivers** (`exe/entity-core-peer`, `exe/wire-conformance`): the S4 conformance +
  codec-oracle drivers (`--port`/`--debug-open-grants`/`--validate`; emit `LISTENING …`).
  Test/conformance tooling only — **excluded** from the published gem surface.

---

## 3. Public API surface (the S5 "settle the surface" decision)

The stable contract is the README §Use two tiers — **Tier 1** model + codec + identity
(`EntityCore::Cbor`, `Entity`, `Envelope`, `PeerId`, `Identity`, `Signature`, `Hash`, the `Error`
lattice) and **Tier 2** full peer (`EntityCore::Peer`, `Transport`, `Store`, `Capability`,
`Handler`, `CoreTypes`). Internal units (`Varint`, `Base58`, `Wire` framing, the
`data/core_type_floor` render table) are implementation detail and may churn without a semver bump;
the `exe/` drivers are test tooling and are not part of the gem.

**Why the surface is documented, not enforced** (the honest `0.1.0-pre` state, matching OCaml/Zig/
CL/Java): Ruby has **no module-private keyword** — `require "entity_core"` exposes the whole
`EntityCore` namespace, and `private`/`private_constant` would have to be applied class-by-class. A
hard freeze (privatizing internals + relocating the in-repo test clients that reference them by name)
is build-risky against the current all-source-in-repo layout and best done once the surface is frozen
against a first external consumer — exactly OCaml's `.mli` / Zig's `root.zig` / CL's export-tier
deferral. Until then the tiers are documented in README §Use + here.

---

## 4. Packaging notes specific to Ruby

- **RubyGems version-spelling: dotted `0.1.0.pre`, NOT SemVer-dash `0.1.0-pre` (A-RUBY-010, NEW).**
  `Gem::Version` treats a literal `-` as a `.pre.` separator, so `Gem::Version.new("0.1.0-pre")`
  canonicalizes to the malformed `0.1.0.pre.pre` (verified in-container, Ruby 3.4.4 / RubyGems
  3.6.7). The idiomatic pre-release spelling is the **dotted `0.1.0.pre`** — canonicalizes to itself,
  `.prerelease?` true, and `gem install` hides it from default resolution (consumers need
  `--pre` / an explicit pin). So `EntityCore::VERSION = "0.1.0.pre"` is the gem coordinate, while the
  CHANGELOG/README/this-doc carry the cohort `0.1.0-pre` label. **This is the exact distant-idiom
  shape as Common Lisp's A-CL-010** (ASDF's dotted-integer-only `:version` rejecting `0.1.0-pre`) —
  the second cohort ecosystem whose version grammar disagrees with the SemVer-dash, against the
  SemVer-suffix-accepting majority (Maven `-pre`, opam, build.zig.zon, package.json, mix.exs, Cargo).
  Logged so a future promotion re-applies the spelling. **Escalation: operator.**
- **RubyGems is a real upload registry.** Publishing is `gem push entity_core_protocol-0.1.0.pre.gem`
  after `gem signin` / API key (contrast the git-repo-indexed CL Quicklisp / Zig build.zig.zon URLs).
  No namespace-verification gate like Java's Maven Central reverse-DNS (A-JAVA-005) — but the **gem id
  must be confirmed non-squatted** before first push (A-RUBY-005; fall back to
  `entity_core_protocol_ruby` if `entity_core_protocol` is taken).
- **Zero-runtime-gem-dependency posture is a packaging advantage.** A consumer of the published gem
  inherits *no* transitive runtime deps (crypto/hashing from stdlib openssl/digest; CBOR/base58/
  varint hand-rolled) — the cohort's lightest tier (tied with Elixir/Haskell/Java/Zig), and uniquely
  reaching *full crypto agility* there via OpenSSL stdlib with no FFI. The only pin a consumer takes
  is Ruby `>= 3.2` (`Data.define` + openssl ≥ 3.0).
- **Gemspec link-metadata deliberately unset.** RubyGems validates `homepage`/`source_code_uri`/
  `changelog_uri` as real http(s) URLs; `repository_url` is TBD until first publish, so these are
  left unset (which is why `gem build` warns "no homepage specified" — a benign, expected warning).
  The operator sets them to the published URLs at publish time.
- **Crypto-agility — primitives NATIVE, full MATRIX deferred (cohort-wide).** Ed25519 + Ed448 +
  SHA-256/384 are native via stdlib openssl (zero FFI) and the M2/M3/M6 `root_cap` cap-token shapes
  are byte-confirmed (A-RUBY-007). The agility *full MATRIX* harness (the key-type × hash-format
  cross-product end-to-end) is the documented non-v0.1 item — no FFI or second provider needed when
  it lands. Does NOT affect the §9.1 floor (Ed25519 + SHA-256, 69/69 byte-green) nor the connect-path
  agility slice.
- **The `exit!(0)` shutdown footgun (S4 note, resolved).** `exe/entity-core-peer`'s signal trap uses
  `exit!(0)` rather than `listener.close`: killing the accept-loop `Thread` while it is blocked in the
  C `accept(2)` CFUNC segfaults MRI (`Thread#kill` racing a blocking CFUNC). The harness tears down
  the whole container, so a hard exit is the race-free shutdown. Host-driver detail, not a library
  matter.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S5 A-RUBY-* items are resolved-in-peer and routed; none block release. **There are no ⚑ arch
asks from this peer** — the honest cohort-fit result is a **dry well**: Ruby read the now-ratified
v7.75 findings as text and *corroborated* them live against the oracle rather than surfacing anything
new (full text in `status/SPEC-AMBIGUITY-LOG.md`; retrospective in `ARCHITECTURE-REVIEW.md` §A.2):

- **A-RUBY-010** (NEW, packaging) — RubyGems treats `0.1.0-pre` as `0.1.0.pre.pre`; idiomatic spelling
  is dotted `0.1.0.pre`. The Ruby analogue of CL A-CL-010. **Owner: operator.**
- **A-RUBY-005** RubyGems id `entity_core_protocol` confirm-non-squatted — **owner: operator** (S5
  registry step; fall back to `entity_core_protocol_ruby`).
- **A-RUBY-009** absent v7.75 test-vector snapshot + the deferred-gate-count note — **owner:
  research/operator** (non-blocking; codec byte-identical v7.73→v7.75 per the MANIFEST, the live
  `--profile core` run is the version-authoritative superset).
- **A-RUBY-002/-003/-006/-007/-008** (RESOLVED) — Ed448 native byte-verified / openssl raw-key API /
  f16-from-bits / root_cap cap-token shape byte-confirmed / full 53-type §9.5 floor 53/53.
- **A-RUBY-001/-004** (RESOLVED) — native hand-rolled codec / thread-per-connection-under-GVL
  validated end-to-end (the 64-thread one-winner CAS race proves the explicit Mutex is load-bearing).

**Corroborated (read as ratified v7.75 text, not re-litigated):** peer-id §1.5 canonical form,
401/403/401 §5.2/§5.2a trichotomy, §4.10 resource_bounds (413 + the 403→400 chain-depth), the
A-JAVA-010 §1.1 arbitrary-ECF-`data` shape, lowercase address-space hex (the A-CL-009 trap). The
cohort's prior spec-first peers drained the ambiguity well; the 12th peer finding nothing new is the
convergence thesis's strongest single data point.

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar, an external
consumer confirms the peer, AND the `entity_core_protocol` gem id is confirmed available:

1. **Decide in-repo vs standalone repo** (see `ARCHITECTURE-REVIEW.md` §B.1). Per-language sibling
   repos are deferred keystone-wide (S10); current default is in-repo under `protocol-generator/ruby/`.
2. **Confirm the `entity_core_protocol` gem id is non-squatted** (A-RUBY-005) on rubygems.org; fall
   back to `entity_core_protocol_ruby` if taken. (No Maven-Central-style namespace gate.)
3. **Settle the public-surface freeze** (§3): apply `private`/`private_constant` to the internal
   units and relocate the in-repo test clients that reference them, build-verified in the
   `ruby-toolchain` image.
4. **Promote version** `0.1.0.pre → 0.1.0` in `lib/entity_core/version.rb` + the `0.1.0-pre` label in
   CHANGELOG/README once the promotion gate (§1) is met. (Drop the A-RUBY-010 `.pre` spelling note
   on promotion — the release version `0.1.0` has no pre-release suffix.)
5. **Set the gemspec link-metadata** — `spec.homepage` / `spec.metadata["source_code_uri"]` /
   `["homepage_uri"]` / `["changelog_uri"]` to the chosen repo's http(s) URLs (currently unset; this
   clears the "no homepage specified" `gem build` warning), and set `repository_url` in
   `profile.toml [publishing]`.
6. **Publish** — `gem build entity_core_protocol.gemspec` then `gem push
   entity_core_protocol-<version>.gem` (after `gem signin` / API key). A `.pre` gem stays hidden from
   default resolution (consumers need `--pre` / an explicit pin) — correct for the unpromoted line.
   **Tag the release** at the reviewed commit at this point only (lifecycle §"no auto-tag").
7. **Wire CI** (`run-s3/s4.sh` + `run-origination-core.sh` + `bundle exec rake test` in
   `ruby-toolchain`, `--network=none`, assert `summary.failed == 0`) to the chosen repo's runner, or
   fold into the keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
8. **Pin discipline** (S11): Ruby 3.4.4 + the bundled openssl 3.x + Minitest/Rake pins stay exact;
   re-pinning is deliberate + reviewed.

---

## 7. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged to
RubyGems — gated on the id-availability check A-RUBY-005 + arch v0.1; `0.1.0` promotion pending
external consumer; public-surface freeze pending; CI authored-offline but not wired to a remote — by
design). Regression GREEN after packaging (**S2 69/69 · S3 11/11 · S4 653 · 291P/268W/0F/94S ·
origination 3/3 · 53-type 53/53 · `rake test` 32/0**). The gem builds + validates clean
(`entity_core_protocol-0.1.0.pre.gem`, `prerelease? == true`, zero runtime deps; only the
deliberately-unset-homepage warning). Ambiguity log finalized + routed — **no ⚑ arch asks** (dry
well; A-RUBY-005/009/010 → operator/research). Architecture review + publishing-options written
(`status/ARCHITECTURE-REVIEW.md`). Operator handoff (§6) prepared. **S5 objective met; the Ruby peer
#12 (first dynamic/scripting peer, 10th byte-compatible core impl) is publish-ready and parked at
`0.1.0-pre` (gem coordinate `0.1.0.pre`) pending arch v0.1 sign-off + the RubyGems id check.**
