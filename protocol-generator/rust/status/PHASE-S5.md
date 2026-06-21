# Phase S5 — Publish (entity-core-protocol-rust)

**Status:** **documented + packaged, NOT published** (operator decides
publishing; `cargo publish` DEFERRED per S10). · **Version line:** `0.1.0-pre` · **Spec basis:**
V7 spec-data **v7.75**; codec corpus v0.8.0. · **Peer:** Rust, **clean-room** (built from the V7
spec + keystone lifecycle contracts + language-neutral sibling profiles, **NOT** from the
hand-written Rust siblings `entity-core-rust` / `entity-core-codec-ffi-rust`).

S5 polishes the S4-conformant clean-room Rust peer into a *ready-to-publish* artifact.
`/entity-rosetta` never publishes (lifecycle §Publishing) — this phase sets the package metadata,
authors the closeout docs, re-verifies the gates, and prepares the operator handoff. An operator
runs `cargo publish` when arch signs off v0.1 and a first external consumer confirms it. This doc
is the release-readiness record + the operator handoff + the steward findings summary.

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **665·0F @ e8524ed** (292P / 268W / 0F / 93skip), machine-verified `summary.failed == 0` ([`CONFORMANCE-REPORT.{md,json}`](CONFORMANCE-REPORT.md)) |
| Codec byte-identical (S2) | ✅ | **69/69** vs `conformance-vectors-v1`, re-run green at S5 (`wire-conformance`), 0 codec fixes |
| §9.5 53-type registry | ✅ | 53/53 byte-identical (render-from-model) |
| multisig accept-path | ✅ | **11/11, 0 skip** — `valid_2of3_peer_signed_accepted` PASS (oracle co-signs AS the peer) |
| origination-core | ✅ | 3/3 (`reference_connect`, `reference_ready`, `dispatch_outbound_reentry` over real TCP) |
| `cargo test --lib` | ✅ | **33/33** re-run green at S5 (codec units + §9.5 byte-diff + round-trip) |
| `cargo fmt --check` / `cargo clippy -D warnings` | ✅ | clean (re-verified at S5, offline) |
| Dep-minimization (2 direct deps) | ✅ | `ed25519-dalek =2.2.0` + `sha2 =0.10.9`; CBOR/Base58/varint hand-rolled; `Cargo.lock` = 24-pkg closure, `curve25519-dalek` held at 4.1.3 (4.2.0 yanked); `#![forbid(unsafe_code)]` |
| LICENSE present (Apache-2.0, S9) | ✅ | [`LICENSE`](../LICENSE) (peer-local copy, identical to repo-root S9 default) |
| README + conformance status | ✅ | [`README.md`](../README.md) — clean-room caveat, 665·0F status, Ed448-deferred/hybrid-FFI note, in-container build/test, `--name`/`--validate` host usage |
| CHANGELOG (spec-version pinned) | ✅ | [`CHANGELOG.md`](../CHANGELOG.md) — `0.1.0-pre tracks V7 v7.75` |
| Package metadata (`Cargo.toml`) | ✅ | name `entity-core-protocol-rust`, `0.1.0-pre`, edition 2021, `license = "Apache-2.0"`, description, `rust-version = "1.96"`, `keywords`/`categories`, `[lib] entity_core_protocol`, bins `wire-conformance` + `entity-peer-host`, `exclude` parks `output/`/`status/`/`arch/`/`profile.toml`/`run-*.sh` |
| `cargo package --locked` (offline) | ✅ | **succeeds** in `rust-toolchain:latest`, `--network=none` against the vendor mirror — packaged 29 files (src-only), verify-build compiles clean |
| Toolchain pin (S11) | ✅ | rust/cargo **1.96.0-1.fc43** (`containers/rust-toolchain/Containerfile`, reviewed distro channel → pin-for-repro); MSRV asserted 1.96 (verified-build floor) |
| Public API surface | ◑ documented | `entity_core_protocol` lib (codec island) + `peer` module; explicit semver freeze deferred to publish-prep / first consumer (§3) |
| Ambiguity log finalized (owner + status) | ✅ | [`SPEC-AMBIGUITY-LOG.md`](SPEC-AMBIGUITY-LOG.md); A-RUST-001…008 all owner-routed (§5) |
| **Published (`cargo publish`) / tagged** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6); `publish = false` guards an accidental upload; no tag pushed |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) ≥1 external consumer confirms it works — **not yet met** (no Rust consumer wired). Stays
`0.1.0-pre` until then.

---

## 2. What this peer ships

- **Rust crate** `entity-core-protocol-rust` (`Cargo.toml`, edition 2021). Library
  `entity_core_protocol` (`src/lib.rs`); the full peer under `src/peer/`; codec at the crate root
  (`src/{cbor,base58,varint,value,content_hash,peer_id,signature,error}.rs`).
- **Library:** pure-Rust, native codec, no FFI. **Two direct registry deps** —
  `ed25519-dalek` (Ed25519, audited) + `sha2` (SHA-256 floor + SHA-384 agility); the
  canonical-CBOR (ECF) layer, Base58, and LEB128 varint are hand-rolled (no `ciborium`/`bs58`/
  `leb128`; A-RUST-001). `#![forbid(unsafe_code)]`. `cargo build`/`test` run `--network=none`
  against the committed `Cargo.lock` (vendored mirror).
- **Two binaries:** `wire-conformance` (the S2 `emit-canonical` analogue, 69/69 codec gate) and
  `entity-peer-host` (the S4 conformance driver / single-peer listener — `--port`, `--name`,
  `--validate`, `--debug-open-grants`; emits `LISTENING …`). Test/conformance, not the lib surface.

---

## 3. Public-surface (the S5 "settle the surface" decision)

The stable contract is the two-tier exported surface: **Tier 1** the `entity_core_protocol` codec
island (`cbor`/`content_hash`/`peer_id`/`signature`, `Value`/`Key`, `CodecError`/`Result`) and
**Tier 2** the `peer` module (boot + serve). The codec internals (`cbor`/`base58`/`varint`) are
`pub` so the conformance harness can reach them, but they are implementation detail and may churn
without a semver bump. An explicit signature freeze — auditing the minimal exported surface and
locking it against a first external consumer — is a mechanical publish-prep pass, **deferred until
the surface is frozen against that consumer** (the honest S5 state for an all-source-in-repo peer;
mirrors the Go/Zig/OCaml deferral). `///` rustdoc is on the exported surfaces today (`cargo doc`).

---

## 4. Packaging notes specific to Rust

- **crates.io = the registry; `cargo publish` = the upload.** Unlike Go/Zig (git-tag-as-package),
  Rust has a central registry. `cargo package --locked` produces the source crate (verified here,
  offline); `cargo publish` uploads it. **DEFERRED per S10** — `publish = false` in `Cargo.toml`
  is a hard guard so no accidental upload can happen even if `cargo publish` is run. The version
  line lives in `CHANGELOG.md` + `Cargo.toml` until the operator publishes.
- **`exclude` keeps the crate lean.** The package ships `src/` + `tests/` + manifest + lockfile +
  LICENSE/README/CHANGELOG only (29 files). The gitignored `output/` (vendor mirror + oracle
  ELFs), the `status/` docs, `arch/`, `profile.toml`, and the `run-*.sh` S4 harnesses are
  `exclude`d — they are repo/keystone companions, not crate content. `target/` + `.git` are always
  excluded by cargo.
- **`repository` is parked empty** (publish-time field; the S10 in-repo-vs-standalone decision
  fixes the URL). crates.io accepts publish without it; `cargo package` emits a benign
  "no documentation, homepage or repository" warning — expected, not a gate.
- **MSRV `rust-version = "1.96"`** is asserted at the *verified-build* floor (the pinned distro
  toolchain). A lower MSRV is plausible (plain std + ed25519-dalek + sha2) but is NOT claimed
  without a verified lower-bound build — re-pin deliberately if a lower floor is proven.
- **Ed448 / crypto-agility higher bar is OUT of S5 core scope** (A-RUST-002): native-full-agility
  is not cleanly reachable in Rust (RustCrypto `ed448-goldilocks` signing is `0.14.0-pre` +
  unaudited; stable `0.9.0` has no signing). When agility enters scope the design is **hybrid** —
  native Ed25519 (shipped) + FFI Ed448 via `libentitycore_codec`'s `ec_ed448_*` over the C-ABI.
  That introduces a C-ABI dep + an `ec_abi_version` pin in the manifest (lifecycle §Version-pin,
  codec_strategy=ffi clause). Documented now so the manifest doesn't claim agility it lacks.
  Mirrors Go A-GO-002 / Zig A-ZIG-002 / OCaml A-OC-002.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S4 A-RUST-* items are resolved-in-peer and owner-routed; **none block release**, and
**none is a new spec-semantic defect**. Full text in
[`SPEC-AMBIGUITY-LOG.md`](SPEC-AMBIGUITY-LOG.md):

- **A-RUST-002** Ed448 deferred → hybrid-FFI — owner: **operator** (local profile decision, no
  spec issue). The **headline** finding: native-full-agility incl. Ed448 is not cleanly reachable
  for Rust, so Rust joins the cohort's gap→hybrid-FFI band (Go/Zig/OCaml/Swift; Haskell's native
  route was the exception). Strengthens, does not re-open, the cohort agility finding.
- **A-RUST-001** CBOR hand-roll (vs `ciborium`/`minicbor`) — owner: operator (local; documented
  swap-bar: a lib reproducing `map_keys.*`/`float.*`/`tag_reject.*` byte-for-byte WITH decode-side
  rejection).
- **A-RUST-003** `std::thread` over `tokio` — owner: operator (dep-minimization). **A-RUST-004**
  `sha2` 0.10.x pin (not 0.11.0) — owner: operator. **A-RUST-005** map-key order on encoded bytes
  (provably = length-then-lex for the ECF key space) — owner: operator (impl note; do NOT "fix" it
  into a decoded-value comparator). **A-RUST-006** peer-layer signature target = 33-byte
  content_hash (distinct from the S2 codec's ECF-bytes signer) — owner: operator (peer convention,
  §3.5 + cohort). **A-RUST-007** nonce from `/dev/urandom` + hand-rolled PEM base64 (no `rand`/
  `base64` crate) — owner: operator (dep-minimization). **A-RUST-008** S4 offline vendor mirror
  (gitignored, re-derivable from `Cargo.lock`) — owner: operator (build-mechanism).

No item blocks release. **No A-RUST entry escalates to architecture** — every one is an
operator/research-level profile/library/build decision. The spec-semantic discovery well is dry,
as expected for a same-as-sibling peer (§6 below).

---

## 6. Findings / escalation summary (for the keystone steward)

**Clean-room held.** The peer was authored from the V7 spec + the keystone `shared/lifecycle`
contracts + the language-neutral sibling profiles. The hand-written Rust siblings
`entity-core-rust` and `entity-core-codec-ffi-rust` were **never opened, read, grepped, or
referenced** at any phase (S1–S5). The Go oracle's *public conformance mechanism*
(`cmd/internal/wire-conformance` emission protocol) was studied — permitted: it is the oracle and
a cohort output, not a Rust sibling — to learn the byte-validation shape, not to copy a codec. The
committed tree at every phase is source + scripts + status only; oracle binaries and the offline
vendor mirror live under the gitignored `output/`.

**Framing: adoption + generator-independence cross-check; no new spec defect.** Rust is a
**same-language-as-sibling** peer, so its discovery value is bounded by design — the value is (a)
an independent, dep-minimized, from-scratch Rust reimplementation byte-agreeing with the Go oracle
(665·0F on the **first** oracle run, 0 peer-code iterations) and (b) a generator-independence proof
that the `/entity-rosetta` pipeline reaches a clean fixed point in a language that already has a
hand-written core. **The discovery well is dry** — no novel spec-semantic ambiguity surfaced at any
phase. This is the *expected* outcome for a same-as-sibling peer (the v7.75 surface is tight and
already trodden by 9 prior peers), and it is itself a positive signal: the spec did not wobble
under a second independent Rust reading.

**Ambiguity log: all operator-level.** A-RUST-001…008 are profile/library/build decisions, not
arch asks (see §5). The **headline is A-RUST-002** (Ed448 deferred → hybrid-FFI), which
*corroborates* the cohort agility finding (Rust sits in the gap→hybrid-FFI band) rather than
raising anything new. **Nothing requires architecture action.** Recommended steward note: the live
`--profile core` total is oracle-version-specific (665 @ e8524ed) — record per-language targets as
`N·0F @ <commit>`; the binding gate is `failed == 0`.

---

## 7. Operator handoff — how to publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an
external consumer confirms the peer:

1. **Decide in-repo vs standalone repo** (S10). Per-language sibling repos are deferred
   keystone-wide; current default is in-repo under `protocol-generator/rust/`.
2. **Settle the public-surface freeze** (§3): audit the `entity_core_protocol` + `peer` exported
   surface, confirm the codec internals don't leak into the stable contract, build-verify in
   `rust-toolchain:latest`.
3. **Promote version** `0.1.0-pre → 0.1.0` in `Cargo.toml` + `CHANGELOG.md` once the promotion
   gate (§1) is met.
4. **Set `repository`** in `Cargo.toml` and `repository_url` in `profile.toml [publishing]`
   (currently empty — the per-language repo is deferred per S10).
5. **Flip `publish`** from `false` and run `cargo publish --locked` at the reviewed commit (only at
   this point — lifecycle §"no auto-tag/publish"). Re-age the crate pins per S11 if the lock has
   drifted (`ed25519-dalek`/`sha2` re-verified ≥30 days old).
6. **Tag the release** at the reviewed commit (operator's deliberate final step).
7. **Pin discipline** (S11): the toolchain pin stays exact (rust 1.96.0-1.fc43, reviewed distro
   channel); re-pinning is deliberate. The two crate pins keep the ≥30-day registry discipline.

---

## 8. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged;
`0.1.0` promotion pending external consumer; public-surface freeze pending). `cargo package
--locked` succeeds offline; the lint floor + codec 69/69 + 33 lib units re-verified green at S5;
no peer source touched. Package metadata complete (name/version/edition/license/description/
keywords/categories/MSRV/`exclude`). LICENSE + README + CHANGELOG authored. Ambiguity log finalized
+ owner-routed (all operator-level; no arch escalation). Steward findings summary written (§6:
clean-room held; adoption + generator-independence framing; dry discovery well; no new spec defect;
headline A-RUST-002 Ed448→hybrid-FFI). Operator handoff (§7) prepared. **S5 objective met; the
clean-room Rust peer is publish-ready and parked at `0.1.0-pre` pending arch v0.1 sign-off.**

**Readiness:** `lang/rust` is ready for operator merge → keystone `master` — S1–S5 complete, all
gates green (codec 69/69, validate-peer 665·0F @ e8524ed, fmt+clippy clean, `cargo package` OK),
clean-room held, no arch escalation; `cargo publish` deferred per S10.
