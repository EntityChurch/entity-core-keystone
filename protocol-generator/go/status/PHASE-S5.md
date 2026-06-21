# Phase S5 — Publish (entity-core-protocol-go)

**Status:** **documented + packaged, NOT published** (operator decides
publishing). · **Version line:** `0.1.0-pre` · **Spec basis:** V7 spec-data **v7.75**; codec
corpus v0.8.0. · **Peer:** Go, **clean-room** (built from the V7 spec + keystone lifecycle
contracts + language-neutral sibling profiles, **NOT** from `entity-core-go` — the oracle's
own source).

S5 polishes the S4-conformant clean-room Go peer into a *ready-to-publish* artifact.
`/entity-rosetta` never publishes (lifecycle §Publishing) — this phase produces the artifacts +
the runbook; an operator publishes when arch signs off v0.1. This doc is the release-readiness
record + the operator handoff. The architecture review + the publishing-options decision surface
live in [`status/ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md).

---

## 1. Release-readiness checklist

| Gate | State | Note |
|---|---|---|
| S4 `--profile core` green | ✅ | **653 / 291P / 268W / 0F / 94skip**, machine-verified `failed==0` @ oracle `75c532e` ([`CONFORMANCE-REPORT.{md,json}`](CONFORMANCE-REPORT.md)) |
| Codec byte-identical (S2) | ✅ | 69/69 vs `conformance-vectors-v1`, first run, 0 codec fixes |
| §9.5 53-type registry | ✅ | 53/53 byte-identical (render-from-model), first run (`TestCoreTypeRegistryByteIdentical`) |
| origination-core | ✅ | 3/3 PASS (`reference_connect`, `reference_ready`, `dispatch_outbound_reentry`) |
| `go test ./...` | ✅ | re-run green at S5: codec 69/69 + registry 53/53 + S3 11/11 loopback smoke |
| `go build` / `go vet` / `gofmt -l` | ✅ | clean (re-verified at S5) |
| Stdlib-only (zero deps) | ✅ | `go.sum` **empty/absent** — re-verified; single S11 pin = the toolchain |
| LICENSE present (Apache-2.0, S9) | ✅ | [`LICENSE`](../LICENSE) (peer-local copy, identical to repo-root S9 default) |
| README + conformance badge | ✅ | [`README.md`](../README.md) — clean-room caveat, build/test/run-conformance in-container, stdlib-only story, verdict + reproduce |
| CHANGELOG (spec-version pinned) | ✅ | [`CHANGELOG.md`](../CHANGELOG.md) — `0.1.0-pre tracks V7 v7.75` |
| Package metadata (`go.mod`) | ✅ | `src/go.mod` — module path, `go 1.25`, version-line + spec/oracle pins in header comment, **stdlib-only** |
| Toolchain pin (S11) | ✅ | Go **1.25.10** (`containers/go/Containerfile`, fedora dnf — reviewed distro channel); satisfies oracle's `go 1.25.0` minimum. Zero registry deps → supply-chain trivial |
| CI config (Podman, offline) | ✅ authored, not wired | [`.github/workflows/conformance.yml`](../.github/workflows/conformance.yml) — runs gofmt+vet, `go test`, `validate-peer --profile core` in `go:latest`, `--network=none`, asserts `failed==0`. **No remote/CD attached** (operator/arch decides the CI home — §6) |
| Public API surface | ◑ documented | `package entitycore` (Tier 1) + `peer` (Tier 2); codec internals under `internal/` (compiler-enforced private). Explicit semver freeze deferred to publish-prep / first consumer (§3) |
| Ambiguity log finalized (owner + status) | ✅ | [`SPEC-AMBIGUITY-LOG.md`](SPEC-AMBIGUITY-LOG.md); A-GO-001..007 all owner-routed (§5) |
| **Published / tagged** | ⛔ **deferred** | operator action after arch v0.1 sign-off (§6) — no auto-tag, no `go get`-able tag pushed, no submission |

**Promotion gate `0.1.0-pre → 0.1.0`** (lifecycle §Version-pin): (a) S4 fully green ✅ *and*
(b) ≥1 external consumer confirms it works — **not yet met** (no Go consumer wired). Stays
`0.1.0-pre` until then.

---

## 2. What this peer ships

- **Go module** `github.com/entity-core/entity-core-protocol-go` (`src/go.mod`, `go 1.25`).
  Public API at the module root (`package entitycore`); the full peer under `peer/`; codec
  internals under `internal/{cbor,base58,varint}` (compiler-enforced encapsulation).
- **Library:** pure-Go, native codec, no FFI/cgo. **Zero third-party modules** —
  `crypto/ed25519` + `crypto/sha256` + `crypto/sha512` + `net` + `testing` cover everything;
  CBOR/base58/varint hand-rolled. `go build`/`go test` run fully `--network=none`.
- **Host executable** (`cmd/host`): the S4 conformance driver (`--port`, `--debug-open-grants`,
  `--validate`; emits `LISTENING …`). Test/conformance only, not the library surface.

---

## 3. Public-surface (the S5 "settle the surface" decision)

Go's `internal/` gives **compiler-enforced privacy for free** — `internal/{cbor,base58,varint}`
are unreachable by any consumer and may churn without a semver bump (a Go-native advantage no
other cohort language has as cleanly). The remaining stable contract is the two-tier exported
surface (README §Use): **Tier 1** `package entitycore` codec island (`EncodeECF`/`DecodeECF`,
`ContentHash`, peer-id format/parse, `NewIdentity`/`Sign`/`Verify`) and **Tier 2** the `peer`
subpackage (`NewPeer`, `Serve`, config, store). An explicit signature freeze — auditing that no
exported name leaks an internal and that the surface is the locked minimum — is a mechanical
publish-prep pass, **deferred until the surface is frozen against a first external consumer** (the
honest S5 state for an all-source-in-repo peer; mirrors the Zig/OCaml deferral). godoc comments are
on the exported surfaces today.

---

## 4. Packaging notes specific to Go

- **No central registry.** Go has no crates.io/npm/NuGet equivalent. A package is a git repo;
  consumers `go get github.com/entity-core/entity-core-protocol-go@vX.Y.Z`, the version is a SemVer
  git tag, and the checksum is recorded in *their* `go.sum` + the public `sum.golang.org` transparency
  log. Decentralized + checksum-pinned **by design** — a supply-chain-friendly property. No publish
  command, no index submission.
- **The module-path / tag nuance (document, don't act).** Go resolves a module path to a repo **+ the
  in-repo directory where `go.mod` lives.** Today `go.mod` is at `protocol-generator/go/src/` inside
  the keystone monorepo. A clean `go get module@v0.1.0-pre` wants `go.mod` at a repo *root* (the
  standalone-repo lift, Option 2 in ARCHITECTURE-REVIEW §B.1) — otherwise the module path must encode
  the subdir and tags must be subdir-prefixed per Go's sub-module tagging rule. **Recommendation:
  do NOT git-tag for `0.1.0-pre`** — `-pre` is parked pending arch sign-off + a first consumer;
  tagging is the operator's deliberate final step and is cleanest *after* the in-repo-vs-standalone
  decision (which fixes the tag form). The version line lives in `CHANGELOG.md` + the `go.mod`
  comment until then. This is the Go analogue of "package metadata is set but no `cargo publish`/tag
  is run."
- **Stdlib-only is a packaging advantage.** Zero third-party modules → no transitive lockfile to
  audit, no `go.sum` fan-out (`go.sum` is empty). The only pin a consumer inherits is the Go toolchain
  version. The single S11 pin is `go 1.25.10`.
- **Ed448 / crypto-agility higher bar is OUT of S5 core scope** (A-GO-002): Go's stdlib has no Ed448,
  `golang.org/x/crypto` has none either, and no audited pure-Go Ed448 in a reviewed channel exists.
  When agility enters scope the design is **hybrid** — native Ed25519 (shipped) + FFI Ed448 via cgo
  (`libentitycore_codec` for the Ed448 family only). That introduces a C-ABI dependency + an
  `ec_abi_version` pin in the manifest (lifecycle §Version-pin, codec_strategy=ffi clause).
  Documented now so the manifest doesn't silently claim agility it doesn't have. Mirrors Zig
  A-ZIG-002 / OCaml A-OC-002.

---

## 5. Ambiguity-log finalization (owner + escalation status)

All S1–S4 A-GO-* items are resolved-in-peer and routed; none block release. Full text in
[`SPEC-AMBIGUITY-LOG.md`](SPEC-AMBIGUITY-LOG.md):

- **A-GO-006** §5.2 401/403 request-time boundary — owner: **architecture** (corroborates F20 /
  OCaml A-OC-008 / Zig A-ZIG-006 from the oracle's *own* language, derived clean-room; now 5+
  independent peers). **The one notable spec-signal of this peer** — a *corroboration*, closing the
  "cross-language artifact" door, not a new ask. Validated live.
- **A-GO-002** Ed448 native gap — resolved-by-deferral (hybrid-FFI when agility in scope). The
  genuinely cross-cohort contribution: even Go's best-resourced stdlib + `x/crypto` lacks a
  reviewed-channel Ed448, strengthening the Zig/OCaml finding. owner: research (informational).
- **A-GO-007** live `--profile core` total = 653 (not the docs' 576) — owner: research
  (informational; the delta is non-failing newer-category skips + a wider `type_system` probe; the
  binary gate is `failed==0`). Recommend keystone refresh the recorded per-language target string to
  the live `75c532e` value.
- **A-GO-001** CBOR library (hand-roll vs `fxamacker/cbor`) — owner: operator (local Go decision;
  documented swap-bar). **A-GO-003** `nint` carrier — owner: operator (impl carrier; wire is
  spec-pinned). **A-GO-004** module-path placeholder — owner: operator (publish-time URL). **A-GO-005**
  corpus version skew (v7.71 file IS the v7.75 ECF corpus) — owner: research (recommend a stamped
  `test-vectors/v7.75/`).

No item blocks release. The peer-id §7.4-vs-§1.5 contradiction is **not** re-raised here: this
clean-room peer reproduces the already-resolved §1.5-canonical reading (corroborates the fix; did
not re-discover the defect, which was settled before this peer was built — see ARCHITECTURE-REVIEW
§A.2 for the same-idiom-bound honesty).

---

## 6. Operator handoff — how to actually publish (when arch signs off v0.1)

`/entity-rosetta` does not publish. When architecture signs off the v0.1 conformance bar and an
external consumer confirms the peer:

1. **Decide in-repo vs standalone repo** (ARCHITECTURE-REVIEW §B.1). Per-language sibling repos are
   deferred keystone-wide (S10); current default is in-repo under `protocol-generator/go/`. For Go,
   the standalone lift is **materially cleaner** because of the go.mod-path/tag nuance (§4) — lean
   that way if/when the cohort splits.
2. **Settle the public-surface freeze** (§3): audit the `package entitycore` + `peer` exported
   surface, confirm no internal leaks, build-verified in the `go:latest` image.
3. **Promote version** `0.1.0-pre → 0.1.0` in `CHANGELOG.md` + the `go.mod` comment once the promotion
   gate (§1) is met.
4. **Set `repository_url`** in `profile.toml [publishing]` (currently empty — the per-language repo is
   deferred per S10).
5. **Tag the release** at the reviewed commit (only at this point — lifecycle §"no auto-tag"). For Go
   that tag *is* the distribution: consumers `go get module@<tag>`; the checksum auto-records in their
   `go.sum` + `sum.golang.org`. **There is no `publish` command to run.** Tag form depends on step 1
   (root `go.mod` → plain `v0.1.0`; subdir `go.mod` → subdir-prefixed tag).
6. **Wire CI** (`.github/workflows/conformance.yml`) to the chosen repo's runner, or fold it into a
   keystone-wide CI home if arch defines one. No remote/CD is attached today by design.
7. **Pin discipline** (S11): the toolchain pin stays exact (`go 1.25.10`); re-pinning is deliberate +
   reviewed. No registry-pulled deps to re-age (`go.sum` empty).

---

## 7. Phase exit

Release-readiness checklist green except the deliberately-deferred lines (published/tagged; `0.1.0`
promotion pending external consumer; public-surface freeze pending). CI authored (reproducible-offline)
but not wired to a remote — by design. Ambiguity log finalized + owner-routed. Architecture review +
publishing-options written ([`ARCHITECTURE-REVIEW.md`](ARCHITECTURE-REVIEW.md)), with the honest
clean-room / limited-signal framing (Go = oracle idiom → independent cross-check value, bounded
spec-refinement). Operator handoff (§6) prepared. Nothing regressed: `go build`/`vet`/`gofmt`/`go test`
re-verified green at S5; codec 69/69 + registry 53/53 + smoke 11/11 unbroken; `go.sum` empty.
**S5 objective met; the clean-room Go peer is publish-ready and parked at `0.1.0-pre` pending arch
v0.1 sign-off.**
