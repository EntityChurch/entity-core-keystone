# entity-core-protocol-julia — Phase S5 summary (packaging COMPLETE; publish deferred)

**Phase:** S5 (packaging + publish)
**Date:** 2026-07-12
**Container:** `entity-core-keystone/julia-toolchain:latest` (Julia 1.11.5, fedora:43, system libsodium)
**Status:** ✅ **Packaging COMPLETE** — the peer is a native, stdlib-only Julia package
(`Project.toml` + `src/` tree) that loads + precompiles + boots to `LISTENING` in-container,
sealed-offline. Registry publish **deferred** (`0.1.0-pre`), matching the cohort convention.

> **Honest framing (ADR-0012):** Julia is a Tier-3 **corroboration / generator-robustness**
> peer sharing the cohort's generation lineage — the 682·0F pass is **cohort-consistent, not
> independent convergence**. No fresh spec finding surfaced. All conformance numbers are
> oracle-pinned (`682·0F @ cc1970f`, P 292 / W 294 / F 0 / S 96); every skip is bisected in
> `CONFORMANCE-REPORT.md`.

## Release-readiness checklist

| Artifact | State | Notes |
|---|:---:|---|
| `README.md` | ✅ | What the peer is (native multiple-dispatch codec + UInt64/BigInt hybrid numeric), build/test/run (offline `julia --project` A-JULIA-009 path), conformance badge **682·0F @ cc1970f**, native crypto floor + Ed448-deferred note, ADR-0012 honest framing |
| `CHANGELOG.md` | ✅ | `0.1.0-pre` entry; spec pinned "tracks ENTITY-CORE-PROTOCOL v0.8.0 (V8)"; honest-framing note |
| `LICENSE` | ✅ | Apache-2.0 (copy of the repo-root Apache-2.0 text; per `profile.toml [license]`) |
| `Project.toml` | ✅ | Package metadata: `name = "EntityCore"`, `uuid = b7e5f2a4-…-5b6c`, `version = "0.1.0-pre"` (was erroneously the spec `0.8.0` — corrected to the package version), `[compat] julia = "1.11"`, stdlib `[deps]` SHA + Sockets, `Test` in `[extras]`/`[targets]` |
| CI (`.github/workflows/julia.yml`) | ✅ | Podman offline three-gate: S2 codec 71/71 → S3 loopback smoke → S4 `validate-peer --profile core` (asserts `summary.failed == 0`). Mirrors the cohort pattern (prolog/zig/haskell/swift/fortran); read-only permissions, no CD, no publish |
| Version-pin | ✅ | Library `0.1.0-pre`; spec `v0.8.0 (V8)`; oracle `cc1970f`; UUID minted (see below) |
| Ambiguity log finalized | ✅ | All A-JULIA-001..012 owner/escalation-tagged; S5 finalization footer added (`SPEC-AMBIGUITY-LOG.md`) |
| Conformance badge | ✅ | README links `status/CONFORMANCE-REPORT.md` (682·0F @ cc1970f) |
| S2/S3/S4 floors | ✅ | S2 codec 71/71 · type registry 53/53 · S3 smoke 6/6 · S4 682·0F — unregressed |

## UUID / version-pin decision

- **UUID:** `b7e5f2a4-1c3d-4e6f-8a90-1d2e3f4a5b6c` — already minted into `Project.toml` (a
  Julia package must carry a UUID; the profile deferred it to "minted-at-S5"). **Retained**;
  it is the stable package identity for General-registry registration when publish happens.
- **Version:** `0.1.0-pre`. The pre-existing `Project.toml` had `version = "0.8.0"` — the
  **spec** version had leaked into the **package** `version` field. Corrected to `0.1.0-pre`
  (the cohort convention; the spec version v0.8.0 is tracked in CHANGELOG/README, not in the
  package version). Promote to `0.1.0` when S4 stays green **and** an external consumer
  confirms — same deferred state as OCaml / Elixir / Zig / Fortran.

## Publishing (deferred — matches the cohort)

Per `profile.toml [publishing]`: Julia's registry is the **General registry** (`Pkg`), keyed
by the package UUID; registration is a PR via Registrator/JuliaHub. A package need not be
registered to be `Pkg.add`ed by URL. Publish = tag a git release carrying this tree with a
working `Project.toml`; General-registry registration is a later, review-gated community step.
`repository_url` / `registry_url` are TBD on first publish — the same deferred `0.1.0-pre`
state as the rest of the cohort. **Registry upload is an operator decision after review;
`/entity-rosetta` never publishes.** (Note: General-registry Registrator historically rejects
pre-release version strings — that is a promote-to-`0.1.0` step at registration time, not a
blocker for the deferred/add-by-URL state.)

## Operator handoff (deferred registry publish)

1. Review this tree (`README.md` / `CHANGELOG.md` / `LICENSE` / `Project.toml` / CI).
2. When a community pull exists: set `profile.toml [publishing] repository_url`, tag a git
   release (`0.1.0-pre` → `0.1.0` once an external consumer confirms + S4 stays green;
   drop the `-pre` for General-registry Registrator).
3. Ed448 / SHA-384 agility is deferred (floor is Ed25519 + SHA-256); wire the opt-in C-ABI
   `ec_ed448_*` sub-package (`src/ffi_ed448.jl`) when an adopter scopes it. The floor peer
   ships native + C-ABI-free.

## The peer is complete through the conformance gate

S1 (profile — Tier-3 corroboration/robustness; multiple-dispatch codec + UInt64/BigInt hybrid
numeric) → S2 (codec **71/71**, fixed-width UInt64 head-form `{0, 2⁶³−1, 2⁶³, 2⁶⁴−2, 2⁶⁴−1}`
byte-exact; native crypto via `ccall` libsodium) → S3 (peer machinery: two-peer loopback smoke
6/6; single-threaded Task scheduler, structural §7b) → S4 (`--profile core` **682·0F** @
`cc1970f`, genuine 2-of-3 multisig accept-path + 8/8 unit, §6.11 reentry live via Channel,
type registry 53/53, origination-core 3/3) → **S5 (packaged)**.

The peer closed as **corroboration** — the spec's type distinctions are carried cleanly by a
dispatch-typed native value model (multiple dispatch, no side channel), and its numeric
determinism survives a UInt64/BigInt hybrid substrate. Steady-state value is now the
Tier-tracked re-run on future amendments.

---

## Ready-to-lift blocks for the OVERSEER (do NOT let the sub-agent edit the shared files)

The overseer integrates these into `CONFORMANCE-MATRIX.md` and `research/LANDSCAPE.md`.

### Proposed `CONFORMANCE-MATRIX.md` — §1 Primary status table row

> Tier note: Julia's `profile.toml` classes it **peer-tier-3** (LANDSCAPE Tier 3,
> corroboration/generator-robustness — a *native* technical-computing substrate, distinct from
> the FFI-hybrid alien-substrate "probe" rows). Suggested Tier cell `3`; overseer may prefer
> `probe` for post-release-track grouping.

```
| **Julia** | 3 | v0.8.0 | `cc1970f` | 682 · **0F** | **native** hand-rolled (pure-Julia, **multiple-dispatch** canonical CBOR) | **native** — system libsodium via `ccall` (Ed25519 + SHA-256; native-audited-lib tier, NOT the C-ABI) | deferred (→ opt-in FFI, C-ABI `ec_ed448_*`; libsodium has no Ed448) | Pkg (Project.toml + git), `0.1.0-pre` |
```

### Proposed `CONFORMANCE-MATRIX.md` — §2 Capability & parity table row

```
| Julia | 3 | `--name` | ✅ | ✅ genuine + accept-path **ran** (`valid_2of3_peer_signed_accepted`) + 8/8 unit | **single-threaded Task scheduler (cooperative, structural) + §6.11 Channel reentry** | **native-codec / multiple-dispatch / UInt64+BigInt hybrid numeric** |
```

### Proposed `CONFORMANCE-MATRIX.md` — intro-paragraph sentence (cohort count + recap)

> The intro currently says "Cohort: 28 peers (incl. … APL …)". Add Julia to the count and a
> recap clause in the same style:

```
**Julia** (the native technical-computing corroboration/generator-robustness peer) was measured **natively** at `cc1970f` (**682·0F Result: PASS**, 292P/294W/0F/96S, 0 fail-counting skips; genuine 2-of-3 accept-path passed + 8/8 in-peer unit; type registry 53/53; origination-core `dispatch_outbound_reentry` 3/3) — reached with a **fully NATIVE floor** (no C-ABI): a pure-Julia **multiple-dispatch** canonical CBOR codec, native `SHA` stdlib, and Ed25519 via **system libsodium through `ccall`** (the native-audited-lib crypto tier — Elixir `:crypto` / Haskell crypton class — not the keystone C-ABI FFI-hybrid the alien-substrate probes use). Its hybrid **UInt64 (fixed-width, self-test mandatory) + BigInt** numeric model corroborates the C#/Zig head-form class; single-threaded Task scheduler gives structural §7b store-safety free. No fresh spec finding (corroboration outcome).
```

### Proposed `research/LANDSCAPE.md` — Tier-3 table row (replace the `not-started` Julia row)

```
| **Julia** | T3 | **hand-rolled ECF** (A-005 confirmed; `CBOR.jl` gives no ECF canonical guarantees — declined A-JULIA-002) | **system libsodium via `ccall`** (native-audited-lib tier — Ed25519+SHA-2 native; **Ed448 gap** — libsodium has no Ed448 → opt-in FFI deferred A-JULIA-004) | **native floor** (SHA/Sockets/Test stdlibs + system libsodium; zero registered packages, `--network=none`) | **✅ S1→S5 green** — 682·0F @ `cc1970f` (292P/294W/0F/96S); corroboration/generator-robustness peer on the **multiple-dispatch codec** + **UInt64+BigInt hybrid numeric** axes; genuine 2-of-3 accept-path + 8/8 unit; origination-core `dispatch_outbound_reentry` 3/3; publish-ready `0.1.0-pre`. See `protocol-generator/julia/status/`. |
```

### Proposed `research/LANDSCAPE.md` — post-release-track table row (optional)

> If the overseer keeps Julia in the "Post-release" table alongside Tcl/Rexx/…:

```
| **Julia** | **native technical-computing substrate** — multiple-dispatch codec (type-distinguished major-type selection, the OPPOSITE of Tcl EIAS) + UInt64/BigInt hybrid numeric | **native** (pure-Julia canonical CBOR + native `SHA` stdlib + Ed25519 via system libsodium `ccall`; NO C-ABI) | **✅ S1→S5 green** — 682·0F @ `cc1970f`; corroboration (no fresh finding). `protocol-generator/julia/`. |
```
