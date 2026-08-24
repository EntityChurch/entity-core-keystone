# entity-core-keystone

**One protocol, forty-six substrates, one conformance bar.**

entity-core-keystone generates a complete **entity-core protocol peer** — Layers 0–4: substrate,
identity, interaction, capability, bootstrap — for an arbitrary target language, from a pinned snapshot
of the normative spec. It has done so 46 times, in languages ranging from Rust to COBOL to APL to
hand-written x86-64 assembly to Pure Data patches, and measured every one of them against the same
conformance oracle.

This is the **keystone** in the literal sense: the place where every language and every ecosystem in the
project meets and has to agree. A peer here is not a port or a binding — it is an independent
implementation of the same wire contract, and it either clears the bar or it doesn't.

**Generating peers is the means; spec refinement is the end.** Every run of the generator forces a
careful reading of the spec through a new substrate's constraints, and every ambiguity that surfaces
goes back to architecture. The peers are valuable, but the sharpened spec is the point.

---

## Start here

New to the project? These three, in order:

1. **This file** — what it is, how to run it (below).
2. **[`research/PEER-ATLAS.md`](research/PEER-ATLAS.md)** — every peer, what it was built to stress, and
   what it taught. The best single answer to *"why is there a peer written in SQL?"*
3. **[`CONFORMANCE-MATRIX.md`](CONFORMANCE-MATRIX.md)** — the per-peer transparency contract. Check a
   peer's row here before you pull it. This file is never the authoritative number; that one is.

Then, depending on what you came for:

| You want to… | Go to |
|---|---|
| Run the thing, generate a peer | [Quick start](#quick-start) ↓ |
| Understand what 46 substrates taught us | [`research/SUBSTRATE-TAKEAWAYS.md`](research/SUBSTRATE-TAKEAWAYS.md) |
| Read the cross-language cryptography survey | [`research/CRYPTO-LANDSCAPE.md`](research/CRYPTO-LANDSCAPE.md) |
| See the whole language territory + what's viable | [`research/PARADIGM-MAP.md`](research/PARADIGM-MAP.md) |
| Read the narrative capstone | [`research/PROJECT-RETROSPECTIVE.md`](research/PROJECT-RETROSPECTIVE.md) |
| Add a peer in your language | [Adding a peer](#adding-a-peer) ↓ |
| Work in this repo as an agent or contributor | [`AGENTS.md`](AGENTS.md) + [`AGENTS-STANDARD.md`](AGENTS-STANDARD.md) |

---

## Quick start

**The host needs only `make` and `podman`.** No language toolchains — every build, test, and conformance
run happens inside a pinned per-toolchain container. Nothing is written outside the working tree.

```sh
git clone <this-repo> && cd entity-core-keystone
make help          # the target list
make build         # the shared base image (the release gate)
make caps          # show resolved resource ceilings + the toolchain list
```

Build one language's toolchain and run its conformance harness:

```sh
make go                                     # build the go toolchain image
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm \
  --network=none --security-opt label=disable -v "$PWD":/work:Z \
  entity-core-keystone/go:latest \
  sh /work/protocol-generator/go/run-s4.sh   # -profile core by default
```

Every peer has the same entry point — `protocol-generator/<lang>/run-s4.sh` — and each script documents
its own exact invocation in its header comment. Runs are sealed offline (`--network=none`) and every
container carries hard memory/pid/cpu ceilings so a runaway build cannot take the host down. Per-machine
overrides go in a gitignored `caps.local.mk`; see [`RESOURCE-CAPS.md`](RESOURCE-CAPS.md).

**Other useful verbs:** `make images` (every toolchain), `make lint` (verifies the SHA-256-pinned spec
snapshot), `make check` (lint + test), `make clean`.

## Generating a peer

The user-facing surface is the `/entity-rosetta` skill — a tool-neutral Agent-Skill in
`skills/entity-rosetta/`, readable by any `SKILL.md`-aware agent, not tied to a vendor.

```
/entity-rosetta <lang>                 # full S1 → S5 pipeline
/entity-rosetta <lang> --phase codec   # codec layer only
/entity-rosetta <lang> --phase peer    # peer machinery only
/entity-rosetta <lang> --phase verify  # conformance only
/entity-rosetta --profile-only <lang>  # S1 only: research + author the profile
/entity-rosetta --list                 # status across all targets
```

The five phases run S1 (research the ecosystem, author `profile.toml`) through S5 (packaging). They are
**loose guidance for an agent, not a deterministic pipeline** — deliberately so.

The rule that keeps generated peers idiomatic rather than transliterated: **the profile decides, the
agent doesn't.** Library choice, error model, async style, naming, and packaging all come from
`profile.toml` + `templates/`. An unauthorized decision goes in the ambiguity log instead — nobody picks
"the popular logger" on the fly.

## How conformance works

Two oracles built from `entity-core-go` are ground truth. **They are never doctored.** If an oracle
disagrees with a generated peer, the peer is wrong — and a genuine oracle bug is escalated to
architecture, never patched here.

- **`wire-conformance`** — the pure codec oracle. Byte-identical output or nothing.
- **`validate-peer`** — the live-peer oracle, driven per language by `run-s4.sh`.
  **`--profile core` is the gating profile.**

Every published number is **oracle-pinned with its full breakdown** — `755 · 3F — 309P/337W/3F/106S
@ c1b0708` — never a bare percentage. A skip counts as a failure. A peer measured on a different set of
checks than its neighbours is not a low-scoring peer, it is an **invalid measurement**, and it gets
quarantined rather than listed in the same column; `tools/check-set-gate.py` enforces that mechanically.

Two commands you'll want:

```sh
tools/tier-status.py                      # where every peer stands vs the current oracle pin
tools/run-cohort-census.sh --tier M1      # re-measure the gating tier (5 peers)
```

**Maintenance tiers** (`tools/peer-tiers.tsv`) govern re-measurement *cadence*, not quality and not
whether a peer may be published. An oracle re-pin is landed when **M1** — `go` `haskell` `lean` `ocaml`
`swift` — is re-run at 0 FAIL. Everything runs before a release.

## Where things live

Three arms, each owning its own status; cross-arm coordination flows through `research/`.

| Arm | Owns | Path |
|---|---|---|
| **protocol-generator** | per-language full-peer generation, profiles, per-peer status | `protocol-generator/<lang>/` |
| **ffi-generator** | FFI binding generation — the codec C-ABI first | `ffi-generator/<shape>/` |
| **research** | landscape, evaluations, diagnostics, stewardship, escalation | `research/` |

Each peer holds `src/` (generated source), `profile.toml`, `templates/`, `status/` (phase reports,
`CONFORMANCE-REPORT.{md,json}`, `SPEC-AMBIGUITY-LOG.md`), `reference/` (golden drift files), and
`run-s4.sh`. Shared, language-agnostic inputs are in `protocol-generator/shared/`.

The **codec C-ABI** (`ffi-generator/c-abi/spec/`) is a language-agnostic contract with interchangeable
implementations — `entity-core-codec-ffi-{rust,c}`, both building the same `libentitycore_codec` +
`entitycore_codec.h`. Seventeen substrates that cannot reach canonical CBOR + Ed25519 in-language consume
it; native-codec languages cross-check against it. It is what makes the long tail of the language
landscape reachable at all.

Plus `containers/` (per-toolchain Podman images), `ops/` (CI + release), `tools/` (the census and pin
tooling), and `skills/entity-rosetta/`.

**Out of scope:** standard-extension implementations (TREE, CONTENT, IDENTITY, ATTESTATION, QUORUM,
REGISTRY, RELAY). The community installs those atop a generated peer.

## The spec and the vectors

The two inputs everything is generated against are co-versioned and **arch-authored** — operators never
hand-edit them. Each `<version>/` directory is immutable once stamped; an amendment lands as a new
subdirectory, never an in-place edit.

| Input | Path |
|---|---|
| **The spec** — 3 normative files | `protocol-generator/shared/spec-data/v0.8.0/` |
| **Conformance / diagnostic vectors** — ECF codec, crypto-agility, type-registry corpora | `protocol-generator/shared/test-vectors/v0.8.0/` |

Both are verbatim, byte-for-byte, SHA-256-pinned snapshots with provenance in their own `MANIFEST.md`.
`make lint` verifies the pins.

## Conformance state, honestly

**The re-pin that was pending here has now happened, and it went red.** As of 2026-08-21 the oracle is
`entity-core-go @ c1b0708` and the spec snapshot is `v0.8.2`. The cohort is measured at **two pins**:

- **The 5 tier-M1 peers** (`go` `haskell` `lean` `ocaml` `swift`) were re-run at `c1b0708`. **All 5
  FAIL** — `go`/`haskell`/`ocaml` 3F, `swift` 2F, `lean` 83F (2 real + 81 cascade from one defect).
  Every FAIL is one of the five new core `capability` checks.
- **The other 40 measured peers** are still on `de8f807` (2026-08-17), where 35 of them were
  `--profile core` → 0 FAIL. **That verdict does not carry forward** and those rows are labelled
  historical: they have never been run against the new checks, and the check sets differ (755 vs 740)
  so the numbers aren't even comparable.

**These are not regressions — they are a feature nobody had implemented.** §5.6's MIN_DEFINED
temporal-ceiling construction (a minted capability's lifetime must be clamped by the caller's expiry
and the policy's `ttl_ms`) was never built in any peer; `mintToken` sets no `expires_at` at all, and
no conformance vector exercised it until now. One of the three is a **fail-open security defect**:
`go`/`haskell`/`ocaml` *honor* a presented capability whose `expires_at` is negative.

Also documented, not hidden, at the older pin: `asm-x86_64` / `asm-arm64` / `riscv64` (an invalid
measurement, see matrix §1a), `cobol` (a standing liveness cascade), `turbowarp` (exploratory, never
in scope for the core gate); `apl` is upstream-blocked and unmeasured.

> **Do not cite a "40 peers pass" figure from this repo right now.** The honest current statement is
> the two-pin split above. `CONFORMANCE-MATRIX.md` is authoritative; its 2026-08-21 banner carries the
> full accounting, and `tools/tier-status.py --gate` exits non-zero until M1 is fixed.

### On the word "independent"

Read this before citing a peer count anywhere.

These peers are **keystone-*generated***. They share a generation lineage, and most FFI-hybrid ones share
a single codec `.so`. They are **not** 46 independently-authored code bases and we do not claim they are.
A cohort of generated peers all passing one author's vectors is **cohort-consistent, not independent
convergence**.

What *is* real and load-bearing is **spec-forced convergence**: dozens of substrates with different
integer widths, float models, crypto stacks, string models, and concurrency runtimes each converge on the
*same* conformance fixed point. That is strong evidence the spec is unambiguous on the tested surface —
but it is convergence on a shared spec via a shared generator, not independent authorship.

The genuinely independent code bases are the ground-up sibling repos `entity-core-{go,rust,py}`, built
without the generator. (Confusingly, keystone *also* ships clean-room Go/Rust/Python peers — "clean-room"
there means the generator never opened the hand-written sibling, i.e. independence *of generation*. Still
generated, still shared lineage.)

## Adding a peer

**New peers are welcome, and the set is not finished.** We are collecting *forms*, not languages — a peer
earns its place by forcing the protocol through a shape no existing peer forced it through.
[`research/PEER-ATLAS.md`](research/PEER-ATLAS.md) §6 spells out what we would most like to see: new
computational models, unusual runtimes and platforms, and especially **substrates that lack a primitive
everything else assumes**.

That said — if you want a peer in your language simply because it's your language, that is a good enough
reason and the generator exists for exactly that. Just know it will likely corroborate rather than
discover, and that's fine.

To propose one, open an issue naming the substrate and, most usefully, **which axis you think it varies**.
See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the DCO sign-off requirement — contributions are Apache-2.0,
AI use is welcome and unrestricted, and the gate is an accountable human plus the quality bar.

## Background

This repo is the operational descendant of architecture's peer-generator and repo-setup explorations —
the *why* (scope, the FFI-vs-native-vs-hybrid choice, the cross-language matrix) and the *how* (this
repo's structure, its standards, and the hand-off boundary).

## License

Apache-2.0 ([`LICENSE`](LICENSE)) for the generator and its outputs by default; a per-language profile may
set a different license per its ecosystem norm. Spec text is licensed separately.

---

## Supporting the project

This project is developed in the open. If it's useful to you, the best support is to use it, report
issues, and contribute back — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

To support the work directly, see the project's funding page.
