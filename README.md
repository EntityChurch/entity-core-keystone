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
| See what 46 implementations found wrong with the spec | [`protocol-generator/shared/findings/`](protocol-generator/shared/findings/README.md) |
| Read the adversarial review of our own claims | [`protocol-generator/shared/syntheses/`](protocol-generator/shared/syntheses/README.md) |
| Add a peer in your language | [Adding a peer](#adding-a-peer) ↓ |
| Work in this repo as an agent or contributor | [`AGENTS.md`](AGENTS.md) + [`AGENTS-STANDARD.md`](AGENTS-STANDARD.md) |

---

## Quick start

**The host needs only `make` and `podman`.** No language toolchains — every build, test, and conformance
run happens inside a pinned per-toolchain container. Nothing is written outside the working tree.

### You need `entity-core-go` cloned beside this repo

**This is the one thing that is not self-contained, and it is worth understanding before you start.**
The conformance oracles — `validate-peer` (the live-peer gate) and `entity-peer` (the reference peer) —
are Go binaries built from the sibling `entity-core-go` repo. They are **deliberately not committed
here**: keystone validates *against* them and must not derive peer code *from* them, which is the
clean-room boundary the whole project rests on. So a fresh clone of this repo alone has no oracle, and
without one there is no conformance gate.

Clone them as siblings:

```sh
mkdir entity-core && cd entity-core
git clone <entity-core-keystone>
git clone <entity-core-go>          # the oracle source — required
cd entity-core-keystone
```

```
entity-core/
├── entity-core-keystone/     ← you are here
└── entity-core-go/           ← the oracle is built from this
```

The layout is the default; override with `GO_REPO=/path/to/entity-core-go` on any tool that needs it.

Then:

```sh
make build                    # the shared base image (the release gate)
make go                       # the go toolchain image — needed to build the oracle
tools/oracle-bootstrap.sh     # build validate-peer + entity-peer into output/s4-oracles/
```

`oracle-bootstrap.sh` needs network **once** (Go module download). Every conformance run after that is
sealed offline. It verifies what it built against the content digests in
[`tools/oracle-pin.env`](tools/oracle-pin.env) and **refuses with exit 3 if they do not match**, rather
than building a different oracle and reporting a green run against it.

Run a peer's conformance harness:

```sh
podman run --memory=4g --memory-swap=4g --pids-limit=2048 --cpus=4 --rm \
  --network=none --security-opt label=disable -v "$PWD":/work:Z \
  entity-core-keystone/go:latest \
  sh /work/protocol-generator/go/run-s4.sh   # -profile core by default
```

Every peer has the same entry point — `protocol-generator/<lang>/run-s4.sh` — and each script documents
its own exact invocation in its header comment. Runs are sealed offline (`--network=none`) and every
container carries hard memory/pid/cpu ceilings so a runaway build cannot take the host down. Per-machine
overrides go in a gitignored `caps.local.mk`; see [`RESOURCE-CAPS.md`](RESOURCE-CAPS.md).

**Other useful verbs:** `make images` (every toolchain), `make lint` (spec-snapshot integrity plus the
committed-report, published-anchor and link-integrity gates), `make check` (lint + test), `make clean`.

> ### If `oracle-bootstrap.sh` exits 3
>
> It is telling you the oracle it built is not the oracle these numbers were measured on, and it
> names both digests. That is the gate working — the alternative is a clean build of the *wrong*
> check set and a green run that means nothing.
>
> The usual cause is that your `entity-core-go` clone predates the pinned oracle. Update it and
> re-run. Every published number here is anchored on a **content digest** of the oracle's check set
> rather than a commit hash ([ADR-0012] Amendment 1, and [The pin](CONFORMANCE-MATRIX.md) for the
> full anchor set), so the check succeeds against any clone carrying that oracle regardless of what
> the commit is called — verified against a republished history, byte-identical result.
>
> **Only `entity-core-go` is load-bearing.** The other siblings (`entity-core-protocol` for spec
> sources, `entity-system-architecture` for guides) are not needed to build or run anything here —
> the spec snapshot is vendored and SHA-256-pinned under `protocol-generator/shared/spec-data/`.
> Generating a peer, reading the research, building any toolchain image and `make lint` all work
> from a clean clone with no oracle at all.

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
architecture, never patched here. They are gitignored local tools, not committed source — see
[Quick start](#you-need-entity-core-go-cloned-beside-this-repo) for how to build them.

- **`wire-conformance`** — the pure codec oracle. Byte-identical output or nothing.
- **`validate-peer`** — the live-peer oracle, driven per language by `run-s4.sh`.
  **`--profile core` is the gating profile.**

Every published number is **anchored on a content digest with its full breakdown** — the `go` peer
reads `755 · 0F — 312P/337W/0F/106S @ 95edd774…` — never a bare percentage, and never a commit hash ([ADR-0012]
Amendment 1: published commits are authored fresh at the release boundary, so a hash from our
internal history resolves for no outside reader, while a digest of the oracle's own check set
survives it — `CONFORMANCE-MATRIX.md` §"The pin" carries the full anchor set). A skip counts as a failure. A peer measured on a different set of
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
`run-s4.sh`. Shared, language-agnostic material is in `protocol-generator/shared/` — the pinned spec
snapshot and test vectors, the lifecycle prompts, and the cross-cutting output: `findings/` (the spec
findings routed to architecture), `syntheses/` (the convergence analysis and the red-team review of our
own claims), `evaluations/` (the paradigm-frontier verdicts) and `diagnostics/`.

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
| **The spec** — 3 normative files | `protocol-generator/shared/spec-data/v0.8.2/` (current pin; `v0.8.0` retained as a point-in-time pin) |
| **Conformance / diagnostic vectors** — ECF codec, crypto-agility, type-registry corpora | `protocol-generator/shared/test-vectors/v0.8.0/` (no `v0.8.2` vector set has been cut) |

Both are verbatim, byte-for-byte, SHA-256-pinned snapshots with provenance in their own `MANIFEST.md`.
`make lint` verifies the pins.

## Conformance state, honestly

The whole cohort is measured at **one** pin — the 755-check set `95edd774…`, spec snapshot
`v0.8.2` — with every row a fresh measurement at that pin:

- **39 of the 45 measurable peers pass `--profile core` 0-FAIL.** Tiers M1 (5/5) and M2 (8/8) since
  2026-08-22; M3 12/13 and the probes 13/18 since 2026-08-28. The maintenance-tier gate is green.
- **`cobol` 30F** — the CAP trio plus its standing 27-FAIL liveness cascade, a separate
  investigation.
- **3 peers produce INVALID MEASUREMENTS** (`asm-x86_64`, `asm-arm64`, `riscv64`) — starved runs
  that executed fewer checks than the pinned set. They are quarantined, not scored. A run measured
  on a different set of checks is not a worse score; it is not a score.
- **`wasm-wat` 2F** (hand-authored WebAssembly text) and **`turbowarp` 3F** (the block-interpreter
  probe, which never gates) are the two the propagation did not reach.
- `apl` remains upstream-blocked and unmeasured.

**The failures were never regressions — they were a feature nobody had implemented.** §5.6's
MIN_DEFINED temporal ceiling (a minted capability's lifetime must be clamped by the caller's expiry
and the policy's `ttl_ms`) was absent in every peer: `mintToken` set no `expires_at` at all, and no
conformance vector exercised it until this pin. Fixing M1 also turned up a **fail-open** —
`go`/`haskell`/`ocaml` *honored* a capability whose `expires_at` was negative — and a §6.3 rule every
peer was breaking: a rejected frame is owed a `400 non_canonical_ecf`, not silence.

**The fix shape did not vary across thirty-six languages** — roughly 200 lines over five or six
files, in the same five places every time — and that invariance is the strongest evidence the spec
reading is right, rather than merely that the tests pass. Two peers turned out to be carrying more
than the CAP trio, and both were found the same way: **fixing a wrong denial made the FAIL count go
UP, and the new failures were the truth.** `sql` went 2F → 7F → 0F once a scope-canonicalization bug
stopped standing in for two authorization checks it had never implemented.

> **The honest one-line summary: 39 of 45 measured peers are publishable today.** "No green report →
> no publish" is unchanged, and it now withholds the other **6** — plus the unmeasured `apl`, which
> has no green report either, so 7 of the 46 in the tree. (Written as a subtraction on purpose: two
> numbers in one sentence that must sum to a third is a shape that rots silently, and this one has
> been wrong before.) `CONFORMANCE-MATRIX.md` is authoritative — its banner carries the full
> accounting, §1a the invalid measurements, §1b the cascade.

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
