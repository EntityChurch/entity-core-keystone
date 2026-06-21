# entity-core-keystone

**The keystone of the Entity Core arch.**

Via the `/entity-rosetta` generator skill (the *rosetta* that translates one spec into every language), `entity-core-keystone` generates **`entity-core-protocol-<lang>`** — a full core protocol peer (V7 Layers 0–4: substrate, identity, interaction, capability, bootstrap) — for arbitrary target languages. No extensions (community owns those); just the core protocol the rest of the network speaks. Plus the **codec C-ABI** — a language-agnostic contract (`ffi-generator/c-abi/spec/`) with interchangeable implementations (`entity-core-codec-ffi-{rust,c}`, both building `libentitycore_codec`) that languages without mature canonical-CBOR + Ed25519 stacks consume directly, and native codecs cross-check against.

Generating peers is the means; the end is **spec refinement** — run the generator across enough languages and V7 versions and every spec ambiguity surfaces, feeds back to architecture, and sharpens both the spec and every peer. It's the keystone: if this holds, the whole multi-language arch holds. Correctness is defined by the conformance oracles (`wire-conformance` + `validate-peer`), not by determinism (convergence-not-determinism; see `AGENTS.md`).

## Conformance & honest independence

The cohort is **21 generated core peers** (OCaml, Swift, Haskell, Go, Lean, C#, TypeScript, Java, Elixir, Common Lisp, Rust, Python, Zig, C, Ada, Ruby, Prolog, C++, Kotlin, PHP, Dart), all **`validate-peer --profile core` → 0 FAIL** on one current oracle. The per-peer transparency contract — spec version, oracle commit, codec strategy, crypto floor, known gaps, packaging — is `CONFORMANCE-MATRIX.md`.

**On the word "independent" (read this before citing a peer count).** These 21 peers are **keystone-*generated*** — they share a generation lineage. They are *not* 21 independently-authored code bases, and we do not claim that. What is real and load-bearing is **spec-forced convergence**: 21 different languages/runtimes (different integer widths, float models, crypto stacks, string models, concurrency runtimes) each converge on the *same* conformance fixed point. That is strong evidence the spec is unambiguous on the tested surface — but it is convergence on a shared spec via a shared generator, not independent authorship.

The genuinely independent code bases are the **bespoke ground-up reference impls** — the sibling repos `entity-core-{go,rust,py}` — built without the generator. (Confusingly, the keystone *also* ships clean-room Go/Rust/Python peers: "clean-room" there means the generator never opened the hand-written sibling while generating, i.e. an independence-of-*generation* cross-check — still generated, still shared lineage.) The artifact that lets any impl claim conformance to the *spec* rather than to the Go oracle's quirks is the **language-neutral golden-vector corpus**, co-versioned with the spec.

## Three arms

- **`protocol-generator/`** — per-language full-peer generation. One sub-directory per target language (`csharp/`, `typescript/`, `java/`, …); each holds the language profile, templates, generated source, and conformance status. Shared spec-data + test-vectors + lifecycle prompt templates live in `shared/`.
- **`ffi-generator/`** — FFI binding generation, organized by binding *shape*. `c-abi/` is the first: a canonical C-ABI codec spec (`c-abi/spec/`) with interchangeable impls `entity-core-codec-ffi-{rust,c}` and a differential conformance harness; future `wasm-abi/` etc. as needed.
- **`research/`** — landscape + evaluations + diagnostics + stewardship. The cross-arm knowledge base. The conformance harness contract lives in `research/diagnostics/` (`validate-peer-usage.md`, `conformance-invariants.md`, `oracle-vendoring-policy.md`).

Plus `containers/` (Podman base images per toolchain), `ops/` (CI + release scripts), and `.claude/skills/entity-rosetta/` (the user-facing `/entity-rosetta` skill).

## Where the spec and the test vectors live

The two inputs everything is generated against — the **normative spec** and the **golden vectors** — are co-versioned and live under `protocol-generator/shared/` (see its `README.md` for the full signpost):

| Input | Path | Provenance |
|---|---|---|
| **The spec** (3 normative files: `ENTITY-CORE-PROTOCOL.md`, `ENTITY-CBOR-ENCODING.md`, `ENTITY-NATIVE-TYPE-SYSTEM.md`) | `protocol-generator/shared/spec-data/v0.8.0/` | Verbatim byte-for-byte SHA-256-pinned snapshot of `entity-core-architecture`'s published specs; integrity + arch source-commit in that dir's `MANIFEST.md`. |
| **The conformance / diagnostic vectors** (ECF codec, crypto-agility, type-registry corpora — `.cbor` fixtures + `.diag` human source) | `protocol-generator/shared/test-vectors/v0.8.0/` | Byte-identical vendor of arch's canonical fixtures; SHA-256 + inventory in that dir's `MANIFEST.md`. |

**Current version is `v0.8.0` (V8)** — also recorded in the repo-root `VERSION` file. Both directories are immutable per `<version>/`; a spec amendment lands as a new sub-directory, never an in-place edit. Architecture authors both — operators never hand-edit spec-data or canonical vectors. (Note: at the V8 cutover the core spec was de-versioned `ENTITY-CORE-PROTOCOL-V7.md` → `ENTITY-CORE-PROTOCOL.md`.)

## Build — make + podman, bare host

The host needs **only `make` + `podman`** — no native language toolchains. Every build/test/conformance run happens inside a pinned per-toolchain container image.

```
make build          # the shared base image (the release gate)
make images         # every per-language toolchain image
make <toolchain>    # one image, e.g. make go / make dotnet9 / make zig-toolchain
make caps           # show the resolved resource caps + toolchain list
```

Every `podman build`/`run` carries hard per-container resource ceilings (memory + zero-swap, plus pids/cpus on run) so a runaway build can't take the host down; committed defaults are in the `Makefile`, per-machine overrides go in a gitignored `caps.local.mk`.

## Generating a peer

```
/entity-rosetta <lang>                # full S1 → S5 pipeline
/entity-rosetta <lang> --phase codec  # codec layer only
/entity-rosetta --list                # status across all language targets
```

The skill spins up the language's Podman toolchain, runs the generated peer against `wire-conformance` + `validate-peer` from `entity-core-go`, and writes to `protocol-generator/<lang>/src/`. See `AGENTS.md` for the working standards (containers everywhere, verbatim spec-data, no-doctoring oracles, profile-decides, conformance gates) and the three-arm hand-off boundary.

## Background

This repo is the operational descendant of architecture's peer-generator and
repo-setup explorations — the *why* (scope, the FFI-vs-native-vs-hybrid choice,
the cross-language matrix) and the *how* (this repo's structure, its standards,
and the hand-off boundary).

## License

Apache-2.0 (`LICENSE`) for the generator and its outputs by default; a per-language profile may set a different license per its ecosystem norm.

---

## Supporting the project

This project is developed in the open. If it's useful to you, the best support is
to use it, report issues, and contribute back — see
[CONTRIBUTING.md](CONTRIBUTING.md).

To support the work directly, see the project's funding page.
