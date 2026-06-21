
# entity-core-keystone — AGENTS.md

Read **AGENTS-STANDARD.md** first. This file adds entity-core-keystone specifics.

## Overview

The **canonical conformance anchor** for the ecosystem (provided, not mandatory — anyone
may build a ground-up implementation instead). The `/entity-rosetta` generator skill
produces a full core-protocol peer (`entity-core-protocol-<lang>`) for any target language
from the pinned spec snapshot + conformance oracles + per-language profiles. **Generating
peers is the means; spec refinement is the end** — every run surfaces spec ambiguities that
feed back to architecture. A generated peer is *done* when the oracle loop says so
(statistical convergence on conformance — see the shared standard), not when it is provably
bug-free; other language communities pull it in and surface the rest.

Also owns the **codec C-ABI**: a language-agnostic contract (`ffi-generator/c-abi/spec/`)
with interchangeable implementations (`entity-core-codec-ffi-{rust,c}`), all building the
same `libentitycore_codec.{so,dylib,dll}` + `entitycore_codec.h` (provenance via
`ec_impl_info()`, not the filename). Languages without mature canonical-CBOR + Ed25519
stacks consume it; native-codec languages cross-check against it.

Out of scope: standard-extension implementations (TREE, CONTENT, IDENTITY, ATTESTATION,
QUORUM, REGISTRY, RELAY). Community installs those atop the generated peer.

## Setup / environment

- **Containers everywhere (Podman, no host writes).** Every build, test, and conformance
  run happens inside a per-toolchain `containers/<toolchain>/` image (`fedora:43` base; e.g.
  `containers/base/`, `containers/go/`, `containers/lean-toolchain/`). No host filesystem
  writes outside the working tree's `output/` dirs; use the `make extract` pattern to pull
  outputs back out for inspection. **Cap resources on every podman run/build** (the
  `PODMAN_BUILD_CAPS`/`PODMAN_RUN_CAPS` `--memory`/`--memory-swap` ceilings; `CAP_SWAP ==
  CAP_MEM` → a runaway container is OOM-killed cleanly at the cap instead of dragging the
  host into swap; tune per-host via `caps.local.mk`, see `RESOURCE-CAPS.md`).
- **Per-language worktree model:** each target lives under `protocol-generator/<lang>/`
  (generated `src/`, `profile.toml`, `templates/`, `status/`, `reference/`, `run-s4.sh`,
  `run-origination-core.sh`). Shared, language-agnostic inputs are in
  `protocol-generator/shared/`.
- **Three-arm split** — each arm owns its own status; cross-arm coordination flows through
  `research/`:

  | Arm | Owns | Lives in |
  |---|---|---|
  | protocol-generator | Per-language full-peer generation; profile authoring; per-language status + ambiguity logs | `protocol-generator/<lang>/` |
  | ffi-generator | FFI binding generation (codec FFI first; future WASM) | `ffi-generator/<shape>/` |
  | research | Landscape eval, validate-peer + diagnostics knowledge, stewardship + escalation | `research/` |

## Build & test

User-facing surface is the `/entity-rosetta` skill (`.claude/skills/entity-rosetta/`):

```
/entity-rosetta <lang>                 # full S1 → S5 pipeline
/entity-rosetta <lang> --phase codec   # codec layer only
/entity-rosetta <lang> --phase peer    # peer machinery only
/entity-rosetta <lang> --phase verify  # conformance only
/entity-rosetta --profile-only <lang>  # S1 only: research + author profile
/entity-rosetta --list                 # status across all language targets
```

Two conformance **oracles** are ground truth (built from `entity-core-go`, see Boundaries):

- **`wire-conformance`** — pure codec oracle (lower bar). Codec + types must pass
  byte-identical to `entity-core-codec-ffi`.
- **`validate-peer`** — live-peer oracle (higher bar). Full peer passes the extension-free
  categories; driven per language via `run-s4.sh`.
- **`--profile core` is the gating profile** (extension-free categories); `--profile full`
  exists for full peers. Run a single category with `validate-peer ... -category <name>`
  (e.g. `-category multisig`, `-category type_system`).
- Reference peer `entity-peer` + the oracle binaries are rebuilt from `entity-core-go` HEAD
  with `CGO_ENABLED=0 GOWORK=off` in `containers/go` (`cmd/` is its own module with local
  `replace`; without `GOWORK=off` the workspace forces `-mod=mod` errors). They are
  gitignored local tools placed in `output/s4-oracles/` — **not auto-rebuilt**, so when arch
  adds validator vectors the vendored binary is stale and silently runs the OLD check set;
  always rebuild from go HEAD and verify the new vectors compiled
  (`strings .../validate-peer | grep <vector_name>`).
- **Peer startup convention: `--name NAME`** loads the peer's Ed25519 identity from
  `~/.entity/peers/NAME/keypair` (entity-core PEM = base64 of a 32-byte seed) — persistent
  identity + peer-manager interop. `--validate` enables the `system/validate/*` conformance
  handlers, **off by default** (`dispatch-outbound` is a standing dialer, never live in
  production). `--debug-open-grants` is the degenerate seed policy `default→*`, deprecated.
- **Origination-core probes are reference-peer-gated** — a single-peer `run-s4` honest-SKIPs
  them; run them via `run-origination-core.sh`.

**No green report → no publish** (the shared standard's conformance gate).

## Project structure

Per-language layout under `protocol-generator/<lang>/`: `src/` (generated source),
`profile.toml`, `templates/`, `status/` (`PHASE-S*.md`, `CONFORMANCE-REPORT.{md,json}`,
`SPEC-AMBIGUITY-LOG.md`), `reference/` (golden drift files), `run-s4.sh`,
`run-origination-core.sh`.

Shared, language-agnostic — `protocol-generator/shared/`: `spec-data/<version>/` (pinned
spec snapshot — currently the single **`v0.8.0` / V8** snapshot; the `v7.*` snapshots were
retired at the V8 cutover, core wire byte-unchanged), `lifecycle/` (S1–S5 phase prompts),
`seed-policy/` (peer-authority bootstrap convention, keystone-authored). FFI:
`ffi-generator/c-abi/spec/` (canonical C-ABI), `ffi-generator/<shape>/output/`.

**All-source-in-repo until stabilization** — generated source stays in
`protocol-generator/<lang>/src/`; FFI outputs in `ffi-generator/<shape>/output/`. Migration
to per-language sibling repos is deferred until the pipeline stabilizes / package-manager
friction demands it / a community asks. (FFI impls are *named* as future repos so they lift
out cleanly.)

The generator's phases are **loose LLM guidance, not a deterministic pipeline** — document
process as plain prose (a README), don't formalize it into state machines / DAGs / rigid
gates. Live status lives in each peer's `status/` + `research/stewardship/` session notes;
`CONFORMANCE-MATRIX.md` (repo root) is the adopter-facing per-peer/tier transparency
contract — check it (not the dated STATUS narrative) first.

## Boundaries — do NOT modify

- **`protocol-generator/shared/spec-data/<version>/`** — a verbatim, byte-for-byte,
  **SHA-256-pinned** snapshot of the authoritative normative specs, pinned to a source commit
  in `MANIFEST.md`. **Architecture's to author.** Never paraphrase, restructure, or "extract
  facts" into it (a literal copy *is* the maximally faithful reading of the no-paraphrase
  rule); each `<version>/` is **immutable** once stamped — amendments get a new subdirectory,
  never an in-place edit.
- **Conformance oracles never doctored.** If the oracle disagrees with the generated codec,
  the *generated* code is wrong — fix the code, don't relax the test. Oracle bugs escalate to
  arch/Go (a `HANDOFF-TO-ARCH-*.md`), never patched here. Derive behavior from the **spec**,
  not from the oracle's Go source — reading the oracle to match its code inverts the
  keystone's purpose; spec-vs-oracle divergence is a *finding*. (Authoring against the
  oracle's *type-registry shapes* is the one legitimate byte-exact exception — those shapes
  are the spec's type definitions.)
- **`protocol-generator/<lang>/reference/` golden files** — a drift signal (diff across runs),
  not a determinism guarantee; never edited to mask a regression.
- **Never write to the architecture repo** (or any sibling). Reviews, proposals, and feedback
  go in THIS repo's `research/stewardship/` as `HANDOFF-TO-ARCH-*.md`; architecture pulls them
  in on its own schedule. A direct cross-repo commit, even with good content, lands as an
  unprovenanced surprise that can't be cleanly undone — the damage is the broken process.
- **After any repo-wide mechanical commit** (global find/replace, date-stamp, rename), don't
  trust the "just docs" framing — re-verify the SHA-256 spec-data pins and machine-consumed
  values (lockfile build-metadata, Containerfile `ARG …=DATE`, Go pseudo-versions) before
  accepting. Run such transforms on prose `.md` only.
- Secrets: never read `config.secret` values (see the shared standard).

## Durable cross-language lessons

Reusable peer-build knowledge worth carrying across runs (the per-session `vNNN` / `peer-sN`
diary lives in `research/stewardship/`, not here):

- **Profile decides; the agent doesn't.** Library, error-model, async-style, naming, and
  packaging choices are all driven by `profile.toml` + `templates/`. Unauthorized decisions
  go to the ambiguity log — no picking "the popular logger." No language-specific syntax
  (Go tags, C# attributes, Rust derives) ever leaks into `shared/`.
- **No platform CBOR lib suffices for canonical ECF** (incl. Rust `ciborium`, .NET
  `System.Formats.Cbor`): every peer hand-rolls the shortest-float ladder + recursive
  major-type-6 tag-reject + length-then-lex key sort on top. This is why a from-spec C codec
  is reasonable, and why the FFI layer exists.
- **Integer head-form is a fixed-width artifact, not a protocol property.** Branch the
  profile by language class: fixed-width ints (OCaml int63 / C# ulong / TS bigint / Zig u64)
  must carry the head form + self-test `[2⁶³, 2⁶⁴−1]`; bignum languages
  (Elixir/Python/Ruby/Lisp/Haskell) carry the full range free.
- **Crypto availability is a spectrum** that the S1 profile must classify: native-stdlib /
  native-audited-lib-incl-Ed448 (Haskell crypton, Elixir OTP `:crypto`) / native-pure-lang
  (Common Lisp) / gap → **hybrid-FFI** via `libentitycore_codec` (OCaml/Zig/Swift; Ed448
  only, Ed25519+SHA stay native). Hybrid-FFI is scoped to an **opt-in sub-library** so the
  shipped default core peer stays self-contained + FFI-free.
- **Concurrency taxonomy (§7b store-safety):** actor-isolation (Swift/Elixir) *or*
  STM-transactions (Haskell) satisfy store-safety structurally; raw-thread/image runtimes
  (Zig/CL) enforce it manually. The §6.11 handler-outbound demux is ~free on actor/CSP
  substrates but a correlation-map tax on thread/async peers — factor into effort estimates.
- **Type registry: render natively, don't ingest bytes.** A peer publishes `system/type/*`
  via its language's reflection over its *own* data model + an override table for entity-type
  pins — single source of truth in code, with the Go-rendered vectors as a byte-exact
  diff/drift target. "Output these bytes to hit the check mark" adds zero independent signal.
  Scope to **core + operational + the type-system bootstrap** only; a core peer never
  pre-publishes extension vocabularies (extensions bring their own types when installed).
- **FFI shared-lib gotchas** (every `entity-core-codec-ffi-<lang>` + any dual-impl
  differential): with a verbatim header + linker version-script, do **not** use
  `-fvisibility=hidden` (hidden symbols can't be promoted by `global:` → zero exports; let
  the version script alone control exports, verify with `nm -D`). A same-soname differential
  needs `dlmopen(LM_ID_NEWLM, …)`, not `dlopen` (glibc dedups by soname → silently compares a
  lib against itself).
- **Conformance-green can be vacuous.** A rejection-only oracle category (e.g. `multisig` was
  100% malformed→403) lets a fail-closed peer pass without implementing the primitive — and a
  non-core category never gates. The keystone payoff is the *finding* (an untested,
  inconsistently-implemented core primitive) as much as the fix; always add an accept-path
  unit test in the direction the oracle can't cover.
- **The extensibility boundary is research, not a one-off.** "Does a core peer already
  support installing a handler + outbound dispatch?" surfaced three buildable gaps
  (handler-register stubbed / handler outbound dispatch / a retroactive hand-maintained
  `--profile core` map) — design the core ↔ extension ↔ SDK boundary, don't bolt on a spike.
  Compute is an entity-native handler dispatching through the *same* §6.6 path (dispatch
  uniformity).
- **Peer-selection: discovery yield is substrate-bound, not idiom-bound.** Spec gaps come
  from wire-touching axes (integer width / float model / crypto availability / string model);
  a peer novel only off-wire (concurrency / error-idiom / packaging) adds generator
  robustness, not new findings. With 15 peers the spec-discovery well is dry on the current
  surface — steady-state value is **re-running the existing cohort against each amendment**,
  not adding language #N. Maintenance is tier-tracked (a Tier-1 lockstep set re-runs on every
  amendment; lower tiers catch up as capacity allows). The tier roster is
  `research/LANDSCAPE.md` (Tier 1 major platforms / native-codec-viable → Tier 5 functional/niche).
- **Lean proof vector** (the highest-signal channel): build the conformant peer first, then
  prove selected invariants in Lean — a proof needing an unstated hypothesis is an
  under-specified precondition (→ `A-LEAN-*` finding), a counterexample is a spec defect.
  Prove what's feasible; an unprovable-here-but-spec-sound invariant is a documented scope
  boundary, not a failure. Distinguish **soundness from completeness** in every theorem
  (conformance vectors never flag that gap); the proof covers the authority *logic interior*
  — crypto, the IO/concurrency shell, and the adversarial-input parser stay owned by KATs,
  race tests, and fuzzing. Ship the peer mathlib-free; proofs live in a `proofs/` target.
