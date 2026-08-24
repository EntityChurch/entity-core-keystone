---
name: entity-rosetta
description: Generate a full core protocol peer (entity-core-protocol-<lang>) for a target language. Drives the 5-phase pipeline (S1 profile → S2 codec → S3 peer → S4 conformance → S5 publish) using the pinned v0.8.0 (V8) spec-data + per-language profile + conformance oracles. Output is idiomatic native source for the target language plus a conformance report and spec-ambiguity log. Container-bound execution per the project's Podman standard.
---

# /entity-rosetta — Core Protocol Peer Generator

> **Portable skill (Agent Skills open standard).** This file uses only the core
> `name` + `description` frontmatter and a plain-markdown body, so any
> SKILL.md-aware agent (Claude Code, Codex CLI, Gemini CLI, Cursor, …) can run
> it. The substance lives in tool-neutral reference files under
> `protocol-generator/shared/lifecycle/` that a non-skill agent can read
> directly; `AGENTS.md` is the cross-agent router that points here (ADR-0016).

## What it does

Generates **`entity-core-protocol-<lang>`** — a full core protocol peer in the target language. V8 Layers 0–4 (substrate, identity, interaction, capability, bootstrap). No standard-extension bundle (community installs those). Either native codec (using the target language's CBOR + Ed25519 libraries) or FFI codec (consuming `entity-core-codec-ffi`) per the per-language profile.

## Invocation

```
/entity-rosetta <lang>                    # full S1 → S5 pipeline
/entity-rosetta <lang> --phase codec      # S2 codec layer only
/entity-rosetta <lang> --phase peer       # S3 peer machinery only (assumes codec passes)
/entity-rosetta <lang> --phase verify     # S4 conformance only
/entity-rosetta --profile-only <lang>     # S1 only: research + author profile
/entity-rosetta --list                    # show language status across all targets
```

## Phases (S1 → S5)

Each phase loads its prompt-script from `protocol-generator/shared/lifecycle/PHASE-S<N>-<NAME>.md`:

| Phase | Script | Objective | Output |
|---|---|---|---|
| **S1** | `PHASE-S1-PROFILE.md` | Survey target language ecosystem; author profile.toml | `profiles/<lang>/profile.toml`, containerfile, ambiguity-log entry |
| **S2** | `PHASE-S2-CODEC.md` | Build codec layer (native or FFI per profile); byte-identical vs `entity-core-codec-ffi` | Codec module + green wire-conformance |
| **S3** | `PHASE-S3-PEER.md` | Connection, dispatch, capability validation, store, processor, handler interface | Compiling peer + smoke runner |
| **S4** | `PHASE-S4-CONFORMANCE.md` | Run `validate-peer` extension-free categories until green | `CONFORMANCE-REPORT.md` |
| **S5** | `PHASE-S5-PUBLISH.md` | README, license, CI in Podman, package metadata, version-pin | Publishable artifact + v0.1 release |

## Three-layer prompt

The agent's system prompt assembles from three layers:

1. **`PROMPT-CONSTANTS.md`** — invariants every invocation honors (spec-data authority, ambiguity-log discipline, no doctoring failures, container-bound execution, etc.)
2. **`PHASE-S<N>-*.md`** — per-phase task contract
3. **`profile.toml`** (from `protocol-generator/<lang>/`) — per-language ecosystem facts the agent must respect

Layers 1 and 2 live in `protocol-generator/shared/lifecycle/`. Layer 3 is per-language under `protocol-generator/<lang>/`.

## Inputs at invocation

```
spec-version:        v0.8.0 (current pinned snapshot; or as passed)
spec-data:           protocol-generator/shared/spec-data/<version>/
test-vectors:        protocol-generator/shared/test-vectors/<version>/
reference-encoder:   built libentitycore_codec.{so,dll,dylib} from either
                     ffi-generator/c-abi/entity-core-codec-ffi-{rust,c}/  (any conforming
                     C-ABI impl; build dir is gitignored; spec at ffi-generator/c-abi/spec/)
oracle-pure:         <entity-core-go>/cmd/internal/wire-conformance binary
oracle-live:         <entity-core-go>/cmd/validate-peer binary
language-id:         <lang>
profile:             protocol-generator/<lang>/profile.toml
templates:           protocol-generator/<lang>/templates/
output-target:       protocol-generator/<lang>/src/
container:           podman://entity-core-keystone/<lang-toolchain>:latest
```

## What the skill orchestrates

1. Validate inputs exist (spec-data version, profile, oracles built, container image)
2. Pick container per profile's `container_base`
3. Mount workspace into container
4. Load three-layer prompt for the requested phase
5. Invoke agent loop within the container
6. On phase completion: write outputs to `protocol-generator/<lang>/src/`, status to `protocol-generator/<lang>/status/`, ambiguities to `protocol-generator/<lang>/status/SPEC-AMBIGUITY-LOG.md`
7. Run conformance oracles where appropriate; surface any failures
8. Update the per-language status row (`CONFORMANCE-MATRIX.md` + `protocol-generator/<lang>/status/`)

## What the skill does NOT do

- Picks library versions on the agent's behalf (profile decides)
- Doctors failing oracle output (S5 standard: green report or no publish)
- Modifies `protocol-generator/shared/spec-data/` (architecture's territory)
- Commits or publishes — operators do that after reviewing output
