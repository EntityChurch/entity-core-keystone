# Layer 1: Prompt constants — every invocation honors these

> Loaded by `/entity-rosetta` skill at every phase. These are the invariants that don't change per language or per phase.

## You are generating a full core protocol peer

You are generating `entity-core-protocol-<lang>`: a full core protocol peer in the target language. The scope is **V7 Layers 0–4** (substrate, identity, interaction, capability, bootstrap). You are NOT implementing any standard-extension (TREE, CONTENT, IDENTITY, ATTESTATION, QUORUM, REGISTRY, RELAY, etc.). The extension surface stops at the dispatcher interface — community installs handlers above that boundary.

## The spec is authoritative

The spec is `entity-core-architecture/V8/entity-core-protocol/specs/ENTITY-CORE-PROTOCOL.md` at the version named in your input. **You read it as ground truth.** The spec-data in `protocol-generator/shared/spec-data/<version>/` is a **verbatim, SHA-pinned snapshot** of the authoritative specs (byte-for-byte copies — not an extraction or paraphrase, per S2); read it as your pinned copy of the spec at that version. If it disagrees with the live spec head, that's **version skew** — flag it in `SPEC-FINDINGS-LOG.md`; never paraphrase the spec yourself.

## The oracles are ground truth

`wire-conformance` (pure codec, from `entity-core-go/cmd/internal/wire-conformance`) and `validate-peer` (live peer, from `entity-core-go/cmd/validate-peer`) are the conformance ground truth. **If they disagree with your output, your output is wrong.** Fix the generated code; do not relax or work around the test.

## Profile decides; you don't

The per-language profile (`protocol-generator/<lang>/profile.toml`) is the authority on:
- CBOR library choice + version
- Crypto library choice + version
- Error model (exceptions / `Result` / `Either`)
- Async style (sync / async / both)
- Naming idioms (camelCase / PascalCase / snake_case)
- Build system, package layout, publishing target

**You do not get to pick "the popular logger" or "the standard linter."** If a decision isn't authorized by the profile, log it in the ambiguity log and continue with a best-guess flagged as such.

## Ambiguity-log discipline

Every guess goes in `protocol-generator/<lang>/status/SPEC-AMBIGUITY-LOG.md`. Format per entry:

```
## A-<NNN>: <one-line description>

**V7 section:** <pointer or "absent">
**Profile field:** <field name or "absent">
**Your guess:** <what you chose to do>
**Rationale:** <why this guess>
**Escalation:** <"arch — spec needs clarification" / "research — profile needs field" / "operator — local decision">
```

**No silent guesses.** Items escalate to architecture as proposal candidates per `research/stewardship/HANDOFF-FROM-ARCH-v1.md`.

## No language-specific syntax in shared spec-data

`protocol-generator/shared/spec-data/` is language-agnostic. You DO NOT modify it. Language-specific shapes (C# attributes, Go tags, Rust derives) belong in `templates/` and `profile.toml`, never in `shared/`.

## Container-bound execution

You are running inside a Podman container (per `containers/<toolchain>/Containerfile`). Do not write outside the mounted workspace. `make extract` semantics for getting outputs out to the host filesystem.

## Idiom over translation

Generated output must read as code a `<lang>` developer would write. If you find yourself emitting "Go-flavored C#" or "Python-flavored Rust," stop and reconsider. The profile's idiom fields are the contract — follow them.

## What you don't do (explicit list)

- Invent spec semantics. Every protocol-shaped decision grounds in a V7 §-pointer or goes in the ambiguity log.
- Silently work around oracle failures. Failing test → code bug, not test bug.
- Pick library choices the profile doesn't authorize.
- Write language-specific syntax into shared spec-data.
- Implement any standard-extension (TREE, CONTENT, etc.).
- Skip phases for speed. Output without a green report doesn't ship.
- Commit or publish anything. Operators review outputs and commit.
