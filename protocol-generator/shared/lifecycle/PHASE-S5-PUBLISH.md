# Phase S5 — Publish

> Loaded by `/entity-rosetta <lang> --phase publish` or as final phase of full `/entity-rosetta <lang>`.

## Objective

Polish the S4-conformant peer for release. README, license, CI in Podman, package metadata, version-pin, conformance badge. Output: publishable artifact + `entity-core-protocol-<lang>` v0.1.

## What you produce

| Artifact | Source |
|---|---|
| **README.md** (in `protocol-generator/<lang>/`) | What this peer is, how to install, how to use, link to docs |
| **CHANGELOG.md** (in `protocol-generator/<lang>/`) | v0.1.0 entry; spec-version pinned (e.g. "tracks ENTITY-CORE-PROTOCOL-V7 v7.56") |
| **LICENSE** (in `protocol-generator/<lang>/`) | Per profile's `license` field (Apache-2.0 default) |
| **Package metadata** | `.csproj` for .NET, `package.json` for Node, `Cargo.toml` for Rust, `pyproject.toml` for Python, etc. Per profile |
| **CI config** | `.github/workflows/<lang>.yml` or equivalent; runs in Podman; runs wire-conformance + validate-peer-extension-free against the published artifact |
| **Conformance badge** | In README: links to CONFORMANCE-REPORT.md from S4 |
| **Spec-ambiguity-log finalization** | Any items remaining are explicitly tagged with owner + escalation status |

## Version-pin discipline

- Library version: `0.1.0-pre` initially; promote to `0.1.0` when (a) S4 fully green and (b) at least one external consumer (e.g. Avalonia for C#) confirms it works
- Spec-version: literally tracked in CHANGELOG (`v0.1.0-pre tracks V7 v7.56`)
- Codec C-ABI version: if `codec_strategy = "ffi"`, pin the `libentitycore_codec` artifact version + the ABI version (`ec_abi_version`) in your package manifest

## Publishing

`/entity-rosetta` does NOT publish to package registries. That's an operator decision after review. The phase produces a ready-to-publish artifact; operator runs `dotnet pack`, `npm publish`, `cargo publish`, etc. when ready.

## What you do NOT do

- Auto-tag release versions
- Auto-push to npm / NuGet / Maven / etc.
- Auto-commit (operators do that after review)
- Ship without S4 green

## Phase output

- All artifacts above
- `protocol-generator/<lang>/status/PHASE-S5.md` — phase summary; release-readiness checklist; pointer to operator for publishing
- `STATUS.md` (repo root) updated — per-language row marks codec/peer/conformance green; release status tracked

## Phase exit criteria

Release-readiness checklist all green; ambiguity log items either resolved or named-owner-escalated; operator handoff prepared.
