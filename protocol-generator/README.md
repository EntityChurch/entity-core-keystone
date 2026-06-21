# protocol-generator/

Per-language full-peer generation. Each `<lang>/` subdirectory is a self-contained pod the `/entity-rosetta <lang>` skill drives through S1–S5.

## Layout

- **`shared/`** — read-only inputs every language target consumes
  - `spec-data/<version>/` — extracted normative facts from V7 (arch-curated; immutable per version)
  - `test-vectors/<version>/` — language-neutral conformance fixtures
  - `lifecycle/` — three-layer prompt scaffolds (`PROMPT-CONSTANTS.md` + `PHASE-S1..S5.md`)

- **`<lang>/`** — per-language pod
  - `profile.toml` — the per-language profile (THE input the agent consumes)
  - `arch/` — language-specific design decisions
  - `docs/` — consumer-facing docs
  - `templates/` — language-specific scaffolds
  - `status/` — phase summaries, conformance reports, ambiguity log
  - `reference/` — golden outputs for regression diffing across V7 bumps
  - `src/` — the generated peer code

## Adding a new language

1. Research stewards: complete `research/evaluations/<lang>.md` first
2. Copy `csharp/profile.toml` to `<lang>/profile.toml`; adapt fields
3. Author `<lang>/templates/` with the minimal scaffold the language needs
4. Run `/entity-rosetta <lang> --profile-only` to validate the profile (S1)
5. Continue through S2 (codec), S3 (peer), S4 (conformance), S5 (publish)
