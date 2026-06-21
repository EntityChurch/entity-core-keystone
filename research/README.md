# research/

The stewardship arm. Cross-arm knowledge base + escalation hub.

## Files

- **`LANDSCAPE.md`** — live per-language survey. Tiers, library choices, codec strategy, current status. Update as profiles get drafted and phases pass.
- **`evaluations/<lang>.md`** — per-language deep-dives. CBOR + Ed25519 + build-system audits. Reproducible audit trail. Authored BEFORE the corresponding `<lang>/profile.toml` so profile choices have a documented basis.
- **`diagnostics/`** — debugging playbooks. `validate-peer-usage.md` is the canonical entry point. New failure modes get pinned here so the next operator finds them faster.
- **`stewardship/`** — the cross-language findings register (`SPEC-FINDINGS-LOG.md`) plus the running steward record. The architecture / operators / stewards hand-off boundary is described in `AGENTS.md` (the three-arm split).

## Who owns this

Research stewards. The role:
- Keep `LANDSCAPE.md` accurate
- Author `evaluations/<lang>.md` before operators touch a new language profile
- Triage ambiguity-log items from `protocol-generator/<lang>/status/SPEC-AMBIGUITY-LOG.md` and escalate to architecture as proposal candidates
- Onboard new operators (this README + `AGENTS.md`)

## How operators interact

- Read `LANDSCAPE.md` to see what languages are queued and at what tier
- Read `evaluations/<lang>.md` before authoring a new profile
- Read `diagnostics/` when conformance failures don't have an obvious root cause
- Pin novel failure modes back into `diagnostics/` when you solve them

## How architecture interacts

- Receives ambiguity-log escalations via stewards
- Updates `spec-data/<version>/` when V7 amends
- Updates the working standards (in `AGENTS.md`) when needed
- Otherwise stays out of the way
