# research/

The stewardship arm. Cross-arm knowledge base + escalation hub.

## Start here

If you are new, read in this order: **`PEER-ATLAS.md`** (what every peer is for) →
**`SUBSTRATE-TAKEAWAYS.md`** (what they collectively taught) → **`PROJECT-RETROSPECTIVE.md`** (the
narrative capstone). The repo-root `README.md` links into all three.

## The synthesis layer — what we learned

- **`PEER-ATLAS.md`** — **the map of the cohort.** Every peer grouped by the substrate *form* it
  represents, what axis it was selected to stress, and what it taught. Also carries the selection
  principle (we collect forms, not languages) and the standing invitation for new peers. The best
  entry point to the whole research arm.
- **`PROJECT-RETROSPECTIVE.md`** — the capstone synthesis. What the project is, how we got here, and
  what generating entity-core onto the cohort taught us about the protocol, the substrates, and the
  method. Backbone: `SUBSTRATE-TAKEAWAYS.md`.
- **`SUBSTRATE-TAKEAWAYS.md`** — what translates across substrates / what needs a seam / what doesn't.
  The operational spine of the retrospective and the source the `AGENTS.md` durable-lessons bullets
  are distilled from.
- **`CRYPTO-LANDSCAPE.md`** — the cross-language **cryptography survey**: how 46 ecosystems provision
  Ed25519 + SHA-256, the five provisioning tiers, and why Ed448 availability is decided by C-library
  scope rather than language capability.

## The territory — what exists and what's worth building

- **`PARADIGM-MAP.md`** — whole-territory cartography of language/substrate families, each with a
  viability class (NATIVE / HYBRID-FFI / QUERY-NATIVE / WRAPPER-ONLY / STUNT / SAME-FAMILY).
- **`COMPLETENESS-ROADMAP.md`** — the forward queue: remaining targets and priority.
- **`LANDSCAPE.md`** — the per-language survey: landscape tiers, library choices, codec strategy.
  ⚠ Its Tier 1–5 are **landscape** tiers (what's worth building), *not* the M1/M2/M3 **maintenance**
  tiers (how often a peer is re-measured). The two do not correlate — see the banner in that file.

## The working record

- **`evaluations/<lang>.md`** — per-language and per-paradigm deep-dives. CBOR + Ed25519 + build-system
  audits, authored BEFORE the corresponding `<lang>/profile.toml` so profile choices have a documented
  basis. **Per-language only** — the cross-cutting paradigm surveys (`authority-as-query.md`,
  `visual-paradigms.md`, `declarative-query-viability.md`, `oz-io-viability.md`,
  `wasm-codegen-comparison.md`) moved to `../protocol-generator/shared/evaluations/` on
  2026-08-23 so they publish without a keep-list entry, same as the findings.
- **`diagnostics/`** — debugging playbooks. `validate-peer-usage.md` is the canonical entry point;
  also `conformance-invariants.md` and `oracle-vendoring-policy.md`. New failure modes get pinned here
  so the next operator finds them faster.
- **`stewardship/`** — the cross-language findings **register** (`SPEC-FINDINGS-LOG.md`), the dated
  session record, and where a new `HANDOFF-TO-ARCH-*.md` escalation is **drafted**. **This is the only
  channel to architecture** — we never write to a sibling repo; arch pulls handoffs in on its own
  schedule (`AGENTS.md`, three-arm split).
- **`../protocol-generator/shared/findings/`** — where a handoff **lands** once it is written up: the
  25 durable spec findings, under undated names. A handoff is a *process* artifact (dated, addressed,
  in flight); the finding it carries is *research output* (durable, citable, and the conclusion of
  having implemented this protocol 46 times). Moving them out of `research/` on 2026-08-23 is what
  makes them publish — see `AGENTS.md` "The findings publish; the escalation stays a draft" for the
  full rule and why the register deliberately did **not** move with them.
- **`architecture-reviews/`** — reviews of arch-authored material.

The dated cross-cutting analyses that used to live at this level — the convergence set, the red-team
critical review, substrate-theory alignment, the machine-boundary assessment — moved to
`../protocol-generator/shared/syntheses/` on 2026-08-24, undated, for the same reason the findings did:
a dated name under a doc-root prefix strips at release, and three of them were already cited from the
published surface. They are a point-in-time analysis, not a living document.

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
