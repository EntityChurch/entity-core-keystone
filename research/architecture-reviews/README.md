# Architecture Reviews — per-language running dev logs

Post-implementation **running** logs, one per generated peer
(`entity-core-protocol-<lang>`). Distinct from `research/evaluations/<lang>.md`,
which is the *pre*-implementation ecosystem survey that grounds the profile:

| Doc | When | Question it answers |
|---|---|---|
| `research/evaluations/<lang>.md` | before S1/S2 | which libraries, native-vs-FFI, what risks — feeds `profile.toml` |
| `research/architecture-reviews/<lang>.md` | appended each phase | **what composition did we actually build, and why** — the choices, the friction, the deviations to watch |

**Purpose.** As the generator runs across languages we want a register of the
*architecture decisions each peer made and the reasoning behind them*, so we can
later ask cross-language questions: did every native peer hand-roll shortest-float?
did every peer separate the Layer-1 cap verdict the same way? where did the spec
force each impl into the same corner (→ spec proposal candidates), and where did
idiom legitimately diverge (→ leave alone)? These logs are the raw material for that
analysis. They are descriptive, not normative — the spec + oracles are authority.

Append one dated entry per phase per language. Keep the "known deviations / watch
list" current — it is the standing input to the next S4 `validate-peer` run.
