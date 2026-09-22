# `ops/`

**This directory is a placeholder, and saying so is the point.** It has no children. Until
2026-09-17 this file described an `ops/ci/` and an `ops/release/` that have never existed, under a
status note reading *"both children to be populated by operators as the first language reaches
S5"* — by then all 46 languages had reached S5. **A wrong instruction is worse than a missing
one**: a missing one sends a reader to look, a wrong one sends them down a hole. Corrected rather
than deleted, because the question *"where is CI, where is release"* is a real one and a reader
who opens `ops/` deserves the answer.

## Where CI actually is

**Per peer, not here.** A peer that carries continuous integration carries it in its own tree, at
`protocol-generator/<lang>/.github/workflows/`. **15 of the 46 do** — `ada` `apl` `c` `cpp`
`forth` `fortran` `go` `haskell` `julia` `kotlin` `nim` `prolog` `smalltalk` `swift` `zig` — and
that is a count, not a floor: the other 31 are measured the same way, by the same oracle, through
the same harness, just not on a hosted runner.

**The measurement that decides anything is not CI.** It is `protocol-generator/<lang>/run-s4.sh`
against the pinned oracle, and the cohort-wide form is `tools/run-cohort-census.sh`. Those run on
a developer's machine or in a container, they are the source of every number in
`CONFORMANCE-MATRIX.md`, and a hosted runner is a convenience on top. See `AGENTS.md` for the
axis sweeps and what each one's authority is.

## Where release actually is

**Not in this repo, by design.** Publication is operator-driven from the ecosystem's release
tooling (`entity-core-devops`): this repo *declares* what is canonical in `CANONICAL-DOCS.toml`
and the pipeline decides what reaches public `master`. That split is [ADR-0031], and the whole
interface from our side is that one file — we do not curate a public tree, and there is
deliberately no publish script here to get out of step with the one that runs.

`make dist` and `make publish` are **reserved verbs** in the ecosystem's make convention: this
repo implements neither, because neither would be true.

## Why the directory stays

It is the conventional place a contributor looks, so it answers rather than 404s. If real
per-language release helpers are ever wanted, this is where they go — but note the standing rule
they would have to satisfy: a helper that only works on the machine that authored it is not a
recipe, and anything vendoring a dependency closure derives it from the tree's own lockfile.
