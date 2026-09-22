# Keystone memory — index

What a session would otherwise rediscover the hard way. **Findable by the symptom**, because
that is what a reader arrives with — every file opens with an *Arrive here when* line.

This is not status and not a diary: no dates in the prose, no session narration, and an entry
is **superseded in place** rather than appended to (git holds the history). What lives where:

| file | answers | when |
|---|---|---|
| [`WIRE-AND-CODEC.md`](WIRE-AND-CODEC.md) | Canonical ECF, framing, refusal dispositions, the put-admission path, the type registry, and the codec C-ABI | a peer drops a frame, answers the wrong status or code, stores something it should have refused, or two codec implementations disagree |
| [`AUTHORITY-AND-SCOPE.md`](AUTHORITY-AND-SCOPE.md) | The section-5 scope algebra, granter frames, capability minting and temporal fields, the scope matchers, and the PD-2 gate | a request is refused with 403 and should not be, a delegated capability is honoured and should not be, or a mint produces the wrong expiry |
| [`SUBSTRATE-AND-RUNTIME.md`](SUBSTRATE-AND-RUNTIME.md) | What a target language's runtime does to a peer: crypto availability, concurrency shape, lifetimes and leaks, source-format hazards, and the visual and query paradigms | the peer crashes, hangs, leaks, or a source file will not compile for a reason particular to the language |
| [`PEER-HOST-AND-SEAMS.md`](PEER-HOST-AND-SEAMS.md) | The keystone peer contract and the extension-host surface — what a third party can install, reach, and read in a constructed peer | an installed handler cannot be reached, an in-process surface differs from the wire, or an extension can see something it should not |
| [`CONTROLS-AND-PLANTS.md`](CONTROLS-AND-PLANTS.md) | Why a green gate may have measured nothing: vacuous checks, inert controls, plant discipline, and probe design | a gate or test passes and you are not sure it asked anything |
| [`CENSUS-AND-REPORTS.md`](CENSUS-AND-REPORTS.md) | Reading a run: rates and intermittents, stale and mixed-age reports, exclusions, cross-tabulation, and what the cohort can tell you that one peer cannot | a number moved, a peer looks unfairly good or unfairly terrible, or a result will not reproduce |
| [`ORACLE-AND-PINS.md`](ORACLE-AND-PINS.md) | The oracle pin and its anchors, check-set digests, comparability, budget starvation, maintenance tiers, and every input a peer's verdict derives from | two numbers are not comparable, a run stopped early, or a pinned input moved under you |
| [`HARNESSES-AND-AXES.md`](HARNESSES-AND-AXES.md) | The per-peer `run-sN` harnesses and the cohort axis sweeps: invariants of that interface, teardown, argv, streams, container boundaries, and which axis has an authority behind it | `run-s*.sh` behaves differently than documented, an axis has no cohort runner, or a gate rewrote something it should not have |
| [`CONTAINERS-AND-BUILD.md`](CONTAINERS-AND-BUILD.md) | Podman images, pinned dependency closures, offline sealing, and the stale-build-artifact family | a build works here and nowhere else, an image will not rebuild from scratch, or a fix did not reach the artifact under test |
| [`FINDINGS-AND-ESCALATION.md`](FINDINGS-AND-ESCALATION.md) | Authoring a finding that survives review: the false-negative family, negative claims, counts and the surface they range over, and verifying a routed claim in both directions | you are about to publish a count, a negative claim, or a correction to a counterpart |
| [`PUBLICATION-AND-DOCS.md`](PUBLICATION-AND-DOCS.md) | The publication boundary: the keep-list, what a citation must resolve to, and how published prose rots while every gated number stays correct | a published document points at something a reader cannot open, or a number's anchor does not resolve |
| [`ROUTING-AND-TRACKERS.md`](ROUTING-AND-TRACKERS.md) | Packets out, packets in, and what a claim from another repo is worth until you have re-derived it | you are sending a packet, reconciling a tracker, or about to act on something a counterpart told you |
| [`COHORT-SWEEPS.md`](COHORT-SWEEPS.md) | Landing one rule across 46 peers: vanguard first, what propagates by rebuild and what does not, and the controls on the closing claim | a rule must land on every peer, or a cohort-wide claim needs a closing measurement |

## The rule that bounds this directory

> **An entry that could become a check SHOULD become one — and is then deleted from here.**

Memory is where a finding waits *while it is still only prose*. It is not where findings retire.
So the maintenance pass is not "trim the file"; it is, per entry: *could a test, a lint rule, a
build assertion or a gate make this impossible instead of merely documented?* Most entries in
these files already name their enforcement point — most of the gates `make lint` runs started life here.

## What does NOT belong here

| | goes to |
|---|---|
| How to work in this repo today — setup, build, boundaries | [`../../../AGENTS.md`](../../../AGENTS.md) |
| Where the cohort stands this week | [`../../STATUS.md`](../../STATUS.md), [`../../../CONFORMANCE-MATRIX.md`](../../../CONFORMANCE-MATRIX.md) |
| A dated session record, kept as evidence of what was believed then | `research/stewardship/`, `docs/status/` |
| A finding routed to another repo | `protocol-generator/shared/findings/` (the research output), `docs/outbox/` (the packet) |
| What a substrate taught, written for a reader outside the project | [`../../../research/SUBSTRATE-TAKEAWAYS.md`](../../../research/SUBSTRATE-TAKEAWAYS.md) |
