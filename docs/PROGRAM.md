# The program — where keystone sits, what it owes, and how it ends

_Updated 2026-09-05._

**What this file is.** The single orientation document for keystone's **position and trajectory**:
which seats it sits between, what flows each way, what is measured today, what is queued, and what
"finished" looks like. It is deliberately the only place that answers *"where is this going."*

**What this file is not, and where those facts live instead** — one canonical home per fact:

| Question | Document |
|---|---|
| What does each peer score? | **`CONFORMANCE-MATRIX.md`** — authoritative for every per-peer number |
| Short current-state orientation | `docs/STATUS.md` |
| Which languages are worth building, and their support tiers | `research/LANDSCAPE.md` |
| Which peers are still queued to build | `research/COMPLETENESS-ROADMAP.md` |
| Which rules bind whom | `docs/CONTRACT-LAYERS.md` |
| What we found wrong with the spec | `protocol-generator/shared/findings/` (register: `research/stewardship/SPEC-FINDINGS-LOG.md`) |
| How we work | `AGENTS.md` + `AGENTS-STANDARD.md` |

---

## 1. The shape changed, and the charter has not caught up

`AGENTS.md` opens by calling this repo *"the canonical conformance anchor for the ecosystem."* That
was accurate when there was one relationship to describe: **arch writes the spec, go builds the
oracle, we implement the spec N times and route back what breaks.** One input, one output, one
customer.

That is no longer the shape. Keystone now sits between **four** seats and the traffic runs both ways:

```
        entity-core-protocol            entity-system-architecture
        (normative spec text)           (proposals, guides, rulings, the ledger)
                  │  vendored by hash              │  routes rulings ⇄ receives findings
                  ▼                                ▼
        ┌─────────────────────────────────────────────────────┐
        │              entity-core-keystone                   │
        │                                                     │
        │  46 peers · the codec C-ABI · the conformance       │
        │  evidence · and now a spec layer of its own         │
        └─────────────────────────────────────────────────────┘
                  ▲                                │
                  │  oracle, pinned by digest      │  host contract, profiles,
                  │                                ▼  a working peer to build against
        entity-core-go                    entity-system-generator
        (validate-peer, entity-peer)      (builds systems ON peers)
```

**The new edge is the one on the bottom right, and it is what makes this a hub rather than an
anchor.** `entity-system-generator` is not a peer author; it builds *systems on top of* peers. It
needs things the protocol deliberately does not specify — can a third party install a handler into a
constructed peer, in what order do consumers fire, what may a handler body read. Those obligations
bind **our** peers and nobody else's, so nobody upstream will ever write them down. Hence the
**keystone specification layer** (`research/stewardship/DESIGN-2026-09-04-…`): a small, versioned,
digest-pinned document set that is ours to author and ours to gate.

**The framing that has held up:** we were the keystone *for the core protocol* — the piece that made
one spec load-bearing across many implementations. We are now the keystone *for the stage above it* —
the piece that makes 46 peers load-bearing for something built on them. Same job, one level up.

**The charter is stale on exactly this point and the fix is scoped**, not a rewrite: `AGENTS.md`
describes the arms and the boundaries correctly and describes the *relationships* as they were.
Correcting that is queued below, not done.

## 2. Where it actually stands, measured

**The cohort — 46 of 46 conforming, no exclusions.**

| | |
|---|---|
| Peers at `778 · 0F` | **46 of 46**, zero FAILs anywhere |
| Modal row | `335P/336W/0F/107S` — **27 peers share it exactly** |
| Oracle pin | executed check-set digest `7aa6f3de…` (778 checks) |
| Spec snapshot | `v0.8.2.11` (vendored; no peer regenerated against it yet) |
| Committed reports at the pinned set | **46 / 46**, 0 stale |
| Disclosed gaps behind a 0-FAIL row | **one, 46 entries** — `connectivity/connect_ping_before_hello` is allowlisted on every peer against **F59**, an upstream gate defect the reference peer reproduces. The entries come out when the §9.0 carve-out lands. *(This row read "none — the allowlist is empty" from 2026-09-03 until 2026-09-09, one day past the entries going in.)* |
| `make lint` | green across **13** gates + 5 gate self-tests |

**The verification axes.** Every axis a number is published on needs a cohort runner *and* a gate;
an axis with neither is an exclusion nobody declared.

| Axis | State | Authority |
|---|---|---|
| **S4** conformance | 46 GREEN | `entity-core-go` oracle, pinned by digest |
| **S2** codec / crypto-agility | 46 GREEN | architecture's vendored corpora |
| **S3** loopback interop | 18 GREEN, 28 no-gate | **ours** — hand-written, no oracle behind it |
| **origination** | folded into S4 — retired as a separate axis | the oracle's `-reference-peer` flag |
| **FFI / codec C-ABI** | **GREEN, and newly gated** — `ffi-generator/c-abi/run-ffi-gate.sh` | mixed; see `ffi-generator/c-abi/status/FFI-ARM-STATE.md` |

**The FFI row is new and the reason it is new is the most useful thing on this page.** That arm was in
no sweep and no gate — `run-axis-sweep.sh` walks `protocol-generator/*` and the FFI arm is not
peer-scoped — while **34 peers link the artifact it builds**. A leak on the per-request path of every
one of them survived months and was found *by accident*, while measuring an unrelated peer. Every
harness that would have caught it already existed. Nothing ran them.

**Two known gaps, named rather than carried quietly** (detail in `FFI-ARM-STATE.md`): the Rust codec
impl has no independent corpus harness — it is verified only against its C sibling, which is a mutual
check — and it has no vendored crate closure, so its build needs the network.

## 3. What is queued, in order, with sizes

### 3a. The `0.8.2.11` catch-up — **re-measured 2026-09-06, and the target moved twice under it**

Our snapshot is now **`v0.8.2.11`** (vendored 2026-09-06; no peer regenerated against it yet). The protocol is at `0.8.2.11` — it was **eight** bumps ahead when this section was written. The governing packet
is **`ROUTING-2026-09-06-d`**, which supersedes `-b`, which had already superseded the
`ROUTING-2026-09-05-b` this section was first written against. Arch retracts its own sequencing
promise in it and says why: *"this is the last arch fold queued today" was true when written at 06:23
and is no longer.* **Check `ENTITY-CORE-PROTOCOL.md` line 3 against `0.8.2.11` before spending a
cycle** — arch's own instruction, and one `head -3` is cheaper than a sweep.

**The "everything changes what a peer emits, never what it accepts" claim in the previous revision of
this section is WITHDRAWN.** It was true through `0.8.2.9` and `0.8.2.11` ended it: §6.3 adds a `put`
**admission ladder**, which is an accept-side rule and therefore the class that *partitions a cohort
during adoption* rather than merely diverging its error strings. That is a different kind of work
from the rest of the arc and is sized separately, in `docs/status/HANDOFF-2026-09-06`.

**Measured rather than guessed** (method: attribute by *category*, never by commit subject — and the
extraction method was validated against the recorded pin digest as a control before its new value was
trusted):

- **All 3** normative files moved, **`+117/−24`** together. `EXTENSION-TREE` v4.5 is cited by §6.3 but
  is **not in our snapshot** — we pin the three core documents only.
- The go oracle grew **+26 declared checks, 0 removed**; **19 are core** — 11 (`connectivity_conn_errors.go`)
  + 2 (`connectivity_section33.go`) in `catConnectivity`, and **6 (`tree_put_error_codes.go`) in
  `catTreeOps`**. The other 7 are `catType` (5) and `catRelayStoreBounds` (2), neither in
  `coreProfileCategories`.
- `core_gate_fingerprint` is **byte-identical across the pin** (`8261a033fe1af56b…`) — **sixth** time
  in this exact shape. It will not warn us. The candidate declared digest at go HEAD is recorded in
  `docs/status/HANDOFF-2026-09-06`, not here: it anchors a commit that moved four times that day, so
  it is a measurement rather than a pin, and this file publishes.
- Executed core set: **needs re-measuring against a candidate oracle built to a scratch path.** The
  `758 → 772` below is the previous pin's and is now both stale and a floor.
- Probed on **three peers of three lineages** (`go`, `rust`, `python`) with an oracle built to scratch
  — a diagnostic, not a census, and the pinned oracle was untouched. **All three identical:
  `772 · 324P/336W/5F/107S`.** Seven of the thirteen new checks already pass; nothing outside them
  moved.

**Five failures, three defects, one authored fix propagated 46 times:**

1. **§4.5 `protocols` is not enforced at all** — absent/empty must be `400 invalid_request`, non-empty
   non-intersecting must be `400 incompatible_protocol`; peers answer `200` to both.
2. **The connect op ladder answers an unknown operation as a handler 501** (`unsupported_operation`)
   where `0.8.2.4` pins `400 invalid_request` — it is a malformed request, not a missing operation.
3. **The second-hello state check covers `established` but not mid-handshake** — `409
   connection_sequence_error`.

**The control that makes this actionable: go's own reference peer at HEAD passes 13 of 13.** These
are our defects, not oracle artifacts.

Plus, separately and already confirmed in our tree: **the 501 slot.** Four peers emit
`not_implemented` — `asm-x86_64`, `asm-arm64`, `riscv64`, `pd`. The remedy is one word,
`unsupported_operation`. Zero `unknown_operation` cohort-wide. The **500** row is satisfied by a
**source audit**, not a check: `0.8.2.7` rules that a conformant peer cannot be made to fail
internally on demand, so no conformance client can drive it.

**A third item is ours and is newer than the packet: the 404 code slot.** §3.3 pins the 404 default
`code` = `handler_not_found`, and `0.8.2.9` settles the consequence — *"an undefined spelling is
non-conformant"*, with the **code slot** as the unit of conformance rather than any single spelling.
**8 of 46 peers emit no `handler_not_found` anywhere in source**, five of them confirmed by direct
read to emit `404 not_found` at the handler-resolution-miss site. It has never been measured here:
the check that drives it is absent from all 46 committed reports and arrives with the re-pin.

**A fourth item arrived with `0.8.2.11`: the §6.3 `put` admission ladder** — 6 new `catTreeOps`
checks, an accept-side rule, and a surface no generated peer had ever been driven on. **Measured
2026-09-06 and it is no longer the unmeasured item; it is the largest one.** `tools/put-probe` over
the wire on every peer: of the **40 measurable, ZERO implement any row**. **37 accept the two-key
`{type, data}` form and 36 STORE it** — arch's worst-case class, near-universal. **40 of 40 accept an
empty-string `type`.** **10 accept an entity whose `content_hash` does not match its content** (a
§1.8 validate-before-trust failure that no code-table fix touches). No peer emits `invalid_request`,
`hash_mismatch` or `unsupported_content_hash_format` anywhere on this surface. 5 peers unmeasurable
(they refuse or drop a *valid* `put`; probe self-check clean on all five), `turbowarp` unbuildable.
Detail: `protocol-generator/shared/findings/put-admission-wire-census.md`.

**So the accept-side half is now sized, and it is NOT a re-vendor**: it is new implementation on
every peer, and two of its three defect classes are outside the code table. **The emit-side half is
not a regeneration either** — it is the shape of the §5.6 mint-ceiling sweep that went across 36
languages: author once, propagate, re-census.
Order: ~~probe `put` across 46~~ (**done**) → ~~vendor `v0.8.2.11`~~ (**done**) → fix → sweep 46 → re-pin the oracle → re-census
and re-measure the tracked reports. **The vendor and the re-pin are deliberately decoupled**: go is 54
commits past our pinned oracle and landed two `fix(tree)` commits on this exact surface on 2026-09-06,
with rust and py being routed the same day, so pinning to a moving HEAD buys a second census.

### 3b. The keystone specification layer — **unblocked, ours, not started**

Three documents under `docs/spec/`, declared and digest-pinned: the peer host contract (H1…H7), the
`profile.toml` schema, and what a keystone peer is measured on beyond `--profile core`. Arch has
accepted the boundary (`12f478c`: *"keystone accepted the host contract; the track opens and D1 was
never blocking"*). Blocks on nothing.

**What is already proven, so nobody re-measures it.** The cohort-wide unknown is *not* "does this
peer have an extension seam." Decomposing the host contract against conformance data we already own:

| Property | Measured by | Result |
|---|---|---|
| A runtime-mutable dispatch container exists and **dispatch reads it** | wire `register` → `core_register_body_binding` + the four §11.6.1 path writes | **46 / 46 PASS, by execution** |
| Reserved-pattern refusal | `core_register_reserved_refused` · `_publishes_nothing` | **46 / 46 PASS** |
| A handler body resolves and dispatches | `validate_echo_dispatch` | **46 / 46 PASS** |
| **A third party in a separate compilation unit, depending only on the published package, constructs a peer and installs a language-native body** | one host program per language | **1 / 46** |
| The frame budget in force for the request is readable by a handler body | host-seam probe, across the packaging boundary | **1 / 46** |
| Entity-native dispatch is delegable to an installed evaluator | same probe, with a decline/throw/fast-path control set | **1 / 46** |
| Emit consumers fire in **registration order** (`SYSTEM-COMPOSITION` §2.2) | same probe — **no oracle category tests this anywhere** | **1 / 46** |

The oracle's own source says why the last row is different: *"the default body-binding seam is
entity-native compute"* — the wire path installs a **declarative** body, never a language-native
callable. **So the open question is the packaging boundary and the native body, not the seam.**

**And it is the question source reading is worst at.** Of four peers nominated as satisfying the
contract from source reads, **three were wrong**, each at a different boundary — class scope in C++,
assembly scope in C#, and in `julia` a live exported entry point onto a container **nothing reads**.
`typescript` is the only verified host; 45 peers are `unknown` and stay that way until a harness
executes.

**Two of the seven requirements are now closed on that peer, by execution.** The frame budget in
force for a request is readable by a handler body — it was private to the transport, which made a
`CONTENT` MUST unimplementable — and entity-native dispatch is delegable to an installed evaluator,
which was hardcoded, making *"ship your own compute semantics"* unreachable. Both carry
planted-defect controls, and **`--profile core` did not move**: exactly 1 of 758 severities differs
from the committed report and it is the documented `t1_1_concurrent_demux` timing flake. Consumer
**invocation order** — normative in `SYSTEM-COMPOSITION` §2.2 and tested by no oracle category
anywhere — is measured in the same pass.

**The packaging survey behind H4 was re-derived, and 11 of its 46 rows were wrong**, every one of
them understating the cohort: **25 peers publish to a real registry, 13 are source-vendored** (a
genuine consumption mode — no registry exists for those substrates), **8 declare no distribution
target**. Five registry-publishing peers had been filed as declining, including `lean`, an M1 peer.
The cause is a survey keyed on a list of manifest filenames, which cannot see a language whose
packaging system was not on the list and reports *absent* rather than *could not look*. Detail:
`protocol-generator/shared/evaluations/extension-host-packaging-boundaries.md`.

**And H4 as written conflates two independent axes** — is there an in-process construction surface,
and is there a distribution unit. Peers answer them opposite ways: `c` has no registry and is the
most library-shaped artifact in the tree; `node-red` and `turbowarp` ship a `package.json` and are
applications. Declining stays a legitimate profile value; a single `host | declined` field is what
cannot express it.

### 3c. Standing, lower priority

- **S3 has 28 no-gate peers**, and it is the one axis with no external authority — which is exactly
  the axis whose checks have twice gone stale silently.
- **The two FFI gaps** in §2.
- **`AGENTS.md`'s relationship framing** (§1).
- The cohort regeneration against a current snapshot — a provenance gap, still the wrong place to
  start, and the `0.8.2.9` arc does not change that.

## 4. How this ends

**Core protocol is meant to freeze. When it does, keystone freezes behind it** — that is the design,
not a wind-down.

What "finished" looks like:

- **The peers stop moving** because the spec stops moving. Maintenance tiers already govern the
  cadence; at freeze the cadence goes to zero and the tiers become a support policy.
- **The evidence stays.** The conformance matrix, the findings register and the pinned digests are the
  durable output — *"we implemented this protocol 46 times, here is what we found wrong with it"* is
  the artifact, and it outlives the activity that produced it.
- **The generator takes over as the primary consumer.** Keystone's job becomes support: answer what
  breaks, keep the host contract honest, keep the gates green.
- **New languages remain cheap and occasional.** The discovery well has been dry on the current wire
  surface since roughly peer 15 and is still dry at 46. A new peer is catalog completeness, not a
  spec-discovery bet, and it lands at a low tier by policy.

**What would legitimately reopen it**, so this is falsifiable rather than a hope: a spec amendment
that moves the wire; a *ground-up* implementation disagreeing with the cohort (which would be real
evidence, where 46 cohort peers agreeing is not — they share a generation lineage); a generator
requirement the host contract cannot express; or a defect class found in one peer that the other 45
turn out to share, which has happened repeatedly and is the single highest-yield thing this repo does.

**The honest limit on all of it, and it is the same sentence as always:** 46 peers passing one
author's vectors at one pinned check set is **cohort-consistent, not independent convergence**. Every
number on this page is measured, reproducible from its digest, and is not a claim that the peers are
correct.
