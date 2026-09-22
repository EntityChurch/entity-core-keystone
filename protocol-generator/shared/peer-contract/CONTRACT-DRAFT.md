# The keystone peer contract — v2.0-draft.1 (provisional)

**Status: DRAFT, provisional, measured on one peer.** This is keystone's reshaping of
`entity-system-generator`'s *keystone peer contract, first pass* (2026-09-13), checked against
architecture's SDK texts and against our own tree. It is meant to be run, broken and corrected
before it is ratified. **It does not replace `docs/spec/SPEC-KEYSTONE-PEER.md` v1.0 yet.** On
ratification its normative sections move there in place as v2.0, the v1.0 digest is retired in
`tools/keystone-spec-pin.env`, and this file is deleted.

**Machine truth:** `requirements.toml` (the requirement set, levels, evidence, and which driver
cases decide each one). **Fixtures:** `FIXTURE-HOST.md`. **Suite:** `tools/peer-contract/`.
A report cites this contract by `contract_digest` (sha256 over `requirements.toml`, this file and
`FIXTURE-HOST.md`, in that order) — never by commit.

---

## 0. The contract on one page

> A **keystone peer** is a core-conformant peer that anyone can **run**, **embed** and **extend**
> through one interface — the same in every language up to spelling — and that keystone has
> **certified** against this contract, with a report anyone can recompute.

| Seat | Does |
|---|---|
| **keystone** | owns this text, the suite, each peer's report; brings a peer up to the contract on request |
| **a consumer** (the generator, an extension author, an application, a conformance suite) | reads the report, builds on a certified peer, never patches the peer or re-measures what the report certifies |
| **architecture** | owns the SDK texts this contract cites; rules on §6 |

**How a language is brought up:** implement the peer's surfaces; write its **contract host** —
`run_host(argv, install_fixtures)` in a separate package, exactly as `FIXTURE-HOST.md` specifies;
write the few **local tests** the registry names; add `run-contract.sh`. Then
`tools/peer-contract/run.sh <peer>` either certifies it or names every row that failed. **The suite
does not change per language.**

## 1. Levels, evidence, certification

- **REQUIRED** — certification needs `pass`. **MODULE** — `pass`, or `declined` with a reason in the
  peer's `contract/declined.toml`. A requirement the suite cannot yet measure is not in the set; it is
  listed in §5 so a certification never implies coverage the suite lacks.
- **Evidence.** `driver`: the shared Go driver observes it over the wire; every listed case must pass
  **and at least one listed control must hold in the same run** (an uninstalled pattern 404s, a
  refused identity 403s, a denied dimension denies). `local`: tests in the peer's tree with the
  requirement's name prefix, used only for what the wire cannot observe.
- **Certified** = the peer's committed core conformance report has 0 failures at the pinned executed
  check set with no starved category, **and** every REQUIRED row is `pass`, **and** every MODULE row
  is `pass` or `declined`. A missing row is `unknown`, never `pass`. `report.py --check` recomputes
  every committed report's verdict from its own rows.
- **The suite itself is proven per peer by plants** (`tools/peer-contract/plant.py`): named defects
  applied to a scratch copy of the peer must turn their named cases red, after an unplanted copy ran
  all green. The report carries the plant results. *Reshaped from the draft, which asked for an
  observed-red control per requirement per run: intrinsic controls give that on every run; plants
  prove the controls are not vacuous on that peer.*

## 2. run — the peer as a process

### run.cli
**Normative.** Both hosts accept exactly `--port --bind --name --validate --seed-policy
--max-frame-bytes --ready-file --debug-open-grants --help`, and exit non-zero with no readiness record
on anything else. `--debug-open-grants` stays working (deprecated) for at least one release after
`--seed-policy` is on every certified peer. **Defined by:** this contract.
**Observation.** Driver launches with every flag; a launch with an unknown flag must exit non-zero.

### run.identity
**Normative.** `--name NAME` loads `$HOME/.entity/peers/NAME/keypair` (the entity-core PEM of a
32-byte seed). **Defined by:** this contract (the ecosystem's peer-manager convention).
**Observation.** The record's `peer_id`, and the hello's `peer_id`, equal the id derived from a seed
the driver provisioned.

### run.ready
**Normative.** One stdout line `LISTENING <json>` once listening and after `configure` returned, with
`record = "keystone-peer-ready/1"`, `transport`, `addr`, `peer_id`, `posture`, `posture_digest`,
`limits {max_frame_bytes, max_chain_depth}`, `validate`; `--ready-file` writes the same JSON.
**Defined by:** this contract. **Observation.** The line parses; the file equals the line.

### run.serve
**Normative.** The peer serves without an oracle and binds where `--bind` says, so an instrument in
another network namespace can reach it (conformance's X1). **Defined by:** this contract.
**Observation.** The record's address is the requested bind. *v0 measures the bind, not a
cross-namespace dial.*

### run.posture
**Normative.** `--seed-policy PATH` is honoured in keystone's seed-policy format; the record reports
the sha256 of the file's bytes. **Defined by:** this contract + `shared/seed-policy/`.
**Observation.** A narrow identity reaches its one handler and is refused elsewhere; an identity not
named falls to the discovery floor and is refused; the digest matches.

### run.limits
**Normative.** `--max-frame-bytes N` sets the inbound frame budget; the record echoes it and the
transport enforces it. **Defined by:** this contract (core §4.10(a) requires a finite bound).
**Observation.** Echoed value; a frame under the budget is served; a frame over it is refused.
*v0 accepts either `413 payload_too_large` or the connection refusing the frame; §4.10(a) asks for
the 413 best-effort, and a stricter case is owed once the cohort is measured on it.*

### run.stop
**Normative.** On SIGTERM the process ends within 5 s and the port stops accepting.
**Defined by:** this contract. *Reshaped from "exit 0": a runtime whose language forbids unsafe
signal handling ends by signal, and the property that has actually broken harnesses here is the
port outliving the process.* **Observation.** Exit observed, then a dial is refused.

## 3. embed — the peer as a library

### embed.host_main
**Normative.** The peer's own host is a library function, `run_host(argv, configure)`: it parses
`run.cli`, loads `run.identity`, applies `run.posture`, calls `configure` **before listening**, emits
`run.ready`, and serves. The bare host is `run_host(argv, no-op)`. **Defined by:** this contract.
**Observation.** The contract host serves the fixtures; the bare host started with the same flags
emits the same record (same fields and values, no `contract_host`) and has no fixtures.

### embed.package
**Normative.** A program in a separate package, depending only on the peer's package, reaches every
surface in §3 and §4. **Defined by:** this contract (supersedes H4). **Observation.** The contract host
*is* that program: it is built as its own package and announces so in its record. *Package metadata
alone is not evidence (H4's own lesson); the compile is.*

### embed.create
**Normative.** Several independent peers in one process, and a peer with no listener.
**Defined by:** `SDK-OPERATIONS` §8.1 (both MUST). *The seed policy and frame budget as construction
values are keystone's; §8.1's `PeerConfig` names neither.* **Observation.** Local test.

### embed.data
**Normative.** *Provisional (§6 Q2).* A program holding the peer reaches its data surface in-process:
`put(entity)` into the content store; `get(hash)`; `bind(path, entity, context)`; `get_at(path)`;
`unbind(path, context)`. It is **the peer's own store** — a binding made through it is what a wire
`system/tree get` answers, and a wire write is what it reads. A bind or unbind given an execution
context delivers that context on its tree-change event. **The surface never files an entity under a
hash that is not its content hash**: an entity carrying another entity's hash is refused by `put`
and `bind`, and nothing becomes readable under the carried hash. The surface is unauthorized — it is
in-process code's own access, not a caller's — which is why its integrity rule is stated here and
not left to §5.2. **Defined by:** this contract. The operation set is the one three extensions on
the rust peer were measured to use (`entity-system-generator`'s census), named provisionally ahead
of §6 Q2; the integrity rule is core §3.1's content addressing applied to the store an authority
lookup reads (see §6 Q8). **Observation.** Hash equals the §1.8 content hash; get finds what put
stored and does not find a never-stored hash; an in-process bind is visible on the wire and a wire
put is visible in-process; the consumer log names the caller for a bind and an unbind; unbind
removes on both sides; a forged-hash entity is refused and unreadable.

## 4. extend — installing extensions, and what their code receives

### install.handler
**Normative.** `register_handler(spec, body) → handle` performs the core §6.13(a) writes (types,
handler entity, grant, grant signature, interface) and binds the body in a private index; refuses a
bound pattern with `409 pattern_collision` and an invalid spec with `400 invalid_handler_spec` before
writing anything; does not refuse `system/*`. **Defined by:** `SDK-OPERATIONS` §11.6, §11.6.1, §12.5
(supersedes H1, H3). **Observation.** A witness derived from a request field and registration-time
state, from a second peer; 404 at a never-installed pattern; the interface bound with its op types;
the three refusals as the surface reported them.

### install.remove
**Normative.** Closing the handle removes the dispatch index entry first, then the handler,
interface and grant entries; close is idempotent; a closed pattern answers 404.
**Defined by:** `SDK-OPERATIONS` §11.6.2. **Observation.** Close twice (true, false); 404; artifacts
gone.

### install.grant
**Normative.** The handler's grant is minted attenuated to `internal_scope`; a null scope yields a
grant covering nothing — never a wildcard. **Defined by:** `SDK-OPERATIONS` §11.6, §11.6.3.
**Observation.** Under its own grant a handler may put inside its scope and is refused outside it;
a null-scope handler is refused.

### install.types
**Normative.** A spec's types are bound at `system/type/{name}` and survive the handle's close.
**Defined by:** `SDK-OPERATIONS` §11.6.1, §11.6.2. **Observation.** Bound; still bound after close.

### install.consumer
**Normative.** Tree-change and content-store consumers can be registered **after construction** and
unregistered; they are invoked synchronously in registration order; a write's content-store event
precedes its tree-change event. **Defined by:** `SYSTEM-COMPOSITION` §1.2, §1.3, §2.2 for the order
and synchrony; **this contract** for registration after construction and for unregistration, which
`SYSTEM-COMPOSITION` §1.2 does not define (it says "during peer initialization") — see §6 Q2.
**Observation.** The consumer log's order; delivery stops after unregister.

### install.evaluator (MODULE)
**Normative.** An entity-native evaluator can be installed; the built-in `compute/literal` floor
answers **first** and the evaluator takes the fallback, discriminated by the body.
**Defined by:** this contract (supersedes H7). **Observation.** The evaluator answers its body; a
literal is answered by the floor even though the fixture evaluator would claim it.

### context.contents
**Normative.** A handler body's context carries operation, params, resource, pattern and suffix, the
author, the caller's verified capability and the handler's grant. **Defined by:** `SDK-OPERATIONS`
§11.4 item 5 names the capability, grant, tree access and execute function in prose; the rest is this
contract (§6 Q2). **Observation.** The fixture echoes each field and the driver compares values.

### context.unforgeable
**Normative.** Only the dispatcher constructs a context. **Defined by:** this contract (what
`EXTENSION-CONTENT` §3.4 needs to be implementable). A language with no enforced boundary declares a
runtime token and its strength. **Observation.** Local test: construction outside the peer fails for
the stated reason, with a positive control that the type is otherwise usable.

### context.dispatch
**Normative.** A body can dispatch a local EXECUTE through the same resolution, permission check and
body selection a wire EXECUTE takes, under a capability given as a parameter (default: the caller's),
with no escalation past it. **Defined by:** `SDK-OPERATIONS` §11.4 ("execute function") + this
contract for the authority and bounds. **Observation.** Allowed under a caller who holds the
authority; refused under one who can reach the handler but not the target.

### context.frame_budget
**Normative.** The frame budget in force for the request's connection is readable from the context.
**Defined by:** this contract (supersedes H6). **Observation.** Equals the `--max-frame-bytes` the
driver chose, which no peer ships as a default.

### context.authority_chain
**Normative.** `identity_in_authority_chain(cap_hash)` answers whether the request's author is a
granter in that capability's verified chain. **Defined by:** `SDK-OPERATIONS` §11.3 SEC-3 (MUST).
**Observation.** Local test: accept for an identity in the chain, deny for one that is not.

### event.context
**Normative.** A tree-change event carries the execution context of the request that caused it,
including through a local sub-dispatch. **Defined by:** `SYSTEM-COMPOSITION` §1.4 (supersedes H8).
**Observation.** The consumer log names the remote caller — driven from a second identity, so the
fabricated value (the local peer) and the correct one differ.

### authority.path_permission
**Normative.** A public predicate over `(operation, path, token, handler_pattern, local_peer)`,
resources matched against the local peer with no granter frame. **Defined by:** this contract
(supersedes H9). **Observation.** One accept and one deny per dimension, under a narrow token.

## 5. Pending — named, not measured, not certified

| name | why it is not in v2.0-draft.1 |
|---|---|
| `run.transports` | declared value only; nothing to measure until a peer serves `ws` |
| `run.validate` | `GUIDE-CONFORMANCE` §7a.2 says the §7a handlers use the bootstrap install path; §7d.1 says §7d's use the public primitive. The draft conflated them (§6 Q4) |
| `embed.lifecycle` | `close_peer` is not an SDK MUST (§16); no consumer has needed it |
| `embed.local_execute` | `SDK-OPERATIONS` §8.1 local-only mode handles operations "via `execute()`"; rust exposes no public local execute. Owed before `embed.create` can claim local-only mode in full |
| `context.outbound` | the §6.13(b) seam exists; the suite has no reentry fixture yet |
| `authority.token` | the draft cited `SDK-OPERATIONS` §11.1, which defines grant lifecycle over `system/capability`, not local construct/attenuate/verify. Needs a definition first |
| `deliver.*` | a pushed tag and manifest are a release-step property, not a per-peer requirement. Reports already carry `delivery {commit, tree_dirty, artifacts, toolchain_image, oracle_provenance_sha256}` |

## 6. Questions for architecture, with the evidence behind them

| # | Question | Evidence |
|---|---|---|
| **Q1** | **Amend `GUIDE-CONFORMANCE` §7d's owner** from "built per-peer by the generator" to keystone, since keystone certifies its own peers and the generator is one consumer? | §7d owner column; §7.0 |
| **Q2** | **Should the SDK name the operations this contract currently defines:** consumer registration *after construction* and unregistration (SC §1.2 says "during peer initialization"), a content-store consumer operation (SC §1.1/§2.2 list them, no operation), the `HandlerContext` fields beyond §11.4's prose list, and the data surface an extension may use — `embed.data` now names a provisional five, from three extensions' measured use? | SC §1.2; SDK §11.4 is build-time prose with no MUST |
| **Q3** | **Are the evaluator seam (H7), the connection frame budget (H6), the path predicate (H9) and dispatcher-only contexts SDK obligations?** | none has an SDK counterpart today |
| **Q4** | **§7a.2 vs §7d.1** — may the §7a validate handlers stay on the bootstrap path? | the two sections disagree |
| **Q5** | **`SDK-OPERATIONS` §11.6.1 writes three tree entities; core §6.13(a) pins five** (a grant signature at `system/signature/{grant_hash}`), while §11.6 says the entities are "identical to" `system/handler:register`'s. Which governs an in-process install? | rust follows core (five) |
| **Q6** | **§11.6.1 writes a grant only when `internal_scope` is non-null; core §6.1 step 1 requires a grant to dispatch.** Is a null scope "no grant entity" or "a grant covering nothing"? | rust mints an empty-scope grant, which satisfies both |
| **Q7** | **`SYSTEM-COMPOSITION` §1.4** says every tree event carries an execution context; the draft said autonomous writes carry none. Which? | SC §1.4 asks application writes to provide `chain_id` and `author` |
| **Q8** | **Does core §3.1's content addressing bind an implementation's in-process store API, not only the wire `included` map?** 0.8.2.23's `K1` makes resolution through an unverified address a defect on the envelope path. A peer's store is keyed by content hash and read by the authority path (a grantee resolved by hash), and an SDK that lets extension code file an entity under a hash it does not have reopens `K1` in-process. The rust peer's `Entity` fields were public and its store trusted them until this draft | `embed.data/forged-hash-not-filed`; rust `Store::put_entity` / `bind_with_context` |

**Keystone-side gap, stated against ourselves:** `SDK-OPERATIONS` v1.13's "no `system/*` refusal"
rests on core 0.8.2.13's withdrawal of the reservation. Our pinned core snapshot is `v0.8.2.11`, which
still has it. The rust peer follows the SDK in-process and the pinned oracle on the wire, on purpose,
until we vendor a later snapshot — which is owed, and moves the cohort.

## 7. Mapping — nothing agreed is lost

| v1.0 / ask | becomes |
|---|---|
| H1, H3 | `install.handler` |
| H2 | `install.consumer` |
| H4 | `embed.package` |
| H5 (`[extension_host]`) | per-peer `contract/bindings.toml`, echoed into the report; the report replaces `h1_status` for any peer that has one |
| H6 | `context.frame_budget` |
| H7 | `install.evaluator` |
| H8 | `event.context` |
| H9 | `authority.path_permission` |
| generator K-5 | `context.dispatch` |
| generator K-6/K-7/K-8 | `run.posture`, `run.cli` |
| conformance X1/X2/X4 | `run.serve`, `run.cli` + `run.ready`, `run.limits` |
