# spec-data v0.8.2.11 — Snapshot Manifest

**Spec version:** Entity Core Protocol **0.8.2.11**. `ENTITY-CORE-PROTOCOL.md` carries `**Version**: 0.8.2.11` on line 3 (verified in this snapshot, not assumed).
**Snapshot type:** verbatim copy of the authoritative normative spec files — **no paraphrase, byte-for-byte** (S2). Each file was hashed from the source blob and compared against the written copy before acceptance; all three matched.

**Supersedes for new work:** `v0.8.2.3/`, `v0.8.2/` and `v0.8.0/` (all kept in place as point-in-time pins, as every prior snapshot is).

**Authorized by** `entity-system-architecture` `ROUTING-2026-09-06-d` (the CONSOLIDATED packet, which supersedes `-b` by name; `-b` had already superseded `ROUTING-2026-09-05-b`). Directory named for the version the spec header carries. Per the standing rule we do **not** vendor a `v0.8.3/`: the fourth component is an arch-managed in-flight signal that the operator strips and renames at the release cut.

**`EXTENSION-TREE.md` v4.5 is NOT vendored, deliberately.** We pin the three core normative documents only. Its Appendix A is load-bearing for this snapshot *by reference* — §6.3's new admission ladder cites it for the `put` error codes — so read it in the sibling; do not copy it here.

## Provenance

| Field | Value |
|---|---|
| Source repo | `entity-core-protocol` (sibling) |
| Source path | `specs/` |
| Source ref | **`dev`** at `6c6c11d` |
| Method | `git show 6c6c11d:specs/<file>` into the snapshot path; each output hashed and compared against the source blob before acceptance. All three matched. |
| Read at | 2026-09-06 |

As with `v0.8.2.3`, this is vendored from an **unreleased line** — `master` is still the released
`0.8.2`, and the fourth component exists precisely so core text can move without cutting a release.
There is no published artifact to vendor from. The SHA-256 table below is therefore not merely the
preferred anchor, it is the **only** one: `6c6c11d` is a `dev` commit, [ADR-0027] authors published
commits fresh at the release boundary, and this directory publishes (`protocol-generator/**` ships
undeclared). The commit is an internal build coordinate and is **not** citable in anything published.

## Files (the three authoritative normative inputs)

| File | Spec version | SHA-256 |
|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` | **0.8.2.11** | `c97e1860a586f7ef252615cd3560c4cff688c9909a57008505463faf6dc3e6ac` |
| `ENTITY-CBOR-ENCODING.md` | **1.6** | `433e094e86f0a9aa5b5d47732599b46d14fe35f3d4956371676a644c3d287f37` |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | 4.2.1 | `043fc80d4fd21ff074082e1f3c76b779d73d9f172a90d3f2a986d68e0cde740d` |

Verify integrity: `sha256sum -c` against this table, or `git show 6c6c11d:specs/<file> | sha256sum`
in the sibling while that ref still resolves.

## What's different from v0.8.2.3

Measured in this tree (`diff v0.8.2.3/<f> v0.8.2.11/<f>`), not read off the routing packet:

| File | vs v0.8.2.3 | Changed lines | Version label |
|---|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` | changed (`f899b8ea…` → `c97e1860…`) | **113** (+77 / −11) | 0.8.2.3 → **0.8.2.11** |
| `ENTITY-CBOR-ENCODING.md` | changed (`74ace6c2…` → `433e094e…`) | **11** (+6 / −2) | 1.5 → **1.6** |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | changed (`2cec31bb…` → `043fc80d…`) | **17** (+9 / −5) | 4.2.1 (unmoved) |

**All three moved.** The type-system label did not, which is the reason to read the digest and not
the version string — its `core/entity` row change is a *predicate* for the new §6.3 ladder (below).

**Eight fourth-component amendments landed in this window**, `0.8.2.4` through `0.8.2.11`. Seven of
them are about what a peer **emits**; the eighth is about what it **accepts**, and that distinction
is the most important thing in this manifest.

### 0.8.2.4 — FM-2: the connect surface reconciled

§4.7's table: row 3 (`incompatible_key_type`) **retired** — it described an intersection model §4.5
no longer uses. Row 1 names its trigger. Row 5 is scoped to §1.2 ingest with an explicit *"a
conformance check MUST NOT treat this as a handshake obligation"*. **Row 10 is split**: a state
conflict is **409**, matching `connection_already_established` directly above it; an **unknown
operation on the connect path is `400 invalid_request`**, now declared at core level.
§4.6's proof-of-possession numbering becomes a **normative order** — for an input failing more than
one step the responder MUST emit the **lowest-numbered** failing step's code — with the constraint
on the emitted pair rather than the internal sequence, so a peer may still check cheaply first.
Four new §9.1 rows give the obligations somewhere a check can read them.

**Reaches every peer.** This is worklist item 1 and the largest single item in the sweep.

### 0.8.2.5 — CE-1: the pre-establishment EXECUTE was already answered

A non-connect EXECUTE arriving before the handshake completes is **`401 authentication_failed`**.
Ruled *not a new rule*: §4.2's third pre-authorization bullet has governed it since 0.8.1 (F32),
and §5.2a supplies the code. Recorded here because the amendment's finding is that it is a
**conformance gap two releases old rather than a design question** — and the two codes seats had
been standing in with (`connection_required`, `handshake_failed`) appear nowhere in either spec repo
and are named non-conformant.

### 0.8.2.6 — §3.3 named a default code for three statuses and left three bare

Two folds in one version so the cohort vendors once.

- **The 501 synonym.** `unsupported_operation` is the default; **`unknown_operation` is a synonym
  and MUST NOT be emitted.** Measured across every tier before ruling — and note the *status*
  differed too (400 vs 501), so a client keying on `result.data.code` got a different remedy
  depending on which implementation refused.
- **The pre-authorized connect path holds in ANY connection state**, before *and after*
  establishment. §3.3's exception is on the **path** and carries no state qualifier, so a
  post-establishment `ping` bearing no `author`, no `capability` and no signature **MUST be served**,
  and a responder MUST NOT refuse it for their absence. (The state qualifier was absent and §5.1 was
  being read as the general rule with this bullet as its exception, which is the wrong way round.)

### 0.8.2.7 — the default-code column had no stated force

Ruled **MANDATORY for the generic case** at every row naming a default; the "advisory" reading is
refuted, because the generic case is the one with no other information in it and therefore exactly
the case a caller cannot branch on unless the spelling is fixed. Adds **satisfaction mode** per row:
**501 and 404 are wire-drivable**, **500 is NOT drivable by a conformance client** (source audit at a
named commit, not a check), and — load-bearing for how we measure — **the unit of conformance is the
code SLOT, never a single spelling**: retiring one synonym while a second remains in the same slot
does not satisfy the row.

### 0.8.2.8 — three code-set corrections

`unsupported_mode` is **removed** from §9.1's 501 synonym list (it is a *different failure* at the
same status — EXTENSION-REGISTRY's stored-domain-control refusal — and "a synonym is a second
spelling of the same failure"). The **half-open connection is named**: `hello` complete,
`authenticate` not, is *not* established, so an unauthenticated `ping` there is
**409 `connection_sequence_error`** — stated because two adjacent rules each look like they cover it
and neither does. The **500 row gains a specific set**: `io_error` (an OS I/O operation failed) and
`storage_error` (a content-store or tree bind/read failed), which are distinct and not interchangeable.

### 0.8.2.9 — the slot rule stated a permission and a prohibition and never the consequence

An **undefined spelling is non-conformant and falls back to that status's default.** The absence of
a code table for an operation is **not** an unfilled slot: a peer that wants a more-specific code and
finds none defined emits the row's default. Where the condition genuinely names something a caller
would branch on, the peer holds it as a **named divergence and routes it** rather than minting a site.

### 0.8.2.10 — one rule, thirteen homes, two strengths, and the canonical home carried the weak one

**Entity fidelity is a MUST.** `ENTITY-CBOR-ENCODING.md` §5.4 item 5 goes **SHOULD → MUST** ("MUST
preserve unknown fields"), as do §4.6 and §9.3's unknown-**format** preservation lines. §5.4 declares
itself the canonical home of the contract and had been carrying the *weak* strength while
`ENTITY-CORE-PROTOCOL` §2.10 and `ENTITY-NATIVE-TYPE-SYSTEM` §2.4 said MUST — so §9.1's
MUST-implement list stated the rule at both strengths at once.

The settling argument is a correctness claim about the network rather than a style preference:
content hashing covers all of `{type, data}`, so a peer that strips a field it did not model
publishes a **different hash for the same entity** and breaks content addressing for every
downstream consumer.

§5.4 also gains the **three-acts frame** — *relay* (store the original, forward the original) and
*re-encode* (lossless parse, canonical re-encode) are both claims that *this is still the sender's
entity* and MUST preserve every byte of meaning; *transform* deliberately authors a derived entity
under a **new content hash** the publisher signs as their own. **A transform is not a fidelity
violation. Silently emitting a transform while claiming a relay is.**

### 0.8.2.11 — §6.3's `put` admission ladder — **THE FIRST ACCEPT-SIDE RULE OF THE ARC**

Everything above changes what a peer **emits**. This one changes what a peer **accepts**, and arch
flags the consequence directly: an accept-side rule *"partitions a cohort during adoption rather
than merely diverging its error strings."*

`put` is a **receipt** path. The submitter authors the entity; the peer validates what it received
(§1.8 item 1) and **MUST NOT** author a submitted entity's `content_hash` on the submitter's behalf.
Two ordered steps:

1. **Structure.** `put-request.entity` is typed `core/entity` (§3.9; `ENTITY-NATIVE-TYPE-SYSTEM.md`
   §8.1), **whose three fields are all required** — and *that* is the type-system change in this
   snapshot: the `core/entity` row read `{type, data, content_hash?}` and now reads
   `{type, data, content_hash}` with **"All three keys are required."** The value is an entity when
   it is a map with a non-empty text `type`, a present `data` (any CBOR value — null is legal), and
   a `content_hash` that is a well-formed `system/hash` whose byte length matches its format code.
   Any failure → **`400 invalid_request`**. A well-formed hash naming an *unsupported* format code is
   the separate §1.2 case → **`400 unsupported_content_hash_format`**, explicitly **not** this row.
2. **Hash.** Carried `content_hash` vs `content_hash({type, data})`. Disagreement → **`400 hash_mismatch`**.

**Step 1 strictly precedes step 2**, and the ordering is a **data dependency rather than a
convention** — step 2's inputs are exactly what step 1 establishes. The spec states why it cannot be
tested the obvious way: *"no vector carrying a single fault can discriminate the order"*, since each
row's own input reaches its own branch either way. **The discriminating input carries both faults at
once**, and §9.1's new row names it, "since that is the input a row-scoped author does not write."

**`hash_mismatch` appears at two different statuses.** Content disagreement is **400**; the CAS
precondition loss is **409** (`EXTENSION-TREE` Appendix A). Same code, different status, different
row — a peer that collapses them satisfies neither.

**The authoring step exists and belongs to the SDK.** `SDK-OPERATIONS.md` §3.2's
`put(path, type, data) → hash` constructs the `core/entity` — computing `content_hash` — before
anything reaches the wire, which is the only way it can return that hash. **A peer that accepts the
two-key `{type, data}` form is supplying an authorship the protocol assigns to the submitter**, and
ends up holding an entity under a hash nobody agreed to.

## Conformance scaffolding NOT in this snapshot (read before generating)

Unchanged from `v0.8.2.3`: the **§7a conformance test-handlers** (`system/validate/echo`,
`system/validate/dispatch-outbound`), the **§7b concurrency gate**, the **§4.10 `resource_bounds`
probe**, and the **generator-menu defaults** live in `GUIDE-CONFORMANCE.md` (non-normative,
arch-owned) plus the keystone generator menu — **not in these three files**.

| Field | Value |
|---|---|
| File | `GUIDE-CONFORMANCE.md` |
| Source repo | `entity-system-architecture`, path `guides/` |
| SHA-256 | recorded in `tools/oracle-pin.env` (`guide_conformance`) — re-verify at the oracle re-pin, not here |
| Status label | **Draft** |

## Status in this repo

**This snapshot is vendored and is NOT yet consumed.** No peer has been regenerated against it; all
46 are written against `v0.8.2.3` and measured against the `f313028` oracle
(`core_executed_check_set_digest c34abcae…`, 758 checks). That is a tracked gap, not an oversight.

**The oracle re-pin is deliberately NOT landed with this vendor**, and the two are separable: the
spec snapshot is what the peers are *written against*, the oracle pin is what they are *measured
against*. `entity-core-go` is 54 commits past the pinned oracle ref and landed two `fix(tree)`
commits on this exact surface on 2026-09-06 while routing a put-admission handoff to `rust` and
`py`. Pinning to a HEAD being edited on the surface we are adopting buys a second 46-peer census.

**The `put` ladder's cohort exposure is MEASURED rather than estimated** — arch's instruction was not
to size it from an assumption of conformance. See `tools/put-probe/` and
`protocol-generator/shared/findings/put-admission-wire-census.md`.
