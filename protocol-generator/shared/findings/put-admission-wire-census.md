# `system/tree:put` admission — a 46-peer wire census of §6.3's `0.8.2.11` ladder

**Date:** 2026-09-06 · **From:** `entity-core-keystone` · **Measured against:** `ENTITY-CORE-PROTOCOL.md` **0.8.2.11** (`protocol-generator/shared/spec-data/v0.8.2.11/`, `c97e1860…`) · **Instrument:** `tools/put-probe/`

> **STATUS — the gap this measured is CLOSED, and §5 of this document was WRONG. See §7.**
> The ladder is now authored on all 46 peers and all 46 measure **6 of 6 conformant**. Coverage
> is **46 measured**, not the 40 / 5 / 1 split below: the five "unmeasurable" peers were a
> **probe fault** — a duplicate key in the `included` map — and `turbowarp`'s bundle failure was
> one emitted no-op import. The measurement in §4 stands as the state of the cohort *before* the
> fix; §5's reasoning does not, and is corrected in place rather than deleted because the wrong
> inference is the part worth keeping.

**The headline, and it is not a code-spelling story.** Of the **40 peers this could be measured
on, ZERO implement any row of the ladder**. **37 of 40 accept a submitted entity carrying no
`content_hash` at all, and 36 of them STORE it** — the peer authors a hash the submitter never
supplied and then holds the entity under it. **40 of 40 accept an entity whose `type` is the empty
string.** **10 of 40 accept an entity whose `content_hash` does not match its own content.** The
strings `invalid_request`, `hash_mismatch` and `unsupported_content_hash_format` are emitted by
**no peer, on any input, anywhere on this surface.**

This was measured because architecture asked for it in those terms — *"Do not size the work from
the assumption that they are conformant and this is a re-vendor"* — and the instruction was right.

---

## 1. Why this surface had never been driven

§6.3's `put` admission ladder is **new normative text at `0.8.2.11`** and is the **first
accept-side rule of the whole `0.8.2.x` arc**: `0.8.2.4` through `0.8.2.10` are rules about what a
peer *emits*. Arch names the consequence directly — an accept-side rule *"partitions a cohort
during adoption rather than merely diverging its error strings."*

The row did not exist until `EXTENSION-TREE` v4.4 and **had no predicate until v4.5**. The
predicate is a type we already had: `put-request.entity` is typed `core/entity`, and
`ENTITY-NATIVE-TYPE-SYSTEM.md` §8.1 declares three fields with no `optional` marker on any of them
— a row that, until this same version, read `{type, data, content_hash?}` and now reads
`{type, data, content_hash}` with **"All three keys are required."**

## 2. The ladder, and the one thing that cannot be tested the obvious way

1. **Structure.** A map with a non-empty text `type`, a present `data` (any CBOR value — null is
   legal), and a `content_hash` that is a well-formed `system/hash` whose byte length matches its
   format code. Any failure → **`400 invalid_request`**. A well-formed hash naming an *unsupported*
   format code is the separate §1.2 case → **`400 unsupported_content_hash_format`**.
2. **Hash.** Carried `content_hash` vs `content_hash({type, data})`. Disagreement → **`400 hash_mismatch`**.

**Step 1 strictly precedes step 2 as a data dependency**, and the spec states why no ordinary
vector can check it: *"no vector carrying a single fault can discriminate the order"*, since each
row's own input reaches its own branch either way. **The discriminating input carries both faults
at once.**

## 3. Instrument and controls

`tools/put-probe/` is a standalone Go binary in the shape of `tools/p47-probe`, so it drops into
every peer's existing container + startup harness via `ORACLE=` with no harness edits. It performs
a full §4.1 handshake, then issues authenticated `system/tree:put` EXECUTEs — `author`,
`capability`, a target-matching request signature, and the handshake's capability material
forwarded verbatim.

| case | submitted value | expected |
|---|---|---|
| **A** | valid entity | **200** — POSITIVE CONTROL |
| **B** | `{type, data}`, no `content_hash` | 400 `invalid_request` |
| **C** | empty `type`, hash correct **for that value** | 400 `invalid_request` (step-1 fault alone) |
| **D** | well-formed 33-byte hash that is simply wrong | 400 `hash_mismatch` (step-2 fault alone) |
| **E** | empty `type` **and** wrong hash | 400 `invalid_request` — **the ordering discriminator** |
| **F** | well-formed hash, format code `0x40` (reserved band) | 400 `unsupported_content_hash_format` |

**Three controls, and each one caught something.**

- **Positive (A).** A peer that cannot complete a legal `put` is reported `trusted: false` and its
  other rows are **not** read as §6.3 answers. This fired immediately: the probe's first two runs
  were **probe faults**, not peer answers — a stray decode call that made the capability material
  silently empty (`403 capability_denied`), and then a `system/peer` entity carrying `peer_id` in
  its hashable basis (`401 unresolvable_grantee`). Without the control both would have been
  published as cohort findings.
- **Differential (C · D · E).** C and D isolate one fault each so E's answer means something. A
  peer that refused *everything* would trivially "pass" E; the ordering verdict is reported
  **INDETERMINATE** unless both single-fault arms refuse *and* refuse differently.
- **Probe self-check.** Every forwarded `included` entry is re-decoded and re-hashed and must equal
  the map key it is filed under (§3.1). Without this, a byte-slicing bug in the probe and a peer
  defect are the same observation. It reports **0 of 4 bad on every peer**.
  **CORRECTED — that sentence used to end "which is what licenses §5's reading of the five
  unmeasurable peers." It licenses no such thing.** The check verifies that each forwarded entry
  AGREES WITH its key; it says nothing about whether the keys are UNIQUE, and the fault in §5 was
  a DUPLICATE key. **An invariant check licenses exactly the invariant it checks** — offering it as
  general assurance is how a probe fault gets published as a cohort finding. The encoder now
  deduplicates by construction and reports the count it dropped, so the dedup can never be silent.

**B is followed by a GET on the same path**, because a peer that answers 200 and a peer that
answers 200 having stored nothing are different findings — and the difference is exactly arch's
third behaviour class.

## 4. Results — 40 peers measured

| row | answer | peers |
|---|---|---:|
| **B** — two-key form | **`200` (accepted)** | **37** |
| | `400 unexpected_params` | 3 |
| | *of the 37 accepted: entity **STORED** at the path* | **36** |
| **C** — empty `type` | **`200` (accepted)** | **40** |
| **D** — hash mismatch | `500 internal_error` | 13 |
| | `400 unexpected_params` | 13 |
| | **`200` (accepted)** | **10** |
| | `400 non_canonical_ecf` | 2 |
| | `400 invalid_entity` | 1 |
| | *no response at all* | 1 |
| **F** — unsupported format code | identical distribution to D | — |

**Peers conformant on any row: 0 of 40.**

Three things are worth separating, because they are different severities:

- **The two-key form (B) is the correctness defect**, not a code-spelling one. §6.3: a peer that
  accepts it *"is supplying an authorship the protocol assigns to the submitter"*, and the GET
  confirms **36 peers ended up holding an entity under a hash nobody agreed to**. The three that
  refuse (`asm-arm64`, `asm-x86_64`, `riscv64`) get the **status** right and the code wrong, and
  they are the only peers in the cohort that store nothing.
- **Ten peers accept a mismatched hash** (`asm-arm64` `asm-x86_64` `cobol` `datalog` `io` `pd`
  `riscv64` `sql` `swift` `wasm-wat`). That is a §1.8 validate-before-trust failure independent of
  §6.3's code table — the peer binds a path to content that does not hash to the hash it was given.
- **`zig` answers D and F with nothing at all** — a §4.9(c) deliver-or-signal drop, the class this
  repo has recorded five times, on a new input.

**The ordering question (E) is INDETERMINATE cohort-wide and cannot yet be asked**: every peer
answers C with `200`, so there is no step-1 refusal for a step-2 refusal to be ordered against.
The discriminator becomes measurable only after step 1 exists somewhere.

## 5. ~~Five peers could not be measured, and the probe is not the reason~~ — RETRACTED: it was the probe

> **This section was wrong, and its title was the wrongest part of it. Kept in full, struck rather
> than deleted, because the mechanism generalizes.**
>
> `authedExecute` unions the probe's own peer entity into the handshake's forwarded `included`
> map — which already contains it, because the probe IS the grantee — and the map encoder sorted
> keys without deduplicating. **Every authenticated frame therefore carried the same byte-string
> key twice.** A CBOR map with a duplicate key is not canonical ECF at all, and a decoder is
> entitled to refuse the whole frame.
>
> **`csharp` did, in strict CTAP2 mode, on every case including the positive control — and it was
> the only peer of 46 strict enough to say so, which is exactly why it read as the outlier.** Its
> refusal even named the wrong reason (below), which is what let a probe fault look like a peer
> defect wearing a peer's own error code. `typescript` and `node-red` dropped the frame silently;
> `forth` and `smalltalk` refused.
>
> **The one true finding in this section survives:** `csharp`'s single code and single message
> standing in for several canonicalization branches is real, and it is what made the diagnosis take
> a debug build instead of a read. The rest of the section is a description of our own bug.
>
> After the fix all five are measurable and trusted. **Coverage: 46 measured.**
>
> **And the dedup COUNT names the affected population, which is what closes this
> retraction rather than merely asserting it.** The encoder reports how many duplicate
> keys it discarded per peer: **7 peers report 7, the other 39 report 0** — and the 7
> are `csharp`, `forth`, `node-red`, `smalltalk`, `typescript` (the five reported
> unmeasurable), `turbowarp` (which inherits the `typescript` engine) and `nim`. Those
> are exactly the peers whose `authenticate` response echoes the GRANTEE's own peer
> entity in its `included` map, which is what made the probe's union duplicate a key at
> all. `nim` is the informative outlier: same duplicate, decoder tolerated it. A silent
> dedup would have fixed the symptom and left this unknowable.



`csharp` · `forth` · `node-red` · `smalltalk` · `typescript` complete the handshake — grantee
resolves, capability material forwards, **self-check clean (0 of 4 bad)** — and then refuse or drop
the *valid* `put`, so the positive control fails and **none of their rows is reported**.

- `csharp` answers **`400 non_canonical_ecf`, message *"CBOR tags are forbidden anywhere in an
  entity"*.** The probe emits no major-type-6 anywhere, and it *cannot* be forwarding one: its
  decoder errors on major 6, so a tag in the peer's own returned material would have produced zero
  forwarded entries rather than four. So the message names a condition that is not present —
  **one code and one message are standing in for several canonicalization branches**, which makes
  the refusal undiagnosable from the wire. That is a small finding in its own right.
- The other four **answer nothing at all** and hold the connection, which is a §4.9(c) drop.

**Stated as unmeasured rather than folded into the counts.** 34 other peers answer the identical
envelope with `200`; that is strong evidence it is legal, and it is not proof, because a cohort
sharing a generation lineage can be uniformly permissive. **`turbowarp` produced no report at all**
(its bundle build fails, pre-existing and unrelated).

**Coverage: 40 measured · 5 unmeasurable · 1 unbuildable = 46.**

## 6. What this changes

**The `put` ladder is not a re-vendor item.** It is new implementation work on every peer, and on
36 of them it closes a defect where the peer authors content on a submitter's behalf. The
worklist's item 5 was carried as *"completely unmeasured; arch expects the first run to surface
something"* — it surfaced the maximum.

**Two of the three defect classes are outside the code table** and will not be fixed by a
code-spelling sweep: the accept-and-store behaviour, and the ten peers that bind a mismatched hash.

**Reproduce:**

```
podman run … -e ORACLE=/work/output/s4-oracles/put-probe … sh /work/protocol-generator/<peer>/run-s4.sh
tools/run-cohort-census.sh --probe put-probe          # all 46
```

Per-peer JSON: `output/scratch/put-probe/<peer>.json` (gitignored — re-run rather than cite a copy).

## 7. Closed — 46 of 46 conformant (2026-09-07)

The ladder is authored on every peer in the cohort and every peer measures **6 of 6**:

| case | input | every peer now answers |
|---|---|---|
| A | valid put | `200` |
| B | `{type, data}`, no `content_hash` | `400 invalid_request` |
| C | empty `type`, hash correct for it | `400 invalid_request` |
| D | well-formed but wrong hash | `400 hash_mismatch` |
| E | **both** faults | `400 invalid_request` |
| F | format code `0x40` | `400 unsupported_content_hash_format` |

Measured across all 46 in one census run with the current probe: **46 of 46
`6/6 conformant`, 46 of 46 `trusted: true`, and 46 of 46 reporting the ordering verdict
`step 1 precedes step 2 (conformant)`.**

**The ordering question is now ANSWERABLE and the answer is conformant.** §4 reported it
INDETERMINATE cohort-wide because every peer accepted the step-1-only input, so there was no
step-1 refusal for a step-2 refusal to be ordered against. With step 1 implemented, C and D refuse
differently and E's `invalid_request` means what the spec says it should.

**What the fix is not.** It is not a code-spelling sweep. Three defect classes closed:

1. **36 peers authored the submitter's `content_hash` and stored the entity under it.** Every peer
   now binds the CARRIED hash, and several gained an explicit receipt constructor (`Entity.admitted`,
   `ent-admitted`, `Ent_Admitted`, `admittedType:data:hash:`) whose doc comment says it is reachable
   only from the ladder that just verified those bytes. Where an existing `of_cbor`/`from_cbor`
   already recomputed and refused on a carried mismatch, step 2 routes through it — verifying is the
   opposite of authoring.
2. **10 peers bound a path to content that did not hash to the hash they were given** — a §1.8
   validate-before-trust failure independent of the code table.
3. **Adjacent defects the ladder had to remove rather than sit beside.** `sql` defaulted an absent
   `type` to `primitive/any`, storing an entity under a type the submitter never sent. `ada` and
   `datalog` treated a present-but-MALFORMED entity as the §6.3 REMOVAL case and unbound the path —
   a destructive reading of a value the spec says to refuse.

**Per-peer honesty about the supported set.** Each peer's `hashDigestLen` names the codes it can
actually VERIFY, not the codes its construction path will serialise. Peers whose entity carries a
fixed 33-byte hash (`c`, `cpp`, `fortran`, the ISA trio) or whose hash primitive is the SHA-256
floor (`lean`, `rust`, `unison`, `apl`, `wasm-wat`, `pd`, `sql`, `cobol`, `nim`) verify `0x00`
alone; peers with a real SHA-384 path also verify `0x01`. **The same input therefore answers
`unsupported_content_hash_format` on different codes on different peers, which is the honest answer
rather than a uniform one.**

**Conformance impact: none, measured.** The pinned oracle's own `put` vectors all carry a
well-formed `content_hash`, so the ladder is additive at this check set — verified per-check rather
than by summary, peer by peer, against each committed report.

**Standing limit, unchanged.** 46 peers agreeing is **cohort-consistent, not independent
convergence**: this is one ladder authored from one reading of §6.3 and propagated, and its
uniformity is evidence of a shared generation lineage. What it is *not* is a re-vendor — it was
**+4,201 / −128 lines across 56 files** in ~36 languages, and the three adjacent defects above were
found only because something finally drove the surface.
