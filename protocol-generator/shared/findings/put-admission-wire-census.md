# `system/tree:put` admission — a 46-peer wire census of §6.3's `0.8.2.11` ladder

**Date:** 2026-09-06 · **From:** `entity-core-keystone` · **Measured against:** `ENTITY-CORE-PROTOCOL.md` **0.8.2.11** (`protocol-generator/shared/spec-data/v0.8.2.11/`, `c97e1860…`) · **Instrument:** `tools/put-probe/`

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
  defect are the same observation. It reports **0 of 4 bad on every peer**, which is what licenses
  §5's reading of the five unmeasurable peers.

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

## 5. Five peers could not be measured, and the probe is not the reason

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
