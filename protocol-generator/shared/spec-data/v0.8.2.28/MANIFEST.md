# spec-data v0.8.2.28 — Snapshot Manifest

**Spec version:** Entity Core Protocol **0.8.2.28**. `ENTITY-CORE-PROTOCOL.md` carries
`**Version**: 0.8.2.28` on line 3, `ENTITY-CBOR-ENCODING.md` carries `**Version**: 1.8`, and
`ENTITY-NATIVE-TYPE-SYSTEM.md` carries `**Version**: 4.2.1` — **all three read out of this snapshot,
not assumed.**
**Snapshot type:** verbatim copy of the authoritative normative spec files — **no paraphrase,
byte-for-byte** (S2). Each file was hashed from the source blob with
`git show 3684c0b:specs/<file> | sha256sum` and compared against the written copy **before**
acceptance; all three matched.

**Supersedes for new work:** `v0.8.2.25/`, `v0.8.2.11/`, `v0.8.2.3/`, `v0.8.2/` and `v0.8.0/` (all
kept in place as point-in-time pins — a snapshot is immutable once stamped and amendments get a new
directory, never an in-place edit).

**`EXTENSION-TREE.md` is NOT vendored, deliberately** — unchanged policy. We pin the three core
normative documents only; its Appendix A stays load-bearing *by reference* for §6.3's `put` error
codes and §2.2a for the resource-optional/BROAD-RESULT declarations §3.3 consumes. Read it in the
sibling; do not copy it here.

## ⭐ VENDORED BEFORE IT IS CONSUMED — which is the order `v0.8.2.25`'s manifest asked for

`v0.8.2.25`'s manifest opens with a defect notice: **33 of 46 peers were taken to `0.8.2.25` before
that directory existed**, implemented from architecture's routed packets rather than from a pin in
this tree, and it names the remedy — *"the correct order is vendor, then implement."*

**This snapshot is that order.** No peer implements `0.8.2.26`–`.28` yet; the cohort sits at
`0.8.2.25` on all 46 rows (`tools/peer-tiers.tsv` `spec_pin`, gated). The pin is here first so the
cohort work can be derived from the text rather than from a packet, and so a reviewer can re-run the
round.

## ⛔ ONE DOCUMENT MOVED WITH AN UNMOVED `Version:` HEADER — diff by DIGEST, never by header

`ENTITY-NATIVE-TYPE-SYSTEM.md` is **`4.2.1` at `v0.8.2.25` and `4.2.1` here**, and its content
changed (`043fc80d…` → `cb0a63e2…`). A vendor keyed on the version string would have concluded the
type system had not moved for the **seventeenth** consecutive revision and skipped it.

This is `entity-system-conformance`'s **`F79`** — *two documents changed normative content with
unmoved `Version:` headers* — arriving live on the very next vendor after they warned us about it,
and it is the reason the digest comparison above is the acceptance step rather than a formality.
**Read the digest, not the version string**, and note the trap's shape: the header is not *wrong*,
it is merely *unchanged*, so nothing anywhere reports an error.

## Provenance

| Field | Value |
|---|---|
| Source repo | `entity-core-protocol` (sibling) |
| Source path | `specs/` |
| Source ref | **`dev`** at `3684c0b` |
| Source subject | `0.8.2.28: CQ-16 — the root-hash refusal had a code in the pseudocode and no row in the table, and a peer read the table` |
| Method | `git show 3684c0b:specs/<file>` into the snapshot path; each output hashed and compared against the source blob before acceptance. All three matched. |
| Read at | 2026-09-16 |

As with every snapshot since `v0.8.2.3`, this is vendored from an **unreleased line** — `master` is
still the released `0.8.2`, and the fourth component exists precisely so core text can move without
cutting a release. There is no published artifact to vendor from. The SHA-256 table below is
therefore not merely the preferred anchor, it is the **only** one: `3684c0b` is a `dev` commit,
[ADR-0027] authors published commits fresh at the release boundary, and this directory publishes
(`protocol-generator/**` ships undeclared). The commit is an internal build coordinate and is **not**
citable in anything published.

Per the standing rule we do **not** vendor a `v0.8.3/`: the fourth component is an arch-managed
in-flight signal that the operator strips and renames at the release cut.

## Files (the three authoritative normative inputs)

| File | SHA-256 |
|---|---|
| `ENTITY-CORE-PROTOCOL.md` | `d1888c131806401798b46d2a730c8a9e79e5380296ef91d97d9ed86cae15730b` |
| `ENTITY-CBOR-ENCODING.md` | `36e83350944d304316fc7f434c85bdd5e0060f00f0ea1bc50d67bd0fa8664d5f` |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | `cb0a63e23862dccb6c421fabbcdcce765a67a8fb8f818b1a1eb41f1530460305` |

## What moved since `v0.8.2.25` — measured here, not read off a packet

Three revisions (`0.8.2.26`, `.27`, `.28`) plus `ENTITY-CBOR-ENCODING` v1.7 → v1.8. Line deltas
against the `v0.8.2.25` snapshot:

| File | added | removed |
|---|---:|---:|
| `ENTITY-CORE-PROTOCOL.md` | 75 | 20 |
| `ENTITY-CBOR-ENCODING.md` | 61 | 33 |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | 2 | 2 |

**The arc's subject is SINGLE NORMATIVE HOMES.** Almost every change pins one section as the
authority for a rule and demotes its restatements elsewhere to pointers. That shape matters for how
the cohort work is scoped: a restatement being corrected is not necessarily a behaviour change, and
several of these are documents catching up with rules already in force.

### The changes a peer could have to act on

- **§1.2 is the single normative home of the `content_hash_format` registry `[MUST]` (0.8.2.27).**
  `ENTITY-CBOR-ENCODING` §4.3/§4.4 had **transposed `0x03` and `0x04`**, so the corpus bound
  `"ecfv1-blake3"` to two different codes depending on which document an author read. Our peers
  verify `0x00` only (the SHA-256 floor), so the transposition is very unlikely to have reached
  anything — **but that is a prediction and it is not measured**; the check is each peer's
  `hashDigestLen`-equivalent and its `unsupported_content_hash_format` arm.
- **§4.11 sharpened (0.8.2.26/.27).** `400 non_canonical_ecf` is **not conformant on the framing
  arm**, and *the framing arm is bytes that DO NOT DECODE*; `non_canonical_ecf` names a **CLASS**
  with the tag-policy rule one member of it; the table **assigns codes and does not define the
  class**; and the connection close is a **CHOICE** where the frame was consumed whole and **FORCED**
  where it was not (a refusal leaving the stream desynchronized must close).
- **A new 400 row at 0.8.2.27** for non-canonical ECF that *does* decode, and **a new refusal row at
  0.8.2.28** for root-entity self-consistency (the root's own `content_hash` not matching
  `content_hash({type, data})`) — which `CQ-16` records as having had a code in the pseudocode and
  **no row in the table**, so a peer that read the table could not have implemented it.
- **§3.3 default declared (0.8.2.26):** an operation whose specification declares **neither**
  resource-optional shape is treated as **BROAD-RESULT**, and its present-but-effectively-empty case
  is `400 path_required`.
- **§1.8 (0.8.2.26):** a uniform verdict on an UNREFERENCED `included` entry is mechanism-shaped and
  **MUST NOT be required** — with the two mechanisms explicitly noted as *not equally robust to
  partial adoption*.
- **`ENTITY-NATIVE-TYPE-SYSTEM` §10.2 (0.8.2.26):** the signature is computed over the target's
  **full `content_hash`** — format code ‖ digest — not the digest alone, with §7.3 named as the
  normative home and this sentence marked a pointer. §7.3 already said so; the restatement had
  drifted by one field.
- **`ENTITY-CBOR-ENCODING` §4.1/Rule 2 (v1.8):** the map-key ordering is RFC 8949 **§4.2.3
  length-first**, explicitly **not** §4.2.1 bytewise. Every peer in this cohort hand-rolls
  length-then-lex because no platform library suffices, so this is expected to be a no-op here — and
  the section now carries the warning that a library's "canonical" mode may implement the other one.

⚠ **None of the above is a conformance claim about this cohort.** It is a reading of the diff,
recorded so the next session scopes from the text. What each peer actually does is `unknown` until an
instrument drives it — and the executed 778-check set has no vector on most of this surface, which is
exactly what `tools/pa-probe` and `tools/arc-probe` exist for.

## Consumption state

**Not yet consumed. `spec_pin` is `0.8.2.25` on all 46 peers and the gate agrees with the matrix.**
When a sweep lands these revisions it moves that column, and
`tools/spec-pin-gate.py --since <ref>` is the reconciliation that says every peer it claims was
touched actually was.

**The oracle re-pin is deliberately NOT landed with this vendor**, unchanged policy: the spec
snapshot is what peers are **written against**, the oracle pin is what they are **measured against**,
and nothing requires the two to move together. The pin remains `78db4a9` (executed set
`7aa6f3de…`, 778 checks).
