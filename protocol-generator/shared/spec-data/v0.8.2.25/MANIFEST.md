# spec-data v0.8.2.25 — Snapshot Manifest

**Spec version:** Entity Core Protocol **0.8.2.25**. `ENTITY-CORE-PROTOCOL.md` carries
`**Version**: 0.8.2.25` on line 3 (verified in this snapshot, not assumed).
**Snapshot type:** verbatim copy of the authoritative normative spec files — **no paraphrase,
byte-for-byte** (S2). Each file was hashed from the source blob with
`git show 1a8e0c1:specs/<file> | sha256sum` and compared against the written copy **before**
acceptance; all three matched.

**Supersedes for new work:** `v0.8.2.11/`, `v0.8.2.3/`, `v0.8.2/` and `v0.8.0/` (all kept in place
as point-in-time pins, as every prior snapshot is — a snapshot is immutable once stamped and
amendments get a new directory, never an in-place edit).

**`EXTENSION-TREE.md` is NOT vendored, deliberately** — unchanged policy from `v0.8.2.11`. We pin
the three core normative documents only; its Appendix A stays load-bearing *by reference* for
§6.3's `put` error codes. Read it in the sibling; do not copy it here.

## ⛔ This snapshot is vendored AFTER the cohort implemented against it, and that is a defect

**Stated here rather than in a status file, because this is the document a future reader will check
the provenance in.** Thirty-three of forty-six peers were taken to `0.8.2.25` across six sweep
tranches on 2026-09-14/15 — **before this directory existed.** Peer source cites `.13` through `.25`
in 1,211 places across 38 peers while the newest pinned snapshot was `v0.8.2.11`.

The rules implemented are the landed rules and several were re-derived from the spec text during the
sweep, so **this is a provenance defect, not a known correctness defect** — the distinction matters
and neither half should be inflated. What was actually missing is the ability to verify the cohort's
work against a pinned copy **from inside this tree**, which is the entire reason `spec-data/` exists
and is a boundary.

The correct order is **vendor, then implement**: `AGENTS.md`'s boundary rule says derive behaviour
from the spec, and for fourteen revisions the cohort derived it from architecture's routed packets
instead. Those packets quote normative text faithfully — that is why the outcome is sound — but a
packet is not a pin, and a reader nine months from now cannot re-run a review round.

**The vendor gap is now closed and the verification it enables is owed:** re-derive the sweep's rules
against this text rather than against the packets they were implemented from.

## Provenance

| Field | Value |
|---|---|
| Source repo | `entity-core-protocol` (sibling) |
| Source path | `specs/` |
| Source ref | **`dev`** at `1a8e0c1` |
| Source subject | `0.8.2.24 → 0.8.2.25: the pre-admission refusal is one invariant, not five patches` |
| Method | `git show 1a8e0c1:specs/<file>` into the snapshot path; each output hashed and compared against the source blob before acceptance. All three matched. |
| Read at | 2026-09-15 |

As with `v0.8.2.11` and `v0.8.2.3`, this is vendored from an **unreleased line** — `master` is still
the released `0.8.2`, and the fourth component exists precisely so core text can move without cutting
a release. There is no published artifact to vendor from. The SHA-256 table below is therefore not
merely the preferred anchor, it is the **only** one: `1a8e0c1` is a `dev` commit, [ADR-0027] authors
published commits fresh at the release boundary, and this directory publishes
(`protocol-generator/**` ships undeclared). The commit is an internal build coordinate and is **not**
citable in anything published.

Per the standing rule we do **not** vendor a `v0.8.3/`: the fourth component is an arch-managed
in-flight signal that the operator strips and renames at the release cut.

## Files (the three authoritative normative inputs)

| File | SHA-256 |
|---|---|
| `ENTITY-CORE-PROTOCOL.md` | `589cc8f1905184931c4586babb103f2b25d2584e534671768ef6d5e730377710` |
| `ENTITY-CBOR-ENCODING.md` | `dd6aa47de343b335ececc3c7c654da019dc9e473eb4639af3dc9d7a202a8393f` |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | `043fc80d4fd21ff074082e1f3c76b779d73d9f172a90d3f2a986d68e0cde740d` |

## What moved since `v0.8.2.11` — measured here, not read off a packet

| File | Change |
|---|---|
| `ENTITY-CORE-PROTOCOL.md` | **559 changed lines** across fourteen revisions (`.12` → `.25`) |
| `ENTITY-CBOR-ENCODING.md` | **7 changed lines** |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | **BYTE-IDENTICAL** — `043fc80d…` at both pins; the type system has not moved since `v0.8.2.11` |

**The type-system file being unchanged is worth stating explicitly** rather than leaving as the
absence of a row: it means nothing in this snapshot's delta touches the type registry, and a reader
comparing a `type_system` category result across the two pins is comparing like with like.

The headline of the delta for this cohort is **§4.11, the pre-admission refusal** — arch's ruling on
`CQ-34`/`CQ-35`, which folded `entity-system-conformance`'s 34-peer measurement and `entity-core-go`'s
three-seat measurement into one invariant: a peer refusing a frame pre-admission MUST put a coded
`EXECUTE_RESPONSE` on the wire, and **a silent drop and a bare close are distinct non-conformances
that must be scored separately.** That is the rule the six sweep tranches implement.
