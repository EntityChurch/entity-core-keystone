# Conformance assumes a payload capacity the spec never states

**Date:** 2026-09-02
**Raised by:** entity-core-keystone (46-peer cohort)
**Surface:** `ENTITY-CORE-PROTOCOL.md` §4.10(a); `GUIDE-CONFORMANCE.md`; the `concurrency`
category of `validate-peer`
**Status:** open — routed to architecture

## The claim

A peer can satisfy every normative sentence about payload limits and still be
**unmeasurable** by the conformance suite, because the suite stages payloads whose size
the spec never requires anyone to accept.

## Sections read

Stated explicitly, because a finding that asserts a gap is an unfalsifiable negative
unless it says where it looked (the F51 withdrawal, `AGENTS.md`).

- `ENTITY-CORE-PROTOCOL.md` §4.10(a) — the only normative text on inbound size limits.
- `ENTITY-CORE-PROTOCOL.md` §1.6, and the framing paragraph at line 477 of `v0.8.2.3`.
- `ENTITY-CORE-PROTOCOL.md` §3.1, §3.3, §6.11 — envelope, EXECUTE, concurrency.
- `ENTITY-CBOR-ENCODING.md` §6.3, §9.1.
- Grepped the whole `v0.8.2.3` snapshot for `payload_too_large`, `413`, `frame`,
  `MiB`, `maximum` and `minimum`.

## What the spec says

Two sentences, and they point in opposite directions from a conformance point of view.

§4.10(a), a **MUST**:

> The peer MUST reject an inbound EXECUTE whose wire size exceeds its **configured
> maximum** with `413 payload_too_large` … The default maximum MUST be **finite** (an
> unbounded/absent default is non-conformant).

And the framing paragraph:

> The core protocol places **no restriction on entity size**. Frame size limits are
> transport-specific — peers negotiate or agree on limits appropriate to their
> transport. TCP implementations **SHOULD** use a reasonable default frame limit (e.g.,
> 16 MiB) …

So the normative requirement on a peer is: pick a finite maximum, and refuse above it
with a specific status. There is **no floor**. 16 MiB is a SHOULD and an example.

## What conformance requires

`concurrency/t1_3_no_head_of_line` stages a `tree.put` whose frame measures
**264 109 bytes** on the wire (measured by instrumenting the oversize branch of a
peer's serve loop and reading the declared length off one run — not inferred from the
check name or from the vector description, which says "256 KiB").
`concurrency/t1_4_frame_write_atomicity` stages a 16 KiB entity.

A peer whose configured maximum sits below those refuses them, correctly, with
`413 payload_too_large`. The oracle then records the check as **SKIP** — and a skip is
not a neutral outcome. `validate-peer` prints:

> `2 skip(s) count as FAIL — an unexercised surface is an UNTESTED surface`

and the run summary becomes `Result: FAIL (un-allowlisted skips)`. So a peer that obeys
§4.10(a) exactly as written can be marked as failing the suite **for obeying it**.

## Why it is not simply an implementation bug

It would be, if the capacity were free. In one cohort peer it is not, and the reason is
structural rather than lazy:

- `entity-core-protocol-cobol` canonicalises CBOR with a **recursive** program whose
  per-invocation `LOCAL-STORAGE` holds a 64-entry map-pair table. The value slot in that
  table is what bounds the largest map value the peer can canonicalise, and
  `LOCAL-STORAGE` is allocated and initialised **per call, per nesting level**.
- Raising that slot to 512 KiB to clear the 264 KB probe costs ~34 MB per call.
  Measured on the full suite: sustained load dropped **7454 of 10000** requests and the
  `concurrency` category went from **15.5 s to 9 m 50 s**. Both robustness checks, which
  had been passing, failed.
- The peer settled at a 32 KiB entity ceiling, which clears `t1_4` and not `t1_3`.

The point is not that COBOL is awkward. It is that **the cost of capacity is a property
of the substrate**, and the spec deliberately declines to require any particular
capacity, while the suite requires a specific one. Any peer on a fixed-extent or
non-heap substrate lands in the same place.

## What we are asking for

One of these, architecture's call. We are not proposing wording.

1. **State a floor.** If conformance assumes a minimum acceptable payload size, make it
   normative — "a conformant TCP peer MUST accept an inbound EXECUTE of at least N
   bytes" — so that a peer below it is failing a stated requirement rather than an
   unstated one. This is the option that makes the current oracle behaviour correct.
2. **Make the probe adaptive.** Have the check discover the peer's configured maximum
   (it is already observable: send one oversize frame, read the `413`) and stage a
   payload the peer has said it accepts. This tests head-of-line blocking, which is what
   the check is *about*, rather than testing capacity as a side effect.
3. **Rule the SKIP correct and non-gating for this case**, and say so in
   `GUIDE-CONFORMANCE.md`, so implementers know a capacity refusal is a legitimate
   terminal state rather than an open defect.

Our preference, weakly held, is (2): the check's own description is *"fast not gated
behind slow on one connection"*, and payload size is incidental to that. But (1) is the
one that makes the numbers we publish mean the same thing across the cohort, and it is
the one an adopter can act on.

## What we already fixed on our side

The half of this that was genuinely ours. §4.10(a)'s `413` is a MUST and one peer's
oversize path drained the frame body and emitted **nothing**, so the caller waited out
its own deadline and the check reported `i/o timeout`. That is a §4.9(c) silent drop and
it is now a correlated refusal. The remaining gap is the one described above.

## Cohort scope

One peer of 46 is bounded below the staged payload. The other 45 accept it. That is a
small number, and it is exactly the population this repo exists to hear from: the
substrates where a convenience assumption stops being free.
