# HANDOFF-TO-ARCH — 2026-07-18 — Critical-review outputs (net-new items)

**From:** the keystone critical-review effort. **To:** architecture (pull on your own schedule; no cross-repo
writes were made). **Severity:** none blocks; all are notes, one design proposal, one extension-layer gap.

> This is the arch front-door for the **net-new** items from a four-dimension adversarial review of core.
> The converged picture is in `research/SYNTHESIS-RECONCILIATION-2026-07-18.md`; already-filed findings
> (F32–F41, F37, F44–F46) remain in `AGGREGATE-F32-F41.md` — the review
> *corroborated* those, no change. Detail behind each item below:
> `research/RED-TEAM-CRITICAL-REVIEW-2026-07-18.md` and `research/IMPLEMENTATION-HISTORY-REVIEW-2026-07-18.md`.

## The one-line summary

A minimality/security/design/implementation-history assault on core found **no novel in-core defect and no
place core forces bad design.** Net-new residue: two one-line concurrency-contract MUSTs, one hex-case
sentence, two small prose notes, one design proposal to evaluate, and one extension-layer PQ gap. Plus an
editorial recommendation to right-size the retrospective's minimality wording.

## Core spec notes (candidate one-liners — all "silently-violable MUST-prose" family)

1. **RT-13a — §4.8 store-safety: atomic/lock-guarded refcounts (MUST).** Add: *"On a multi-threaded peer,
   refcounts on shared entities MUST be atomic (or lock-guarded)."* Surfaced by the C peer (A-C-009): a
   plain-`int` refcount passes S2/S3 green then use-after-frees under the live §4.8 gate (22/31 run-1 FAILs
   cascaded from one crash). GC'd peers never hit it; C++ gets it free (atomic control block) — a
   no-GC-specific surface. Absent from F1–F46.
2. **RT-13b — §1.6 frame-write atomicity (MUST).** Add: *"Concurrent dispatch MUST NOT interleave the bytes
   of distinct frames on a connection."* Surfaced by the Io peer (A-IO-002): invisible on atomic-write
   substrates; corrupts the wire on a yielding write primitive. Absent from F1–F46.
   *(RT-13a+b are one theme: concurrency-contract MUSTs that runtimes provide for free on the "easy"
   substrates and that are load-bearing on manual-memory / yielding ones — the class a spec author on an easy
   substrate can't see.)*
3. **RT-14 — normative lowercase hex.** Add: *"content-hash hex in tree paths MUST be lowercase."* Surfaced
   by the Common Lisp peer (A-CL-009): lowercase is currently de-facto *only* because the Go reference impl's
   `hex.EncodeToString` defaults lowercase; case-sensitive keys make uppercase-hex substrates pass
   self-loopback and fail the oracle. (Also the one concrete "Go convention became de-facto spec" instance
   the review found — the RT-3 monoculture residual, caught in the wild.)
4. **format_code=128 asymmetry (§4.3/§4.7) — clarifying sentence.** Construct-emits vs receive-rejects is
   correct but stated nowhere; **3 peers independently escalated it** (OCaml A-OC-004, CL A-CL-007, Prolog
   A-PL-011). The behavior is gated (F16); the requested sentence never landed.
5. **`unregister` type-ownership/refcount (informational).** `system/handler:unregister` leaves the handler's
   `system/type/*` entities in the tree; types may be shared and the spec pins no ownership/refcount model
   (C# A-012, OCaml A-OC-009). Low priority; "leave in place" is the safe default today.
6. **§1.1 scalar-`data` accept-path vector (coverage).** Entity `data` is any ECF value, not necessarily a
   map (A-JAVA-010, folded into v7.75 prose but no F-number). Confirm a conformance vector stores a
   scalar-`data` entity so a map-only model is caught at the codec bar, not only at the §7b gate — the
   vacuous-green shape.
7. **RT-10 — continuation `suspend()` seam is documented only in the extension (LOW, boundary-doc).**
   Verified vs pinned V8: core has no `suspend()`/register-suspension-handler and no execution-context
   `chain_depth` counter; the seam lives only in EXTENSION-CONTINUATION §3.9. It is MAY-level and
   backward-compatible, forces no core change, but is a *fourth* dispatcher seam that maps onto none of the
   three §6.13 hooks (register/outbound/emit). Either name it in core §6.13 as an explicit MAY, or state core
   dispatch has no suspension concept. **Its `chain_depth` half is already actioned** by the in-flight
   `PROPOSAL-CONTINUATION-BOUNDS-PROPAGATION` (promotes `chain_depth` to a core §3.11 `system/bounds` field —
   network-forced, additive, no wire renumber); only the seam-naming remains.

## Design proposal to evaluate (not a defect)

7. **W6 — mint-time resource absolutization.** The §PR-8 granter-frame canonicalization bug beat 6/6
   reference implementations because relative cap resources canonicalize at *verify* time against the granter
   frame. Since a bare relative resource is only ever valid at root-mint over the granter's own resources
   (delegated/cross-peer already MUST use explicit form, §5.5a), canonicalizing to absolute form **at mint**
   and matching absolute at verify makes the whole bug class *structurally impossible*. Cost: the resource
   string denormalizes the granter peer_id (redundant with the `granter` field). Pressure-test for a cap
   shape whose resource frame is genuinely unknowable at mint; if none, this is a correct-by-construction win
   worth landing before the core freezes.

## Extension-layer (not core)

8. **F-PQ — cross-algorithm identity migration.** The PQ-migration story is incomplete: routine rotation
   (`identity-rotation-handoff`, §4.3) needs the *old* key (useless once its algorithm breaks); compromise
   recovery (`identity-rotation-recovery`, §4.4) is quorum-signed but the spec never *requires* the recovery
   quorum to sit on a stronger/independent (unbroken) algorithm; cross-algorithm rotation is unspecified; and
   `PROPOSAL-MULTIKEY-MULTIHASH-ALIGNMENT` (referenced in EXTENSION-IDENTITY) has **no file** in the arch
   repo. Core is *not* implicated — it provides key_type/hash_type agility and the quorum-handle model, and
   does not block the fix. Routes to identity/quorum. Foundational: the ecosystem should not lean on identity
   before it survives a primitive break.

## Editorial (for any public framing)

9. **Right-size the retrospective's minimality verdict (W5).** "Minimal by the spec's own MUST/MAY
   construction" is largely circular (the partition is the designers' claim, not an independent proof). The
   defensible verdict — see the synthesis §6 — is "proven implementable + deterministic across the landscape;
   the mandatory core is small with strong-not-absolute evidence it is near its intrinsic shape; minimality
   asserted, not independently proven." This *drops only the one unearned claim* and keeps everything else.

## The positive results worth carrying (not everything is a finding)

The review also produced strong *confirmations* arch can rely on: core is paradigm-neutral (re-verified
against the raw 427-entry implementation record); **core is sufficient for its own central paradigm —
entity-compute rides the frozen core with zero forced core change, its seams (`expression_path`,
entity-native dispatch, emit) already designed into the V8 text, the axis-1 prototype needing "no new
primitive"** (spec-level + prototype corroboration, not an independent keystone build — no keystone peer
ships compute); §4.10 DoS hardening holds; the conformance method is robust (cross-impl diff, no privileged
impl); the type system is opt-in with extensions building on it at zero core cost; multisig-root-only is a
clean boundary; the coverage well is dry (no unprobed wire-touching axis; big-endian/EBCDIC hosts are
covered-by-construction); and the Lean proof vector *drove* the v7.76 §5.10 determinism amendments (time +
revocation as declared Layer-1 inputs) — the keystone→arch loop working on the highest-signal channel.
