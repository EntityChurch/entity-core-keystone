# HANDOFF-TO-ARCH — F38: mint-timestamp precision is a CORRECTNESS parameter on a content-addressed protocol (+ companion: open-seed resource form)

**Date:** 2026-07-15 · **Findings:** F38 / F39 (`research/stewardship/SPEC-FINDINGS-LOG.md`);
surfaced as **A-PD-016** / **A-PD-017** (`protocol-generator/pd/status/SPEC-AMBIGUITY-LOG.md`)
**Owner:** `arch` (GUIDE-CONFORMANCE note) · **Severity:** guidance gap (a silent, marathon-only
token-aliasing bug class no vector names) · **Blocks:** nothing
**Spec surface:** ENTITY-CORE-PROTOCOL.md §3.6/§5.5 (token shape) + GUIDE-CONFORMANCE @ `spec-data/v0.8.0`

> Keystone cannot edit `spec-data/**` (immutable, boundary). This is a request for arch to fold a
> GUIDE-CONFORMANCE note on its own schedule; the keystone side is already fixed (Pd peer +
> `protocol-generator/shared/seed-policy/` convention doc + AGENTS.md durable-lesson bullet).

## F38 (primary) — second-truncated mint timestamps alias same-scope re-mints

A capability token is content-addressed over `{grants, grantee, granter, created_at}`. If a peer
stamps `created_at` at **second** precision (e.g. `time(NULL)*1000`), two mints of the SAME scope
for the SAME grantee within one second are **byte-identical → same content hash → the same
capability**. Nothing in the spec marks the timestamp's precision as load-bearing, and no
conformance vector gates it directly.

**How it bit (Pd peer #33, `--profile core` marathon @ `cc1970f`):** the oracle's
`revoke_happy_path` re-minted a scope that collided with the **§4.4 session floor cap** minted in
the same second — revoking the fresh token revoked the session cap, and every later category
**403-cascaded**. The nasty property: **isolated `-category` runs stay green** (no same-second
re-mint of a session-colliding scope); only the full-profile marathon, where the capability
category runs early on a long-lived session, exposes it. The C peer avoided it *implicitly*
(`ec_now_ms()` was already ms-precision) — i.e. the cohort's greenness on this point is
accidental, not spec-driven.

**Keystone fix (landed):** ms-precision wall clock (`clock_gettime(CLOCK_REALTIME)`) at every
mint site; Pd gate now **682·0F Result: PASS**, stable across four runs.

**The ask:** add a GUIDE-CONFORMANCE note — *on a content-addressed protocol, mint-timestamp
precision is a correctness parameter, not a formatting choice*: any peer whose `created_at`
stamps coarser than the oracle's (or any client's) re-mint cadence will alias tokens, and
revocation of one aliases them all. Recommended phrasing: `created_at` MUST be stamped at
millisecond precision from a real-time clock at every mint site (never truncated/cached), OR the
mint path must otherwise guarantee same-scope re-mints are distinguishable. A direct vector is
hard (timing-dependent); the note is the right vehicle — same class as the F29 "conformance-green
can be vacuous" family.

## F39 (companion) — the open/debug seed needs the ABSOLUTE all-peers resource form

A consequence of the ratified §5.5a bare-star ruling that any open-access/debug seed
implementation hits: `resources: ["*"]` looks universal but §5.5a makes bare `*`
**granter-local** (`/{granter}/*`), so the `universal_address_space` probes' writes into a
FOREIGN namespace (`/{fixturePeer}/system/validate/uas/*`) have no covering grant and the whole
category **silently skips** ("connection grants do not cover") — a skip, not a fail, so it's easy
to miss. The seed must carry BOTH forms: `resources: {include: ["*", "/*/*"]}`. The Go
`-open-access` peer covers this internally.

**Keystone side (already fixed):** the Pd peer's `EC_OPEN_GRANTS` seed carries both forms, and
the keystone-owned seed-policy convention (`protocol-generator/shared/seed-policy/README.md`)
already documents the degenerate-open grant as `{handlers:["*"], resources:["*","/*/*"],
operations:["*"]}`.

**The ask (small):** one GUIDE-CONFORMANCE (or SDK-OPERATIONS §2.1) sentence noting that an
open-access seed requires the dual form because §5.5a bare-star is granter-local — plus, if
cheap, an oracle diagnosability nudge: `universal_address_space`'s "connection grants do not
cover" skip could name the missing absolute form, since the current message reads as
environmental rather than a seed-shape defect.

## Disposition

**Not a spec-logic defect** (§5.5a and the content-addressed token model are both correct).
**Not an oracle bug** (the revoke probe is legitimate; it merely exposes the aliasing). A
**guidance gap**: two traps that every future peer implementation walks into unless told, both
invisible to isolated category runs. Keystone carries both as durable cross-language lessons
(AGENTS.md); generated peers are already conformant. Does not block any phase.
