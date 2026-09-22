# spec-data v0.8.2.31 — Snapshot Manifest

**Spec version:** Entity Core Protocol **0.8.2.31**. `ENTITY-CORE-PROTOCOL.md` carries
`**Version**: 0.8.2.31` on line 3, `ENTITY-CBOR-ENCODING.md` carries `**Version**: 1.8`, and
`ENTITY-NATIVE-TYPE-SYSTEM.md` carries `**Version**: 4.3` — **all three read out of this snapshot,
not assumed.**
**Snapshot type:** verbatim copy of the authoritative normative spec files — **no paraphrase,
byte-for-byte** (S2). Each file was hashed from the source blob with
`git show 8958aab:specs/<file> | sha256sum` and compared against the written copy **before**
acceptance; all three matched.

**Supersedes for new work:** `v0.8.2.28/`, `v0.8.2.25/`, `v0.8.2.11/`, `v0.8.2.3/`, `v0.8.2/` and
`v0.8.0/` (all kept in place as point-in-time pins — a snapshot is immutable once stamped and
amendments get a new directory, never an in-place edit).

**`EXTENSION-TREE.md` is NOT vendored, deliberately** — unchanged policy. We pin the three core
normative documents only; its Appendix A stays load-bearing *by reference* for §6.3's `put` error
codes and §2.2a for the resource-optional/BROAD-RESULT declarations §3.3 consumes. Read it in the
sibling; do not copy it here.

## ⭐ VENDORED BEFORE IT IS CONSUMED — second consecutive snapshot in the correct order

`v0.8.2.25`'s manifest recorded a provenance defect: 33 of 46 peers were taken to `0.8.2.25` before
that directory existed, implemented from routed packets rather than from a pin in this tree, and it
named the remedy — *"the correct order is vendor, then implement."* `v0.8.2.28` was the first
snapshot in that order and this is the second. At the moment of stamping, `spec_pin` is `0.8.2.25` on
all 46 roster rows (gated by `tools/spec-pin-gate.py`), so the text the sweep derives from is here
rather than in a packet, and a reviewer can re-run the round.

## ⛔ `v0.8.2.28` IS VENDORED AND WAS NEVER IMPLEMENTED — and that is deliberate, not a gap

`.29` **withdraws text `.28` still carries.** §3.6's `peers:` IdScope value is written path-shaped
(`"/{peer_id}/path"`) through `.28` and is pinned **flat** — a bare Base58 identifier or the bare
wildcard `*`, never a path — at `.29`. A sweep to `.28` would therefore have implemented a shape
already retracted. `v0.8.2.28/` stays in place as a point-in-time pin and the cohort jumps
`0.8.2.25 → 0.8.2.31` in one step.

## ⬜ THE HEADER FOLLOWED THIS TIME — which is why the digest is still the acceptance step

`v0.8.2.28`'s manifest recorded the opposite case: `ENTITY-NATIVE-TYPE-SYSTEM.md` read `4.2.1` on
both sides of a content change (`043fc80d…` → `cb0a63e2…`), which is
`entity-system-conformance`'s **`F79`**. Here the same file moves `4.2.1 → 4.3` **and** its content
moves, so the header is informative. **That is luck, not a property**, and one clean revision does
not retire the rule: `ENTITY-CBOR-ENCODING.md` is `1.8` on both sides here and is **byte-identical**
(`36e83350…` at `.28` and here), so on this vendor the header is consistent in both directions —
which is exactly the state in which a header-keyed vendor works and tells you nothing about the next
one. **Read the digest, not the version string.**

## Provenance

| Field | Value |
|---|---|
| Source repo | `entity-core-protocol` (sibling) |
| Source path | `specs/` |
| Source ref | **`dev`** at `8958aab` |
| Source subject | `0.8.2.31: the floor did not follow, and one row still published the rule 0.8.2.22 corrected` |
| Method | `git show 8958aab:specs/<file>` into the snapshot path; each output hashed and compared against the source blob before acceptance. All three matched. |
| Read at | 2026-09-16 |

As with every snapshot since `v0.8.2.3`, this is vendored from an **unreleased line** — `master` is
still the released `0.8.2`, and the fourth component exists precisely so core text can move without
cutting a release. There is no published artifact to vendor from. The SHA-256 table below is
therefore not merely the preferred anchor, it is the **only** one: `8958aab` is a `dev` commit,
[ADR-0027] authors published commits fresh at the release boundary, and this directory publishes
(`protocol-generator/**` ships undeclared). The commit is an internal build coordinate and is **not**
citable in anything published.

Per the standing rule we do **not** vendor a `v0.8.3/`: the fourth component is an arch-managed
in-flight signal that the operator strips and renames at the release cut.

## Files (the three authoritative normative inputs)

| File | SHA-256 |
|---|---|
| `ENTITY-CORE-PROTOCOL.md` | `f1024e65abe1ab4483b33defb591a7d8466eb9d75757ea27d217c7cd158ff865` |
| `ENTITY-CBOR-ENCODING.md` | `36e83350944d304316fc7f434c85bdd5e0060f00f0ea1bc50d67bd0fa8664d5f` |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | `6272423bb134693d4d09111e5ffdf07372845217c40d5f08c167a60c1b49e4de` |

## What moved since `v0.8.2.28` — measured here, not read off a packet

Three revisions (`0.8.2.29`, `.30`, `.31`). Line deltas against the `v0.8.2.28` snapshot:

| File | added | removed |
|---|---:|---:|
| `ENTITY-CORE-PROTOCOL.md` | 128 | 21 |
| `ENTITY-CBOR-ENCODING.md` | **0** | **0** — byte-identical |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | 6 | 5 |

New `[MUST]`-marked obligations per revision, counted from the diffs: **`.29` = 12, `.30` = 3,
`.31` = 2.** `.29` ties the arc high (`.22` was 12); `.30` and `.31` are the two lowest readings
since `.19`. **Two low revisions are not a trend** — the same count was 1, 1 at `.19` immediately
before a 7 and a 12 — so this is recorded as a measurement and not as evidence the corpus is
settling.

**The arc has two subjects.** `.29` is a **single-normative-home sweep of the identity entity** — the
`system/peer` shape had eight declared homes and the `0.8.2.15` correction reached two of them — plus
the `peers`-dimension canonicalization rules that were never written. `.30` and `.31` are about
**restatements publishing superseded rules positively**: `.30` finds an ordering inferred from a code
pin, `.31` finds §9.1's conformance floor still publishing a discriminator §6.8 corrected eight
revisions earlier.

### The changes a peer could have to act on

Ordered by expected cohort cost. **None of this is a conformance claim about the cohort** — it is a
reading of the diff, recorded so the sweep scopes from the text. What each peer actually does is
`unknown` until an instrument drives it.

- **NEW pseudocode function `resolve_peer_scope` (§5.2; `.29`), two call sites** — `check_permission`
  and `check_grant_covers`. It performs **§1.5 FORM canonicalization of the `peers` dimension** on
  both operands *before* the literal id-scope match, and the dispositions of an unresolvable value
  are **asymmetric by position**: an unresolvable `include` entry is **dropped** (the grant is
  narrower than authored — authority withheld), an unresolvable `exclude` entry **refuses the whole
  grant** (returning null so the caller skips it). Both fail closed. The defect it closes is a
  **fail-open**: a received non-canonical `peers.exclude` had no verifier rule, so the literal
  matcher silently failed to match it and *the excluded peer was not excluded*.
  ⚠ **`.29` also states, at `[MUST]` level, that conflating this with §5.4 PATH canonicalization is
  itself the defect** — *"neither is a reading of the other."* Skipping the form canonicalization
  because the grammar forbids the path canonicalization gives the `exclude` fail-open; applying the
  path canonicalization because the form one was required gives the F40 over-grant.
- **§9.1's authority-selection floor row was WRONG and is corrected (`.31`).** The row published
  *"selected by WHO NAMED THE PATH … handler-derived → the executing handler's own grant"* for
  **eight revisions**, which is the discriminator §6.8 **corrected at `0.8.2.22`**. The rule is
  *whether the access serves a live caller's request*: in service of the caller's request — a path
  the caller named **or one the handler derived within that request** (a listing entry, an extract or
  snapshot binding, a merge expansion, a subscription payload) — requires **the caller's verified
  capability AND the executing handler's own grant, and BOTH MUST pass**. A peer built to the old row
  flattens that intersection, which makes the §6.3 listing filter vacuous and lets a narrow caller
  merge anywhere the tree handler can reach. **A peer swept to `.25` may have been swept to the
  wrong row** — this is the item to drive first.
- **§6.2/§6.5/§6.7: `501` is reachable only after `check_permission` (`.30`)** — a request that is
  both unauthorized and unimplemented answers **`403`**, never `501`. Stated as a
  **confidentiality property**: the reverse order makes the response a two-valued oracle over a
  handler's manifest for a caller holding any grant on that path, which is the operation-existence
  leak §6.7 names and refutes **on the strength of this ordering and nothing else**. The §9.1 floor
  row adds a constraint on the *check set*: this row MUST be driven with a grant that **covers** the
  probed operation, or it measures the ordering instead of the row.
- **§4.11: where the close is a CHOICE, it is bounded (`.29`)** — a peer **MUST NOT** close while
  **any admitted request is in flight** on that connection (§4.9(c) owes each a response; §4.10
  forbids degrading service to them). This binds every whole-decoded member of the pre-admission
  class identically — forbidden tag, root-hash failure, mis-keyed `included` — because the property
  that makes continuation possible is the same in each: the length prefix completed, so the stream is
  synchronized. *"Continuing is therefore the only disposition that is conformant on every
  connection."*
- **Tag policy is ANY NESTING DEPTH and tag 55799 is a member (`.29`)** — *"in a data-field
  position"* is `ENTITY-CBOR-ENCODING` §6.3's shorthand; the scope is **any** major-type-6 item
  anywhere within a `data` field at any depth, including inside the `data` of any `included` entity,
  and **including tag 55799** (permitted as a file-format marker, forbidden on the wire). §6.3 is the
  sole authority and no restatement may narrow it. This is `tools/pa-probe`'s `D5` arm, already on
  the owed list, now normative.
- **§4.6 step 3 tests the BINDING, not the FORM (`.29`)** — a `peer_id` in a non-canonical but
  well-formed wire form that decodes to the presented `public_key` binds correctly and **MUST NOT**
  be refused `401 identity_mismatch`; that code is reserved for a peer-id resolving to *different*
  key material. A deployment refusing the non-canonical form refuses it **as a form**: `400
  unsupported_key_type` where the form is unimplemented, otherwise **`400 invalid_request`**, and
  **`401 identity_mismatch` is NOT conformant** on that input. ⭐ **Strictness is explicitly NOT a
  conformance surface** — a check set MUST NOT assert that a peer accepts a non-canonical form and
  MUST NOT assert that it refuses one, and MUST accept either outcome. What IS drivable is the
  canonicalize-on-acceptance obligation where a peer accepts.
- **§3.6: a `peers:` IdScope value is FLAT (`.29`)** — a bare Base58 peer-id or the bare wildcard
  `*`, **never a path**, at `[MUST]`. A path-shaped `peers:` pattern matches no bare peer-id value at
  all, silently, so an `include` written that way grants nothing and an `exclude` written that way
  excludes nobody. Rule 4 is new: **on a RECEIVED pattern, canonicalize at COMPARISON** — a wire
  capability is signed, so its bytes cannot be rewritten and the mint-side rules do not reach it.
  Rule 3 is narrowed: the MUST-accept-the-mint obligation now binds only an implementation that has
  *chosen* to accept, because as written it contradicted §1.5's stricter-local-policy carve-out at
  MUST level and made every strict deployment non-conformant.
- **`peer_id` is NOT a field on `system/peer` (`.29`, `[MUST]`)** — in the type declaration (§10.1),
  its Appendix B twin, and three prose sites in the core document, all of which kept the pre-v7.65
  three-field shape after `0.8.2.15` corrected §4.5a item 1a and §4.6's pseudocode and swept no
  further. **We already implement this** — `tools/put-probe` found and fixed it 2026-09-07 — so
  upstream is catching up to the cohort. Expect zero cost; **verify rather than assume.** The §6.4
  note that the entity content is `{peer_id}` is also withdrawn (a *third* declared shape, and the
  one no section ever specified).
- **§4.2's `ping` is an EXAMPLE and is NOT a core operation (`.30`, `[MUST]`)** — this document
  defines no `ping`: no params type, no result type, no manifest entry, no §9 floor row.
  `EXTENSION-NETWORK` is its owner and only definition, so the pre-authorized-connect sentence is
  **conditional on implementing it** and a core-profile peer that omits it is conformant. A peer that
  does not implement it answers **`501 unsupported_operation`**, and **`400 invalid_request` is NOT
  conformant for this input.** ⚠ *See the open question below — this interacts with §4.7's unknown-
  connect-operation row, which gives `400`.*
- **§4.7's half-open `ping` is `409`, and its stated premise was wrong (`.30`)** — the outcome is
  unchanged; what changed is *why*. The pre-authorized-connect exception **does** apply on a half-open
  connection and decides a different question: it exempts the path from carrying `author` and
  `capability` in **any** connection state, and says nothing about which operations are legal in which
  state. *"Being pre-authorized is not being in-order."* The old premise re-introduced the state
  qualifier `0.8.2.6` removed.
- **§9.1 rows now NAME their normative home (`.31`, `[MUST]`)** and four `.23` rules gain rows they
  never had: resolution integrity on any entity used for an authority decision (§1.8 item 1);
  `included` keying normative in **both** directions, with the **sender** half separately drivable;
  the three resolution-integrity dispositions (§5.2a); and the handler frame — `handler_pattern` names
  the handler that **owns** the operation, is **REQUIRED**, and an absent/null/empty value **MUST NOT**
  be read as *match all handlers*. These are restatements of rules the cohort has at `.25`; they are
  listed because a floor row is what an implementer builds from.

### ⚠ One open question, stated as a question because the section read is not done

`.30` says an unimplemented `ping` is **`501`** and that `400 invalid_request` is non-conformant for
that input. §4.7's row and §3.3's *"an unknown operation is 400"* give an unknown connect operation
**`400`**. The discriminator `.30` supplies is that `ping` is **defined by an extension** and
therefore *implemented-or-not* rather than *unknown* — but a **core** peer has no way to enumerate
what `EXTENSION-NETWORK` defines, so the general rule is not decidable from a core peer's own
knowledge. The narrow case is implementable by naming `ping` explicitly, which is what the text
does. Read §4.7, §3.3 and §6.2 together before treating this as either a finding or a non-issue.

## Consumption state

**Not yet consumed at the moment of stamping. `spec_pin` is `0.8.2.25` on all 46 peers and the gate
agrees with the matrix.** When a sweep lands these revisions it moves that column, and
`tools/spec-pin-gate.py --since <ref>` is the reconciliation that says every peer it claims was
touched actually was.

**The oracle re-pin is deliberately NOT landed with this vendor**, unchanged policy: the spec
snapshot is what peers are **written against**, the oracle pin is what they are **measured against**,
and nothing requires the two to move together. The pin remains `78db4a9` (executed set
`7aa6f3de…`, 778 checks).
