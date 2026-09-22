# Authority and scope — keystone memory

The section-5 scope algebra, granter frames, capability minting and temporal fields, the scope matchers, and the PD-2 gate.

**Arrive here when:** a request is refused with 403 and should not be, a delegated capability is honoured and should not be, or a mint produces the wrong expiry.

Durable findings, not status — each entry names what happens, the mechanism behind it, and
the enforcement point. Moved verbatim out of `AGENTS.md`; the dated session diaries live in
`research/stewardship/` and `docs/status/`. See [`INDEX.md`](INDEX.md) for the other files.

## Entries

- A LANGUAGE'S "absent" AND "present but wrong type" COLLAPSE IN THE OBVIOUS ACCESSOR — and on a temporal field that is a fail-OPEN
- §5.5a's per-link granter frames scope the RESOURCE dimension ONLY — applying them to handlers/operations/peers is invisible until a DELEGATED cap arrives
- A WRONG DENIAL CAN STAND IN FOR A MISSING CHECK, AND FIXING THE DENIAL IS THE ONLY THING THAT EXPOSES IT — so a fix that makes a peer's FAIL COUNT GO UP is a finding, not a regression
- OVER-CANONICALIZING AN ID-SCOPE DIMENSION FAILS IN BOTH DIRECTIONS AT ONCE — it overgrants AND over-denies, and one of the two is what a reviewer is not looking for
- A `created_at` THAT IS A COMPILE-TIME CONSTANT IS A-PD-016 WITH THE CLOCK REMOVED ALTOGETHER
- A PARTIAL IMPLEMENTATION OF A NEW RULE IS WORSE THAN ITS ABSENCE — it produces a plausible value and reads as done
- THE "ABSENT" SPELLING IS A PER-PEER DECISION AND MUST BE READ FROM THE PEER — an accessor whose "something" conflates absent with present is the CAP-6a defect one level up
- RATIFIED, AND IT IS THE SHARPEST FORM YET OF "A WRONG DENIAL CAN STAND IN FOR A MISSING CHECK": A PARAM-VALIDATION `400` WAS ANSWERING TWO SECURITY CHECKS, AND THE HANDOFF THAT SCOPED THE ARC CALLED ALL FOUR FAILURES "ONE CAUSE"
- A GATE'S SUBJECT IS NOT ITS OWNER — §1.4's PD-2 Dimension 1 IS THE TARGET URI'S PEER-RELATIVE PATH, AND THE EXECUTING HANDLER'S OWN PATTERN IS THE PLAUSIBLE WRONG VALUE
- A MATCHER THAT IS ALSO A PROOF SURFACE TAKES A WRAPPER, NOT A NEW CLAUSE; AND A PEER WITH NO CANONICAL STRING TAKES A PREDICATE, NOT A SENTINEL
- RATIFIED, SECOND AND THIRD OCCURRENCE AND A NEW SHAPE — A PREDICATE WRITTEN FOR ONE SPELLING OF AN ADDRESS IS NOT REUSABLE BY A CALLER WITH ANOTHER, AND ON AN AUTHORIZATION DIMENSION IT DENIES EVERY CALLER-SUPPLIED GRANT WHILE THE SHIPPED CONFIGURATION HIDES IT
- A DEFAULT IS A VALUE, NOT AN ABSENCE — a subset or attenuation check that reads an omitted dimension as "covers nothing" refuses the shape every SDK writes
- A THROW OUT OF A MATCHER IS A CONTROL-FLOW ANSWER TO A QUESTION THAT HAS A VALUE ANSWER, AND IT SURFACES AS `500 internal_error`
- ONE NARROWING SEAM, READ BY BOTH SIDES — a dispatch check and a handler that each derive the subject independently are a gap §6.3 cannot close
- A HANDLER PREDICATE MUST ACCEPT EVERY §1.4 SPELLING OF THE PATH, AND THE ONE THE ORACLE USES IS THE BARE PEER-RELATIVE FORM
- Content-addressed mint timestamps: ms precision is CORRECTNESS, not formatting

---

- **A LANGUAGE'S "absent" AND "present but wrong type" COLLAPSE IN THE OBVIOUS ACCESSOR — and on a
  temporal field that is a fail-OPEN.** The CAP-6a mechanism, found identically in go
  (`Entity.Uint` → `(0,false)`), ocaml (`Model.uint_field` → `None`), haskell (`uintField` →
  `Nothing`), lean (`uintField` → `none`) and swift (`uintAt` → `nil`). Every one of these answers
  the same thing for a missing field and for `expires_at: -1`, so `if let ex = uintField(...)`
  silently **skips** the expiry check and honors a capability with a negative or bignum expiry —
  status 200. §6.2 CAP-6a names this exactly: a verifier "MUST NOT treat the unrepresentable field
  as absent." **The fix must run BEFORE the range check it protects**, because the range check is
  the thing the ambiguity defeats. Five languages, five different type systems, one bug — treat any
  `optional-typed` accessor over wire data as answering "unusable", never "absent", wherever the
  distinction is security-relevant.
  **RATIFIED and BROADENED 2026-08-22 across all 8 M2 peers — the fail-open has TWO mechanisms, and
  the second one does not involve a null at all.** The entry above describes only the first. Both
  were found in the same session, six peers, and the grep that catches one misses the other:
  - **Null-collapse** (rust `uint_field`→`None`, python `is_integer(v) and v >= 0`→`None`, elixir's
    guard→`nil`, plus the five M1 peers): the accessor answers the same "nothing" for absent and for
    present-but-negative, so the check **is skipped**.
  - **Arithmetic fail-open** (java/kotlin `Cbor.uint`→the `BigInteger` of ANY int, common-lisp
    `entity-uint`→`(when (integerp v) v)`): the accessor happily returns a NEGATIVE value, so the
    check **is not skipped — it runs and returns the wrong answer.** For a negative `not_before`,
    `now < not_before` is simply false, so the capability passes. No null, no `Option`, no skip; a
    reviewer grepping for "optional accessor over a temporal field" finds nothing here.
  **The rule is the same for both and it is the ordering, not the null-handling:** a representability
  check (`absent → legal · present-and-uint64 → legal · anything else → MALFORMED`) must run **before**
  the range comparison, because the range comparison is what the ambiguity defeats *in either shape*.
  **Enforcement, and it must be two greps, not one:** (a) any optional-typed accessor reaching a
  temporal field, and (b) any comparison against a temporal field whose accessor cannot itself reject
  a negative. **On a bignum substrate the `>2^64` half is a DELIBERATE range check, not an overflow
  trap** — python/elixir/CL/java/kotlin integers do not wrap, so a peer that "just does the
  arithmetic" never fires §5.6 rule 3 and silently saturates instead of dropping the term.
  **A THIRD SHAPE, and the greps above BOTH clear the peer that has it: the mechanism can be right
  and the FIELD LIST short.** `pd` (2026-08-28) had carried the correct three-way accessor since it
  was written — `entity_data_uint` returns 0 for absent, 1 for a uint64, **-1 for
  present-but-not-major-0** — and `authz_check_validity` already refused on the -1. It simply never
  ASKED about `created_at`: the guard covered `expires_at` and `not_before` only, the oracle probes
  all three, and the peer honored a capability whose `created_at` was negative. **CAP-6a is THREE
  fields. Grep the field list, not only the accessor** — an audit shaped around optional-typed
  accessors clears `pd` completely.
  **Fixed-width substrates need NO range test and writing one is dead code** — `unison`'s `Nat` and
  `forth`'s 8-byte TV argument make a present uint64 representable by construction, and a bignum can
  only arrive as a major-type-6 tag, rejected at decode. `forth` needs the opposite move instead:
  its `ent-uint` applies the TV's SIGN byte and hands back a negative cell, so the guard reads the
  tagged value directly because **the sign byte is exactly the bit the accessor discards**.

- **§5.5a's per-link granter frames scope the RESOURCE dimension ONLY — applying them to
  handlers/operations/peers is invisible until a DELEGATED cap arrives.** Found on swift 2026-08-21
  (candidate — one peer, but the enforcement point is exact and go/ocaml both carry the correct form
  with a comment). swift passed `childFrame`/`parentFrame` to all four dimensions of `grantSubset`
  and defaulted the `peers` scope to them too. That is **identical to correct behaviour whenever
  child and parent share a granter** — every self-issued path — which is why 745 of 755 checks
  passed. It breaks for exactly one case: a cap whose granter is the *caller*, where a parent
  handler scope of `["*"]` canonicalizes to `/<thisPeer>/*` while the child's canonicalizes to
  `/<callerPeer>/…`, so a **universal parent grant cannot cover any child grant** and every request
  presenting a delegated cap returns 403. Same trap on the §6.2 **mint-time** subset check, which
  must stay on the local frame on BOTH sides (go and ocaml say so in a comment; swift did not).
  **This is A-PD-017's "bare-star is granter-local, never universal" reached from the frame side
  rather than the seed side** — the two are the same defect wearing different clothes. **Enforcement:
  `grep -n 'scopeSubset\|grantSubset' <peer>` and check that only the RESOURCES call receives the
  granter frames.** Symptom to recognize: several unrelated-looking capability checks failing at
  once with 403 while everything self-issued passes.
  **RATIFIED 2026-08-28 — second occurrence (`sql`), and the enforcement grep is now cheap enough
  that it was run across the whole remaining cohort in one pass (clean: only swift and sql ever had
  it).** `sql`'s `sc` CTE canonicalized `dim IN ('handlers','resources')` against the granter frame,
  which is the same defect reached from `check_permission` rather than from `grantSubset`. Identical
  invisibility: 753 of 755 checks passed, because child and parent share a granter on every
  self-issued path.
  **AND THE CORRECT FRAME IS DIFFERENT ON DIFFERENT SURFACES — get this backwards and you fail in
  the OPPOSITE direction, which is why the one-line grep is not the whole rule.** Measured on `sql`
  and `datalog` the same day:
  - **Dispatch-time resource match** and **chain attenuation** (§5.5a surfaces 1 and 2) take the
    PER-LINK GRANTER frame. `datalog`'s `is_attenuated` passed `local` as BOTH frames, so a
    foreign-granted bare `*` canonicalized to the VERIFIER's `/{local}/*` and falsely covered a leaf
    naming the verifier's namespace — §5.5a names this exact failure ("canon-against-wrong-frame")
    and pins three vectors at it.
  - **The §6.2 MINT-TIME subset takes LOCAL on BOTH sides**, because that mint is self-issued and
    the granter is this peer on both. `sql`'s first cut read the parent side through the
    granter-framed CTE and **denied the CAP-5 probe outright**: the presented cap's
    `resources: ["*"]` canonicalized to `/{caller}/*` while the identical requested pattern
    canonicalized to `/{local}/*`.
  So the failure modes are mirror images — over-applying the frame REFUSES legitimate delegated
  caps, under-applying it ADMITS illegitimate ones — and a peer can have one without the other.
  Check both call sites, not just the one the grep lands on first.
  **THIRD SURFACE, and it is the one a fix to the other two makes VISIBLE rather than breaks**
  (`wasm-wat`, 2026-08-29). §5.5a names three surfaces; the two above are chain attenuation and
  the §6.2 mint. The third is the **dispatch boundary** — `verify_request` matching a presented
  cap's resource patterns against the incoming target path — and there the two sides take
  *different* frames: the cap's patterns frame against **its granter**, the request target
  against the **local peer**. Frame both against the local peer and a foreign-granted bare `*`
  becomes `/{verifier}/*` and authorizes the verifier's own namespace.
  **What makes it worth its own entry is how it surfaced.** `captok_form_dispatch_minted_pl_
  presented_xpeer` was *passing* while the peer refused every foreign-granted cap outright — a
  vacuous pass. Implementing the chain walk made it a real FAIL, because the cap now reached
  dispatch and dispatch had no frame. **A fix to one surface converts the next surface's vacuous
  pass into a true failure**, which reads as "my change broke it" and is the opposite. Enforcement:
  after landing §5.5a on any surface, re-run and expect the OTHER surfaces' foreign-granter vectors
  to move; a fully green run right after the first surface lands means the others were never
  exercised.
  **And a K-of-N root has NO granter frame — the local peer is the correct one, not a fallback.**
  §3.6's M6 already requires the local peer to be in the signer set and to have signed, and §5.5
  says a quorum cap's *"subsequent use is locally rooted"*. Deriving the frame from `granter`
  unconditionally simply fails on a quorum root (there is no single hash to derive from), which
  presents as "multisig is broken" and is a §5.5a bug.
  **Sub-lesson from the same peer, cheap and general: in a path-pattern matcher, test the parent's
  TRAILING `*` before testing whether the child path is exhausted.** `/{peer}/*` must cover
  `/{peer}/` — listing a namespace's own root is inside that namespace, not above it. Getting the
  order wrong refuses every root listing while every deeper path still works, so it looks like a
  permissions problem rather than a matcher problem. Two `tree_operations`/`universal_address_space`
  listing checks caught it; nothing else did.

- **A WRONG DENIAL CAN STAND IN FOR A MISSING CHECK, AND FIXING THE DENIAL IS THE ONLY THING THAT
  EXPOSES IT — so a fix that makes a peer's FAIL COUNT GO UP is a finding, not a regression.**
  Ratified 2026-08-28: two occurrences the same session, both in the peers that author the authority
  interior in a query language, which is exactly where a *specific* wrong refusal is most likely to
  land on a *specific* accept-path vector.
  - `sql`: the handlers over-scoping above denied every delegated cap. That denial was answering
    **three security vectors** (`authz_attenuation_foreign_granter_{1,deep,wildcard_leaf}`) and
    **two authz vectors** (`request_rejects_scope_widening`, `authz_scope_exceeds_1`). Correcting
    the frame took it 2F → **7F**, and the five new FAILs were the truth: the ladder had **no chain
    attenuation rung at all** and the handler passed requested grants through **verbatim with no
    §6.2 mint-bound check anywhere in the peer**. Both are now authored rungs; 0F.
  - `datalog`: `strip_peer` never handled the `entity://` form (no leading slash after the scheme),
    so the handlers dimension could not match any CONCRETE scope and delegated requests were denied
    one rung early. Fixing it exposed the same missing §5.5a frame isolation.
  **This is the INVERSE of "conformance-green can be vacuous", and the two are worth holding
  together.** That rule is about a rejection-only category passing a fail-closed peer — nothing is
  being asked. This one is about a peer answering the right question with the wrong mechanism: the
  vector *is* exercised, the verdict *is* correct, and the reason is unrelated to what the vector
  tests. Only a change that removes the wrong reason can tell them apart.
  **Enforcement, and it is a rule about the number rather than about the code: when a fix raises a
  peer's FAIL count, DO NOT revert to protect the row.** Read each new FAIL; if it names a check the
  peer never implemented, the peer was never passing it. Reverting restores a lower number and a
  worse peer, which is the overclaim this repo exists not to make.
  **THIRD AND FOURTH OCCURRENCE, 2026-08-29, and the scale is different: the missing feature can be
  a WHOLE SPEC SECTION, and a category with no accept-direction vector will never say so.** All four
  hand-authored peers — `asm-x86_64` `asm-arm64` `riscv64` `wasm-wat` — implement **no §5.5
  delegation chain at all**. Each requires a presented capability's `granter` to be the local peer
  and refuses everything else. `asm`'s own source states the trade: *"until the delegation-chain walk
  exists, fail closed: granter ≠ our identity_hash → 403. (Closes forged_root_capability and the
  chain-\* reject probes, which all require denial.)"* — **the author knew it was a stand-in and
  wrote down what it closed; nobody re-read that comment as a list of vectors passing for the wrong
  reason.** Roughly ten `security` chain vectors are in that state (`chain_no_delegation_denied`,
  `chain_max_delegation_ttl_denied`, `chain_per_link_temporal_denied`, `chain_mid_link_expiry_denied`,
  `chain_parent_exclude_drop_denied`, all three `authz_attenuation_foreign_granter_*`, …) — every one
  reject-direction, every one answered correctly by a peer that refuses all chains.
  **Two things generalize, and the second is the sharper one:**
  (a) **Suspect the hand-authored substrates specifically.** It is not chance that these four have it:
  chain walking is the most laborious part of §5.5 to write by hand, so it is the part that gets
  deferred, in assembly and in WAT alike. When a cohort defect is about *effort*, its distribution
  follows authoring cost, not language family — look at how the peer was written before assuming a
  substrate limit.
  (b) **A deferral comment is a conformance claim with no gate on it.** `until X exists, fail closed`
  is honest engineering and completely invisible to every number this repo publishes. **Enforcement:
  `grep -rniE 'until .* exists|deferred|not implemented|fail closed for now' protocol-generator/*/src/`
  and, for each hit, ask which vectors that branch is currently answering.** A peer at 2F with a
  comment like that is not a peer with two problems.
  **And the symptom that led here is worth carrying on its own: CAP-5/CAP-6 failing with `403` does
  NOT mean the §5.6 ceiling is missing.** Both checks present a *delegated* capability, so on a peer
  with no chain support they are refused two gates before the mint is reached, and the failure names
  a feature that is not the one broken. Trace the refusal to its gate before implementing what the
  check is named after — on `wasm-wat` that was one instrumented build and it invalidated a
  documented scope estimate ("an arity + data-segment edit … neither is hard").
  **FIFTH OCCURRENCE, 2026-08-30, and it is the other polarity: a wrong denial can hide a missing
  ANSWER, not only a missing check.** Landing the §5.5 chain walk on `asm-x86_64` let a `request`
  reach code that had been unreachable for as long as the capability gate refused every delegated
  cap two stages earlier — and four early-outs there (`author` / `params` / `params.data` /
  `params.data.grants` absent) fell off the end of the function answering NOTHING. Same shape on
  all three ISA peers and on `cobol`. **Add §4.9(c) to the list of things a blanket refusal can be
  concealing:** when a denial is removed, the newly-reachable code is untested by construction, and
  the first thing to check is not whether it decides correctly but whether it *replies at all*.

- **OVER-CANONICALIZING AN ID-SCOPE DIMENSION FAILS IN BOTH DIRECTIONS AT ONCE — it overgrants AND
  over-denies, and one of the two is what a reviewer is not looking for.** RATIFIED 2026-08-30
  (`cobol`; the swift/sql §5.5a frame over-scoping reached from the F40 side, which makes it the
  same defect in a third dress). `cap-scope-match` canonicalized BOTH the value and the patterns
  against the local peer for handlers, operations and peers. §5.2/F40 makes those three ID-scope:
  matched literally, no frame. Measured simultaneously: an operations include of `/{local}/get`
  AUTHORIZED the bare operation `get` (`f40_id_scope_include_no_overgrant`), and an exclude of
  `/*/get` DENIED it (`f40_id_scope_exclude_literal`). Canonicalization turns a non-matching literal
  into a match, and "a match" is a grant on the include side and a refusal on the exclude side.
  **And fixing the matcher immediately exposed that the VALUE was wrong too** — the handlers
  dimension was being compared as the ABSOLUTE resolved path `/{peer}/system/capability` against
  grants that name handlers relatively, which only ever worked because the matcher canonicalized
  both sides. Removing the canonicalization took CAP-5/CAP-6 to 403; passing the bare handler id
  fixed both. **Two defects held each other up, and neither is visible while both are present.**
  Enforcement: for each scope dimension, ask what KIND of thing the value is. An id is compared
  literally; only a path takes §5.5a. If a matcher takes a frame parameter it must be reachable only
  from the resources dimension — a frame argument on an id-scope call site is the defect.

- **A `created_at` THAT IS A COMPILE-TIME CONSTANT IS A-PD-016 WITH THE CLOCK REMOVED ALTOGETHER.**
  Candidate (`cobol` 2026-08-30, first occurrence, but it is the standing content-addressed-aliasing
  rule at its limit). `mint-token` declared `01 created pic 9(18) comp-5 value 1700000000000.` and
  never assigned it, so every mint with the same grants and grantee hashed identically forever — and
  it silently makes any §5.6 ceiling meaningless, since the expiry would be derived from an instant
  in 2023. Enforcement: grep the mint path for a `created_at` that is not read from the clock, and
  sample that clock ONCE in the caller so the emitted birth instant and the expiry derived from it
  are the same value (the nim lesson, from the other end).

- **A PARTIAL IMPLEMENTATION OF A NEW RULE IS WORSE THAN ITS ABSENCE — it produces a plausible value
  and reads as done.** Candidate (first occurrence, `nim` 2026-08-28, but the enforcement point is
  exact). `nim` was the only peer in the cohort that ALREADY had a §5.6 ceiling, and it was wrong
  three independent ways: (a) it carried only the request's `ttl_ms` term and never the caller
  capability's absolute expiry, so an over-long ttl minted a token that **outlived the capability
  authorizing it** — measured `expires_at 2102711331804` against a caller cap of `1787354931804`,
  ten years past its own authority; (b) it sampled `nowMs()` in the handler and AGAIN inside
  `mintTokenRaw` for `created_at`, so the emitted `created_at` and the expiry computed from it were
  two different instants; (c) `nowMs() + ttl` **wraps** on uint64, so an overflowing ttl minted an
  EARLIER expiry rather than dropping the term. Every one of those still emits an `expires_at` and
  still returns 200.
  **The general trap is in the oracle's own CAP-5 message and is worth quoting: *"a `<= caller_exp`
  check would pass this; CAP-5 requires the exact clamped value"*.** MIN_DEFINED is a value reached
  by CONSTRUCTION, not a bound verified by COMPARISON — any implementation that reaches it by
  comparison satisfies a weaker test than the one the oracle runs. **Enforcement: for a rule
  expressed as an exact computed value, grep the peer for a comparison against that value and treat
  a hit as unimplemented.**

- **THE "ABSENT" SPELLING IS A PER-PEER DECISION AND MUST BE READ FROM THE PEER — an accessor whose
  "something" conflates absent with present is the CAP-6a defect one level up.** Candidate
  (`smalltalk` 2026-08-28). The CAP-6a guard, written the obvious way as
  `v := aCap field: k. v ifNotNil: [ ... ]`, **denied every capability the peer had ever been shown**:
  176 FAILs, handshake still green, every authenticated request 403. `EcEntity>>field:` answers
  `EcAbsent default` for a missing key, **never nil** — the pure-object absent sentinel this peer
  uses throughout (A-ST-000) — so `ifNotNil:` is always true and every absent temporal field read as
  present-but-unrepresentable.
  CAP-6a is about an accessor whose *nothing* conflates ABSENT with MALFORMED. This is an accessor
  whose *something* conflates ABSENT with PRESENT. Same shape, opposite polarity, same discipline:
  **presence comes from the peer's own presence predicate** (`hasField:`, `hasKey`, `map_find != -1`),
  never from the language's null. **Two things made it slow to find, both worth knowing for the next
  live-image peer:** `make image` pipes the Pharo load through `grep -vi 'undeclared\|warning'`, so a
  compile diagnostic in a new method is suppressed by construction and the build still says `built`;
  and the failure presents as a mass 403 with a clean handshake, which reads like an authz regression.
  **Probing the predicate directly in the image answered it in one send** (`EcCapAuthz
  temporalFieldsRepresentable:` on an empty-data entity → `false`, expected `true`) where bisecting
  the conformance run would have taken an hour.

- **RATIFIED, AND IT IS THE SHARPEST FORM YET OF "A WRONG DENIAL CAN STAND IN FOR A MISSING CHECK":
  A PARAM-VALIDATION `400` WAS ANSWERING TWO SECURITY CHECKS, AND THE HANDOFF THAT SCOPED THE ARC
  CALLED ALL FOUR FAILURES "ONE CAUSE".** 2026-09-16, `go` vanguard to `0.8.2.31`. Four candidate-oracle
  FAILs; the handoff attributed them to the singular→plural carrier rename and said *"all four are one
  cause."* That was right about the **symptom** and wrong about the **cause**: the `400 invalid_params`
  refused the probe before any authority code ran, so it was answering two checks for reasons unrelated
  to what they test. The rename alone took it **4F → 2F**, and the two survivors were real:
  - **F63** `dispatch_outbound_narrow_grant_refuses_out_of_scope` — an out-of-scope sub-dispatch
    **SUCCEEDED** while presenting a target-minted credential: the credential was treated as a
    **standalone authorizer**, steering the handler past its own grant. That is §6.8's confused-deputy
    substitution, and §6.8 says outright that the defect is **wire-invisible** — *"both readings produce
    a well-formed response and differ only in which authority was consulted"* — so the only thing that
    can see it is a check whose handler grant is **narrow**, which is why the guide made narrowness a
    scaffold-contract requirement.
  - **E3/F66** `dispatch_outbound_multisig_root_refused` — a **K-of-2 multi-sig-rooted credential
    relaxed Dimension 4** and the sub-dispatch succeeded. §1.4: *minted by the target* means the target
    **solely** minted it; a quorum is a **group's** authority, so a multi-signature root **never**
    relaxes Dimension 4. Over-acceptance.
  **Enforcement, and it is a rule about SCOPING rather than about code: when several checks fail with
  the SAME early refusal, the count of causes is UNKNOWN until that refusal is removed.** A shared
  status is evidence of a shared *gate*, never of a shared *defect* — and a handoff that sizes the work
  from it will under-scope in the direction that reads as cheap.
  *(Three defects in the fix were found by INSTRUMENTING and by nothing else, and each produced a
  403 that is indistinguishable at the wire from an authority verdict: `ctx.pattern` arrives ABSOLUTE
  from §6.6's walk while the grant path wants it peer-relative, so the lookup missed; `target` arrives
  as the SCHEMED ABSOLUTE form, so the handler-pattern dimension matched nothing — which is exactly why
  §1.4 spells out *"the target uri's PEER-RELATIVE path"*, and the strip MUST NOT be unconditional or it
  is the `smalltalk`/`forth` defect; and the granters and signatures arrive **nested in params**, not in
  the envelope's `included`, so a verifier handed `ctx.included` alone cannot resolve one link. A source
  read clears the peer on all three. One trace print answered all of them.)*
  *(And the unit control was UNFAITHFUL TO THE WIRE in the way that matters: it fed the peer-relative
  form the handler produces rather than the schemed form the validator sends, so it passed while the
  wire refused. **A control that constructs its own input shape is testing the shape you believed.**)*

- **A GATE'S SUBJECT IS NOT ITS OWNER — §1.4's PD-2 Dimension 1 IS THE TARGET URI'S PEER-RELATIVE
  PATH, AND THE EXECUTING HANDLER'S OWN PATTERN IS THE PLAUSIBLE WRONG VALUE.** Candidate
  (2026-09-17, `ada`; enforcement exact). The gate reads the *executing* handler's grant (§6.8), so
  the pattern to hand it reads like the executing handler's — and it is the handler the sub-dispatch
  is ABOUT TO REACH, which is what that grant names. Measured as **2 of 778 FAILing**
  (`dispatch_outbound_reentry`, `t1_2_concurrent_reentry`), refusing the oracle's legitimate reentry
  with a **403 indistinguishable at the wire from an authority verdict**.
  **ONE TRACE PRINT SETTLED IT AND NO AMOUNT OF READING WOULD HAVE, because every obvious input was
  right:** grant found, target peer foreign, credential present, and the relaxation *verified*. So
  the refusal was in Dimensions 1–3 — the opposite end from where a 403 on a credential-bearing
  request sends you. **Print the four dimensions SEPARATELY** (`h=FALSE o=TRUE r=TRUE p4=FALSE
  relaxes=TRUE relax_match=TRUE`) rather than the verdict: a conjunction's value names none of its
  terms, and this is A1 pointed at a predicate instead of at a value.
  **AND THE UNIT GATE HAD IT RIGHT WHILE THE CALL SITE DID NOT.** The standing rule is that a control
  constructing its own input shape tests the shape you believed; here the CONTROL was faithful to
  §1.4 and the CALLER was not, so the two disagreed and only the wire could say which. **Read that as
  the argument for driving both, never as a point for the unit test** — a unit gate written from the
  spec and a call site written from the surrounding code are two independent transcriptions, and the
  value of having both is exactly that they can disagree.

- **A MATCHER THAT IS ALSO A PROOF SURFACE TAKES A WRAPPER, NOT A NEW CLAUSE; AND A PEER WITH NO
  CANONICAL STRING TAKES A PREDICATE, NOT A SENTINEL.** Candidate (2026-09-14, from landing one rule
  in 45 languages — the value is in the two peers where the uniform transcription would have been
  wrong). `lean`'s `matchesSeg` is not only the running matcher, it is the **T5a proof surface**: a
  transitivity theorem plus five `rfl`-level arm-characterization lemmas depend on its exact clause
  order, so adding a first arm would re-derive all six to prove a property that is not about pattern
  matching. The guard went in `matchesSegNM` and `lake build EntityCoreProofs` still completes on
  `propext`/`Classical.choice`/`Quot.sound` alone — **which is the check that says the decision was
  right rather than merely cautious.** `pd` never materializes a canonical ABSOLUTE form for local
  grants (its matchers work peer-relatively), so there is no string for a sentinel to ride on; what
  the sentinel EXISTS FOR is two observable properties — *an unresolvable form never matches, in
  either operand* and *such a form in an EXCLUDE denies* — and both are implementable directly as a
  predicate on the pattern. **Rule: transcribe the PROPERTY, and let the representation be the
  peer's. Writing a literal `/never-match` into a peer with no canonical form to put it in is cargo,
  not conformance** — and say which you did, at the site, because the next reader will otherwise
  file the deviation as an omission.

- **RATIFIED, SECOND AND THIRD OCCURRENCE AND A NEW SHAPE — A PREDICATE WRITTEN FOR ONE SPELLING OF
  AN ADDRESS IS NOT REUSABLE BY A CALLER WITH ANOTHER, AND ON AN AUTHORIZATION DIMENSION IT DENIES
  EVERY CALLER-SUPPLIED GRANT WHILE THE SHIPPED CONFIGURATION HIDES IT.** The first occurrence was
  `asm-x86_64`'s `derive_handler` reused for §4.7 row 10 (recorded above, a ROUTING miss that
  answered 501). 2026-09-15 found it twice more, on `smalltalk` and `forth`, INDEPENDENTLY, with
  the same cause and a far worse blast radius: `execHandlerPath:` / `exec-handler-path` dropped the
  leading URI segment UNCONDITIONALLY, on the assumption that a URI always begins with a peer_id.
  §1.4 admits three spellings of one address — `system/tree`, `/{peer}/system/tree`,
  `entity://{peer}/system/tree` — and for the PEER-RELATIVE one, which is what validate-peer and
  every wire probe send, the first segment is `system`, so the handlers dimension compared
  `/{local}/tree` against a grant naming `system/tree` and missed.
  **THE CONSEQUENCE IS THE PART TO REMEMBER: A SELF-MINTED TOKEN PRESENTED STRAIGHT BACK TO THE PEER
  COULD NOT AUTHORIZE ANYTHING.** Mint over `system/capability:request` → 200; present it on the
  next request → 403. Any grant written the way §3.7 and §6.2 write them was unusable.
  **It survived because the shipped seed policy and the oracle's own caps grant handlers as `*`,
  which is VACUOUS OVER THE VALUE** — the dimension passed for a reason unrelated to what it
  compares, so no census could see it and both peers were `778 · 0F` throughout.
  **Two enforcement points, and the second is the one that generalises past addresses.**
  (a) For each peer, find the handler-path derivation and check it against the peer-id predicate
  `extract_peer` already uses — `isPeerIdSeg:` / `seg-is-peerid?` / `is_peer_id` are in every peer,
  one method away, and the two call sites must SHARE the predicate rather than each carrying an
  assumption about the path form. (b) **A dimension whose deployed grants are all `*` is untested by
  construction; to measure it you need a caller-supplied grant that names a value.** That is what
  `arc-probe`'s mint-then-use families do, and it is why they found this and 778 checks did not.
  **AND THE `forth` COPY IS THE SHARPEST VERSION: THE CORRECT WORD WAS ALREADY IN THE TREE, 400
  LINES AWAY, WITH A COMMENT EXPLAINING THE EXACT HAZARD.** `dispatch.fs`'s `uri->handler-path`
  carries an `addressed` flag and says in as many words that stripping a bare path's first segment
  *"would turn system/protocol/connect into protocol/connect"*. The two could not share code because
  Forth resolves names at compile time and `capauthz.fs` loads first — **so the duplicate was
  STRUCTURAL, and the duplicate is the one that drifted.** Where a load order or a module boundary
  forces a forward reference, the answer is the substrate's indirection (`defer` … `is` in Forth, a
  hook, an interface) and never a second copy: this tranche used `defer` for exactly that, following
  the peer's own `req-grants-bounded?` precedent.

- **A DEFAULT IS A VALUE, NOT AN ABSENCE — a subset or attenuation check that reads an omitted
  dimension as "covers nothing" refuses the shape every SDK writes.** Candidate (first occurrence,
  2026-09-15, `cobol`; enforcement exact). §5.2 says an omitted `peers` scope MEANS
  `{include: [local_peer_id]}`. `cap-dim-subset` read the parent's absence as covering nothing, so a
  CHILD that spells the default out explicitly exceeded a parent granting exactly the same thing:
  403 `scope_exceeds_authority` at MINT, and the whole dimension unmeasurable on that peer.
  **Enforcement: for every dimension with a spec-stated default, MATERIALIZE the default on BOTH
  sides of the comparison, and check BOTH asymmetric cases rather than only the measured one.** The
  unmeasured direction here (child omits, parent names) was vacuously a subset, so a parent whose
  `peers` EXCLUDES this peer could have been escaped by a child that simply left the dimension out —
  an over-grant that no wire row drives, found only by asking the question in both directions.

- **A THROW OUT OF A MATCHER IS A CONTROL-FLOW ANSWER TO A QUESTION THAT HAS A VALUE ANSWER, AND IT
  SURFACES AS `500 internal_error`.** Candidate (first occurrence, 2026-09-15, `forth`). §5.4's
  canonicalize was written to THROW on the three reserved prefixes; §5.4 at 0.8.2.20 makes it TOTAL,
  answering a sentinel. The difference is invisible until an unmatchable pattern reaches it from a
  GRANT EXCLUDE, at which point the throw unwinds past every authority rung to the dispatch
  boundary's catch-all and the peer answers 500 where §5.2 pins 403 — a wrong CLASS, not a wrong
  code, and one that reads as a peer bug rather than an authority verdict. **Enforcement: a function
  whose callers are matchers returns a value for every input; if the substrate's idiom is to raise,
  the raise belongs at the ADMISSION boundary where a caller can answer it, not inside the matcher.**
  The retired throw codes are kept in place with a dated `retired` marker rather than deleted, so the
  next reader who greps for them finds why nothing raises them.

- **ONE NARROWING SEAM, READ BY BOTH SIDES — a dispatch check and a handler that each derive the
  subject independently are a gap §6.3 cannot close.** RATIFIED 2026-09-15 across all nine peers of
  this tranche, and it is `F84`'s empty cell answered rather than restated. §5.2 evaluates the
  EFFECTIVE target set and the handler acts on one entry of it; if the two derivations are separate
  code, the check can authorize `targets[0]` while the handler acts on a different entry, and §6.3's
  handler-level check is then guarding a hole that its own inputs cannot see. Every peer here got a
  single `effective_target` and BOTH sides read it. **Enforcement: grep each peer for the places
  `resource.targets` is reduced to a subject; more than one is the defect, whatever each one does.**
  *(And where the ladder's refusals live matters: an effective list that is EMPTY or AMBIGUOUS is not
  an authorization question, so the dispatch stage neither authorizes nor refuses it — the handler
  answers it with the code the request's SHAPE earns, `path_required` or `ambiguous_resource`.)*
  **AND A LADDER THAT SPLITS ONE CASE INTO TWO DROPS WHATEVER USED TO FALL BETWEEN THEM — ON THE
  §3.3 LADDER THAT VALUE IS THE EMPTY STRING.** Candidate (2026-09-16, `fortran`, caught by the
  census and by nothing else). Before the effective-set ladder, `len(target) == 0` was reached by an
  ABSENT resource *and* by a present-but-empty target string, and both correctly took the root
  listing. The ladder separates those two, so the empty STRING now needs saying out loud: it
  canonicalizes to `/{local}/`, which is a DIRECTORY, and dropping it into the concrete-get arm
  answers **404 for the root of the peer's own tree**. Measured as
  `tree_operations/path_root_listing` PASS → FAIL on the first cut, and it is the only reason that
  half of the change was not `0 of 778`. **Enforcement: when a ladder splits one branch into several,
  enumerate the inputs the OLD branch accepted and place each one explicitly** — the reference peers
  spell it `target == "" || target ends with "/"` in a single arm, and that `""` is doing work no
  reader would guess.

- **A HANDLER PREDICATE MUST ACCEPT EVERY §1.4 SPELLING OF THE PATH, AND THE ONE THE ORACLE USES IS
  THE BARE PEER-RELATIVE FORM.** Candidate (2026-09-08, `asm-x86_64` then ported to three more).
  §4.7's row 10 — *an operation name the responder does not implement, in any state* → `400
  invalid_request` — has to be scoped to the CONNECT handler, because the same unknown operation on
  `system/tree` is `501 unsupported_operation` and on an unregistered path `404 handler_not_found`.
  The obvious way to scope it is to reuse whatever the peer already computed for the address gate,
  and on the asm peers that is `derive_handler`, which strips an `entity://<peer>/` prefix and
  **falls back to `system/tree` for anything else**. `validate`'s `connectURI` is the bare
  `"system/protocol/connect"` — no scheme — so the reuse matched nothing, the peer kept answering
  501, and the build was clean. **A predicate written for one caller's path form is not reusable by
  a second caller with a different one**: the new `uri_is_connect` accepts all three spellings and
  says at its definition why `derive_handler` is not it. Enforcement is the check itself — but the
  cheap tell is that a scoping predicate which never fires looks identical to a peer that has not
  been changed.

- **Content-addressed mint timestamps: ms precision is CORRECTNESS, not formatting** (A-PD-016). A
  token is `{grants, grantee, granter, created_at}` — second-truncated `created_at` makes same-scope
  same-second mints hash-identical, so the oracle's revoke probe aliases the session floor cap and
  the marathon 403-cascades (isolated category runs stay green; only the full profile exposes it).
  Sibling trap: the **open/debug seed needs `resources: ["*", "/*/*"]`** — §5.5a bare-star is
  granter-local, never universal, so without the absolute all-peers form the seed can't cover
  foreign namespaces and universal_address_space silently skips (A-PD-017).
