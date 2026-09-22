# protocol-generator/shared/spec-data/v0.8.2.31/

**Verbatim snapshot of the authoritative normative spec files** — byte-for-byte copies of `entity-core-protocol/specs/{ENTITY-CORE-PROTOCOL,ENTITY-CBOR-ENCODING,ENTITY-NATIVE-TYPE-SYSTEM}.md`, not paraphrased tables. The snapshot pins generation inputs to a spec version for reproducibility per `(spec-version, lang, profile)` (S8), so generators can be re-run + version-stamped as the spec moves.

- **Authoring authority:** architecture only. Operators do NOT write spec-data. This snapshot is a mechanical copy — no editorial content is ours.
- **No paraphrase:** spec-data MUST literal-quote the spec wording; paraphrase is a bug.
- **Immutable:** once stamped, a `<version>/` directory is never edited in place. Amendments get a new directory — which is what this one is.
- **Integrity:** see `MANIFEST.md` for the SHA-256 of each file. **The digests are the only anchor here** — this snapshot is vendored from an *unreleased* line (`0.8.2.31` is not on published `master`, which is still `0.8.2`), so there is no released artifact to check a filename or a tag against. The source commit is recorded as an internal build coordinate and is not citable in anything published.
- **Version:** Entity Core Protocol **0.8.2.31**, `ENTITY-CBOR-ENCODING` **1.8**, `ENTITY-NATIVE-TYPE-SYSTEM` **4.3**.
- **Directory is named `v0.8.2.31`, not `v0.8.3`** — the fourth component is an arch-managed in-flight signal that lets core text move without cutting a release; the operator strips it and names the number at the cut.
- **Conformance scaffolding + generator defaults** are in `GUIDE-CONFORMANCE.md` + the generator menu — **not in this snapshot**.
- **`EXTENSION-TREE.md` is deliberately NOT vendored** and is still load-bearing *by reference*: §6.3's ladder cites its Appendix A for the `put` error codes, and §2.2a is what declares which operations are resource-optional and BROAD-RESULT — which §3.3 consumes. Read it in the sibling.

**Targets:** all peers from here forward. Supersedes `v0.8.2.28`, `v0.8.2.25`, `v0.8.2.11`, `v0.8.2.3`, `v0.8.2` and `v0.8.0` for new work; all are kept in place as point-in-time pins.

> ⛔ **`v0.8.2.28` WAS VENDORED AND IS DELIBERATELY NEVER IMPLEMENTED.** `.29` withdraws text `.28`
> still carries: a `peers:` IdScope value is written **path-shaped** (`"/{peer_id}/path"`) through
> `.28` and is pinned **flat** — a bare Base58 id or the bare `*`, never a path — at `.29`. Sweeping
> to `.28` would have implemented a retracted shape. The cohort jumps `0.8.2.25 → 0.8.2.31` in one
> step and `v0.8.2.28/` stays as a point-in-time pin.

> ⬜ **THE HEADER FOLLOWED THIS TIME, AND THAT IS LUCK.** `v0.8.2.28`'s README records the opposite
> case — `ENTITY-NATIVE-TYPE-SYSTEM.md` read `4.2.1` on both sides of a content change, which is
> `entity-system-conformance`'s **`F79`**. Here that file moves `4.2.1 → 4.3` **and** its content
> moves, and `ENTITY-CBOR-ENCODING.md` is `1.8` on both sides and **byte-identical**
> (`36e83350…` at `.28` and here) — so on this vendor the header is consistent in both directions,
> which is exactly the state in which a header-keyed vendor happens to work and tells you nothing
> about the next one. **The digest comparison remains the acceptance step.**

> ⭐ **VENDORED BEFORE CONSUMED — second consecutive snapshot in that order.** `v0.8.2.25` was
> vendored *after* 33 of 46 peers had implemented against routed packets, and its manifest calls that
> a provenance defect with the remedy named: *"the correct order is vendor, then implement."* At
> stamping, `spec_pin` is `0.8.2.25` on all 46 rows and gated, so the sweep derives from this text
> rather than from a packet.
>
> **The oracle re-pin is deliberately NOT landed with this vendor**, unchanged policy: the spec
> snapshot is what peers are **written against**, the oracle pin is what they are **measured
> against**, and nothing requires the two to move together. The pin remains `78db4a9`
> (executed set `7aa6f3de…`, 778 checks).

**What's new vs `v0.8.2.28`:** three amendments (`0.8.2.29`–`.31`); **128/21** and **6/5** added/removed lines in the core protocol and the type system, and `ENTITY-CBOR-ENCODING.md` **unchanged**. New `[MUST]` obligations per revision are **12, 3, 2** — `.29` ties the arc high, `.30` and `.31` are the two lowest since `.19`, and two low readings are not a trend.

**The arc has two subjects.** `.29` is a single-normative-home sweep of the **identity entity** (the `system/peer` shape had eight declared homes and `0.8.2.15` corrected two of them) plus the **`peers`-dimension canonicalization rules that were never written**. `.30` and `.31` are about **restatements publishing superseded rules positively** — `.30` finds an ordering that was *inferred* from a code pin, `.31` finds §9.1's conformance floor still publishing a discriminator §6.8 corrected eight revisions earlier.

**The three items most likely to be real cohort work**, with the rest enumerated in `MANIFEST.md`:

1. **§9.1's authority-selection floor row was wrong for eight revisions (`.31`).** The correct rule (§6.8, since `0.8.2.22`) selects on *whether the access serves a live caller's request*, not on who named the path — and an access in service of a caller's request, **including a path the handler derived within it**, requires the caller's capability **AND** the handler's own grant, both passing. A peer built to the old row flattens that intersection, which makes the §6.3 listing filter vacuous. **A peer swept to `.25` may have been swept to the wrong row.**
2. **`resolve_peer_scope` (`.29`)** — §1.5 **form** canonicalization of the `peers` dimension before the literal match, at both `check_permission` and `check_grant_covers`, with **asymmetric** dispositions for an unresolvable value: `include` → drop it, `exclude` → refuse the grant. It closes a **fail-open** where a received non-canonical `peers.exclude` silently failed to match and the excluded peer was admitted.
3. **`501` is reachable only after `check_permission` (`.30`)** — unauthorized **and** unimplemented answers `403`. A confidentiality property: the reverse order lets a caller enumerate a handler's operation set one probe at a time.
