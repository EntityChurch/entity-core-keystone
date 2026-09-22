# protocol-generator/shared/spec-data/v0.8.2.28/

**Verbatim snapshot of the authoritative normative spec files** — byte-for-byte copies of `entity-core-protocol/specs/{ENTITY-CORE-PROTOCOL,ENTITY-CBOR-ENCODING,ENTITY-NATIVE-TYPE-SYSTEM}.md`, not paraphrased tables. The snapshot pins generation inputs to a spec version for reproducibility per `(spec-version, lang, profile)` (S8), so generators can be re-run + version-stamped as the spec moves.

- **Authoring authority:** architecture only. Operators do NOT write spec-data. This snapshot is a mechanical copy — no editorial content is ours.
- **No paraphrase:** spec-data MUST literal-quote the spec wording; paraphrase is a bug.
- **Immutable:** once stamped, a `<version>/` directory is never edited in place. Amendments get a new directory — which is what this one is.
- **Integrity:** see `MANIFEST.md` for the SHA-256 of each file. **The digests are the only anchor here** — this snapshot is vendored from an *unreleased* line (`0.8.2.28` is not on published `master`, which is still `0.8.2`), so there is no released artifact to check a filename or a tag against. The source commit is recorded as an internal build coordinate and is not citable in anything published.
- **Version:** Entity Core Protocol **0.8.2.28**, `ENTITY-CBOR-ENCODING` **1.8**, `ENTITY-NATIVE-TYPE-SYSTEM` **4.2.1**.
- **Directory is named `v0.8.2.28`, not `v0.8.3`** — the fourth component is an arch-managed in-flight signal that lets core text move without cutting a release; the operator strips it and names the number at the cut.
- **Conformance scaffolding + generator defaults** are in `GUIDE-CONFORMANCE.md` + the generator menu — **not in this snapshot**.
- **`EXTENSION-TREE.md` is deliberately NOT vendored** and is still load-bearing *by reference*: §6.3's ladder cites its Appendix A for the `put` error codes, and §2.2a is what declares which operations are resource-optional and BROAD-RESULT — which §3.3 consumes. Read it in the sibling.

**Targets:** all peers from here forward. Supersedes `v0.8.2.25`, `v0.8.2.11`, `v0.8.2.3`, `v0.8.2` and `v0.8.0` for new work; all are kept in place as point-in-time pins.

> ⛔ **THE TYPE SYSTEM MOVED AND ITS `Version:` HEADER DID NOT.** `ENTITY-NATIVE-TYPE-SYSTEM.md` reads
> `4.2.1` at `v0.8.2.25` and `4.2.1` here, and its content changed (`043fc80d…` → `cb0a63e2…`, §10.2:
> a signature is over the **full `content_hash`**, format code ‖ digest, not the digest alone).
> `v0.8.2.25`'s own README says *"The type system is BYTE-IDENTICAL to `v0.8.2.11`… Read the digest,
> not the version string"* — **that instruction is what makes this vendor correct, and following the
> header instead would have skipped the file.** This is `entity-system-conformance`'s **`F79`**
> arriving on the next vendor after they raised it.

> ⭐ **VENDORED BEFORE CONSUMED, which is the order the previous snapshot asked for.** `v0.8.2.25` was
> vendored *after* 33 of 46 peers had already implemented against routed packets, and its manifest
> calls that a provenance defect with the remedy named: *"the correct order is vendor, then
> implement."* No peer implements `.26`–`.28` yet — `spec_pin` is `0.8.2.25` on all 46 rows and gated —
> so the pin is in place first and the cohort work can be derived from this text rather than from a
> packet.
>
> **The oracle re-pin is deliberately NOT landed with this vendor**, unchanged policy: the spec
> snapshot is what peers are **written against**, the oracle pin is what they are **measured
> against**, and nothing requires the two to move together. The pin remains `78db4a9`
> (executed set `7aa6f3de…`, 778 checks).

**What's new vs `v0.8.2.25`:** three amendments (`0.8.2.26`–`.28`) plus `ENTITY-CBOR-ENCODING` v1.7 → v1.8; **75/20, 61/33 and 2/2** added/removed lines respectively. **The arc's subject is SINGLE NORMATIVE HOMES** — most changes pin one section as the authority for a rule and demote its restatements to pointers, so a corrected restatement is not automatically a behaviour change. The items a peer could have to act on are enumerated in `MANIFEST.md`; the headline ones are §4.11's sharpening (`non_canonical_ecf` is a CLASS and is **not** conformant on the framing arm, where the framing arm is *bytes that do not decode*; the close is a CHOICE where the frame was consumed whole and FORCED where it was not), two new refusal rows (§1.11 non-canonical-but-decodable at `.27`, root self-consistency at `.28`), §3.3's BROAD-RESULT default for an operation declaring neither shape, and §1.2 becoming the single home of the `content_hash_format` registry after `ENTITY-CBOR-ENCODING` was found to have **transposed `0x03` and `0x04`**.
