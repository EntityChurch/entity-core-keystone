# entity-core-protocol-cobol — Spec Ambiguity Log

> Discipline: every guess goes here; no silent guesses. Items escalate to
> architecture/research via `research/stewardship/`. COBOL is the slate's one
> genuine *discovery* bet (decision D2): an alien substrate — decimal-first
> numerics (PIC/COMP-3), fixed-width records, GnuCOBOL, FFI-everything over the
> codec C-ABI (no native COBOL CBOR/crypto). Its value is the NEW probes the
> decimal-first idiom surfaces, plus independent corroboration of prior findings.
> Entries prefixed `A-CBL-` to namespace from the other peers' logs.
>
> Phase coverage: **S1 spike (feasibility) + S1 profile**. S2+ append below.

---

## A-CBL-002: the codec C-ABI is entity-envelope-grained, not value-grained — FFI does not eliminate the canonical CBOR value codec  ⚑ OPERATOR/RESEARCH (refines the "FFI-everything" slate assumption)

**V7 section:** §1 ECF / canonical CBOR; C-ABI spec §4.1 (`ec_encode_ecf`,
`ec_content_hash`). **Profile field:** `[codec].strategy` (set `ffi-hybrid`).

**The finding (S1 profile, confirmed against the rust impl).** RELEASE-READINESS
§2 lists COBOL as "FFI everything (no COBOL CBOR/crypto)" with work collapsing to
"a binding shim + peer machinery." But the C-ABI is **entity-grained**:
`ec_encode_ecf(type, data)` and `ec_content_hash(type, data)` take the entity
`data` field as **already-canonical CBOR** — the rust impl comments it directly:
*"`data` is the opaque, already-canonical CBOR of the data field (N4); the entity
hashed is the 2-key map {data, type} (canonically key-sorted)."* There is no
C-ABI surface that canonicalizes an arbitrary nested value built from scratch
(`ec_encode_bare_value` is test-only and identity-on-canonical-input, not a
general canonicalizer). So the peer must produce canonical CBOR for every data
payload it constructs (params maps, capability tokens, signature triples, wire
message bodies) and parse canonical CBOR for every payload it receives.

**Consequence.** COBOL hand-rolls a **canonical CBOR value codec** (`cbor.cob`) —
the same A-005 layer every native peer owns — covering uint/nint/text/bytes/array/
map/bool/null with RFC 8949 §4.2 length-then-lex map ordering, minimal ints,
definite lengths, and the N2 recursive major-type-6 tag-reject on decode. What the
FFI *does* eliminate, byte-exact: crypto (Ed25519/Ed448), SHA-2, base58/peer-id,
entity 2-key framing + hashing, envelope signature verification, and the decode
tag-scan. Net: meaningfully less than a native peer, but not a thin shim.

**Float scope cut.** The ECF float ladder (f16/f32/f64 shortest) appears only in
the S2 conformance corpus, never in peer data payloads. Those corpus vectors are
validated via the FFI bare-value round-trip rather than re-deriving floats in
COBOL; the COBOL value encoder omits float. Documented in PROFILE-RATIONALE.

**Escalation.** OPERATOR/RESEARCH — corrects the slate's "thin shim" expectation
for entity-grained C-ABI FFI peers (also informs the future Odin peer, same C-ABI).
Not a spec defect; not a blocker. The Odin peer should inherit this expectation.

## A-CBL-001: COBOL's decimal-first numeric model corroborates the uint64 integer-head-form trap — and shows the current test surface doesn't catch it (strengthens F7 / A-OC-001 u64-range vectors)  ⚑ DISCOVERY CORROBORATION

**V7 section:** §1.x integer encoding (CBOR major type 0/1, the uint64 head-form
carrier); cross-refs F7 (u64-range test vectors), A-OC-001 (OCaml int63→Int64).
**Profile field:** numeric carrier strategy (to be recorded in `profile.toml`
`[codec]` + `PROFILE-RATIONALE.md` once S1 proper runs).

**The finding (from the S1 feasibility spike, P3).** COBOL is decimal-first:
`PIC 9(n)` is a *decimal-digit* width, not a bit width. `2^64 − 1 =
18446744073709551615` is **20 decimal digits**, but:
- the comfortable COBOL'85 ceiling is `PIC 9(18)` — **one digit-class short of
  uint64**; assigning uint64 max to it **silently truncates** (spike: top two
  digits lost), and
- GnuCOBOL **refuses to declare** a >18-digit `USAGE COMP-5`/binary field at all
  (*"binary field cannot be larger than 18 digits"*).

So the natural, idiomatic COBOL integer field cannot hold a full uint64. The
carrier that works is an **8-byte `PIC 9(18) COMP-5`** (physical storage holds the
full 2^64 range; the digit count is a display/MOVE-truncation cap, not a storage
cap) built with `-fno-binary-truncate`, native byte order aligning with the C
`uint64_t` over the FFI boundary. Full detail + reproducer:
`protocol-generator/cobol/spike/SPIKE-FINDINGS.md` Finding D.

**Why this is a spec-candidate, not just an impl note.** A COBOL peer written with
the natural `PIC 9(18)` field would **pass the current conformance vectors** (which
do not exercise integers above 10^18) **while silently truncating real uint64
values on the wire.** This is a concrete demonstration that the test surface does
not currently catch the integer-head-form truncation class — the precise argument
for adding the queued **u64-range vectors (F7 / A-OC-001)**. COBOL is the 5th
distinct native-int trap class (after OCaml int63, C# ulong, TS bigint, Zig
overflow-trap) and the one that best motivates closing F7.

**Your guess (carrier decision for the build).** uint64 rides an 8-byte
`PIC 9(18) COMP-5` with `-fno-binary-truncate`; `PIC 9(20+)` DISPLAY decimal only
where a >18-digit value must be shown/decimal-compared. Since the strategy is
FFI-everything, the codec C-ABI does the actual CBOR integer encode/decode
(big-endian); COBOL holds/compares the host-order value across the boundary.

**Escalation.** Corroborates and strengthens F7 / A-OC-001 — route to architecture
as additional evidence for u64-range vectors when that candidate is next reviewed.
Not a blocker for the COBOL build.

## A-CBL-003: the `tag_reject.1/2/3` corpus vectors contain NO major-type-6 bytes — they reject via trailing-data / structural malformation, not a tag  ⚑ RESEARCH (corpus-labeling observation)

**V7 section:** ECF §3.2 tag-scanner (N2); test-vectors `conformance-vectors-v1`
`tag_reject.*`. **Profile field:** none (a corpus observation).

**The finding (S2 codec bring-up).** Decoding the `tag_reject` vectors byte-by-byte
(COBOL navigator + an independent Python tokenizer) shows `tag_reject.1` (named
"tag 0 datetime in data field") and `tag_reject.2` ("tag 1 epoch ts") contain **no
major-type-6 byte at all**. Their bytes are a well-formed `map(2)` —
`{type:"test/v1", data:"1"}` — followed by **trailing bytes** (e.g. `.2` =
`… 62 7473 1a 661fa680`, a bare `"ts"` + plain uint, not a `0xc1`-tagged value).
`tag_reject.3` similarly: `map(2)` + trailing; its only major-6 bytes (`0xcc 0xdd`)
are interior hash bytes, not tags. `tag_reject.4` (`d9d9f7a0`) is a genuine
top-level tag, and `tag_reject.5` nests a tag in an envelope's included entity.

**Why it matters.** A decoder that implements the N2 invariant *literally as
described* — "reject any major-type-6 item" — and stops at the first complete
top-level value would **accept** `tag_reject.1/2/3` (no tag present, the leading
map is valid). Rejecting them requires the *additional* property that a canonical
decoder **consume exactly the input** (trailing data ⇒ reject). So these vectors
actually gate full-consumption, not tag-rejection, despite the `tag_reject.*`
naming. The COBOL decoder rejects all five correctly (tag OR incomplete-consume),
but the naming would mislead an implementer reading the corpus as the contract.

**Your guess / handling.** Reject on tag (N2) OR on trailing bytes after the
top-level value (full-consume). Verified correct, not relaxed (all 5 reject; the
68 structural/crypto vectors fully consume).

**Escalation.** RESEARCH/arch — corpus-quality note: consider renaming
`tag_reject.1/2/3` (they test trailing-data/structural reject) or adding a genuine
nested-tag-in-data vector, and stating the full-consume requirement explicitly
alongside N2. Low severity (a correct decoder rejects them); surfaced because the
keystone's value is catching exactly this label/contract drift via a fresh reader.
