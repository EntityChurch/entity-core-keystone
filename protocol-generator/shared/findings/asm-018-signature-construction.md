# HANDOFF-TO-ARCH — A-ASM-018 / F36: two distinct "signature" constructions (ECF-bytes vs content_hash)

**Date:** 2026-07-15 · **Finding:** F36 (`research/stewardship/SPEC-FINDINGS-LOG.md`) ·
local id **A-ASM-018** (`protocol-generator/asm-x86_64/status/SPEC-AMBIGUITY-LOG.md`)
**Owner:** `arch` (spec-clarity / one-line disambiguation) · **Severity:** documentation
(no wire change, no defect) · **Blocks:** nothing
**Spec surface:** `ENTITY-CORE-PROTOCOL.md` §7.3 + `ENTITY-CBOR-ENCODING.md` §E signature vectors,
@ `spec-data/v0.8.0` (V8; core wire byte-unchanged V7→V8)
**Surfaced by:** the L2 native-codec differential (`asm-x86_64`), signing empirically pinned.

> Keystone cannot edit `spec-data/**` (immutable boundary). This is a request for arch to add a
> clarifying note on its own schedule; no local patch was made. Derived from the **spec** + the
> pinned corpus bytes, not the oracle's Go source.

## The finding

The ECF conformance corpus's **`signature`** category signs the target entity's **canonical ECF
bytes** — `ed25519_sign(seed, ECF({type, data}))` — whereas the **protocol** signature in §7.3
signs the entity's **content_hash** (the spec's "Sign full hash bytes: format code + digest",
for authenticate/capability entities). These are two *different messages* under the same word
"signature".

**How it was pinned (empirical, not assumed):** the corpus golden 64-byte signatures match
`sign(seed, ECF-bytes)` and do **not** match `sign(seed, content_hash)` (33 bytes: format code +
32-byte digest) nor `sign(seed, digest)` (32 bytes). Sign/verify round-trips independently
(isolating the discrepancy to *message choice*, not a crypto bug). `signature.2`'s unsorted data
`{z:1, a:2}` additionally confirms the message is the *canonically-sorted* ECF: the native
key-sorting `ec_encode_ecf` reproduces the golden; feeding the encoder unsorted data does not.

Both constructions are legitimate and non-contradictory:
- The **corpus** exercises the lower-level codec primitive *"canonically-encode-then-sign"* — the
  right thing to test at the ECF/codec layer.
- The **protocol** (§7.3) wraps signing over the `content_hash` for entity authentication.

The gap is purely **naming/documentation**: an implementer who reads only §7.3, sees
"signatures sign the content_hash," and wires their codec's `signature` path to sign the
content_hash will **fail the corpus `signature` vectors** — a confusing failure with no spec
pointer explaining that the corpus tests a different (lower-level) construction.

## Ask

A one-line disambiguation, wherever the corpus `signature` vectors are described
(`ENTITY-CBOR-ENCODING.md` §E and/or a cross-reference from §7.3): state that the corpus
`signature` category signs the **canonical ECF bytes** of `{type, data}` (the codec-level
`encode-then-sign` primitive), which is **distinct** from the §7.3 protocol signature over the
**content_hash**. Naming the two constructions (e.g. "ECF-signature" vs "entity/content_hash
signature") would remove the trap entirely.

## Why it's worth a note despite being non-blocking

This is the "conformance-green can be vacuous / a green check can hide a real distinction"
family the keystone exists to surface: the corpus and the protocol use the same word for two
different signed messages, and only a byte-level differential (which the asm L2 codec ran)
distinguishes them. Cheap to fix in prose; saves every future codec implementer the same
empirical bisection we just did.

## Provenance

- Local finding: `protocol-generator/asm-x86_64/status/SPEC-AMBIGUITY-LOG.md` → A-ASM-018.
- Differential + symbol proof: `protocol-generator/asm-x86_64/status/PHASE-L2.md` (M2/M3),
  `make diff` (`signature.1/2/3` green on native sorted `ec_encode_ecf` + FFI `ec_ed25519_sign`).
- Corpus: `protocol-generator/shared/test-vectors/v0.8.0/conformance-vectors-v1.diag`,
  `signature.*` @ pinned SHA-256 in `MANIFEST.md`.
