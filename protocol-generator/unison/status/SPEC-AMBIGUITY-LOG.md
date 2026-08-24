# entity-core-protocol-unison — Spec / Profile Ambiguity Log

Format per `lifecycle/PROMPT-CONSTANTS.md`. Every guess is logged. Distinguish
**spec-findings** (→ arch, spec needs clarification), **profile-gaps** (→ research, profile
needs a field), and **local decisions** (→ operator). Peer #43 (operator-directed, Unison).

**Severity note:** NONE of the S1 entries below are blocking. The codec floor is
builtins-only (zero third-party dep), so no library pin gates S2; agility (Ed448/SHA-384) is
DEFERRED (WARN not gating under `--profile core`), not TBD. No NEW spec defect surfaced at S1
(expected — the wire-discovery well is dry on the current surface; this peer is
coverage/generator-robustness).

---

## A-UN-001: Ed448 + SHA-384 not native; no C FFI escape hatch → agility DEFERRED

**Spec section:** §8.1 key/hash format tables (key_type 0x02 Ed448; hash_type SHA-384 agility);
crypto-agility higher bar.
**Profile field:** `[codec].ed448_library`, `[codec].sha256_source` (SHA-384 note).
**Your guess:** DEFER the whole agility tier (Ed448 + SHA-384). UCM builtins expose native
Ed25519 + SHA-256 (+ SHA-512, SHA3, Blake2b) but NOT Ed448 and NOT SHA-384 (S1 `find crypto`
enumerated Ed25519/P256/Rsa and Sha2_256/Sha2_512/Sha3_*/Blake2*/Md5/Sha1 — no Ed448, no
Sha2_384). Unison is a managed runtime with NO general C FFI, so the `libentitycore_codec`
hybrid-FFI escape hatch (OCaml/Zig/Swift's route for the Ed448 gap) is STRUCTURALLY
UNAVAILABLE. The only in-band route is a pure-Unison Ed448 + SHA-384 impl — large, and
~zero discovery value on a dry wire surface.
**Rationale:** Agility is WARN not gating under `--profile core`; deferring it is established
cohort precedent (Swift A-SW-001, Zig A-ZIG-002, OCaml). The no-C-FFI fact is itself the
crypto-spectrum DATUM this peer contributes: a managed-runtime peer with native
Ed25519+SHA-256 but no agility AND no FFI fallback — a distinct spectrum position from
native-full-agility (Haskell crypton / CL ironclad), native-floor+FFI-agility (OCaml/Zig/
Swift), and gap→FFI-everything (COBOL).
**Escalation:** research — crypto-availability ledger (record the no-FFI managed-runtime
spectrum position + the agility defer). NOT a spec finding.

## A-UN-002: codec_strategy = native, BUILTINS-ONLY floor; @unison/base optional

**Spec section:** absent (implementation strategy).
**Profile field:** `[codec].strategy`, `[idiom].builtins_only_floor`, `[deps].base`.
**Your guess:** `native`, with a BUILTINS-ONLY core floor (zero third-party runtime
dependency). Crypto/hashing (`crypto.*`), Bytes, and TCP sockets (`io2.IO.*`) are all UCM
RUNTIME builtins baked into the binary; CBOR + base58 + varint + the handful of needed
list/text combinators are hand-rolled in-repo. `@unison/base` is OPTIONAL (convenience
combinators only), NOT required.
**Rationale:** Matches the cohort's dependency-minimization ethos (Zig std-only, CL one-dep)
and yields a fully-offline `--network=none` core build after the one-time toolchain pull
(builtins need no `pull`). Base's value is ergonomic combinators, not any primitive we lack.
Choosing builtins-only also removes base-version-pin risk from the S2 gate.
**Escalation:** operator (local strategy decision) + research (the fully-offline builtins-only
story is a generator-robustness datum).

## A-UN-003: numeric = fixed-width 64-bit (Nat/Int); carry head form + [2^63,2^64-1] self-test

**Spec section:** ENTITY-CBOR-ENCODING §2 integer major types 0/1 (full uint64/nint range).
**Profile field:** `[numeric]`.
**Your guess:** Treat Unison as a FIXED-WIDTH peer. BUILD-PROVEN at S1: `Nat` is 64-bit
unsigned (2^64-1 increments to 0), `Int` is 64-bit signed two's-complement (2^63-1 increments
to -2^63). There is NO arbitrary-precision integer builtin. Carry the CBOR integer HEAD FORM
as an explicit artifact and self-test over [2^63, 2^64-1]. Map CBOR major-type-0 unsigned to
`Nat` (full 0..2^64-1); decode CBOR major-type-1 negative as `-(n+1)` with the magnitude
`n : Nat` (Int tops out at 2^63-1 and cannot hold the largest nint magnitudes).
**Rationale:** The durable cross-language head-form lesson: fixed-width ints (like C# ulong /
Zig u64 / OCaml int63 / Fortran) must carry the head form + the high-bit-set self-test;
bignum peers carry the full range free. Unison lacks bignum, so the fixed-width branch applies.
**Escalation:** operator (local, per the durable lesson — not a spec ambiguity; the spec is
explicit that lengths/ranges are byte/uint64-oriented).

## A-UN-004: concurrency = abilities (algebraic effects) over IO — a NEW §7b store-safety shape

**Spec section:** §4.8/§6.11 (inbound concurrent with outbound), §6.13b (handler outbound
closure), §7a (dispatch-outbound reentry), §7b (store-concurrency gate).
**Profile field:** `[concurrency]`.
**Your guess:** Concurrency via ABILITIES (algebraic effects) over the IO ability —
`fork` (green threads), `Promise`/`MVar` (synchronised cells), `Ref`, `scope`/structured
concurrency. Store-safety made STRUCTURAL by an MVar-guarded single-owner store (take/modify/
put serializes all store access — an actor-like guarantee realized through the effect system).
One forked thread per connection; request_id↔continuation demux via an MVar/Ref map or a
per-request `Promise`.
**Rationale:** This is a distinct shape from the existing store-safety families
(actor-isolation, STM, raw-thread, single-thread-event-loop, dataflow-variable): an
effect-system/abilities substrate where the serialization primitive (MVar) is a library value
over the IO ability, not a language-level actor or transaction. A taxonomy DATUM, not a spec
finding — codec is pure/synchronous (S2), so this is exercised at S3/S4. Final shape at S3.
**Escalation:** research (§7b store-safety taxonomy — add the abilities/algebraic-effects
shape). NOT a spec finding; do not over-claim.

## A-UN-005: error model = pure `Either CodecError a` + Exception/Abort abilities at the IO edge

**Spec section:** protocol status mapping (400 non_canonical_ecf / 401 / 403).
**Profile field:** `[error_model]`.
**Your guess:** The pure codec is a total function returning `Either CodecError a` (Unison's
builtin `Either`; an error is a value, nothing to handle in the codec layer). IO-boundary
failures use the `Exception`/`Abort` abilities (the io2 builtins return `Either Failure a`,
lifted/handled at the S3 transport edge). Status codes map a `CodecError`/verdict constructor
at the module boundary.
**Rationale:** The Unison-idiomatic split — pure code returns error values, effects carry
IO failures. Shape converges with Haskell Either / OCaml result (the error axis is low-yield,
idiom-neutral across peers), arrived at independently as the Unison idiom.
**Escalation:** operator (idiom decision; revisitable at S2).

## A-UN-006: build model = content-addressed codebase, headless `ucm transcript` (generator-robustness)

**Spec section:** absent (toolchain/build model).
**Profile field:** `[build]`, `[idiom].content_addressed_codebase`.
**Your guess:** Drive the build headlessly via `ucm transcript <file.md>` (a transcript loads
`.u` source into the content-addressed SQLite codebase, typechecks = builds, `add`/`update`s,
and runs `>` watch-expression conformance checks into `<file>.output.md`). Single-definition
runs via `ucm run.file <file.u> <symbol>`; the peer launches via `ucm run.compiled peer.uc`.
**Rationale:** THE critical de-risk of this peer — Unison source lives in a content-addressed
codebase managed by an interactive-by-design UCM, and our pipeline is container-bound +
non-interactive. PROVEN at S1 (see PHASE-S1.md): `ucm transcript` runs `.u`/`.md` fully
headless in-container under caps, emits a diffable `.output.md`. This transcript-driven,
codebase-oriented build is the novel generator-robustness contribution (a build model no prior
peer used — not a file→compile→link loop).
**Escalation:** operator (local build-model decision) + research (generator-robustness datum:
the headless codebase-oriented build pattern).

## A-UN-007: @unison/base version pin deferred to S2-first-pull (non-blocking)

**Spec section:** absent (dependency management).
**Profile field:** `[deps].base`.
**Your guess:** Do NOT pin an `@unison/base` release at S1. The builtins-only floor does not
require base; IF a later phase elects its convenience combinators, pin a concrete
`@unison/base` release (Unison Share `releases/<semver>`, e.g. `releases/2.9.1` or a newer
≥30-day-old release) at that point and record it in `[deps].base`.
**Rationale:** Base is optional (A-UN-002), and its release list lives on Unison Share (not a
GitHub releases feed, so not cleanly queryable headless at S1). Deferring the pin does NOT
block S2 because the floor hand-rolls the needed helpers. If base IS adopted, the pin is a
one-time networked `pull` at S2/S3 setup, then offline.
**Escalation:** research (record whether base is adopted + its pinned release when decided).

## A-UN-009: Ed25519 pubkey derivation is NOT a builtin (nor in @unison/base) — pure-Unison keygen required for the signature vectors

**Spec section:** ENTITY-CBOR-ENCODING Appendix E `signature` category; §7.3 signing.
**Profile field:** `[codec].ed25519_library` (the S1 "base has a wrapper" note).
**Your guess (S2 RESOLUTION of the S1-deferred keygen question):** Implement Ed25519
public-key derivation (SHA-512(seed) → clamp → scalar-mult the basepoint → compress)
in **pure Unison** over the fixed-width `Nat` builtins (base-2¹⁶-limb GF(2²⁵⁵-19) field
arithmetic + twisted-Edwards point ops), in `src/Ed25519.u`. `crypto.Ed25519.sign.impl`
then signs with `(seed, derivedPubkey, msg)`.
**Rationale / finding:** S1 assumed `@unison/base` provides an Ed25519 keygen wrapper.
S2 in-container verification **contradicts that**: (a) the UCM runtime exposes only
`crypto.Ed25519.sign.impl` / `verify.impl` — **no** key-derivation builtin (P256 has
`publicKey.impl`; Ed25519 does **not**); and (b) `@unison/base`'s `crypto.Ed25519` is a
thin wrapper over the SAME builtins — `PrivateKey`/`PublicKey`/`sign`/`verify` only, **no**
`toPublic`/`fromSeed`/`keyPair`. Since `sign.impl` requires the public key explicitly and
the corpus `signature.*` vectors sign under fixed seeds, the pubkey MUST be derived
in-band. With **no C FFI** (A-UN-001) there is no `libentitycore_codec` fallback either.
Pure-Unison keygen is the only in-band route — and it is **expressible** (not a spec
gap): validated at S2 against the **RFC 8032 §7.1 Test-1** vector (seed `9d61…7f60` →
pubkey `d75a9801…511a`, exact) and end-to-end by `signature.1/.2/.3` passing. Kept in the
**builtins-only floor** (no third-party dep): SHA-512 is a builtin; the field/curve math
is hand-rolled over `Nat`. `@unison/base` is therefore NOT adopted (A-UN-002/007 stand:
its Ed25519 adds nothing we lack).
**Escalation:** research (crypto-availability ledger) — refine the S1 "base has a wrapper"
note: on this managed runtime, Ed25519 *key derivation* is neither a builtin nor a
base-provided primitive; a native-Ed25519-sign peer with no keygen builtin must hand-roll
the curve keygen (a sharper crypto-spectrum datum than S1 recorded). NOT a spec finding.

## A-UN-008: peer_id derived from the §1.5 canonical-form table (corroboration, not a finding)

**Spec section:** §1.5 identity canonical-form table; §7.4 peer_id derivation.
**Profile field:** `[spec].peer_id_derivation`.
**Your guess:** Derive the Ed25519 peer_id from the §1.5 canonical-form table (key_type 0x01,
hash_type 0x00 identity-multihash, digest = the raw 32-byte public key), the reconciled form —
NOT the stale SHA256(pubkey) §7.4 skeleton.
**Rationale:** The peer_id §7.4-vs-§1.5 tension (A-OC-007 / A-ZIG-001 / A-SW-008 / A-CL-002)
is already reconciled in-body (§7.4 defers to the §1.5 table). Unison CORROBORATES the
reconciliation rather than re-surfacing it — a further read landing on the consistent
§7.4 → §1.5. Not a new finding.
**Escalation:** research (corroboration ledger). NOT a spec finding.

---

# S3 entries (peer machinery)

None of the S3 entries below are blocking or spec-findings; they are scope /
strategy / substrate-transport decisions on a dry wire surface (coverage peer).

## A-UN-010: seed-policy file-parse deferred; in-code builders are the S3 floor

**Spec section:** §6.9a (Peer Authority Bootstrap; identity → capability seed policy).
**Profile field:** `[concurrency]`/`[layout]` (host CLI); `shared/seed-policy/`.
**Your guess:** The S3 host exposes the in-code seed policies `SeedStandard`
(default → §4.4 discovery floor) and `SeedDebugOpen` (degenerate `default → *`, =
`--debug-open-grants`). Parsing the shared `seed-policy.schema.json` from a
`--seed-policy FILE` is the next increment (S4/S5), not the S3 floor.
**Rationale:** Mirrors the cohort (Haskell A-HS-011, C#/TS/OCaml) — the two in-code
builders cover the S3 smoke + the S4 `--debug-open-grants` gate; file-parse adds no
wire coverage.
**Escalation:** operator (local scope) + research (record when file-parse lands).
**S4 RESOLUTION — CLOSED, still deferred (confirmed unnecessary for the gate).** No
core-profile category required a `--seed-policy FILE` parse: the gate ran green
(`682·0F @ cc1970f`) on the in-code `SeedStandard` / `SeedDebugOpen` builders with
`--debug-open-grants`. The grant-gated categories (`capability`, `authz`, `security`,
`multisig`, `universal_address_space`) are all satisfied by the degenerate open seed
plus the §4.4 discovery floor. File-parse therefore remains a post-S4 convenience
increment with **zero** conformance coverage attached — it is not a gap, and no future
phase should treat it as one on this peer's account.

## A-UN-011: multi-signature §3.6 granter deferred to S4; single-sig root is the S3 floor

**Spec section:** §3.6 (multi-signature granter, ROOT-ONLY), §5.5 M4·M6 (k-of-n
quorum, root-at-local).
**Profile field:** absent (L3 scope).
**Your guess:** The S3 chain verifier implements the single-sig chain fully (§5.5
root-at-local, per-link signature + §5.5a granter frame, §5.6 attenuation, temporal,
§5.1 revocation, §4.10(b) depth). A map-form (multi-sig) granter root is DENIED at
S3 (`rootAtLocal` requires a bytes granter). The k-of-n quorum verification lands
with the S4 `multisig` category (which the smoke does not exercise).
**Rationale:** Don't gold-plate the S3 floor; multisig is a non-core-gated S4
category, and the smoke path is single-sig. The map/quorum vocabulary carries no
new wire discovery. Pairs with the vacuous-green lesson — add the multisig
accept-path unit test at S4, not a stub now.
**Escalation:** operator (S3 scope boundary). NOT a spec finding.
**S4 RESOLUTION — IMPLEMENTED, CLOSED.** The deferral was caught by the oracle exactly
as the vacuous-green lesson predicts it should be: `valid_2of3_peer_signed_accepted`
FAILED with *"peer rejected (403) a VALID 2-of-3 multi-sig cap it co-signed — fail-closed
on multi-granter rather than a genuine K-of-N implementation"*. Implemented in
`Capability.u`: `rootAtLocal` honors a multi-granter root when the local peer is one of
the listed signers (`mgLocalRoot`); `linkSigOk` dispatches on granter shape and routes the
map form to `multiGranterOk`, which counts **distinct listed signers** carrying a valid
signature over the capability hash (each verified against that signer's resolved
`system/peer` public key) and requires `count >= threshold`, `threshold > 0`.
`multisig` now 11P/0W/0F/0S. Accept-path unit + **negative K-of-N control** (1-of-3 must
deny) in `transcripts/multisig-test.md`:
`MULTISIG-ACCEPT-UNIT PASS (2of3=VAllow, 1of3=VDeny)`.
**Correction to the standing durable lesson:** at oracle pin `cc1970f` the `multisig`
category is **NOT** rejection-only — it ships a genuine accept vector. The lesson's
advice (add an accept-path unit) stands; its factual claim that the category is "100%
malformed→403" is stale at this pin. → research (cohort ledger).

## A-UN-012: type floor = minimal name-only seed at S3; full render byte-diff at S4

**Spec section:** §9.5 (core type floor; render-from-model).
**Profile field:** `[spec]` (type registry).
**Your guess:** `TypeDefs.publish` renders the 53 core+operational+type-system-
bootstrap type names as `system/type {name}` entities through the native S2 codec
and binds them at `/{peer}/system/type/{name}`, so the §9.5 surface exists and tree
get on `system/type/*` is reachable. The full field-spec/layout byte-exact render +
the type-registry byte-diff against the Go vectors is deferred to S4.
**Rationale:** Cohort precedent (Haskell A-HS-009, Swift A-SW-009): the render-from-
model SEAM + a minimal seed is the S3 floor; the byte-exact 53-render is an S4
`type_system`-category task. A core peer publishes only the floor — no extension
vocabularies.
**Escalation:** operator (S3 scope) + research.
**S4 RESOLUTION — IMPLEMENTED, CLOSED.** The name-only seed produced 37 FAILs, all of the
shape *"field X: REQUIRED locally but MISSING remotely"*. `TypeDefs.u` rewritten as a
full render-from-model registry: an `FSpec` field-spec algebra (`type_ref / optional /
array_of / map_of / union_of / key_type / byte_size`, rendered omit-empty) + a `TypeDef`
record (`name / extends / fields / layout`), with all **53** core + operational +
type-system bootstrap definitions — a faithful port of the cross-blessed
Haskell/C#/TS/OCaml/Zig registry. Rendered through our own S2 codec (NOT ingested as
fixture bytes), so the content_hash is computed by our encoder over our model; map-key
declaration order is irrelevant because the codec sorts canonically (length-then-lex over
encoded key bytes). `type_system` 64P/37F → **108P/292W/0F**. The 292 WARNs are
non-§9.5-floor (extension) vocabulary, matched-if-present — the correct shape for a core
peer, which never pre-publishes extension vocabularies.

## A-UN-013: memory-primary signature-ingestion discipline (skip the transient request sig)

**Spec section:** §6.5 (dispatcher signature ingestion); §4.10 (resource bounds).
**Profile field:** `[concurrency]` (store shape).
**Your guess:** The store is a memory-primary assoc-list behind the MVar (builtins-
only floor, no Map dependency). `ingestSignatures` ingests handler-discoverable
signatures (identity / cap / grant) but SKIPS the transient per-request EXECUTE
signature — the one whose `target == the root exec hash`, consumed inline by
`verifyRequest` and never looked up post-dispatch. So the store does not grow a
unique entry per request.
**Rationale:** The durable memory-primary lesson (Io A-IO-022, Rexx A-RX-014):
binding the transient request sig grows an in-memory store per request → GC thrash →
later-category timeouts. An implementation discipline, not a spec gap (§6.5 is fine).
Pairs with the §4.10(a) payload-admission bound.
**Escalation:** research (durable-lesson application; the abilities/MVar store joins
the memory-primary cohort). NOT a spec finding.

## A-UN-014: TCP_NODELAY not settable via UCM socket builtins; §7b transport-menu partial

**Spec section:** §7b (transport menu — `TCP_NODELAY` SHOULD); §4.10(a) (payload bound).
**Profile field:** `[concurrency]`/`[idiom]` (transport).
**Your guess:** The UCM `io2.IO` socket builtins expose no `setSocketOption` /
`TCP_NODELAY`, so the Nagle-off SHOULD is **not settable** on this substrate — logged,
not honored (a substrate limit, not a peer defect). Separately: the §4.10(a) payload
bound checks the 4-byte length prefix and rejects an over-`maxFrame` (16 MiB)
connection BEFORE buffering the body, but a `413 payload_too_large` result frame
needs a `request_id` that lives only in the (unread) body — so the S3 floor
**rejects-by-close** (keeps the peer alive, no OOM); the precise status is an
S4-measured refinement.
**Rationale:** `TCP_NODELAY`-unavailable is a crypto/transport-spectrum datum for a
managed runtime with a fixed builtin socket surface (like the no-C-FFI datum,
A-UN-001). Reject-by-close satisfies "reject over-limit before buffering; keep
serving" for S3; S4's `resource_bounds` category will confirm whether the oracle
expects a body-bearing 413 (if so, an unauthenticated-frame carve-out is the fix).
**Escalation:** research (transport-spectrum ledger) + operator (revisit the payload
status at S4). NOT a spec finding.
**S4 FINAL DISPOSITION — both halves closed, no change required.**
1. **`TCP_NODELAY`** stays **not settable** (UCM's `io2.IO` socket surface exposes no
   `setSocketOption`). It is a §7b **SHOULD**, and the gate is green without it —
   `concurrency` 5/5 and `resource_bounds` 2P/1W with no latency-shaped failure. Confirmed
   substrate limit, not a peer defect; recorded as a transport-spectrum datum for a
   managed runtime with a fixed builtin socket surface (pairs with the no-C-FFI datum,
   A-UN-001).
2. **The 413-vs-reject-by-close question is ANSWERED: reject-by-close is conformant.**
   `resource_bounds` r1 (payload → `413`, a MUST) **passes** with the S3 reject-by-close
   behavior. §1866 explicitly blesses it: because the over-size condition may be detected
   before `request_id` is parsed, the peer SHOULD emit a correlated `413` *when the id is
   available* and otherwise **MAY close the connection** — §4.9(c) deliver-or-signal is
   satisfied by the close. No unauthenticated-frame carve-out was needed.
   The one `resource_bounds` WARN is r3 conn-flood (§4.10(c), a SHOULD, explicitly not
   gated; the peer kept serving all 256 connections) — same shape as the Go reference peer.

---

# S4 entries (live-peer conformance)

Two genuinely **spec-shaped** findings (→ arch) and two implementation/generator datums
(→ research). Both spec findings cost a real iteration: each was a *plausible* reading of
the normative text that the oracle rejected.

## A-UN-015: §3013's "exactly one of two forms" for `peer_pattern` contradicts v7.65 §3.6 rule 3

**Spec section:** §3013 / §3018 (capability policy `peer_pattern` forms) vs V7 §3.6
v7.65 rule 3 (`PEER-PATTERN-2`, Base58 lazy-canonicalization mint).
**Profile field:** absent (L3 policy surface).
**Your guess:** Accept `default`, a full 66-char lowercase-hex `{caller_peer_hex}`,
**or** a Base58 peer_id; reject everything else (notably partial-prefix matchers).
**Rationale / the contradiction:** §3013 states the path's `{peer_pattern}` is *"exactly
one of two forms"* — `{caller_peer_hex}` or `default` — and §3018 reinforces *"No other
pattern forms are defined"* while mandating rejection of partial prefixes (`00abc*`).
Implemented literally, that yields `validPeerPattern = default | full-hex`, which is what
I shipped first — and it **failed** `peer_pattern_2_lazy_canon_mint`:
*"Base58 lazy-canon mint for unknown peer 2KBUz… rejected with status 400 — v7.65 §3.6
rule 3 expects acceptance"*. §437's wire-acceptance carve-out does describe a
pending-canonicalization path (*"via the §6.2 lazy-canonicalize path when at mint time
without prior contact"*), but §3013's enumeration — the section an implementer reads when
writing `peer_pattern` validation — does not mention it and is worded as exhaustive.
A peer that satisfies §3013 as written fails the conformance vector.
**Ask:** have §3013/§3018 name the transitional Base58 form (or cross-reference §3.6
rule 3 / §437) so the enumeration is exhaustive *as written*. The partial-prefix
prohibition is clear and correct and should stay.
**Escalation:** **arch — spec needs clarification** (normative-text contradiction, not an
implementation choice).

## A-UN-016: the unsupported-`key_type` check's ORDER relative to the peer_id↔pubkey identity binding is unstated

**Spec section:** §426 (*"Impls receiving a `key_type` they do not support MUST return
`400 unsupported_key_type`"*) vs §4.6 / §1.3 (peer_id↔public_key identity binding);
vector `AGILITY-UNKNOWN-1` (v7.66 §4.4 surface 6 / §7.1).
**Profile field:** `[codec].ed448_library` (agility deferred, A-UN-001).
**Your guess:** Recover the `key_type` varint from the **presented peer_id** and reject a
non-`0x01` value with `400 unsupported_key_type` **before** evaluating the identity
binding.
**Rationale / the gap:** Both requirements are individually clear; their **precedence is
not stated anywhere**. The natural implementation derives the expected peer_id under its
own supported key_type (`0x01`) and compares — so a peer_id minted under `0xFD` fails the
binding and surfaces as `401 identity_mismatch`. That is a defensible reading (the
identity genuinely does not bind), and it is what this peer did; `AGILITY-UNKNOWN-1`
rejects it: *"target returned status=401 code=identity_mismatch for key_type=0xfd …; want
400 unsupported_key_type or 200"*. An unknown key type is thereby made
indistinguishable from an impersonation attempt, which is the security-relevant part.
This is the same family as the already-landed **F31 401-vs-404 auth-ordering** ruling and
wants the same treatment.
**Secondary, and not called out anywhere:** for codes with **no canonical `key_type`
string** (§431 allocates strings only up to `0xFE`; `0xFD` has none), the `key_type`
entity-data field is absent, so **the peer_id's leading varint is the only in-band
signal**. Detecting the condition therefore *requires a Base58 decoder* in every peer —
an obligation no section states. Peers that only ever *encode* peer_ids (the common
shape) will not have one, and will silently return the wrong status.
**Ask:** state that `key_type` support is validated **before** identity binding, and note
the peer_id-varint decode obligation for string-less codes.
**Escalation:** **arch — spec needs clarification** (unstated ordering + an unstated
implementation obligation).

## A-UN-017: on a native-sign / no-keygen-builtin substrate the pubkey is part of the IDENTITY, not a per-signature derivation

**Spec section:** absent (implementation discipline; §7.3 signing).
**Profile field:** `[codec].ed25519_library` (the S1 "sign.impl takes the public key
EXPLICITLY alongside the seed" note).
**Your guess:** `ed25519Sign : seed -> pub -> msg`, with the caller passing the
**precomputed** `Identity.idPublicKey` derived once at startup.
**Rationale:** S2/S3 shipped `ed25519Sign : seed -> msg`, deriving the pubkey internally
via `ed25519Pub` on **every** signature — a full pure-Unison scalar multiplication (255
twisted-Edwards point ops over 16-limb GF(2²⁵⁵-19) arithmetic). Every minted capability,
handshake, and response signature therefore paid a **keygen**. Consequences, all of which
initially looked like unrelated defects: `concurrency / t2_2_connection_churn` failed at
cycle 15 (*"peer may have degraded under churn"* — diagnosed first as a leak or a
scheduling bug, actually just too slow to keep up), and **seven core categories never ran
at all**, reporting `budget_exhausted` against the oracle's default 60 s global
`-timeout`. Fixing the signature signature (58 s → 30 s total; `concurrency` 35.9 s →
10.7 s) resolved all of it.
**Durable form:** on any peer whose crypto tier is *native sign/verify + hand-rolled
keygen* (this peer, and the same shape wherever `sign.impl` demands an explicit pubkey),
**never expose `sign(seed, msg)`** — it silently makes each signature cost a keygen.
Derive once, carry in the identity record. Sharpens A-UN-009 / the crypto-availability
ledger. **Corollary:** a `budget_exhausted` skip is a **latency defect to fix in the
peer**, never a reason to raise `-timeout` — raising it here would have produced a green
report over a peer that degrades under connection churn.
**Escalation:** research (crypto-availability ledger + the durable cross-language
lessons). NOT a spec finding.

## A-UN-018: block-buffered stdout defeats banner-based readiness detection

**Spec section:** absent (harness / generator robustness).
**Profile field:** `[build].peer_launch`.
**Your guess:** Set `io2.BufferMode.LineBuffering` on stdout in `Host.main` before
emitting the `LISTENING` banner.
**Rationale:** `io2.IO.putBytes` to a **redirected** stdout (a file or pipe, as every
run-script uses) is block-buffered by the GHC-backed runtime, so the banner sat unflushed
while the peer was in fact already listening and serving. The harness's readiness loop
timed out against a perfectly healthy peer — and the failure is deceptive in both
directions: an early probe reports "not ready" on a working peer, and a run that proceeds
anyway happens to succeed, hiding the bug. Pure harness-enablement; no conformance
surface. Generalizes to any substrate whose runtime block-buffers a redirected stdout.
**Escalation:** research (generator-robustness datum; joins the S3 Unison idiom list as
datum 6, with the parse/perf traps 7–9 recorded in `PHASE-S4.md`).
