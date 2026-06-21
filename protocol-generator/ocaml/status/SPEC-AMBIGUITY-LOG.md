# entity-core-protocol-ocaml — Spec Ambiguity Log

> S3 discipline: every guess goes here; no silent guesses. Items escalate to
> architecture/research via `research/stewardship/`. OCaml is the spec-tightness
> peer (#3) — its whole value is the NEW probes it surfaces by deriving from V7
> in a distant idiom. Entries prefixed `A-OC-` to namespace from C#/TS logs.
>
> Phase coverage: **S1 (profile) + S2 (codec) + S3 (peer) + S4 (conformance)**.
> S3/S4 added A-OC-006/007/008 and revised A-OC-003. A-OC-007 (peer-id §7.4 vs
> §1.5) is the headline peer-#3 probe; A-OC-008 corroborates arch F20.

---

## A-OC-001: OCaml native `int` is 63-bit — CBOR integers cannot use it

**V7 section:** ENTITY-CBOR-ENCODING.md §3.2 (integer range 0..2^64-1 / -1..-2^64), §7.1.
**Profile field:** `[codec]` (representation choice).
**Your guess:** Carry CBOR integers as `Int64.t` interpreted as an *unsigned* 64-bit
bit pattern (`Uint of int64` / `Nint of int64`), with all width/minimisation
decisions via `Int64.unsigned_compare`. OCaml's tagged native `int` is 63-bit, so
it silently truncates at 2^62 and cannot represent corpus vector `int.10`
(2^63-1), let alone the full uint64 range.
**Rationale:** The spec range demands a full 64-bit unsigned carrier; `Int64`
with unsigned ops is the OCaml-native way (no bignum dep). Proven by `int.10`
(2^63-1) in the corpus and a self-test at 2^63 and 2^64-1 (`test/selftest.ml`).
**Escalation:** operator — local representation decision. **Cross-peer data point
for arch/research:** re-confirms the integer-width bug class (TS surfaced it as
BigInt, finding F7). Distant idiom, same corner — the 63-bit trap is OCaml-specific
and worth a one-line note in any future "integer representation" guidance.

---

## A-OC-002: No native Ed448 in the OCaml ecosystem (agility family gap) — RESOLVED (hybrid FFI)

**V7 section:** ENTITY-CORE-PROTOCOL-V7.md §1.5 (key_type registry, `ed448`),
crypto-agility seam (v7.67); test-vectors agility corpus `KEY-TYPE-ED448-1`,
`MATRIX-M2/M6`.
**Profile field:** `[codec].ed448_library` = `DEFERRED`.
**Your guess:** Implement the Ed25519 floor natively (mirage-crypto-ec 2.1.0);
**defer Ed448** — `mirage-crypto-ec` does not implement it (mirage/mirage-crypto#112,
open since 2021) and no mature pure-OCaml Ed448 library exists. The 69-vector ECF
floor is Ed25519-only and is unaffected; only the agility higher-bar Ed448 vectors
are blocked.
**Rationale:** The codec lower bar (S7) is fully met without Ed448. Forcing Ed448
now would mean an FFI shim or an unaudited hand-roll — neither justified before
the peer (S3) even exists. Native-first stands for the floor.
**Escalation:** research + arch. **Genuine ecosystem finding:** C# hit the same
NSec/libsodium Ed448 gap and reached for BouncyCastle (an independent pure-managed
crypto). OCaml has **no BouncyCastle-equivalent** for Ed448. So the agility-family
strategy that worked for C# (second crypto provider) does **not** generalise to
OCaml. Options to weigh when agility is in scope: (a) FFI the Ed448 family only
(consume `libentitycore_codec`) while keeping Ed25519 native — a *hybrid* the
LANDSCAPE didn't anticipate; (b) wait for an OCaml Ed448; (c) gate OCaml at the
ECF floor + Ed25519-only agility subset. Recommend (a) when agility is required.

**RESOLUTION — option (a), hybrid FFI.** Ed448 (key_type 0x02) is
now sourced from `libentitycore_codec` over the C-ABI v1.1
(`ec_ed448_{seed_to_pubkey,sign,verify}`); Ed25519 + SHA-256/384 stay native
(`Sign` / `digestif`). Ed448 is the ONLY FFI primitive — SHA-384 is native via
digestif and is cross-checked byte-equal against the FFI `ec_sha384` as a
differential. Scoped to the **opt-in `entitycore_agility` sub-library**
(`src/agility/`, dune-guarded by `EC_AGILITY=1`) so the shipped Ed25519+SHA-256
peer stays self-contained and FFI-free; only consumers needing the higher bar
link the sub-lib + the `.so`. The C and Rust FFI impls are byte-interchangeable
(both verified; provenance via `ec_impl_info`, not the filename). **Byte-verified
25/25** against the agility corpus — `KEY-TYPE-ED448-1` (pubkey / peer_id /
system-peer content_hash / 114-byte signature / sign→verify), `HASH-FORMAT-
SHA-384-1`, `MATRIX-M2/M3/M6` peer identities, and the `VARINT-*` /
`FORMAT-CODE-INTERPRETATION-1` reject probes — via
`protocol-generator/ocaml/run-agility.sh` (harness `test/agility.ml`). The §1.5
size-cutoff (≤32B identity-multihash / >32B SHA-256-form) is exercised across
both key families. The C-ABI dependency + `ec_abi_version` (1.1) are recorded in
`profile.toml [codec].ed448_library` per the lifecycle codec_strategy=ffi clause.
The OCaml agility higher bar (S7) is now met; this finding is **closed**.

---

## A-OC-003: Async framework — eio chosen (idiom decision, validated at S3)

**V7 section:** §4.8 / §6.11 / §6.12 (N6/N7 — inbound concurrent with outbound;
reentrant transport + request_id demux).
**Profile field:** `[async].style` = `eio`.
**Your guess:** Commit to **eio** (OCaml 5 effects-based, direct-style structured
concurrency). The N6/N7 reentrancy invariants map onto eio fibers + switches in
direct style without monadic plumbing. Lwt is the conservative fallback.
**Rationale:** This is the OCaml analogue of C#-`Task` / TS-`Promise` — a genuine
S6 profile fork the kickoff flagged. eio is the forward-looking OCaml-5 idiom and
its structured concurrency fits the reentrant transport. The codec (S2) is pure/
synchronous, so this is **not exercised yet** — it is validated at S3, and the
fallback to Lwt remains open if eio's transport story proves thin.
**Escalation:** operator — local S6 decision; recorded so S3 doesn't re-litigate
it silently.

---

## A-OC-004: `format_code = 128` is *emitted* on construction but *rejected* on receive — asymmetry underspecified  ⚑ NEW PROBE

**V7 section:** ENTITY-CBOR-ENCODING.md §4.3 (Hash Format Registry — 0x80 is
unallocated), §4.7 ("Peers MUST always be able to verify ecfv1-sha256"; unknown
formats). Test surfaces: ECF corpus `content_hash.4` vs agility corpus
`VARINT-MULTIBYTE-1`.
**Profile field:** absent — this is a spec/oracle question, not a profile field.
**Your guess:** On the **construction** side, when handed an explicit
`format_code = 128`, emit `varint(128) ‖ SHA256(ECF({type,data}))` (i.e. treat
128 as "sha256 body, just exercising the multi-byte LEB128 prefix"). This passes
`content_hash.4` (encode_equal). I did **not** wire a receive/decode path that
would reject 128.
**Rationale + the finding:** The two normative corpora treat `format_code = 128`
**oppositely**:
  - **ECF `content_hash.4`** (encode_equal) — construct → MUST *emit*
    `varint(128) ‖ sha256(...)`.
  - **Agility `VARINT-MULTIBYTE-1`** (decode) — receive a hash with format `0x80 01`
    → MUST *reject* with `unsupported_content_hash_format`.
These are reconcilable (construction is told which code to use; the receive path
rejects codes it can't verify), but the asymmetry is **not stated anywhere** — a
spec-first reader deriving the codec from §4.3/§4.7 alone would plausibly reject
128 on *both* sides (since 0x80 is unallocated and §4.7 only mandates sha256), and
then *fail* `content_hash.4`. The ECF corpus silently assumes the encoder will
honour an arbitrary caller-supplied code; the agility corpus assumes the decoder
rejects it. Coming at V7 fresh (no C#/TS source to inherit the resolution from),
OCaml surfaces this as a real gap.
**Escalation:** **arch — spec needs a clarifying sentence.** Proposal candidate:
in §4.3/§4.7 state explicitly that (a) `content_hash` *construction* serialises
whatever `format_code` the caller supplies (forward-compat: the multi-byte varint
is the only thing under test for unallocated codes), while (b) the *receive/verify*
path MUST reject any unsupported/unallocated `format_code` with
`unsupported_content_hash_format`. Without it, the two corpora read as contradictory.
This is exactly the kind of re-probe peer #3 exists to produce (peers #1/#2
inherited the construction-side reading wholesale and never flagged the asymmetry).

---

## A-OC-003 (REVISED at S3): Async framework — eio deferred, stdlib threads chosen

**Update (S3).** The S1 commitment to **eio** was reconsidered when the
peer was actually built. For a `--profile core` peer driven by `validate-peer` in
single-peer mode there is **no handler-initiated outbound dispatch** (origination is
extension-only under §9.0), so the §4.8/§6.11 inbound-concurrent-with-outbound
requirement is satisfied by **one stdlib `Thread` per connection** (`Unix` + `Thread`,
both bundled with the OCaml distribution — **zero new opam deps, zero S11 surface**).
This honors the project's strong dependency-minimization stance (the OCaml peer's
two-opam-dep floor) where eio would have pulled in `eio_main`/`uring`/etc.
**Decision:** stdlib threads now; eio/Lwt remain the documented path for when
handler-initiated outbound (origination, subscription, continuation) enters scope —
that is where structured concurrency earns its keep, and it is out of the core floor.
**Escalation:** operator review — this overturns a logged S1 profile decision. A swap
to eio is localized to `transport.ml` (the `Peer.dispatch` brain is transport-agnostic).

---

## A-OC-006: Type-registry render-from-model — 53/53 byte-identical (resolved)

**V7 section:** §9.5 Core Type Floor Manifest. **Profile field:** type-registry strategy.
**Resolution:** the 53 core types are an **in-code override table** (generated once from
the cross-impl Go-rendered `type-registry-shapes.json` model, committed as
`src/type_defs_data.ml`), rendered through the S2 codec and **diffed byte-for-byte**
against `type-registry-vectors-v1` — **53/53 byte-identical, first run**
(`test/type_registry.ml`). Render-from-model, not ingest-bytes: the peer owns its type
definitions; the canonical vectors are the cross-check. No ambiguity surfaced — the
spec-first field-shape derivation matched the cross-impl model exactly.

---

## A-OC-007: §7.4 NORMATIVE peer-id pseudocode contradicts the §1.5 v7.65 canonical-form table  ⚑ NEW PROBE (peer #3 payoff)

**V7 section:** §7.4 "Peer ID Derivation — NORMATIVE" vs §1.5 "Canonical form per
`key_type` (v7.65 v1 contract)". **Profile field:** none — a spec-internal contradiction.
**The finding.** §7.4's pseudocode, labelled **NORMATIVE**, derives an Ed25519 peer_id as
`Base58(varint(0x01) ‖ varint(0x01) ‖ SHA256(public_key))` — i.e. `hash_type = 0x01`,
the digest is **SHA-256 of the public key**. The §1.5 canonical-form table (v7.65 v1
contract) mandates the **opposite** for Ed25519: `hash_type = 0x00` **identity-multihash**,
the digest **IS the raw public_key** (`Base58(0x01 ‖ 0x00 ‖ public_key)`). The two are
byte-different and a peer that uses the §7.4 form fails connectivity — `authenticate`
step-3 identity binding (`peer_id == derive(public_key)`) mismatches the oracle.
**How peer #3 surfaced it.** Deriving from V7 fresh (no peek at the C#/TS source), the
OCaml peer implemented the §7.4 NORMATIVE pseudocode literally and failed every
handshake with `401 identity_mismatch`. Decoding the oracle's claimed peer_id showed
`01 00 ‖ raw_pubkey` — the §1.5 identity-multihash form. Peers #1/#2 inherited the
correct v7.65 reading from prior knowledge and never flagged the §7.4 staleness.
**Escalation:** **arch — §7.4 is stale and contradicts §1.5.** §7.4 still shows the
pre-v7.65 SHA-256-form as NORMATIVE; it should either reference the §1.5 canonical-form
table or carry the identity-multihash construction directly. (Per §1.5's own
"Wire-acceptance carve-out", the SHA-256-form is at most a backwards-compat *decode*
form, never the canonical *construction* form.) Resolved locally by following §1.5.

---

## A-OC-008: §5.2 "DENY → 403" under-specifies the §4.6 authentication/authorization status split (corroborates arch F20)

**V7 section:** §5.2 verdict-to-status ("DENY → 403 except unresolvable_grantee → 401")
vs §4.6 ("connection-auth is the authentication boundary") + the §3.3 401/403 rows.
**Profile field:** none — status-mapping interpretation.
**The finding.** A fresh reader of §5.2 maps *every* `verify_request` DENY to **403**
(the OCaml peer did). The live oracle requires the request-time **authentication-class**
failures — no/absent/wrong-target/mismatched-signer signature, author not resolvable —
to surface as **401**, distinct from the **authorization-class** capability DENY (403).
§5.2's flat "DENY → 403" text does not draw the boundary that §4.6 draws for the connect
phase; the split must be carried into request-time verification too. **This corroborates
arch finding F20 from a third, spec-first peer** — the §5.2 text is the stale surface;
the oracle (and §4.6's boundary) is ground truth. Resolved by a 3-way verdict
(`Req_authn_fail` → 401, `Req_authz_deny` → 403, `Req_allow`). **Escalation:** arch —
tighten §5.2 to state the authn(401)/authz(403) split explicitly (or cross-reference §4.6),
so the §5.2 pseudocode stops reading as "403 for everything".

---

## A-OC-009: unregister type-teardown + system-path registration guard (Phase B / F1) · informational

**V7 section:** §6.2 ("`unregister` reverses all five steps"); §6.2 (user handlers MUST NOT register at `system/*`)
**Cross-impl:** C# A-012, TS A-012.
**Decision (F1):** `unregister` removes the manifest, interface, grant, and grant-signature (writer/unregister symmetry — the half-removed grant/sig state is the §10.1 hazard the teardown coverage prevents). It does **not** remove installed `system/type/*` entities — types may be shared across handlers, so blind removal on unregister is unsafe with no spec-pinned ownership/refcount model; left in place. System-path registration is governed solely by the dispatch cap-check on `EXECUTE.resource` (`system/*` scope required), per §6.2's registration-cap examples — no separate user-vs-bootstrap guard, since every wire `register` is by definition non-bootstrap and the cap scope is the enforcement.
**Escalation:** operator/architecture — informational. A type-ownership/refcount model for unregister teardown would be a spec addition.

## A-OC-010: §10.1 register dispatch round-trip pulls compute/entity-native vocab into the core gate (Phase B / F1) · ESCALATE: arch

**V7 section:** §6.13(a), §6.2 (behavioral register); PROPOSAL-V7-V7.74 §10.1; §9.4 (body-binding mechanism impl-private)
**Cross-impl:** C# A-011, TS A-011.
**Finding:** the Go `core_register_gate.go` §10.1 round-trip hardcodes Go's *entity-native compute* as the body-binding seam — it puts a `compute/literal(42)` at `<pattern>/expr`, registers with `expression_path`, dispatches op `compute`, and asserts the response round-trips `42`. But `EvaluateExpression` is the **compute extension's** pluggable seam in Go (`core/protocol/dispatch.go`); a pure core peer has nothing wired, so the `--profile core` round-trip cannot pass without a core peer evaluating a `compute/literal` — extension vocab pulled into the core gate. Keystone (OCaml `Peer.entity_native_dispatch`) ships the minimal literal-only body-binding seam (reads `compute/literal`, emits `compute/result`; type labels only, NOT in the §9.5 floor) to keep the round-trip GREEN; richer bodies → 501. The five writes (gate steps 1–3, 5) are unambiguous core and fully covered; only step 4 (dispatch round-trip) carries the coupling. Options for arch/Go: (a) §10.1 SKIPs step 4 for non-compute peers; (b) a minimal `compute/literal` evaluator is declared part of the core body-binding floor (then it belongs in spec, not just the gate); (c) peer-declared body-binding-seam negotiation. Verified in-process by `test/selftest.ml`.

## A-OC-002 / A-OC-003-revised UPDATE: handler-initiated outbound is core floor (Phase B / F2) — misclassification corrected

**V7 section:** §6.13(b), §4.8, §6.11, §9.1 floor (v7.74 A2 erratum).
**Correction:** A-OC-003-revised (S3) and the prior `transport.ml` header read the validate-peer `origination`-category skip under `--profile core` as a *capability-scope ruling* — "no handler initiates outbound; origination is extension-only under §9.0," so one-thread-per-connection sufficed. **v7.74 A2 corrects this at the spec level**: §4.8 + §6.11 (the outbound-from-handlers seam) are part of the §9.1 floor under **both** profiles; the category-skip is a single-peer test-harness limit, NOT a capability-scope ruling. F2 builds the seam from zero (OCaml had no client transport / reentry at all): `transport.ml` now demuxes EXECUTE_RESPONSE → pending-correlation by `request_id`, dispatches inbound EXECUTE on its own thread (§4.8 so a handler awaiting outbound does not block the reader), serializes writes, and exposes the per-connection outbound primitive via `Peer.conn.outbound` + the `Peer.outbound_dispatch` handler-facing closure. Present even though no core handler originates (§6.13(b)). The stale §9.0 deferral header is swept. Verified by the socketpair reentry test in `test/selftest.ml`. (A-OC-002 Ed448 gap is unaffected — still informational.)
