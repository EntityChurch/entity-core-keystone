# entity-core-protocol-zig — Spec Ambiguity Log

> Discipline: every guess goes here; no silent guesses. Items escalate to
> architecture/research via `research/stewardship/`. Zig is the peer-#4 distant
> idiom (systems language — no GC, explicit allocators, error unions, comptime);
> its value is the NEW probes it surfaces by deriving from V7 in that idiom, plus
> independent corroboration of prior spec-first findings. Entries prefixed
> `A-ZIG-` to namespace from the C#/TS/OCaml logs.
>
> Phase coverage: **S1 (profile), S2 (codec)**. S2+ append below.

---

## A-ZIG-001: §7.4 NORMATIVE `derive_peer_id` (SHA-256-form) contradicts the §1.5 v7.65 canonical-form table (identity-multihash)  ⚑ NEW PROBE (independent corroboration of OCaml A-OC-007)

**V7 section:** §7.4 "Peer ID Derivation — NORMATIVE" vs §1.5 "Canonical form per
`key_type` (v7.65 v1 contract)" + §1.5 line 436 `PeerID := ...`.
**Profile field:** none — a spec-internal contradiction, not a profile field.

**The finding.** §7.4's pseudocode, labelled **NORMATIVE**, derives an Ed25519 peer_id as
`base58(varint(0x01) ‖ varint(0x01) ‖ SHA256(public_key))` — i.e. `hash_type = 0x01`
(SHA-256-form), and the digest is the **SHA-256 of the public key**. The same SHA-256
form appears in the §1.5 `PeerID :=` definition (line 436). But the §1.5 **canonical-form
table** (v7.65 v1 contract, lines 444–448) mandates the **opposite** for Ed25519:
`hash_type = 0x00` **identity-multihash**, where the digest **IS the raw public_key**
(`Base58(varint(0x01) ‖ varint(0x00) ‖ public_key)`). Per §1.5: "Wire `peer_id`s in
tree-path segments and operational use MUST use canonical form," and the SHA-256-form is
explicitly demoted to at most a backwards-compat *decode* form ("Wire-acceptance carve-out,"
line 493: MAY decode non-canonical, MUST canonicalize on storage). The two constructions
are byte-different; a peer that *constructs* peer_ids via the §7.4/§1.5-line-436 SHA-256
form produces non-canonical identities that fail tree-path / cap-pattern string-match and
`authenticate` identity binding against an oracle that expects the §1.5-table identity-multihash.

**Your guess.** Construct Ed25519 peer_ids in **canonical identity-multihash form**
(`hash_type = 0x00`, digest = raw 32-byte public_key) per the §1.5 canonical-form table,
and provide a *decode-only* acceptance path for the SHA-256-form (the carve-out). Do NOT
implement the §7.4 SHA-256 construction as the canonical/production path.

**Rationale.** §1.5's canonical-form table is the v7.65 v1 contract and carries the explicit
MUST + the "why canonical form is mandated" operator-coherence argument (lines 444–491).
§7.4 and the §1.5 line-436 `PeerID :=` skeleton still show the **pre-v7.65** SHA-256-form
labelled NORMATIVE without cross-referencing the canonical-form table that supersedes it for
construction. A fresh spec-first reader following §7.4 literally builds the wrong (non-canonical)
identity. Following the canonical-form table is the spec-consistent reading.

**Escalation:** **arch — §7.4 (and the §1.5 line-436 skeleton) are stale and contradict the
§1.5 canonical-form table.** Proposal candidate: §7.4 should either reference the §1.5
canonical-form table or carry the identity-multihash construction directly for `hash_type=0x00`
key_types, and state that the SHA-256-form is a decode-only backwards-compat form, never the
canonical construction. **This independently corroborates OCaml A-OC-007 from a second,
spec-first peer** — two distant-idiom peers deriving from V7 fresh both implemented §7.4
literally and would both fail handshake; the prior C#/TS peers inherited the correct v7.65
reading from prior knowledge and never flagged the §7.4 staleness. That two independent
spec-first passes hit the identical contradiction is strong signal the spec text needs the fix.

---

## A-ZIG-002: No native Ed448 in the Zig std crypto (agility family gap)

**V7 section:** §1.5 (`key_type` registry, Ed448 = `0x02`, "Validated v7.67 Phase 1"),
§7.3 (signature dispatch from `key_type`); crypto-agility seam (v7.67); agility corpus
(KEY-TYPE-ED448, MATRIX-M2/M6).
**Profile field:** `[codec].ed448_library` = `DEFERRED`.

**Your guess.** Implement the Ed25519 floor natively (`std.crypto.sign.Ed25519`); **defer
Ed448** — `std.crypto` provides Ed25519 but **not** Ed448, and no mature audited pure-Zig
Ed448 library exists. The ECF/Ed25519 conformance floor is Ed25519-only and unaffected;
only the agility higher-bar Ed448 vectors are blocked.

**Rationale.** The codec lower bar is fully met without Ed448. Forcing Ed448 now means an
FFI shim or an unaudited hand-roll — neither justified before the peer (S3) exists.
Native-first stands for the floor.

**Escalation:** research + arch. **Genuine ecosystem finding (mirrors OCaml A-OC-002).**
C# routed the same NSec/libsodium Ed448 gap through BouncyCastle (an independent
pure-managed crypto). Zig, like OCaml, has **no BouncyCastle-equivalent** — so the
"second managed-crypto provider" agility strategy does not generalize to Zig either. Options
when agility is in scope: (a) **FFI the Ed448 family only** (consume `libentitycore_codec`)
while keeping Ed25519 native — the hybrid the LANDSCAPE didn't anticipate, and Zig's
first-class C-ABI FFI (`@cImport`/`extern`) makes this arguably cleaner than in any prior
peer; (b) wait for a pure-Zig audited Ed448; (c) gate Zig at the ECF floor + Ed25519-only
agility subset. **Recommend (a)** when agility is required — it keeps the floor std-only and
isolates the unaudited/foreign surface to the one family that needs it. Two distant-idiom
peers (OCaml, Zig) now independently land on the same Ed448 conclusion.

---

## A-ZIG-003: Async framework — threaded chosen (idiom decision; Zig async in flux; validated at S3)

**V7 section:** §4.8 / §6.11 / §6.12 (N6/N7 — inbound concurrent with outbound; reentrant
transport + `request_id` demux).
**Profile field:** `[async].style` = `threaded`.

**Your guess.** Use **OS threads** (`std.Thread`, in std): one reader thread per connection
demuxing EXECUTE_RESPONSE → pending-correlation by `request_id`, inbound EXECUTE dispatched on
its own thread (§4.8, so a handler awaiting outbound does not block the reader), writes
serialized by a `std.Thread.Mutex`.

**Rationale.** Zig's async story is **in flux**: the pre-0.15 colorless `async`/`await`/
`suspend` was removed and a new `std.Io`-based concurrency model is still landing across
0.15/0.16. Betting the peer on an unsettled language feature is the wrong call; OS threads are
stable, in std, and zero-dep. This mirrors the OCaml S3 decision (A-OC-003 revised: stdlib
threads, not eio). The codec (S2) is pure/synchronous, so this is **not exercised yet** — it is
validated at S3, and a move to the std.Io evented model remains open if it has settled by then
and handler-initiated outbound (origination) enters scope (where structured concurrency earns
its keep — out of the core floor).

**Escalation:** operator — local S3 decision; recorded so S3 doesn't re-litigate it silently.

---

## A-ZIG-004 (informational, not yet a guess): decode-path memory-ownership contract is impl-defined and unspecified — Zig forces the question GC peers hide

**V7 section:** absent (§9.2 decoder requirements, §5.3 envelope — no memory/ownership model;
this is correctly an impl concern, not a wire concern).
**Profile field:** `[memory]` (whole section).

**Note (not a wire-behavior guess — flagged early per ambiguity-log discipline).** Zig has no
GC, so the decode path must define **who frees** a decoded entity, its `included` map, and any
borrowed/owned byte slices — a contract the spec is (correctly) silent on and that every prior
GC'd peer (C#/TS/OCaml) never had to make explicit. The profile's `[memory]` section pins the
chosen contract (`decode_ownership = "caller-frees"`, allocator-threaded, `defer`/`errdefer`
cleanup), and `std.testing.allocator` turns any leak into a **test failure** — so free-correctness
becomes a first-class conformance concern unique to this peer. No spec ambiguity (it is an impl
matter), logged only because it is the Zig-specific design surface S2 must get right and the most
likely source of genuinely-new probes (allocation-failure rollback, partial-decode cleanup) that
no prior peer exercised. **Escalation:** operator — local impl decision; informational for arch
(a data point that the spec's silence on memory ownership is fine for GC peers but leaves the
no-GC peer to author the contract from scratch).

**S2 update (RESOLVED, non-blocking).** S2 implemented the contract as profiled:
`Value` is an owned tree freed by `Value.deinit(gpa)`; encode borrows the tree and owns only the
output buffer; map-key sort scratch + the conformance harness's per-vector arena are `defer`/
`errdefer`-freed; partial-decode rollback on a mid-array/mid-map failure frees the bytes built so
far (`errdefer` over `items[0..built]` / `pairs[0..built]`). `std.testing.allocator` (unit tests) +
a leak-checking `GeneralPurposeAllocator` (conformance exe) report any leak; 69/69 + all selftests
run leak-clean. No new probe surfaced — the no-GC decode path is sound at the codec level.

---

## A-ZIG-005: peer_id conformance vectors pin `hash_type=0x01` over an OPAQUE 32-byte digest, not the §1.5-canonical-table identity-multihash (`hash_type=0x00`)  ⚑ S2 corpus observation (relates to A-ZIG-001)

**V7 section:** §1.2 / §7.3 peer_id grammar; §1.5 canonical-form table (v7.65) vs §7.4 /
§1.5 line-436 SHA-256-form skeleton. **Profile field:** none — a corpus-vs-spec observation.

**The finding.** The S2 peer_id vectors (`peer_id.1/.2/.3`) construct
`Base58(varint(key_type) ‖ varint(hash_type) ‖ digest)` with `key_type=0x01`, **`hash_type=0x01`**,
and an *opaque/synthetic* 32-byte `digest` (all-zero, ascending 0x00..0x1f). That matches the
**§7.4 / §1.5-line-436 SHA-256-form skeleton** (`hash_type=0x01`), NOT the §1.5 v7.65
canonical-form table that A-ZIG-001 identifies as the canonical Ed25519 construction
(`hash_type=0x00` identity-multihash, digest = the raw public_key). The vectors don't derive the
digest from a real Ed25519 pubkey, so they test only the *byte-assembly + Base58 + multi-byte
varint* surface — they do **not** discriminate the §7.4-vs-§1.5-table contradiction. So the corpus
neither confirms nor refutes A-ZIG-001; it is silent on the canonical-construction question.

**Your guess.** `peer_id.format` is **construction-agnostic over the component values** — it takes
`{key_type, hash_type, digest}` and assembles the wire bytes. This (a) reproduces the corpus bytes
exactly (69/69), and (b) lets the S3 peer pass the §1.5-canonical components (`hash_type=0x00`,
digest = raw 32-byte pubkey) per the A-ZIG-001 reading when it constructs *real* identities, while
keeping a decode-side acceptance path for the SHA-256 form. The codec layer fixes no policy; the
*construction* policy (which `hash_type`/digest to feed) lives at the S3 peer boundary.

**Rationale.** Keeping `format` value-agnostic is the right codec-level separation: the byte
assembly is mechanical and corpus-exact, while the canonical-vs-backwards-compat *choice*
(A-ZIG-001) is a peer-construction decision, not a codec one. This avoids baking a contested
construction into the codec and lets S3 honor the §1.5 table without a codec change.

**Escalation:** arch — **adds a data point to A-ZIG-001**: the canonical conformance corpus does
not exercise the §7.4-vs-§1.5-table peer_id construction (opaque digests + `hash_type=0x01` only),
so a peer that follows §7.4 literally would still pass S2 and only fail at live handshake (S4) — a
**coverage gap**. Proposal candidate: add a peer_id vector that derives from a real Ed25519 pubkey
in the §1.5-canonical identity-multihash form (`hash_type=0x00`, digest = pubkey) so the corpus
discriminates the contradiction A-ZIG-001 / OCaml A-OC-007 flag. Non-blocking for the S2 floor.

---

> Phase coverage extended: **S3 (peer machinery)**. S3 entries below.

---

## A-ZIG-003 (RESOLVED at S3): threaded transport validated — std.Thread reader + request_id demux

**V7 section:** §4.8 / §6.11 / §6.12 (N6/N7). **Profile field:** `[async].style = threaded`.

**S3 update (RESOLVED, non-blocking).** The S1 threaded decision (A-ZIG-003) is now exercised
and validated. `transport.zig` implements one `std.Thread` reader per connection demuxing inbound
frames: an EXECUTE_RESPONSE routes to the awaiting outbound caller by `request_id` through a
`std.StringHashMapUnmanaged` pending table guarded by a `std.Thread.Mutex` + `std.Thread.Condition`
(§6.11); an inbound EXECUTE is dispatched on its **own** spawned thread (§4.8) so a handler that
originates an outbound EXECUTE (§6.13(b)) via the per-connection `Io.outbound` reentry seam does NOT
block the reader. Writes are serialized by a per-`Io` write mutex. The S3 smoke proves **8 concurrent
EXECUTEs each correlate to their own EXECUTE_RESPONSE (8/8)** over real loopback TCP — the N7 demux.
No new opam/registry deps; std-only as profiled. The `std.Io` evented model remains the open path
if/when handler-initiated outbound origination enters the core (it is extension-only today, §9.0), and
the swap is localized to `transport.zig`. **Escalation:** operator — S1 decision confirmed at S3.

---

## A-ZIG-006: §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403) request-time boundary  ⚑ independent corroboration of OCaml A-OC-008 / arch F20

**V7 section:** §5.2 (`verify_request` "DENY → 403") vs §4.6 (the authn/authz boundary the handshake draws).
**Profile field:** none — a spec under-specification, not a profile field.

**The finding.** §5.2's request-verification pseudocode collapses every failure to a single "DENY → 403".
But the §4.6 handshake distinguishes **authentication** (proving *who* the caller is — signature present,
signer == author, author identity resolvable + signature verifies) from **authorization** (the authenticated
caller's *capability* admits the request). A spec-first reader who maps §5.2 literally returns 403 for an
unauthenticated request that should be **401** (the caller never proved identity). Implemented as a 3-way
`ReqVerdict { allow, authn_fail → 401, authz_deny → 403 }` plus the §5.5 unresolvable-grantee carve-out
(→ 401, taking precedence over the §5.2 grantee==author mismatch → 403). This is the **third** spec-first
peer to independently hit this (OCaml A-OC-008; arch F20 from the live oracle) — convergence signal that
§5.2 should carry the split explicitly rather than the flat "DENY → 403".

**Your guess.** Split request verification into a 3-way verdict; map authn-class failures → 401,
authz-class DENY → 403, per the §4.6 boundary and the live-oracle/F20 ground truth.

**Rationale.** The flat §5.2 text disagrees with §4.6 and with the conformance oracle; following the
oracle (ground truth per PROMPT-CONSTANTS) is the spec-consistent reading. A fresh §5.2-literal pass
would return 403 where the validator expects 401.

**Escalation:** **arch — §5.2 should reference the §4.6 authn/authz boundary and carry the 401/403 split
(plus the §5.5 unresolvable-grantee → 401 carve-out) explicitly.** Corroborates OCaml A-OC-008 + F20 from
a fourth, distant-idiom spec-first peer.

---

## A-ZIG-007 (informational, S3 design): no-GC peer-surface ownership contract — caller-frees lifted onto the dispatch arena

**V7 section:** absent (memory ownership is correctly an impl concern). **Profile field:** `[memory]` (whole section).

**Note (not a wire-behavior guess).** S3 carried the A-ZIG-004 no-GC ownership contract from the codec up to
the peer surface, where it is materially harder than at the codec (entities flow through the store, the
dispatch chain, and out into response envelopes with overlapping lifetimes). The design ruling, validated
leak-clean by `std.testing.allocator` (unit) + a safety-on `GeneralPurposeAllocator` (smoke): **every
dispatch runs against a per-request `std.heap.ArenaAllocator`** — handlers and the capability chain walk
allocate freely from the arena (the clean Zig answer to a recursive borrow graph: free the whole walk in one
shot), and the final response envelope is **deep-cloned into the long-lived `gpa`** so it survives the arena
reset. The store **owns** persistent entities (it dupes on `bind`/`putEntity`); the `Entity`/`Envelope`
`deinit` contract is documented in `model.zig`. No GC'd peer (C#/TS/OCaml-with-GC) had to author this. No
new probe surfaced at the wire level; the arena-per-request + clone-into-gpa pattern is the reusable Zig
generator guidance for the peer surface. **Escalation:** operator — local impl decision; informational for
arch (confirms the spec's silence on memory ownership is fine for the wire, but the no-GC peer must author a
materially richer contract at the peer surface than at the codec).

---

## A-ZIG-008 (S3 deferral, not a guess): full §9.5 53-type registry deferred to S4 (S3 seeds a minimal subset)

**V7 section:** §9.5 (core type floor). **Profile field:** none — a phase-scoping decision.

**Note.** S3 seeds a **minimal subset** of core types (`type_defs.zig`: ~15 types incl. `system/peer`,
`primitive/*`, `system/hash`, `system/capability/*`) as `system/type` entities at
`/{peer}/system/type/{name}` — enough for the smoke's `system/type/system/peer` get to resolve and for
`system/type/*` discovery-floor reads. The **full 53-type byte-conformant registry** (render-from-model,
diffed byte-for-byte against `type-registry-vectors-v1.cbor` — the OCaml A-OC-006 / TS A-006 design) is
**deferred to S4**, where the `validate-peer type_system` category exercises it. This mirrors every prior
peer (the registry is an S4 conformance surface, not an S3 machinery surface). **Escalation:** operator —
phase-scoping; S4 must land the full registry + the type-registry byte-diff test first in the type_system
category. The §7a `system/validate/*` conformance handlers (echo + dispatch-outbound) are likewise S4 (the
opt-in `--validate` switch + bootstrap are wired into `host.zig` and `Peer.conformance`, but the handler
bodies + entity-native dispatch land in S4 alongside the validator that drives them).

**S4 update (RESOLVED).** The full **§9.5 53-type registry** landed in `type_defs.zig` as a native
render-from-model FSpec/TypeDef builder, seeded at `system/type/<name>`. The `A-ZIG-008` build-time test
renders all 53 and diffs each `content_hash` digest against `type-registry-vectors-v1.cbor` →
**53/53 byte-identical on the first run** (the codec being byte-green at S2 reduced the risk to field-shape
data, caught per-type by the vector diff). Live `type_system` went 21→**108 pass, 0 core fail** under
`--profile core` (194 warn = non-§9.5-floor types, matched-if-present). The §7a `system/validate/*` handler
bodies also landed behind `--validate`: `echo` (§6.13(a), returns params verbatim, unit-tested) and
`dispatch-outbound` (§6.11 reentry via `transport.outboundShim`, caller-minted authority in-band). The
current oracle build does NOT gate `--profile core` on `system/validate/*` (no such symbol in its check
set), so they are cohort-parity surface, not on the core gate. A minimal **§6.13(a) entity-native dispatch
floor** (a registered handler's `expression_path` → evaluate a bound `compute/literal` → `compute/result`)
landed to satisfy the v7.74 §10.1 `core_register_dispatch_roundtrip` gate. No new spec ambiguity surfaced.

---

> Phase coverage extended: **S4 (conformance)**. S4 summary below.

---

## A-ZIG-S4-SUMMARY (informational): `--profile core` PASS, 0 FAIL — no new ambiguity

**V7 section:** V7 v7.72 §9.0 core-profile + v7.74 §10.1 / §9.5a. **Profile field:** none.

**Note.** S4 drove the live Go oracle (`entity-core-go` HEAD, v7.74) from the S3 baseline **568 total ·
94 fail** to **568 · 284 pass · 195 warn · 0 fail · 89 skip → PASS** (machine-verified `summary.failed==0`).
The 94 fails were all behaviors my S3 machinery hadn't yet implemented (the 53-type registry, the bootstrap
op-sets, the v7.74 §10.1 register round-trip + entity-native floor, the §9.5a deletion-marker listing-omit
and peer-root listing), NOT spec contradictions — so **no new spec ambiguity surfaced at S4**. The three
standing spec-first probes were validated live against the oracle: **A-ZIG-001** (canonical
identity-multihash peer_id) by connectivity 22/22 + `authz_grantee_1`; **A-ZIG-006** (§5.2 401/403 split)
by authz/security all-green (403 deny-default, 403 scope-exceeds, 401 unresolvable-grantee); **A-ZIG-005**
unchanged. All three remain arch escalations (corroborating OCaml A-OC-007/008 / arch F20 from a fourth,
distant-idiom spec-first peer). **Escalation:** operator — S4 verdict record; the A-ZIG-001/005/006 arch
escalations stand.
