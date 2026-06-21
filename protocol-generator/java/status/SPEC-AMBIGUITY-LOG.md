# entity-core-protocol-java — Spec Ambiguity Log

> Discipline: every guess goes here; no silent guesses. Items escalate to
> architecture/research via `research/stewardship/`. Java is peer #7 — the
> MAINSTREAM OO/static idiom (classes + interfaces, checked exceptions, JVM
> threading, a vendor-curated stdlib). Its idiom axes are largely SATURATED by the
> prior peers, so the expected spec-refinement yield is small — but any NEW finding
> a mainstream stack surfaces is HIGH-signal (a defect the most-deployed enterprise
> language hits is one almost everyone hits). Entries prefixed `A-JAVA-` to
> namespace from the C#/TS/OCaml/Elixir/Zig/CL logs.
>
> Phase coverage: **S1 (profile)** · **S2 (codec)** · **S3 (peer)** · **S4 (conformance)** ·
> **S5 (publish) — FINALIZED**. Every item below is resolved-in-peer and owner-routed; none
> block release. The arch-bound items (⚑) are consolidated for the escalation bundle in
> `status/ARCHITECTURE-REVIEW.md` Part D. S5 finalization summary at the foot of this file.

---

## A-JAVA-001: spec-data snapshot stops at v7.72 while spec HEAD is v7.74 (folded) — corroborates A-CL-001

**V7 section:** repo-wide (snapshot vs HEAD), not a single section.
**Profile field:** `[spec].v7_version_pinned` / `codec_corpus`.
**Your guess:** Derive the profile + codec from `spec-data/v7.72` (the latest
snapshot) and the `test-vectors/v0.8.0` corpus (byte-identical encoding spec
v7.71→v7.72, SHA-verified upstream per the cohort). The v7.73 (nonce-echo §4.6) and
v7.74 (register/outbound/emit/owner-cap §6.13/§6.9a + §7a conformance handlers)
folds are **peer-layer** (S3+), not codec — so S1/S2 are unaffected. Resync the peer
layer to the v7.74 surface at S3, mirroring the cohort builds.
**Rationale:** Same posture every prior peer took (A-CL-001, A-ELX-001, A-OC-S3
resyncs). The codec scope is clean at the snapshot; the peer-layer skew is real but
does not block S1/S2.
**Escalation:** **research/arch** — the v7.73/v7.74 spec-data snapshot is still
missing; the keystone needs a SHA-pinned snapshot at HEAD so the S3 peer-layer build
traces to a pinned spec copy rather than to sibling peers. Corroborates A-CL-001 (now
the second cohort to re-flag the same provenance gap). NON-blocking for S1/S2.

---

## A-JAVA-002: Ed448 — JDK SunEC native (default) vs BouncyCastle opt-in cross-check; raw-key spike at S2

**V7 section:** §1.5 (key_type registry, `ed448` `0x02` validated, v7.67 seed table);
agility corpus `KEY-TYPE-ED448-1`, `HASH-FORMAT-SHA-384-1`, `MATRIX-M2/M3/M6`.
**Profile field:** `[codec].ed448_library`.
**Your guess:** Source Ed448 (and Ed25519, SHA-256/384) **natively from the JDK
SunEC provider** by default — `Signature("Ed448")`, `NamedParameterSpec.ED448`,
`MessageDigest("SHA-384")` — no FFI, no opt-in sub-library, no hybrid. The §9.1
floor (Ed25519 + SHA-256) AND the agility higher bar (Ed448 + SHA-384) are both
reachable from the default build with ZERO third-party dependency. **BouncyCastle
(`bcprov-jdk18on` 1.80) is the OPT-IN agility cross-check / fallback ONLY**; the core
build stays BouncyCastle-FREE.
**Rationale + the headline.** This is the **crypto-axis finding for Java**: the JDK
is the first peer whose vendor-curated stdlib closes the FULL agility bar natively —
the contrast with OCaml (A-OC-002, C-ABI Ed448) and Zig (A-ZIG-002, flat gap), and
the company of CL (pure-Lisp ironclad) and Elixir (OTP NIF) but via a third
mechanism (vendor stdlib provider). Java is ALSO the first peer where the SAME
ecosystem offers BOTH a native-stdlib agility path AND an independent managed
cross-check (BouncyCastle, the C# A-009 precedent) — so the agility corpus gets a
free byte-equality cross-check at no runtime-dependency cost. **The S2 spike** (why
this is logged, not just decided): the JDK exposes EdEC keys as an
(x-sign-bit, y-coordinate) point, NOT a raw byte string — so the raw 32-byte
(Ed25519) / 57-byte (Ed448) public-key extraction (for the §1.5 identity-multihash
peer_id) and raw-seed key construction need explicit encoding handling that must be
verified against an RFC-8032 KAT before trust. If a SunEC Ed448 edge bites
(raw-key encoding, a stripped-JDK provider-availability quirk), fall back to
BouncyCastle for the agility corpus (the route is pre-pinned).
**Escalation:** operator/research — local crypto-source decision; the agility-axis
data point (vendor-stdlib-closes-the-bar + native cross-check available) goes in the
cross-peer architectural review ledger. NON-blocking for the §9.1 codec floor (which
is Ed25519 + SHA-256, both unambiguously JDK-native).

**RESOLVED AT S2.** Decision: **SunEC for sign/verify (both curves, core, zero-dep);
native derivation for the raw public key; BouncyCastle stays opt-in/test-scope.** The
S2 spike confirmed SunEC Ed25519 (RFC-8032 TEST-1 sig byte-equal) and Ed448 (agility
KAT sig byte-equal), and the `BouncyCastleCrossCheckTest` shows SunEC's Ed448 signature
== BC's and the native pubkey == BC's, byte-for-byte. The CORE build is BouncyCastle-
free. The S1 bet ("SunEC closes the FULL agility bar natively") is TRUE for sign/verify
but the raw-PUBLIC-KEY half has a JDK gap — split out as **A-JAVA-007** below. The
§9.1 floor + the agility signature primitive are zero-dep native; A-JAVA-002 is closed.

---

## A-JAVA-003: Concurrency model — JVM threads + JDK 21 virtual threads (idiom decision, validated at S3)

**V7 section:** §4.8 / §6.11 / §6.12 (N6/N7 — inbound concurrent with outbound;
reentrant transport + request_id demux; §6.11 reentry over the inbound connection).
**Profile field:** `[async].style` = `threaded`.
**Your guess:** Use **one thread per connection** (`java.lang.Thread`, carried on
**JDK 21 virtual threads** — Project Loom, JEP 444 GA in 21) plus a
`ConcurrentHashMap<requestId, CompletableFuture>` correlation table. The public
surface is blocking + a `CompletableFuture<T>` async variant. No third-party
dependency (`java.util.concurrent` is stdlib).
**Rationale:** The Java analogue of the C#-`Task` / TS-`Promise` / OCaml-`eio` /
Elixir-processes / Zig-`std.Thread` / CL-`sb-thread` fork; for a `--profile core`
peer the N6/N7 invariants are met by one-thread-per-connection without structured-
concurrency machinery, exactly the shape OCaml/Zig/CL arrived at with stdlib threads
(A-OC-003-revised). The Java-21-specific note: virtual threads make
thread-per-connection cheap — the model other peers justified against thread cost is
the *recommended* model on Loom. The codec (S2) is pure/synchronous, so this is
**not exercised yet** — validated at S3.
**Escalation:** operator — local S6 decision; recorded so S3 does not re-litigate it
silently. Revisit if handler-initiated outbound (origination) enters scope.

**RESOLVED AT S3.** The model is **one virtual-thread reader per connection + one
virtual thread per inbound EXECUTE** (§4.8), with a
`ConcurrentHashMap<requestId, SynchronousQueue>` rendezvous table for the §6.11 demux
and a per-connection write lock. The accept loop stays a platform thread (a long-lived
blocking accept has no carrier benefit). The Java-21 refinement that DID land: virtual
threads (JEP 444 GA in 21) make thread-per-connection AND thread-per-request cheap, so
Java spends a thread per inbound EXECUTE (not merely per connection) without the cost
concern other peers reasoned around — the model they justified *against* OS-thread cost
is the *recommended* Loom carrier. Validated by the smoke's 8/8 concurrent request_id
demux (N7) over real loopback TCP, GREEN first run, zero third-party dep. The §6.13(b)
reentry seam (`Io.outbound`) sends + awaits-correlated-reply on the same connection; a
close wakes a parked waiter via a `closed` flag polled on the rendezvous timeout. The
S1 threaded decision stands. `java.nio` async / `CompletableFuture`-everywhere remains
the open path only if handler-initiated outbound origination enters the CORE
(extension-only today); the swap is localized to `Transport.java`.

---

## A-JAVA-008: full §9.5 53-type registry deferred to S4 (deferral, not a guess; mirrors A-ZIG-008)

**V7 section:** §9.5 (the core type-registry floor) + the `type_system` validate-peer
oracle category.
**Profile field:** `[layout]` / N/A (peer-layer build scope, not a profile value).
**The deferral.** S3 seeds a MINIMAL core-type subset (`CoreTypes.java`: the eight ECF
primitives + the system entities the peer materializes — `system/peer`,
`system/signature`, `system/hash`, `system/capability/token`, `system/handler`,
`system/handler/interface`) so `system/type/*` EXISTS under the local namespace (the
§4.4 discovery floor grants `get` on it) and the loopback can probe it. The FULL 53-type
registry, render-from-model with byte-exact content_hashes diffed against the canonical
type-registry vectors, is the `type_system` oracle category and lands at S4. ALSO
deferred: the `system/type:validate` handler body (currently a placeholder echo) needs a
real type-validate at S4.
**Rationale.** Exactly the Zig deferral (A-ZIG-008): the full registry does not block the
core loopback (the smoke probes a handler-interface path inside the discovery floor),
and render-from-model wants the canonical shapes pinned. The CL peer published all 53 at
S3 from an in-code data table; Java parks that to S4 to keep S3 scoped to the wire
surface, matching the systems-peer (Zig) precedent over the image-based (CL) one.
**Escalation:** none (S4-internal sequencing). NON-blocking.
**CLOSED at S4.** Full 53-type §9.5 registry rendered from the in-code
override table (`CoreTypeDefs.java`, generated by `tools/gen-typedefs.py` from the shared
cross-impl `type-registry-shapes.json`, same 53-name floor + order as OCaml/CL/Go's
`coreTypeFloor`). Diffed **53/53 byte-identical** to `type-registry-vectors-v1.diag`
(`TypeRegistryTest`, peer-side dual of the S2 corpus) AND independently confirmed by the
live oracle's `type_system _match` checks (53/53, 0 FAIL). The `system/type:validate`
placeholder echo is replaced with a real `TypeHandler.validate` body (required-field +
unevaluated-field structural validation against the registered type def, returning
`system/type/validate-result`); note the `type` category is EXTENSION (auto-skipped under
`--profile core`), so the body is cohort-parity surface, not a core gate. RESOLVED.

---

## A-JAVA-010: §1.1 entity `data` is an ARBITRARY ECF value (not necessarily a map) — latent everywhere a peer models data as a map; surfaced by the §7b concurrency gate's primitive/string staging ⚑

**V7 section:** §1.1 (entity = `{type, data, content_hash}`; `data` is "an ECF value").
**Profile field:** N/A (peer data-model invariant).
**The bug it caught.** The Java `Entity` modeled `data` as `EcfValue.Map` (every core
*protocol* entity — handler manifests, grants, type defs, listings — happens to be a map,
and the S2 corpus + S3 loopback only ever round-tripped map-data entities, so the gap was
latent through three phases). The §7b concurrency gate (`t1_1`/`t1_3`/`t2_1`) stages
**`primitive/string`** entities via `tree.put` to `system/validate/concurrency/*`; those
have **scalar** data (a CBOR text string, not a map). `Entity.ofCbor` hard-rejected
non-map data with `IllegalArgumentException` → the dispatcher's catch-all turned it into a
silent **500**, which the gate reported (generically) as "no write grant" → 3 un-allowlisted
SKIPs → `Result: FAIL`. The actual cause was a peer data-model bug, not a grant issue.
**Your guess (the fix).** Generalize `Entity.rawData` to `EcfValue` (any node), add
`makeRaw(type, EcfValue)` and `rawData()`; keep `data()` returning a null-safe map *view*
(the map itself for protocol entities, empty map for scalars) so all existing field-readers
and the 8 `.data()` call sites are unchanged. `ofCbor` now accepts any non-null `data`.
With the fix, all 5 concurrency checks PASS (Java virtual threads handle demux + head-of-line
+ sustained load natively).
**Rationale / why it's worth recording.** Java is peer #7 (the saturated-axes,
high-signal-when-novel probe). This is a **latent interop trap**: any peer whose internal
entity model assumes `data: map` — natural in statically-typed OO/record idioms — passes S2
(map corpus) and S3 (map loopback) green, then silently 500s on the FIRST scalar-data
entity it's asked to store/relay (and the concurrency gate is the first place the cohort
exercises that). The spec says "ECF value" but the cohort's lower-bar surfaces never force
the non-map case, so the assumption is easy to bake in undetected.
**Escalation:** **arch/research** — recommend (a) a conformance vector / S2-corpus entry
with a scalar-data entity (e.g. a stored `primitive/string`) so the map-only assumption is
caught at the codec/peer bar, not only at the §7b gate; and (b) a one-line §1.1 emphasis
that `data` MAY be a non-container scalar. NON-blocking (resolved locally, gate GREEN). ⚑ ARCH-BOUND.

---

## A-JAVA-011: §7b concurrency gate now GATES `--profile core` at oracle HEAD 749e57e (was a §9.0 drift-list carve-out); §7a echo/dispatch-outbound is a generic relay returning the downstream result-entity verbatim — corroborates the §7b concurrency-gate matrix ruling #2

**V7 section:** GUIDE-CONFORMANCE §7b (concurrency) + §7a.1 (echo/dispatch-outbound shape).
**Profile field:** N/A (oracle gate scope + handler-result shape).
**Observation (oracle provenance, not a guess).** Built against the mainline's in-flight
Go oracle HEAD `749e57e` ("validate-peer/concurrency: keystone §7b matrix fixes (3 Go-side
bugs)"), which is **14 commits ahead of origin/main** (committed-but-unpushed). At this
HEAD the §7b concurrency category **runs and gates under `--profile core`** (layered
conditional, not skipped) → the core gate is now **573 checks** (568 + 5 concurrency), all
5 PASSing for Java. This is a clean superset of the OCaml/CL fixed-point (568 · 284P), not a
regression: total 573 · **289P/195W/0F/89S**. Must be re-confirmed when this HEAD lands on
origin/main (the +5 concurrency PASS depends on the Go-side `runT22` ephemeral-fallback fix
+ the relay-shape ruling being upstream).
**Relay-shape (applied, was a cohort gap).** Per the §7b concurrency-gate matrix ruling #2,
`system/validate/dispatch-outbound` is a **generic relay**: it forwards the
inbound `value` bytes (the echo `{value: X}` params) **verbatim** as the outbound EXECUTE's
params data and returns the downstream's **result entity verbatim** — no re-wrap, no unwrap.
The S3 Java handler re-wrapped (`{value: value}`), double-nesting so `echoed.value` decoded
as a MAP not a string (the exact non-conformant party the keystone matrix caught in the
cohort). Fixed `DispatchOutboundHandler` to pass the value map through unwrapped →
`t1_2_concurrent_reentry` PASS + origination-core `dispatch_outbound_reentry` PASS.
**Escalation:** **arch/research** — confirm §7b-gates-core is intended for v0.1 (it changes
the canonical core gate from 568 to 573), and re-confirm Java's 573·0F once `749e57e` is
pushed to origin/main. NON-blocking (gate GREEN at the settled HEAD). ⚑ ARCH-BOUND.

---

## A-JAVA-009: §5.2 flat "DENY → 403" under-specifies the §4.6 authn(401)/authz(403) request-time boundary — corroborates A-ZIG-006 / A-OC-008 (arch F20) ⚑

**V7 section:** §5.2 (`verify_request`) vs §4.6 (the authn/authz split) + §5.5 (the
unresolvable-grantee carve-out).
**Profile field:** `[error_model]` (the exception-subtype → status mapping).
**The finding.** §5.2's `verify_request` pseudocode reads as a binary allow/deny, but the
wire status surface distinguishes **401 (authentication failed: bad/absent request
signature, signer≠author, author identity unresolvable)** from **403 (capability denied:
no cap, chain invalid, grantee≠author, revoked)**, and §5.5 carves out a THIRD case —
an **unresolvable grantee mid-chain → 401**, not 403. Implemented as a three-way verdict
(`Capability.RequestVerdict` = ALLOW / AUTHN_FAIL / AUTHZ_DENY) plus the
`UnresolvableGrantee` signal the dispatcher maps to 401. A flat boolean would mis-status
the authn cases as 403.
**Your guess (the resolution, implemented).** Return a three-way verdict from
`verifyRequest`; map AUTHN_FAIL → 401, AUTHZ_DENY → 403, `UnresolvableGrantee` → 401.
This is the §4.6 boundary applied at request time, derived from V7 (spec-first), not
copied from the oracle.
**Why this matters (the convergence).** This is the **fifth peer to independently hit the
same under-spec** (OCaml A-OC-008 / arch F20, Zig A-ZIG-006, and the CL/cohort
421-carve-out reading) — now mainstream-stack corroboration that §5.2 should name the
401/403/401-carve-out trichotomy explicitly rather than leave it implied by the status
table. A "boring enterprise" language reading §5.2 straight lands on the same gap.
**Escalation:** **arch — §5.2 should make the authn(401)/authz(403)/unresolvable-grantee(401)
trichotomy normative** rather than a flat DENY. Resolved locally; corroborates F20. ⚑
ARCH-BOUND.

## A-JAVA-004: §7.4 NORMATIVE peer-id pseudocode contradicts the §1.5 v7.65 canonical-form table — FOURTH spec-first peer (corroborates A-ZIG-001 / A-OC-007 / A-CL-002) ⚑

**V7 section:** §7.4 "Peer ID Derivation — NORMATIVE" (the `derive_peer_id`
pseudocode area) + the §1.5 path skeleton
(`Base58(varint(key_type) || varint(hash_type) || SHA256(public_key))`) vs the §1.5
"Canonical form per `key_type` (v7.65 v1 contract)" table.
**Profile field:** `[spec]` note + `[codec].ed25519_library` (recorded as a
construction mandate).
**The finding (verified directly in `spec-data/v7.72`).** §1.5 **line 448** (the
canonical-form table) declares Ed25519 → `hash_type = 0x00` **identity-multihash**,
"The digest IS the public_key (v7.64)" — i.e. the raw public key bytes, NO hash. But
§1.5 **line 436** (the path skeleton) and **lines 437–438, 442** still show
`PeerID := Base58(varint(key_type) || varint(hash_type) || SHA256(public_key))` with
`hash_type = 0x01` and even assert "peer-IDs at the current spec are 34 bytes total"
— the stale pre-v7.65 SHA-256 form. **Line 3561** (in the §7.4 / §8 crypto area)
likewise still emits `bytes([0x00]) + digest ; 33 bytes: format code + digest` for
content-hash and the surrounding §7.4 `derive_peer_id` text follows the SHA-256-form
skeleton. The two are byte-different; a peer that constructs from the §7.4 / line-436
form fails `authenticate` step-3 identity binding (`peer_id == derive(public_key)`)
against any conforming peer → `401 identity_mismatch`. Per §1.5's own
"Wire-acceptance carve-out" (Amendment 4 / D, line 493) the SHA-256 form is at most a
backwards-compat *decode* form, never the canonical *construction* form.
**Your guess (the mandate baked into the profile):** derive the Ed25519 peer_id from
the **§1.5 canonical-form table** (`hash_type = 0x00`, raw pubkey) and **ignore the
stale §7.4 / line-436 SHA-256 form**.
**Why this is logged proactively (the saved cycle).** S2's conformance corpus uses
**opaque digests**, so a WRONG peer_id construction **passes S2** and only blows up
at the **S4 handshake**. Three prior spec-first peers (Zig A-ZIG-001, OCaml A-OC-007,
Common Lisp A-CL-002) hit or pre-resolved this; baking the §1.5 form into the profile
at S1 dodges a fourth debug cycle.
**Escalation:** **arch — §7.4 (and the §1.5 line-436 skeleton + line-3561 area) are
STALE and contradict the §1.5 v7.65 canonical-form table.** §7.4 should reference the
§1.5 table or carry the identity-multihash construction directly. This is the
**FOURTH spec-first peer** to corroborate the contradiction (after Zig, OCaml, CL) —
now decisive evidence of a real spec defect that a routine read still walks straight
into. Resolved locally by following §1.5. ⚑ ARCH-BOUND.

---

## A-JAVA-005: Maven Central publish requires a verified reverse-DNS namespace — packaging note (S5)

**V7 section:** absent (build/packaging, not a spec question).
**Profile field:** `[publishing]` (`group_id` / `repository_url`).
**Your guess:** Use the reverse-DNS Maven coordinate `org.entitycore:entity-core-protocol`
and leave `repository_url` empty until first publish. Maven Central (Sonatype Central
Portal) requires the publisher to **verify ownership of the `org.entitycore`
namespace** (DNS TXT record or a hosting-provider proof) before the first deploy — a
step that cannot be completed at S1 (no namespace claimed yet).
**Rationale:** Every prior peer parked its registry coordinate similarly (C#
`repository_url = ""`, OCaml/Zig decentralized). The Java specific is the namespace-
verification gate, which is a one-time S5 operator action, not a code decision.
**Escalation:** **operator** — S5 registry step; claim + verify the `org.entitycore`
namespace (or adopt whatever reverse-DNS the project owns) before the first deploy.
NON-blocking for S1–S4. Recorded so S5 does not treat the empty coordinate as a gap.

---

## A-JAVA-006: Maven 3.9.9 sha512 is an S1-authored sentinel (filled at S2 per the no-fetch boundary)

**V7 section:** absent (toolchain/supply-chain).
**Profile field:** `[deps].maven` (the Containerfile `MAVEN_SHA512` ARG).
**Your guess:** The Containerfile fetches Apache Maven 3.9.9 from the Apache dist
mirror with a `sha512sum -c` gate, but the checksum value is a
`REPLACE_WITH_VERIFIED_SHA512_AT_S2` sentinel authored at S1 (S1 does NOT run
podman / fetch the tarball, per the phase boundary). S2 (first build) MUST fetch the
published `apache-maven-3.9.9-bin.tar.gz.sha512` from downloads.apache.org, verify,
and substitute the real digest — the build **fails closed** until then (the sentinel
will never match). The JDK sha256 (`ea3b9bd4…896a4`) is already filled (read from
the Adoptium release API at S1 — a metadata lookup, not a toolchain fetch).
**Rationale:** Honors the S1 "no build / no toolchain fetch" boundary while keeping
the supply chain pinned: the recipe is checksum-gated by construction, the value is
filled by the phase actually allowed to fetch. The zig-toolchain `ZIG_SHA256`
sentinel precedent. Maven is a reviewed-channel build tool, so the ≥30-day age floor
relaxes, but the exact pin + verified digest still stand for reproducibility +
integrity.
**Escalation:** operator — S2 must fill the verified sha512 before the first build is
trusted. NON-blocking for S1 (authoring only).

**RESOLVED AT S2.** Maven 3.9.9 sha512 filled:
`a555254d6b53d267965a3404ecb14e53c3827c09c3b94b5678835887ab404556bfaf78dcfe03ba76fa2508649dca8531c74bca4d5846513522404d48e8c4ac8b`,
verified against the published `.sha512` on **both** `downloads.apache.org` and
`archive.apache.org/dist` (byte-identical). The Containerfile build fails closed on
mismatch and now PASSES with the real digest. ALSO fixed two adjacent S1-carry build
defects (operator notes, not spec): (1) `dlcdn.apache.org` 404s on 3.9.9 (current-only
mirror) → switched the fetch to the permanent `archive.apache.org/dist`; (2) the
S1-authored `prefetch-pom.xml` had illegal `--` sequences inside an XML comment →
rewrote the comment. Container builds clean; A-JAVA-006 closed.

---

## A-JAVA-007: JDK has no SHAKE256 + SunEC exposes no seed→public-key API — native Ed448 raw-pubkey derivation must be hand-rolled ⚑

**V7 section:** §1.5 (key_type registry; the identity-multihash peer_id construction
needs the RAW public key), §8 (crypto primitives). Not a spec *defect* — a JDK
platform-capability gap that shapes the Java crypto sourcing.
**Profile field:** `[codec].ed448_library` / `[codec].ed25519_library` (raw-key
extraction note carried from A-JAVA-002).
**The finding (verified in-container at S2).** Two adjacent JDK gaps make a fully
JDK-native, dependency-free Ed448 *public-key* path impossible via the obvious route:
1. **SunEC has no seed→public-point API.** A private key built from a raw seed
   (`EdECPrivateKeySpec`) carries ONLY the seed in its PKCS#8 encoding (verified:
   `302e020100300506032b6570042204200000…`), and there is no public method to recover
   the public point from it. SunEC computes the public key internally during signing
   but never exposes it. (A `PublicKey`, once you HAVE one, does expose the point via
   `EdECPublicKey.getPoint()` — an `EdECPoint` of y-coordinate + x-sign-bit — so the
   raw-byte EXTRACTION from a known public key is fine; it's the seed→public step that
   has no API.)
2. **The JDK `MessageDigest` registry ships no SHAKE256.** It has SHA3-{224,256,384,512}
   (fixed output) and SHA-512, but NOT SHAKE256 (the extendable-output function). The
   RFC-8032 Ed448 seed-expansion REQUIRES SHAKE256, so even a hand-rolled scalar-mult
   pubkey derivation can't run on JDK digests alone. (Ed25519's expansion uses SHA-512,
   which the JDK HAS — so Ed25519 native derivation is unblocked; only Ed448 hits this.)
**Your guess (the resolution, implemented + verified).** Keep the core BouncyCastle-
free by **hand-rolling the two missing primitives**: a FIPS-202 SHAKE256 (`Shake256`,
verified vs the NIST `SHAKE256("")` KAT) and the RFC-8032 raw-pubkey derivation for
both curves (`EdKeyDerivation`: SHA-512/SHAKE256 expand → clamp → BigInteger Edwards
base-point scalar multiply → little-endian encode). Verified byte-equal to the Ed25519
RFC-8032 TEST-1 pubkey, the agility `KEY-TYPE-ED448-1` pubkey pin, AND BouncyCastle's
`Ed448PublicKeyParameters` (opt-in cross-check). This is the same hand-roll-the-missing-
primitive stance the codec already takes for CBOR/base58/varint.
**Rationale.** The high-signal mainstream-stack finding (Java is peer #7, the
saturated-axes probe): the JDK's vendor-curated crypto stdlib closes the agility
SIGNATURE bar natively but leaves a RAW-PUBLIC-KEY gap (no SHAKE256, no seed→public).
A "boring enterprise" stack hitting this means it's a gap most JVM implementers of an
identity-multihash peer_id will hit — worth recording. The cost was ~250 lines of
pure, dependency-free code; no FFI, no BouncyCastle in the core, supply-chain-clean.
**Escalation:** **arch/research** — cross-peer crypto ledger data point: the JDK
(SunEC + SunMessageDigest) closes Ed25519/Ed448 *sign/verify* with zero deps but NOT
raw-pubkey derivation (no SHAKE256 XOF, no seed→public API). Contrast: OCaml A-OC-002
(C-ABI Ed448), Zig A-ZIG-002 (flat gap), CL/Elixir (pure native incl. their own
SHAKE/SHA3). Java's answer = SunEC-sign + hand-rolled-derive. NON-blocking (resolved
locally, byte-verified). ⚑ ARCH-BOUND.

---

## S5 FINALIZATION — owner + escalation status, all items

S5 closes the log. Every item is resolved-in-peer; none block release. The arch-bound (⚑)
items are lifted into the consolidated escalation bundle in `status/ARCHITECTURE-REVIEW.md`
Part D. Final disposition:

| Item | ⚑ | Owner | Disposition |
|---|---|---|---|
| **A-JAVA-004** §7.4-vs-§1.5 peer-id | ⚑ | architecture | OPEN-to-arch; **4th-peer convergence** (silent-handshake-kill). Resolved via §1.5; peer_id byte-identical to CL. |
| **A-JAVA-009** §5.2 401/403 boundary | ⚑ | architecture | OPEN-to-arch; **5th-peer convergence** (corroborates F20). Resolved via 3-way verdict. |
| **A-JAVA-010** §1.1 scalar entity `data` | ⚑ | arch/research | OPEN-to-arch; **NEW** high-signal interop trap. Recommend scalar-data vector + §1.1 emphasis. Resolved via generalized `Entity`. |
| **A-JAVA-007** JDK raw-pubkey gap | ⚑ | arch/research | OPEN-to-arch; **NEW** crypto-ledger data point. Resolved via hand-rolled KAT-verified SHAKE256 + derivation. |
| **A-JAVA-011** §7b-gates-core (568→573) | ⚑ | arch/research | OPEN-to-arch; **needs the v0.1 §7b-gates-core ruling + re-confirm when `749e57e` lands upstream** (THE merge/handoff item). Gate GREEN at the settled HEAD. |
| **A-JAVA-001** v7.73/v7.74 snapshot | — | research/arch | OPEN; provenance gap, corroborates A-CL-001. NON-blocking. |
| **A-JAVA-005** Maven Central namespace | — | operator | DEFERRED (S5 registry step). Maven supports `-pre` directly (contrast A-CL-010). |
| **A-JAVA-008** 53-type registry | — | — | CLOSED (53/53 byte-identical). |
| **A-JAVA-002** crypto sourcing | — | operator/research | RESOLVED (SunEC sign/verify zero-dep; raw-pubkey → A-JAVA-007). |
| **A-JAVA-003** concurrency model | — | operator | RESOLVED (JDK-21 virtual threads; unlocked the §7b superset). |
| **A-JAVA-006** Maven sha512 | — | operator | RESOLVED (filled + two-mirror-verified; fails closed). |

**Net S5 spec-refinement harvest:** 1 genuinely-new defect (A-JAVA-010), 1 new crypto-ledger
data point (A-JAVA-007), 2 multi-peer-convergence re-confirmations (A-JAVA-004 → 4 peers,
A-JAVA-009 → 5 peers), and 1 gate/provenance question (A-JAVA-011). The corroboration-heavy
profile the saturated-axes mainstream peer was expected to give, plus one discovery the prior
six map-modeling peers structurally hid. Log finalized.
