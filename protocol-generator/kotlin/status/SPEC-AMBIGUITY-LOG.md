# entity-core-protocol-kotlin — Spec Ambiguity Log

Every guess the agent makes goes here (S3). Items escalate to architecture as
proposal candidates via `research/stewardship/`. **No silent guesses.**

IDs are `A-KT-NNN`. Severity: `blocking` (halts the dependent phase) /
`non-blocking` (logged, work continues with a flagged best-guess) / `informational`
(a recorded decision/corroboration, not an open question).

Kotlin is a **reach peer** (corroboration-only; JVM idiom saturated by the Java
peer #7) — so most S1 entries are **corroborations / recorded decisions**, not new
spec defects. The expectation is **no new spec finding**; anything that does surface
is high-signal and gets escalated.

---

## A-KT-001: Codec strategy — hand-roll native Kotlin codec vs interop into the Java peer's codec

**V7 section:** ENTITY-CBOR-ENCODING (canonical ECF) — general; not a spec ambiguity but a profile decision the operator deferred to S1.
**Profile field:** `[codec].strategy`
**Severity:** informational (decision recorded; resolved at S1)
**Your guess:** **NATIVE, HAND-ROLLED.** Author an independent Kotlin `EcfCodec` rather than calling the Java peer's codec over JVM interop.
**Rationale:** A peer's value is being an *independent reader* of V7; interop-into-Java collapses Kotlin and Java to one reading and zeroes the corroboration value that is this reach peer's entire mandate (the keystone "no trench-coat" principle; cf. C++ decision D1 — an FFI/interop peer that just reuses another impl proves nothing independent). The effort delta is modest because the A-005 finding (no JVM CBOR lib gives ECF canonicality — re-confirmed by the Java peer, which hand-rolled) means there is *no* easy library path for either language; the only marginal cost is "write a Kotlin codec" vs "call Java's," which buys the independence. Crypto is native (JDK SunEC) either way, so the codec is the only real axis and the ruling is to own it. **S2 spike (mandate):** push the `map_keys` + `float` v7.71 vectors through the hand-rolled encoder before the full build (the load-bearing canonical risk: length-then-lex ordering + shortest-float f16). `ffi` is the documented fallback if the spike fails (not expected).
**Escalation:** operator — local decision (recorded for the arch-review independence ledger; no spec change implied).

## A-KT-002: Ed448 / SHA-384 agility route + raw EdEC key extraction (S2 task)

**V7 section:** §1.5 (key_type 0x02 Ed448), agility corpus (v7.67 KEY-TYPE-ED448-1, HASH-FORMAT-SHA-384-1)
**Profile field:** `[codec].ed448_library`, `[codec].ed25519_library`
**Severity:** non-blocking (S2/higher-bar task; the floor is unaffected)
**Your guess:** Ed25519 + Ed448 + SHA-256 + SHA-384 all via **JDK SunEC / SunMessageDigest** (native, no dep), with **BouncyCastle as an opt-in cross-check / fallback**; the core build stays BouncyCastle-FREE. Ed448 agility is a **DEFERRED higher bar** for this reach peer (v0.1 target = the Ed25519+SHA-256 floor). The one S2 wrinkle to verify (shared with Java): extracting the **raw 32-byte (Ed25519) / 57-byte (Ed448)** public key from the JDK's EdEC (sign-bit, y-coordinate) point representation, and constructing keys from a raw seed.
**Rationale:** the JVM closes the full crypto bar natively (the Java peer confirmed SunEC Ed25519+Ed448 + SunMessageDigest SHA-256+384), so no FFI/hybrid is needed — unlike OCaml (A-OC-002 C-ABI) / Zig (A-ZIG-002 gap). BouncyCastle gives a free independent managed cross-check (the C# A-009 / Java A-JAVA-002 precedent). Decide SunEC-vs-BC for the agility corpus at S2 after the raw-key-encoding spike.
**Escalation:** operator — local decision (deferred S2/agility task; no spec change).

## A-KT-003: Async style — coroutines vs the Java peer's threads

**V7 section:** §4.8 / §6.11 (inbound-concurrent-with-outbound, reentrancy N6/N7); §7b concurrency gate (store-safety)
**Profile field:** `[async]`
**Severity:** non-blocking (not exercised until S3; the codec is pure/synchronous)
**Your guess:** **kotlinx.coroutines** (structured concurrency) — one coroutine per connection on `Dispatchers.IO`, a reader coroutine demuxing `EXECUTE_RESPONSE` by request_id via `ConcurrentHashMap<requestId, CompletableDeferred<T>>`; §7b store-safety via a single-threaded store dispatcher / `Mutex`-guarded store. Public surface = both a `runBlocking` facade and native `suspend` functions. Takes `kotlinx-coroutines-core` as the one non-stdlib runtime dep.
**Rationale:** coroutines are Kotlin's headline, idiomatic concurrency model — the second axis on which this peer deliberately diverges from the Java peer (threads → coroutines), giving genuine Kotlin-native reach. A deliberate S6 trade (idiom over Java's literal-zero-dep minimalism), justified because a thread-only Kotlin peer would read as un-idiomatic Java. Validated against §7b at S3.
**Escalation:** operator — local decision (S6 idiom; no spec change).

## A-KT-004: peer_id construction — §1.5 canonical-form table, NOT the legacy SHA-256 form (corroboration)

**V7 section:** §1.5 v7.65 canonical-form table (`spec-data/v7.75` line 459: Ed25519 → hash_type=0x00 identity-multihash, digest = raw public_key); legacy §7.4 SHA-256 form is the stale path
**Profile field:** `[spec]` peer_id note
**Severity:** informational (corroboration — the contradiction is ALREADY reconciled in the v7.75 body by v7.73 erratum E1; no longer an open finding)
**Your guess:** derive the Ed25519 peer_id from the §1.5 identity-multihash canonical form (digest IS the raw public key), ignore the legacy SHA-256 form (at most a decode compat form per the Amendment-4 wire-acceptance carve-out). Bake this into the profile proactively.
**Rationale:** the §7.4-vs-§1.5 contradiction that OCaml (A-OC-007), Zig (A-ZIG-001), Common Lisp (A-CL-002), and Java (A-JAVA-004) surfaced is **already closed** in v7.75 (§7.4 now defers to the §1.5 table). Pinning the correct form proactively still dodges the `401 identity_mismatch` handshake-failure cycle that S2's opaque-digest corpus would NOT catch (a wrong construction passes S2 and only blows up at the S4 handshake). On v7.75 this is corroboration-only.
**Escalation:** research — recorded as a corroboration in the cohort ledger; no new arch escalation (already reconciled).

## A-KT-005: Maven Central publishing namespace not yet verified (S5 task)

**V7 section:** absent (packaging)
**Profile field:** `[publishing].repository_url`
**Severity:** non-blocking (S5 publish-time; does not affect any build/conformance phase)
**Your guess:** `repository_url = ""` (placeholder); Maven Central publishing via the vanilla Gradle `maven-publish` + `signing` plugins requires a verified reverse-DNS namespace (`org.entitycore`), which is the optional S5 registry step.
**Rationale:** namespace verification is a one-time human/registry step gated on first publish; the artifact builds and passes conformance without it. Parked as the S5 deliverable.
**Escalation:** operator — local decision (S5 packaging; no spec change).

## A-KT-006: Containerfile checksum sentinels for Kotlin + Gradle distributions (S2 fill)

**V7 section:** absent (toolchain / supply-chain S11)
**Profile field:** `[container]`, `[deps]`
**Severity:** non-blocking (S1 authoring boundary — S1 does not fetch/build; the sentinels FAIL CLOSED until filled at S2)
**Your guess:** `KOTLIN_SHA256` and `GRADLE_SHA256` in `containers/kotlin-toolchain/Containerfile` are authored as `REPLACE_WITH_VERIFIED_SHA256_AT_S2` sentinels — the build fails closed until the real digests are filled from the published `.sha256` assets (JetBrains/kotlin v1.9.25 release; services.gradle.org gradle-8.10.2-bin.zip.sha256) at the S2 build. The Temurin JDK sha256 is reused from the verified java-toolchain pin.
**Rationale:** S1 is research/authoring only — no podman, no fetch — so the real digests cannot be verified this phase; the sentinel pattern (mirroring the zig ZIG_SHA256 / java MAVEN_SHA512 sentinels) makes the image refuse to build on an unverified download rather than silently trusting it.
**Escalation:** operator — S2 build task (fill + verify the digests before trusting the image).
**S2 RESOLUTION:** sentinels filled + image built. `KOTLIN_SHA256 = 6ab72d6144e71cbbc380b770c2ad380972548c63ab6ed4c79f11c88f2967332e` (kotlin-compiler-1.9.25.zip — confirmed by downloading the asset and matching both the published `.sha256` AND a direct `sha256sum`); `GRADLE_SHA256 = 31c55713e40233a8303827ceb42ca48a47267a0ad4bab9177123121e71524c26` (gradle-8.10.2-bin.zip, from services.gradle.org `.sha256`). Temurin JDK digest reused from the verified java-toolchain pin. Image `entity-core-keystone/kotlin-toolchain:latest` built; the `prefetch/` Gradle Kotlin-DSL project seeds the offline caches (kotlin-stdlib 1.9.25, kotlinx-coroutines 1.8.1, kotlin-test-junit5 1.9.25, junit-jupiter 5.11.4, + opt-in BouncyCastle 1.80). Closed.

---

## A-KT-007: codec spike (A-KT-001 mandate) — hand-rolled Kotlin encoder is byte-correct on the load-bearing canonical risks

**V7 section:** ENTITY-CBOR-ENCODING (canonical ECF) §3.5 (map-key order), §4.x (float Rule 4 / 4a)
**Profile field:** `[codec].strategy = native` (the hand-roll decision, A-KT-001)
**Severity:** informational (spike outcome recorded; the hand-roll bet is confirmed)
**Your guess / outcome:** the spike (run BEFORE the full build) confirmed the two load-bearing risks the profile flagged: (1) **length-FIRST then byte-lexicographic** map-key ordering (map_keys.2/.3/.5/.6 exact bytes; byte-string key `0x43..` sorts before text key `0x68..`), and (2) the **shortest-float incl. f16 ladder** (float.1–14 exact bytes, incl. the 65503.0→f32 boundary that bit cbor2/Python). Both byte-correct on first run. The Go-oracle map-sort is `bytes.Compare` on the FULL encoded key, which for CBOR head-encoding IS length-then-lex (the length lives in the low bits of the initial byte) — so the single `bytes.Compare` order and the "length-then-lex" framing coincide; no divergence. The `ffi` fallback was NOT needed.
**Rationale:** spike-first de-risks the headline native-hand-roll decision; recording the byte-correct outcome closes the A-KT-001 spike obligation.
**Escalation:** operator — local decision (spike recorded; no spec change). Corroboration-only, as expected for a reach peer.

## A-KT-008: peer_id S2 corpus path uses opaque digests — construction-form correctness is NOT exercised until S4

**V7 section:** §1.5 canonical-form table / §7.3 (peer_id grammar)
**Profile field:** `[spec]` peer_id note; `crypto/PeerId.kt`
**Severity:** non-blocking (S2 passes either way; the risk surfaces only at the S4 handshake)
**Your guess:** the `peer_id.*` corpus supplies `(key_type, hash_type, digest)` explicitly and only checks the `Base58(varint(kt)‖varint(ht)‖digest)` FORMAT round-trip — so `PeerId.format` is what S2 exercises (3/3 PASS). The §1.5-canonical CONSTRUCTION from a raw public key (`PeerId.fromPublicKey`: Ed25519 32 B → `(0x01, 0x00, raw_pubkey)`; >32 B → SHA-256-form) is implemented per A-KT-004 but is NOT covered by the S2 corpus — it is first exercised at S4. Flagged so the S4 phase re-verifies the construction against the handshake oracle.
**Rationale:** documents the known S2 coverage gap (the same one A-JAVA-004 noted) so S4 does not assume peer_id construction was conformance-checked here.
**Escalation:** operator — local decision (S4 obligation; no spec change).

---

## A-KT-009: seed→Ed25519 raw-public-key derivation is net-new at S3 (SunEC has no seed→point API)

**V7 section:** §1.5 (peer_id from public key), §3.5 (system/peer entity), §7.3
**Profile field:** `crypto/EdKeyDerivation.kt` (new), `crypto/Ed.rawPublicKeyFromSeed`
**Severity:** non-blocking (resolved in-phase; corroborates the Java A-JAVA-002 seam)
**Your guess / outcome:** the S2 codec corpus only ever supplied OPAQUE peer_id digests (A-KT-008), so seed→raw-public-key was never exercised. The S3 handshake + `system/peer` entity need the RAW 32-byte Ed25519 public key, and JDK SunEC exposes a public key only as an `EdECPoint` (y + x-sign) with NO seed→public-point API. Resolved by porting the proven Java peer's pure-JDK RFC-8032 derivation (SHA-512 expand → clamp → Curve25519 base-point scalar multiply → LE encode) into `EdKeyDerivation.rawPublicKeyEd25519`, cross-checked by feeding the result to SunEC's own verifier on a self-signed message AND validated end-to-end by the loopback handshake (the seed-0x11 peer derives peer_id `2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg`, the cohort-canonical value — so the derivation is byte-correct). Only Ed25519 (the §9.1 floor curve) is wired; Ed448 raw-key derivation stays a deferred agility higher-bar.
**Rationale:** the JVM substrate's known gap (same as Java) — a faithful pure-JDK derivation keeps the core peer BouncyCastle-free per the profile. Corroboration-only (no spec defect).
**Escalation:** operator — local decision; no spec change.

## A-KT-010: envelope `included` is a content_hash→entity MAP — duplicate-hash dedup is mandatory on emit (§3.1)

**V7 section:** §3.1 (envelope `included` shape)
**Profile field:** `peer/Envelope.kt` (`toCbor` dedup)
**Severity:** non-blocking (resolved in-phase; a faithful-codec consequence the smoke caught)
**Your guess / outcome:** §3.1 defines `included` as a MAP keyed by content_hash, so two list entries with the same content_hash MUST collapse to one map entry. The §6.11 reentry path lists the cap's granter peer AND the local identity, which are the SAME entity when the cap's granter IS the local peer (granterPeer == peerEntity) — emitting a duplicate map key that THIS peer's own canonical decoder correctly rejects ("duplicate map key"). Resolved by deduplicating `included` by content_hash (first-seen order) in `Envelope.toCbor` before encoding. Surfaced precisely because the hand-rolled codec enforces §6.3 duplicate-key rejection on decode (a weaker codec would have silently accepted the malformed frame) — the keystone "strict codec catches a peer-layer bug" payoff.
**Rationale:** the dedup belongs on the emit side (the map semantics are normative); the decode-side rejection is correct and stays. Local fix, no spec ambiguity.
**Escalation:** operator — local decision; no spec change. (Worth a generator-note: any peer building `included` from a list must dedup before encode.)

## A-KT-011: §7b store-safety route — concurrent collections (atomic-per-key) over a single-writer dispatcher

**V7 section:** §4.8 store data-race safety, §7b concurrency taxonomy
**Profile field:** `[async].store_safety`; `peer/Store.kt`
**Severity:** non-blocking (profile-authorized; a within-menu choice recorded)
**Your guess / outcome:** the profile names two §7b store-safety options for the coroutine model — a single-threaded store dispatcher OR a `Mutex`-guarded store (the "manual-but-structured" route). Implemented as `ConcurrentHashMap` content/tree maps + `CopyOnWriteArrayList` consumers, relying on the atomic `putIfAbsent`/`put` return value to make the §6.10 emit-on-change decision race-free. This is a THIRD point in the menu (lock-free reads, atomic-per-key writes) that satisfies §4.8 at the granularity the conformance flows need (no concurrent same-path writer contention in `--profile core`), without a global store mutex or a confined single-writer dispatcher. The 8-way concurrent request_id demux smoke exercises concurrent inbound dispatch against the store with no race. If the S4 `concurrency` gate (§7b T2.x) demands stricter same-path atomicity, the single-writer-dispatcher upgrade is the documented fallback.
**Rationale:** the concurrent-collection route is the lowest-ceremony structural-safety option on the JVM and is idiomatic; recorded as a profile-menu refinement (a candidate addition to the generator's §7b store-safety menu for concurrent-collection runtimes).
**Escalation:** operator — local decision; candidate generator-menu note (not a spec change).

## A-KT-012: §6.11 reentry inner-verdict at the smoke is a §5.2 cap check, not the transport (S4 supplies the cross-peer cap)

**V7 section:** §6.11 reentry, §6.13(b) handler outbound, §5.2 request verify
**Profile field:** `peer/Transport.kt` (reentry seam), `SmokeTest` reentry probe
**Severity:** non-blocking (S3 smoke scope boundary, flagged for S4)
**Your guess / outcome:** the S3 smoke proves the §6.11 reentry TRANSPORT end-to-end — B's `dispatch-outbound` handler originates an EXECUTE back to the caller A over the SAME inbound connection, A's reader dispatches it, and B correlates the reply by request_id (outer status 200 over real two-peer TCP). The INNER verdict of the reentrant echo is A's §5.2 capability check on the cap B presents; with only the session cap available (grantee=A, author=B), A returns 403 inner — correct authz, not a transport failure. A genuine inner-200 reentry requires a cap A minted FOR B (grantee=B), which is exactly what S4's `origination-core` `dispatch_outbound_reentry` validator (B-role) supplies. Flagged so S4 does not read the smoke's inner-403 as a defect: the transport seam (the from-zero trap the cohort hit) is built and round-trips; the cross-peer cap is the validator's to provide.
**Rationale:** scopes the smoke's reentry claim precisely (transport proven; inner authz is cap-provisioning) so the S4 gate is a cap-supply step, not a transport rewrite.
**Escalation:** operator — S4 obligation; no spec change.
**RESOLVED (S4):** confirmed at the gate. `run-origination-core.sh` ran the §10.2 `origination-core` probe against the Go `entity-peer --open-access` reference — `dispatch_outbound_reentry` PASS (3/3 origination total, 0 fail) over real two-peer TCP. The validator (B-role) mints the reentry capability (grantee=A) and EXECUTEs `system/validate/dispatch-outbound`; A originates the outbound EXECUTE back over the SAME inbound connection (§6.11 reentry), inner verdict now 200 because the validator supplied exactly the cross-peer cap the smoke could not. Transport seam + cap-supply both proven; A-KT-012 closed — no spec change.
