# Architecture Review — entity-core-protocol-java (peer #7, 9th byte-compatible core impl)

**Author:** keystone steward (S5) · **Spec basis:** V7 spec-data v7.72 +
the v7.73/v7.74 peer-surface closeout (register/outbound/emit §6.13 + §PR-8 granter frame +
§6.9a owner-cap + §7a conformance handlers); codec corpus v0.8.0. · **Audience:** architecture
(spec-tightness feedback) + operators (publishing decision). · **Status:** peer #7 at
`validate-peer --profile core` PASS · 573 / 289P / 195W / **0F** / 89skip; origination-core 3/3;
§9.5 53-type floor 53/53.

This review follows the format/depth of the Zig peer #4 and Common-Lisp peer #5
`ARCHITECTURE-REVIEW.md` (themselves extensions of the three-peer milestone review), carried to
**the cohort's mainstream-stack bookend** — the most-deployed enterprise idiom, with most idiom
axes already saturated by the prior six peers. Part A is the idiom-fidelity + spec-refinement
retrospective; Part B is the publishing-options decision surface; Part C is the one-paragraph arch
summary; Part D is the consolidated findings ledger for the arch escalation bundle.

---

## 0. The thesis peer #7 was chosen to test

The convergence thesis (three-peer review, reinforced by Zig #4's memory/control-flow distance and
CL #5's program-model distance): *if the spec is tight, independently-derived peers converge on the
same conformance fixed point with no wire divergence; the idiom seams diverge cleanly by profile at
impl locality; and a spec-first peer surfaces contradictions the port-peers inherited-correctly-
but-never-flagged.* Six peers (C#/TS/OCaml/Elixir/Zig/CL) had spanned managed-GC → no-GC systems →
homoiconic-multiple-dispatch idioms.

Java is the cohort's **mainstream static-OO / JVM bookend.** Its idiom axes are **largely
saturated** by the prior peers: it is GC'd (like C#/TS/OCaml/Elixir), single-dispatch (like
everyone but CL), exception-based (like C#/TS). So the *expected* spec-refinement yield is small —
but the keystone's selection logic flips that into a different value: **a defect the most-deployed
enterprise language hits is one almost everyone will hit.** The open questions were therefore not
"does a distant idiom diverge?" but: **(a) does the saturated-axes mainstream stack still converge
clean** (a strong corroboration signal if yes, a tightness alarm if not), and **(b) what does the
JVM's *vendor-curated stdlib* — a property no prior peer has in the same form — surface on the
crypto axis?**

**Result: the thesis held, and the mainstream stack paid off in exactly the two ways its selection
predicted.** (a) Every wire-touching decision converged: byte-identical codec (69/69, first run),
byte-identical 53-type registry (53/53), and a peer_id **byte-identical to the Common Lisp peer**
(`2KHoAk7A5JmhygZJAdBua8iRD1CnBoJRfUBHgZeXNRTeFg` from seed `0x11`). The static-OO seams (records +
sealed interfaces + pattern-matching switch, checked exceptions, virtual-thread concurrency)
diverged cleanly at impl locality and **changed no wire byte.** (b) The JVM's vendor-curated stdlib
produced the cohort's most refined **crypto-agility data point** (A-JAVA-007 — native signatures,
hand-rolled raw-pubkey). And the mainstream read of the spec **re-confirmed two standing defects as
multi-peer convergences** (peer-id 4th, 401/403 5th) and surfaced **one genuinely-new high-signal
finding** (A-JAVA-010, scalar entity `data`) that the prior six map-modeling peers all hid.

---

## PART A — Architecture review

### A.1 Did the Java idiom pay off? (the static-OO seams, scored)

The bet of generating peer #7 was that the mainstream OO/static idiom, with mostly-saturated axes,
would still *express the protocol idiomatically* and — where it has a genuinely distinctive
property (the vendor stdlib, virtual threads) — surface something the prior peers couldn't.

**(1) Records + sealed interfaces + pattern-matching switch (the static-OO data/dispatch seam) —
PAID OFF as the *idiom-neutrality bookend* to CL's CLOS multiple dispatch.** The ECF value model is
a **sealed interface `EcfValue` with record variants** (Map/Array/Text/Bytes/Int/Float/Bool/Null);
the codec encoder and the §6.6 handler ladder are **exhaustive pattern-matching `switch`** over the
sealed hierarchy (JEP 441, GA in 21 — the compiler enforces totality, no `default` needed). This is
the **mainstream static-OO expression of the same §6.6 dispatch the cohort converged on** — a
*single-dispatch* handler ladder keyed on `(handler, operation)`, exactly like C#/TS/OCaml/Zig.
The payoff is the **idiom-neutrality ledger's other end**: CL #5 proved §6.6 is mechanism-agnostic
by expressing it as genuine *multiple* dispatch and converging; Java #7 proves the same surface
reads identically in the *most mainstream single-dispatch static-OO* form, with the compiler
enforcing exhaustiveness over a sealed type. **Six single-dispatch idioms + one multiple-dispatch
idiom now converge on the same §6.6 dispatch behavior** — §6.6 is specified at the right altitude
(it names the dispatch *key*, not a *mechanism*). **Verdict:** the static-OO seam is the
*idiom-neutrality bookend* — it confirms the dispatch surface survives the widest mechanism span in
the cohort, from CLOS multiple dispatch to JDK sealed-switch, with zero wire divergence.

**(2) Checked exceptions (the error-model seam) — PAID OFF as fidelity, no wire effect.** Deliberate
return to the C#/TS exception family (vs OCaml's result ADT, Zig's error unions, CL's condition
system) — but Java's **checked** exceptions make the fault surface *compiler-declared* on each
throwing method's signature. Codec/local faults are a typed checked-exception lattice; the cohort
invariant — *protocol status is a value record, never carried by the exception type across
dispatch* — holds for the same reason it held everywhere: the dispatch brain returns a status
*value*; a thrown exception is a codec/local fault, never the cross-dispatch status carrier. The
§5.2 request verdict is a **three-way value** (`RequestVerdict` = ALLOW / AUTHN_FAIL / AUTHZ_DENY)
plus the §5.5 `UnresolvableGrantee` signal mapped to 401 — *not* an exception, exactly so the
authn/authz status split (A-JAVA-009) is a value decision. **Verdict:** the error-model seam
differs structurally (checked, signature-declared) yet produces no wire divergence — the
convergence thesis holding under the cohort's third distinct exception flavor.

**(3) JDK-21 virtual-thread concurrency (the concurrency seam) — PAID OFF as the cohort's
concurrency *inversion*, and it is what unlocked the §7b superset.** Every prior peer reasoned its
concurrency model *against* OS-thread cost — OCaml revised eio→threads (A-OC-003), Zig chose
`std.Thread` over unsettled async (A-ZIG-003), CL used `sb-thread` (A-CL-003) — all landing on
"thread-per-connection is fine because a `--profile core` peer's needs are modest." Java **inverts
the cost premise**: virtual threads (Loom, JEP 444 GA in 21) make thread-per-connection *and*
thread-per-request cheap, so Java spends a vthread per **inbound EXECUTE**, not merely per
connection — the model the cohort justified against thread cost is the *recommended* Loom carrier.
The payoff is concrete and **wire-observable at the gate**: Java is the first peer run against the
oracle HEAD where **§7b concurrency gates `--profile core`**, and all 5 checks (concurrent demux,
no-head-of-line, sustained load, connection churn) PASS on virtual threads natively — taking the
core gate from 568 to **573** (A-JAVA-011). **Verdict:** the virtual-thread seam is the highest-
*operational*-value seam in the cohort — it didn't change a wire byte, but it is the model the §7b
matrix is cheapest to satisfy under, and it is why Java's fixed point is a clean superset rather
than a match.

**(4) The JVM vendor-curated stdlib (the supply-chain/crypto seam) — PAID OFF as the cohort's most
refined crypto-agility data point (A-JAVA-007).** Detailed in §A.3; scored here as the seam that
*could only* come from a vendor-stdlib peer. The JDK is the **first peer whose vendor-curated
stdlib closes the crypto-agility *signature* bar natively** — `Signature("Ed25519")` /
`Signature("Ed448")` + `MessageDigest("SHA-384")`, zero-dependency, no FFI. That puts Java in the
company of CL (pure-Lisp ironclad) and Elixir (OTP NIF) and in sharp contrast to OCaml (A-OC-002,
C-ABI Ed448) and Zig (A-ZIG-002, flat gap) — but via a *third mechanism* (vendor stdlib provider).
**Verdict:** the vendor-stdlib seam is the only seam that distinguishes Java on the saturated crypto
axis, and it yielded both a positive data point (native agility signatures) and a precise new gap
(raw-pubkey, A-JAVA-007) — the maximum yield a saturated-axes peer was expected to give.

**Net: all four seams paid off** — records+sealed-switch as the *idiom-neutrality bookend* to CL,
checked exceptions as fidelity, virtual threads as the §7b-superset unlock, and the vendor stdlib
as the refined crypto data point. Critically, **none changed a wire byte** — the seams landed at
impl locality, which is the convergence thesis holding under the cohort's *most mainstream* stack
(the corroboration end of the distance spectrum, opposite Zig/CL's discovery end).

### A.2 Spec-refinement value — what Java contributed

The keystone's *end* is spec refinement. Peer #7's harvest splits into **one genuinely-new finding,
two multi-peer-convergence re-confirmations, and one new crypto-ledger data point** (full text in
`SPEC-AMBIGUITY-LOG.md`) — the corroboration-heavy profile the saturated-axes mainstream peer was
expected to produce, plus one discovery the prior six structurally hid.

**Top NEW contribution — A-JAVA-010 (scalar entity `data`), the high-signal finding.** §1.1 defines
an entity as `{type, data, content_hash}` where `data` is "an ECF value" — *any* ECF value, not
necessarily a map. But every core *protocol* entity (handler manifests, grants, type defs,
listings) happens to be a map, and the S2 corpus + S3 loopback only ever round-tripped map-data
entities — so a peer that models `data` as a map (natural, almost inevitable, in a statically-typed
OO/record idiom — Java modeled it `EcfValue.Map`) **passes S2 and S3 green** and only fails at the
first scalar-data entity it is asked to store/relay. The §7b concurrency gate is the first place the
cohort exercises that: it stages `primitive/string` entities (scalar CBOR text, not a map) via
`tree.put`, and Java's `Entity.ofCbor` hard-rejected non-map data → a silent **500** → 3
un-allowlisted SKIPs → `Result: FAIL`. The cause was a peer data-model bug, not a grant issue.
**This is the exact class of latent interop trap a self-consistent peer hides until a corner of the
suite forces the non-map case** — and it is the saturated-axes mainstream peer *paying off as a
discovery*: the most natural data model for the most-deployed enterprise idiom is the one that walks
into it, so this is a gap most JVM (and any record/struct-modeling) implementers will hit.
**Escalation: arch/research** — recommend (a) a scalar-data conformance vector (a stored
`primitive/string`) so the map-only assumption is caught at the codec/peer bar, not only at §7b; and
(b) a one-line §1.1 emphasis that `data` MAY be a non-container scalar. Resolved locally
(generalized `Entity` to hold `data` as any `EcfValue`, with a null-safe map *view* for the protocol
field-readers). ⚑ ARCH-BOUND.

**Second contribution — A-JAVA-004 (peer-id construction), now the FOURTH spec-first corroboration.**
§7.4's pseudocode, labelled **NORMATIVE**, derives an Ed25519 peer_id as
`Base58(varint(0x01) ‖ varint(0x01) ‖ SHA256(pubkey))` — `hash_type=0x01`, digest = SHA-256 *of*
the pubkey; the §1.5 line-436 skeleton (verified directly in `spec-data/v7.72`, lines 436–442) and
the line-3561 content-hash area still carry the same stale SHA-256 form. The §1.5 **line-448**
canonical-form table mandates the *opposite*: `hash_type=0x00` **identity-multihash**, digest = the
**raw pubkey** (no hash); §1.5's Amendment-4 carve-out (line 493) demotes the SHA-256 form to
decode-only. The two are byte-different; a §7.4-literal peer fails `authenticate` step-3 identity
binding (`peer_id == derive(pubkey)`) → `401 identity_mismatch`. **Java is the fourth independent
spec-first peer to read §7.4 literally and would have failed handshake — after Zig A-ZIG-001, OCaml
A-OC-007, CL A-CL-002.** Baked the §1.5 form into the profile at S1 to dodge a fourth debug-cycle
burn; the resulting seed-`0x11` peer_id is **byte-identical to the CL peer's committed report.**
**Four spec-first peers from four very different idioms hitting the identical contradiction is now
decisive — the §7.4 text needs the fix** (reference the §1.5 table from §7.4, or carry the
identity-multihash construction directly; state the SHA-256-form is decode-only). **Escalation:
architecture** (high-priority; silent-handshake-kill). ⚑ ARCH-BOUND.

**Third contribution — A-JAVA-009 (401/403 request-time boundary), now the FIFTH-peer convergence.**
§5.2's `verify_request` pseudocode reads as a binary allow/deny, but §4.6 distinguishes
authentication (401 — caller never proved *who*: bad/absent request signature, signer≠author,
unresolvable author) from authorization (403 — capability doesn't admit: no cap, chain invalid,
grantee≠author, revoked), and §5.5 carves out a third case (unresolvable grantee mid-chain → 401,
not 403). Implemented as the three-way `RequestVerdict` + the `UnresolvableGrantee`→401 signal. The
three-peer review already called this "no longer an opinion, it's a spec defect" (C# F20 + TS +
OCaml A-OC-008); Zig A-ZIG-006 made it four. **Java is the fifth independent peer to hit it — a
mainstream "boring enterprise" stack reading §5.2 straight lands on the same gap.** Validated live
(authz_deny/authz_scope_exceeds→403; authz_grantee→401). **Recommend: arch makes the
authn(401)/authz(403)/unresolvable-grantee(401) trichotomy normative in §5.2 and retires the F14
401→403 ruling for auth-class rows** — the five-peer convergence is decisive. **Escalation:
architecture** (corroborates F20). ⚑ ARCH-BOUND.

**Crypto-ledger data point — A-JAVA-007 (JDK raw-pubkey gap).** Detailed in §A.3. The JDK closes
the agility *signature* bar natively but leaves a raw-*public-key* gap (no SHAKE256 XOF, no
seed→public API), requiring a hand-rolled KAT-verified SHAKE256 + RFC-8032 derivation. Not a spec
*defect* — a JVM platform-capability gap that shapes the cross-peer crypto sourcing ledger.
**Escalation: arch/research** (crypto-ledger data point). ⚑ ARCH-BOUND.

**Provenance gap — A-JAVA-001 (v7.73/v7.74 spec-data snapshot missing), STILL OPEN.** Local
`spec-data/` stops at v7.72; the oracle was rebuilt from `entity-core-go` HEAD so the conformance
*check-set IS at HEAD* and the build is oracle-verified-correct — but the peer's v7.73+ behavior was
authored against the **cohort + the oracle's own check messages**, not a SHA-pinned v7.73/v7.74
snapshot. Byte provenance therefore traces to siblings + oracle, not to a pinned spec copy.
**Corroborates A-CL-001** (second cohort to re-flag the same provenance gap). NON-blocking for the
gate; blocking for clean byte-provenance. **Escalation: research/arch.**

**Idiom-neutrality data point — the records+sealed-switch §6.6 ladder (informational).** Detailed
in §A.1(1): Java is the *single-dispatch static-OO bookend* to CL's multiple dispatch — six
single-dispatch + one multiple-dispatch idiom converge on the same §6.6 behavior. **Escalation:
none** — a tightness signal for the review ledger, not a gap.

**Packaging note — A-JAVA-005 (Maven Central namespace verification).** Surfaced at S1, an S5
operator step: Maven Central requires a verified `org.entitycore` reverse-DNS namespace before the
first deploy. Notably, **Maven's version grammar accepts the `0.1.0-pre` qualifier directly** — the
*contrast* with CL's A-CL-010 (ASDF's dotted-integer-only `:version` forced the `-pre` marker into
the CHANGELOG only). No version-split wrinkle here. **Escalation: operator.**

### A.3 Codec / crypto / transport design retrospective

**Codec — convergent, native, zero-dep.** Hand-rolled canonical CBOR (the pattern every native peer
hit): shortest-float ladder (f16⊂f32⊂f64, narrowest bit-exact round-trip), length-then-lex map-key
sort on encoded key bytes, recursive major-type-6 tag rejection, head-form int carrier via
`BigInteger` (Java's `long` has no native unsigned, so the full 0..2⁶⁴−1 range is carried by
`BigInteger` — the CL-bignum / TS-`bigint` posture by a third mechanism, cleanly above C#'s `ulong`
reinterpret and OCaml's 63-bit trap A-OC-001; the [2⁶³,2⁶⁴−1] range is self-tested, A-JAVA self-test
heuristic). 69/69
byte-identical, first run, **0 codec fixes** — the codec was byte-green before the peer existed, so
the only S4 risk was field-shape *data* (caught per-type by the 53/53 registry byte-diff). Base58
and the multicodec LEB128 varint are hand-rolled (neither is in the JDK), the same "hand-roll the
missing primitive" stance the cohort's native peers all took.

**Crypto — the cohort's most refined agility data point (A-JAVA-007), the headline crypto axis.**
The JDK's **SunEC provider closes Ed25519 + Ed448 *sign/verify* natively and zero-dep** —
`Signature("Ed448")`, `NamedParameterSpec.ED448`, `MessageDigest("SHA-384")` — so the §9.1 floor
*and* the agility *signature* higher bar are reachable from the default build with **no FFI and no
third-party runtime dependency.** This is the crypto-axis contrast and company:
  - **Company** with CL (pure-Lisp ironclad, A-CL-005) and Elixir (OTP NIF) — three peers reach
    both curve families natively, by three different mechanisms (vendor stdlib / pure-Lisp / NIF).
  - **Contrast** with OCaml (A-OC-002, sourced Ed448 over a C-ABI, hybrid FFI) and Zig (A-ZIG-002,
    flat gap — `std.crypto` has no Ed448, no audited pure-Zig impl, no BouncyCastle-equivalent).
  - **The precise NEW gap (A-JAVA-007):** the JDK closes the *signature* bar but leaves a raw-
    *public-key* gap. SunEC exposes **no seed→public-key API** (a raw-seed `EdECPrivateKeySpec`
    carries only the seed in its PKCS#8 encoding; SunEC computes the public point internally during
    signing but never exposes it), and the JDK `MessageDigest` registry ships **no SHAKE256** XOF
    (it has SHA3-{224..512} fixed-output + SHA-512, but not the extendable-output function the
    RFC-8032 Ed448 seed-expansion *requires*). Since the §1.5 identity-multihash peer_id needs the
    *raw public key*, a fully-JDK-native dependency-free Ed448 pubkey path is impossible via the
    obvious route. **Resolution:** keep the core BouncyCastle-free by hand-rolling the two missing
    primitives — a FIPS-202 SHAKE256 (verified vs the NIST `SHAKE256("")` KAT) and the RFC-8032
    raw-pubkey derivation for both curves (SHA-512/SHAKE256 expand → clamp → BigInteger Edwards
    base-point scalar-mult → little-endian encode), ~250 lines of pure dependency-free JDK code,
    byte-verified vs the Ed25519 RFC-8032 TEST-1 pubkey, the agility `KEY-TYPE-ED448-1` pin, AND
    BouncyCastle's `Ed448PublicKeyParameters` (the `provided`-scope, test-only cross-check). The
    cohort crypto ledger now reads: **the most-deployed enterprise stdlib closes agility
    sign/verify but not raw-pubkey derivation** — a high-signal gap most JVM implementers of an
    identity-multihash peer_id will hit.

**Transport — convergent shape, virtual-thread primitive (profile-local, validated, A-JAVA-003).**
The shape is the spec-forced cohort shape: 4-byte BE length-prefix + CBOR frame; one reader thread
per connection demuxing `EXECUTE_RESPONSE` by `request_id` (N7); inbound EXECUTE dispatched on its
own thread so it never blocks outbound (N6); a transport-agnostic dispatch brain. The *primitive* is
**JDK-21 virtual threads** (Loom) + a `ConcurrentHashMap<requestId, …>` rendezvous table — the
direct Java analogue of C#'s `ConcurrentDictionary<id,TCS>` / OCaml's per-thread-blocking / Zig's
`std.Thread` / CL's `sb-thread`. The Java-specific refinement (and the cohort *inversion*, §A.1(3)):
because vthreads make thread-per-request cheap, Java spends a thread per inbound EXECUTE, not merely
per connection — so it satisfies the §7b concurrency matrix (which now gates core) the most cheaply
of any peer, all 5 checks PASS. The accept loop stays a platform thread (a long-lived blocking
accept has no carrier benefit). `java.nio` async remains the open path only if handler-initiated
outbound origination enters the CORE (extension-only today); the swap is localized to
`Transport.java`. **Retrospective verdict:** the virtual-thread choice is correct for the core
floor, zero-dep, and is the model the §7b matrix is cheapest to satisfy under.

### A.4 Where peer #7 sits vs the C#/TS/OCaml/Elixir/Zig/CL cohort

| Axis | C# (#1) | OCaml (#3) | Zig (#4) | CL (#5) | **Java (#7)** |
|---|---|---|---|---|---|
| Derivation | reference | spec-first | spec-first | spec-first | **spec-first** |
| Distance / role | ref | (managed) | memory/control-flow | program model | **mainstream OO bookend (corroboration)** |
| Dispatch model | single (switch) | single (match) | single (comptime) | CLOS MULTIPLE | **single (sealed-switch, exhaustive)** |
| Error model | exceptions | result ADT | error unions | condition system | **checked exceptions** |
| Memory | GC | GC | no GC | GC | **GC** |
| Codec | hybrid | hand-rolled | hand-rolled | hand-rolled | **hand-rolled** |
| Third-party runtime deps | NSec, BouncyCastle | mirage-crypto, digestif | ZERO (std-only) | ONE (ironclad) | **ZERO (JDK-only; BC test-scope)** |
| Int carrier | native `ulong` | int64 (A-OC-001) | native `u64`+trap | native bignums | **`BigInteger` (no native unsigned `long`)** |
| Ed448 agility | BouncyCastle | native gap → FFI | native gap (A-ZIG-002) | NATIVE pure-Lisp | **NATIVE SunEC sign/verify; hand-rolled raw-pubkey (A-JAVA-007)** |
| Concurrency primitive | `Task` | threads (A-OC-003) | `std.Thread` | `sb-thread` | **JDK-21 virtual threads (Loom)** |
| Core verdict | 0 FAIL | 0 FAIL | 0 FAIL | 0 FAIL | **0 FAIL** |
| Conformance split | 285P/194W | 284P/195W | 284P/195W | 284P/195W | **289P/195W** |
| Total core checks | 552 | 558 | 568 | 568 | **573** (v7.74 oracle + §7b-gates-core) |

**Position:** peer #7 is the cohort's **mainstream static-OO / JVM bookend and the corroboration
end of the idiom-distance spectrum** (opposite Zig/CL's discovery end). It confirms that the
*most-deployed enterprise idiom*, with mostly-saturated axes, still converges on every wire-touching
decision (codec, registry, **peer_id byte-identical to CL**), spec-first; it is the *single-dispatch
static-OO bookend* of the §6.6 idiom-neutrality ledger (six single-dispatch + CL's multiple dispatch
all converge); it re-confirms the two highest-value standing spec defects (peer-id A-JAVA-004 =
**fourth** spec-first peer; 401/403 A-JAVA-009 = **fifth** peer); and — the saturated-axes peer
*paying off as discovery* — it surfaced **one genuinely-new high-signal defect (A-JAVA-010,
scalar entity `data`)** that the prior six map-modeling peers all hid, plus the cohort's most refined
**crypto-agility data point (A-JAVA-007)**. The 573-vs-568 total is **not a scope difference**: the
+5 is the §7b concurrency category, which at the current in-flight oracle HEAD runs and gates under
`--profile core` (it was a §9.0 drift carve-out at the older OCaml/CL oracle) — see the canonical-
gate question in §A.5; the 289P/195W split is the OCaml/CL 284P/195W fixed point + 5 §7b PASSes.

### A.5 The 568→573 §7b-gates-core question (the open S4 question — arch ruling needed)

**This is the single most important item for the orchestrator's merge/handoff decision.** The
canonical `--profile core` gate count moved **568 → 573** between the OCaml/CL builds and this Java
build, and the reason is **not** a Java scope difference: it is that the Go oracle was built from the
mainline's **in-flight committed-but-unpushed HEAD `749e57e`** ("validate-peer/concurrency: keystone
§7b matrix fixes"), which is **14 commits ahead of origin/main**, and at that HEAD the **§7b
concurrency category runs and *gates* under `--profile core`** (a layered conditional that was a
§9.0 drift-list carve-out — auto-skipped — at the older oracle the OCaml/CL peers ran against). All
5 §7b checks PASS for Java on virtual threads, so the result is a clean superset (573 · 289P/195W/
**0F**/89S), not a regression. Two things follow, and **both need an arch ruling before the count
is treated as canonical:**

1. **Is §7b-gates-core intended for v0.1?** The change re-baselines the canonical core gate from
   568 to 573. If yes, the OCaml/CL/etc. peers should be re-run against the §7b-gating oracle to
   confirm they also reach 573·0F (their concurrency models — `sb-thread`, eio-revised threads —
   should pass, but it is unverified at the new gate); if §7b is meant to stay a §9.0 drift
   carve-out for v0.1, then Java's *canonical* core verdict is the 568-subset (also 0F) and the §7b
   superset is a forward-looking bonus. **The cohort cannot have a single canonical core count until
   this is ruled.**
2. **Re-confirm Java's 573·0F once `749e57e` lands on origin/main.** The +5 §7b PASS depends on the
   Go-side §7b matrix fixes (the `runT22` ephemeral-fallback fix + the dispatch-outbound relay-shape
   ruling) being upstream. The oracle is reproducible-correct at `749e57e` today (symbols verified,
   tree clean at build), but the canonical claim is only stable once that HEAD is pushed. **A re-run
   of `run-s4.sh` against the origin/main oracle is a required post-merge step** (A-JAVA-011).

**Recommendation to the orchestrator:** carry both halves into the merge — (a) Java's verdict is
**0 FAIL either way** (568-subset or 573-superset), so the merge is safe on conformance grounds; but
(b) **do not stamp 573 as the new canonical cohort core count** until arch rules §7b-gates-core for
v0.1 *and* the oracle HEAD lands upstream and Java (+ ideally the cohort) is re-run against it.

---

## PART B — Publishing options (operator-decides)

`/entity-rosetta` does not publish (lifecycle §Publishing). This is the decision surface; the
recommendation is at the end. **No action is taken on it.**

### B.1 In-repo vs standalone repo

**Option 1 — keep in-repo under `protocol-generator/java/` (current keystone default).**
Per-language sibling repos are deferred keystone-wide (S10); all seven peers live in the keystone
monorepo today.
  - *For:* zero lift cost; shared spec-data / test-vectors / oracle stay co-located (the runbooks
    read `../shared/...` and `output/s4-oracles/...` directly); cross-peer changes (spec bumps) land
    atomically; the runbooks' relative paths already assume this root.
  - *Against:* a Java consumer can't `mvn` a monorepo path directly — they would depend on a
    published artifact, not the repo layout; the source-of-record is keystone-wide.

**Option 2 — lift to a standalone `entity-core-protocol-java` repo (S10).**
  - *For:* a clean Maven module root with its own `pom.xml` at the repo root (the Maven-idiomatic
    layout for a published artifact); independent version cadence; the natural home for a CI
    workflow and the concrete `repository_url` (currently empty).
  - *Against:* the lift must vendor or submodule `shared/spec-data` + `test-vectors` + the oracle
    (the peer can't conform without them); spec bumps then require a cross-repo sync; it is an S10
    step the keystone has **deliberately deferred cohort-wide** — doing it for Java alone fragments
    the uniform "all peers in-repo" posture.

### B.2 Distribution mechanism (Java-specific)

Java's registry is **Maven Central** (Sonatype Central Portal) — unlike Zig/CL (decentralized,
git-tag/dist-indexed). "Publishing" is a real upload:
  - **(a) Maven Central via the Central Portal.** The publisher claims and **verifies the
    `org.entitycore` reverse-DNS namespace** (a DNS TXT record on the `entitycore.org` domain, or a
    hosting-provider proof), then `mvn -o -B deploy` to a staging repo, signs the artifacts
    (GPG/PGP), and releases. This is the mainstream path; the namespace verification is the one-time
    operator gate (A-JAVA-005) that **cannot be done by the pipeline** and is why publishing is
    deferred.
  - **(b) GitHub Packages / a private Maven repo.** Lower-ceremony (no namespace verification,
    no Central sync), appropriate for an internal/early consumer; the consumer adds the repo to
    their `settings.xml`.
  - **(c) Source/JAR dependency by local install.** A consumer `mvn install`s the peer into their
    local `~/.m2` (or vendors the JAR) — fully offline, audit-friendly, the same supply-chain stance
    as the keystone. This is how the peer is consumed today (in-container `~/.m2`).

The **zero-runtime-dependency posture** makes distribution light: a consumer inherits *no*
transitive runtime deps from the published artifact (BouncyCastle is `provided`/test-scope, JUnit is
test-scope) — lighter than C#'s multi-provider graph, comparable to Elixir's zero-Hex-dep posture,
and the only pin a consumer takes on is JDK 21.

### B.3 License / version posture

  - **License: Apache-2.0** (keystone S9 default; explicit patent grant) — and *also the JVM
    ecosystem norm* (Apache projects, the Maven Central default), so the default is the idiom here
    (`profile.toml [license]` — not overridden). pom.xml carries the `<licenses>` block. No change
    recommended.
  - **Version: `0.1.0-pre`** (set this phase, in `pom.xml <version>` directly). The cohort-wide
    pre-release line. **Maven supports the `-pre` qualifier idiomatically** — the contrast with CL's
    A-CL-010 (ASDF forced the `-pre` into the CHANGELOG only). **Promotes to `0.1.0`** only when
    (a) S4 fully green [met] AND (b) ≥1 external consumer confirms it works [not yet met — the
    C#-class "Avalonia confirms" analogue]. `CHANGELOG.md` tracks the spec version literally.
  - **Agility full MATRIX** is the documented non-v0.1 item: primitives are native + byte-proven
    (Ed25519 + Ed448 sign/verify via SunEC; raw-pubkey via the hand-rolled SHAKE256+derivation,
    KAT-gated); only the M2/M3/M6 cross-product matrix harness is deferred (cohort-wide).

### B.4 Recommendation (operator-decides — not acted on)

**Keep the peer in-repo under `protocol-generator/java/` for v0.1, at the `0.1.0-pre`/Apache-2.0
line; defer the Maven Central deploy until the operator verifies the `org.entitycore` namespace and
arch signs off v0.1 + a first external consumer confirms.** Rationale: the standalone-repo lift
(S10) is deferred cohort-wide and lifting Java alone fragments the uniform posture; the
zero-runtime-dependency artifact has no distribution friction to solve; and the Maven Central
namespace-verification gate (A-JAVA-005) is genuinely a one-time operator action the pipeline cannot
take. **Lift to a standalone repo + register the Maven Central namespace at the same time the cohort
does** (when arch defines the S10 per-language-repo + CI home), promoting to `0.1.0` once the
external-consumer gate is met. Hold the **agility full MATRIX** as an explicit post-v0.1 item. This
is a recommendation only — **the operator decides; the pipeline does not publish, tag, or push.**

---

## C. Summary for arch (one paragraph)

Peer #7 vindicates the convergence thesis at the cohort's *mainstream static-OO / JVM bookend* — the
most-deployed enterprise idiom, with mostly-saturated axes, reached **0 FAIL spec-first with a
peer_id byte-identical to the Common Lisp peer** and a byte-identical codec (69/69) + registry
(53/53), every static-OO seam (records+sealed-switch, checked exceptions, virtual threads) landing
at impl locality with **zero wire-byte divergence.** Its highest-value contributions are (1) **one
genuinely-new spec defect — A-JAVA-010 ⚑ §1.1 entity `data` is an arbitrary ECF value, not
necessarily a map** (the map-only assumption passes S2/S3 then silently 500s on scalar data at the
§7b gate; the most natural model for the most-deployed idiom walks into it — recommend a scalar-data
vector + a §1.1 emphasis); (2) the cohort's most refined **crypto-agility data point — A-JAVA-007**:
the JDK's vendor-curated stdlib closes the agility *signature* bar natively (zero-dep, company with
CL/Elixir; contrast OCaml C-ABI, Zig gap) but leaves a raw-*public-key* gap (no SHAKE256, no
seed→public) requiring a hand-rolled KAT-verified SHAKE256; (3) independent re-confirmation of the
two standing spec defects — §7.4-vs-§1.5 peer-id (A-JAVA-004 ⚑, now **four** spec-first peers) and
the §5.2 401/403 boundary (A-JAVA-009 ⚑, now **five** peers); and (4) the §6.6 idiom-neutrality
*single-dispatch static-OO bookend* to CL's multiple dispatch. **The one item the arch MUST rule
before the cohort has a single canonical core count: A-JAVA-011 — §7b concurrency now gates
`--profile core` at the in-flight oracle HEAD `749e57e`, moving the core gate 568→573 (all +5 PASS
on Java's virtual threads). Is §7b-gates-core intended for v0.1? And Java's 573·0F must be re-confirmed
once `749e57e` lands on origin/main.** Java's verdict is 0 FAIL either way (568-subset or
573-superset), so the merge is safe; the canonical count is not. The v7.73/v7.74 spec-data snapshot
(A-JAVA-001, corroborates A-CL-001) remains the standing provenance ask; the agility full MATRIX is
a documented, non-v0.1, primitives-already-native item; Maven Central publish (A-JAVA-005) is a
deferred operator step.

---

## PART D — Consolidated findings ledger (for the arch escalation bundle)

Every A-JAVA-### with its arch-bound flag, criticality, and one-line state. Ready to lift into the
cross-peer arch escalation bundle.

| Finding | Arch-bound | Criticality | One-line state |
|---|---|---|---|
| **A-JAVA-004** §7.4-vs-§1.5 peer-id | ⚑ ARCH | **High — silent handshake kill** | **4th-peer convergence** (Zig/OCaml/CL/Java); §7.4 NORMATIVE SHA-256-form contradicts §1.5 identity-multihash table; resolved via §1.5; peer_id byte-identical to CL. |
| **A-JAVA-009** §5.2 401/403 boundary | ⚑ ARCH | High — wrong auth status class | **5th-peer convergence** (OCaml F20 / Zig / Java + cohort); §5.2 flat DENY→403 under-specifies §4.6 authn(401)/authz(403)/§5.5-grantee(401); resolved via 3-way verdict. |
| **A-JAVA-010** §1.1 scalar entity `data` | ⚑ ARCH | High-signal — latent interop trap | **NEW**; `data` is any ECF value, not necessarily a map; map-only model passes S2/S3, silently 500s on scalar data at §7b; recommend a scalar-data vector + §1.1 emphasis; resolved via generalized `Entity`. |
| **A-JAVA-007** JDK raw-pubkey gap | ⚑ ARCH | Medium — crypto-ledger data point | **NEW**; SunEC closes agility *sign/verify* native/zero-dep (company CL/Elixir; contrast OCaml C-ABI, Zig gap) but no SHAKE256 + no seed→public → hand-rolled KAT-verified SHAKE256 + RFC-8032 derivation. |
| **A-JAVA-011** §7b-gates-core | ⚑ ARCH | **High — re-baselines canonical core count** | §7b concurrency now gates `--profile core` at oracle HEAD `749e57e` (568→573); +5 all PASS on virtual threads; §7a dispatch-outbound = generic verbatim relay. **Needs arch ruling (is §7b-gates-core v0.1?) + re-confirm when `749e57e` lands upstream.** |
| **A-JAVA-001** v7.73/v7.74 spec-data snapshot | (research/arch) | Low — provenance gap | OPEN; local snapshot stops at v7.72, oracle check-set IS at HEAD, peer v7.73+ behavior cohort+oracle-sourced; corroborates A-CL-001. |
| **A-JAVA-005** Maven Central namespace | (operator) | Low — packaging step | Deferred; verify `org.entitycore` reverse-DNS namespace before first deploy. Maven supports `-pre` directly (contrast A-CL-010). |
| **A-JAVA-008** 53-type registry | — | CLOSED | Full 53-type §9.5 floor + real type-validate body landed; 53/53 byte-identical. |
| **A-JAVA-002** crypto sourcing | (operator/research) | RESOLVED | SunEC sign/verify both curves zero-dep; raw-pubkey gap split to A-JAVA-007; BC test-scope only. |
| **A-JAVA-003** concurrency model | (operator) | RESOLVED | JDK-21 virtual threads (Loom); 8/8 demux at S3; unlocked the §7b superset. |
| **A-JAVA-006** Maven sha512 | (operator) | RESOLVED | 3.9.9 sha512 filled + verified on two Apache mirrors; build fails closed. |
