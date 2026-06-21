# entity-core-protocol-prolog — Spec Ambiguity Log

> Discipline: every guess goes here; no silent guesses. Items escalate to
> architecture/research via `research/stewardship/`. Prolog is an EXPERIMENTAL
> PROBE of the logic / declarative paradigm — the FIRST logic-programming peer.
> Its value is the NEW probes it surfaces by deriving from V7 in a relational
> idiom, AND the honest paradigm-fit finding (see arch/PROFILE-RATIONALE.md "Does
> this idiom map?" — S1 verdict leans DEFER). Entries prefixed `A-PL-` to namespace
> from the prior logs.
>
> Phase coverage so far: **S1 (profile authoring only)**. No build, no toolchain
> run (S1 boundary). Items tagged "(S2 verify)" are SWI-Prolog library/availability
> facts asserted from documentation that S2 must confirm against the running image —
> the honest S1 posture (swipl is not runnable under the no-build boundary), the
> same "confirm the exact symbol at S2" stance the CL profile took for ironclad.

---

## A-PL-001: Does the logic paradigm map to a byte-exact TCP wire peer at all? (the probe's core question)

**V7 section:** whole-peer (§4 transport, §1.5/§7.3 ECF, §5.5 chains, §6 dispatch)
**Profile field:** `[codec].strategy`, `[idiom].*`
**Your guess:** Authored the FULL native profile, then assessed: the byte-exact
framed-TCP I/O + the two canonical-CBOR side conditions (map-key ordering,
shortest-float) are irreducibly imperative and the latter actively resist the DCG
idiom; the genuinely-relational parts (CBOR structure as DCG, chain-walking,
unification decode) are real but a minority of the surface. **Verdict: lean
DOCUMENT-AND-DEFER**, with a narrow GO gated on an S2 `cbor.pl` spike of the
`map_keys` + `float` vectors (full reasoning in arch/PROFILE-RATIONALE.md).
**Rationale:** S1's explicit job is an honest idiom-fit call grounded in real design
work; defer is a valid clean outcome. The imperative surface dominates (~70–80%); the
idiom would survive in pockets but not characterize the peer — failing the experimental
question's bar.
**Escalation:** operator/research — go/defer decision is the orchestrator's; the
paradigm finding (canonical side conditions resist declarative expression) is
landscape signal for research.

## A-PL-002: library(crypto) Ed25519 + SHA availability on the pinned image (S2 verify)

**V7 section:** §9.1 floor (Ed25519 + SHA-256), §1.5/§7.3 (crypto)
**Profile field:** `[codec].ed25519_library`, `[codec].sha256_source`
**Your guess:** SWI-Prolog's bundled `library(crypto)` provides `ed25519_new_key/sign/
verify` + `crypto_data_hash/3` (sha256/sha384) on an OpenSSL-3 image; fedora:43 ships
OpenSSL-3, so the floor is native. Exact predicate spellings + option terms asserted
from SWI documentation, not run.
**Rationale:** library(crypto) is the de-facto SWI crypto surface and ships in the
distribution; OpenSSL-3 backs it. swipl is not runnable at S1 (no-build boundary) so
this is doc-asserted; the Containerfile build assertion confirms it (fails closed if
the floor is absent).
**Escalation:** operator (local verification) — confirm at S2 first build; FFI
fallback (A-PL-003) is the documented route if absent.

## A-PL-003: Ed448 likely needs FFI (library(crypto) ed448 uncertain) — corroborates A-OC-002 / A-ZIG-002

**V7 section:** §9.x crypto-agility higher bar (v7.67: key_type Ed448 0x02, SHA-384 0x01)
**Profile field:** `[codec].ed448_library`
**Your guess:** Source Ed448 over the C-ABI (`ec_ed448_{seed_to_pubkey,sign,verify}`),
scoped to an opt-in agility module — the OCaml A-OC-002 hybrid shape — UNLESS S2
confirms the bundled library(crypto)+OpenSSL-3 exposes Ed448 via a generic EVP key
path (then it collapses to native, the Elixir position).
**Rationale:** OpenSSL-3 implements Ed448, but SWI's library(crypto) historically
wrapped ed25519 without a guaranteed ed448 predicate. The Containerfile probes ed448
and reports present/absent WITHOUT failing the build (floor is unaffected).
**Escalation:** arch (corroboration — FOURTH peer to find "second managed crypto
provider gives Ed448" does NOT generalize outside BouncyCastle languages; OpenSSL-via-
FFI is the recurring escape) + operator (S2 wires whichever path the probe reports).

## A-PL-004: Canonical-CBOR side conditions resist the DCG idiom (the paradigm-fit finding)

**V7 section:** ENTITY-CBOR-ENCODING §4.x (canonical: map-key ordering + shortest-float)
**Profile field:** `[codec].cbor_library`, `[idiom].dcg_binary_grammar`
**Your guess:** CBOR *structure* is an idiomatic DCG; the canonical *side conditions*
are NOT — length-then-lex map-key ordering is an imperative encode→sort→emit pipeline
(a DCG can't sort its own output), and shortest-float is IEEE-754 bit manipulation in a
language whose floats are opaque doubles. So the codec splits: idiomatic DCG frame +
imperative canonical predicates. Spike `map_keys` + `float` at S2 before committing.
**Rationale:** These two are the specific features where the declarative idiom yields;
this is the load-bearing S1 finding and the gating input to the go/defer call.
**Escalation:** research (paradigm-fit landscape signal: canonical CBOR's determinism
side conditions are the feature that resists logic-programming expression).

## A-PL-005: Determinism must be FORCED against the engine (paradigm-specific correctness hazard)

**V7 section:** §1.5/§7.3 ECF (encode/decode are functions, not relations)
**Profile field:** `[error_model].det_discipline`, `[idiom].det_codec`
**Your guess:** Codec entry points MUST be deterministic (`once/1` / cut / `det`) so the
wire boundary never leaks a choice point; uncontrolled backtracking across an I/O side
effect is a correctness bug. Enforced at every public codec/transport predicate.
**Rationale:** Prolog's defining feature (nondeterministic search) is a HAZARD here — a
re-entered choice point could re-emit bytes or re-decode. This is the Prolog analogue of
"the codec is pure"; here purity must be enforced, not assumed.
**Escalation:** operator (local impl discipline; verify with `det`/`?-` mode checks at S2).

## A-PL-006: Failure-vs-exception error boundary (does any spec path want relational failure?)

**V7 section:** §5.2 verdicts, N2/N3 decode rejection
**Profile field:** `[error_model].style = failure+exceptions`
**Your guess:** Decode-as-relation predicates FAIL (backtrackable) for "this term is not
that"; the codec THROWS `error(entity_core_error(Kind,Detail), Context)` on N2/N3 hard
rejects (non-canonical/truncated/tag-6/bad-seed) — silent failure on malformed input
would mask corruption as absence.
**Rationale:** The ISO Prolog convention (error/2 formal terms) + the relational
failure model give a two-level error story no prior peer had. Probe: does any V7 path
want recoverable relational failure vs a terminal throw? Expectation: all codec-floor
rejects are terminal throws; failure earns its keep only at the query surface.
**Escalation:** note (idiom probe — the failure/exception boundary is the logic-paradigm
analogue of the CL conditions/restarts probe A-CL; expectation is "all terminal").

## A-PL-007: §7b/§4.8 store-race safety — clause DB needs explicit with_mutex for RMW (Zig/CL lesson)

**V7 section:** §4.8 store-safety, §7b concurrency (T2.1/T2.2)
**Profile field:** `[async].store_model`
**Your guess:** The store is the clause DB (`assertz`/`retract`). SWI gives a
logical-update view with an implicit per-predicate lock so a SINGLE assert/retract is
atomic — but a multi-step read-modify-write needs an EXPLICIT `with_mutex/2` critical
section. Wrap every RMW, not just single ops. TCP_NODELAY on accepted streams; no
blocking syscall under a shared lock.
**Rationale:** This is exactly the Zig/CL store-race fall-over that drove the v7.75 §4.8
floor — flagged proactively so S3 does not rediscover it at the concurrency gate.
**Escalation:** operator (S3 impl discipline; the §7b gate verifies it).

## A-PL-008: fedora:43 swi-prolog patch version — confirm 9.2.x stable line (S2 verify)

**V7 section:** absent (toolchain pin, S11)
**Profile field:** `[deps].swipl = 9.2.9`
**Your guess:** Use the fedora:43 `swi-prolog` package IF it is a 9.2.x stable patch;
else source-build the pinned 9.2.9 tag (the commented Containerfile block). Any 9.2.x
stable patch is acceptable; the build asserts the resolved version is on the 9.2.x line.
**Rationale:** 9.2.x is the stable/LTS branch (even minor = stable in SWI's even/odd
scheme; 9.3.x is development). The exact distro patch is unknown without running the
image (S1 no-build boundary).
**Escalation:** operator (S2 first build resolves it; re-stamp the pin to the resolved
patch).

## A-PL-009: ENTITY-CBOR-ENCODING SHA stability v7.71→v7.75 (S2 verify)

**V7 section:** ENTITY-CBOR-ENCODING.md, ENTITY-NATIVE-TYPE-SYSTEM.md
**Profile field:** `[spec].codec_corpus = v7.75`
**Your guess:** Profile + codec derive from `spec-data/v7.75` (latest snapshot, now a
real "Version: 7.75" snapshot — newer than CL's v7.72 read). Confirm at S2 that the
codec-relevant docs are unchanged (no wire-format break) across v7.71→v7.75 by SHA
rather than assuming.
**Rationale:** v7.72→v7.75 folds (nonce-echo, register/outbound/emit, resource bounds)
are peer-layer (S3+), not codec — but verify the ENTITY-CBOR-ENCODING SHA rather than
assume the no-wire-change claim.
**Escalation:** research/arch (provenance — confirm the snapshot SHA chain at S2).

## A-PL-010: peer_id construction §1.5 canonical-form — SETTLED, baked in (corroborates A-ZIG-001 / A-OC-007 / A-CL-002)

**V7 section:** §1.5 (line 459: Ed25519 → 0x00 identity-multihash; lines 446–447 digest
IS the raw 32-byte public_key) — and §7.4 (v7.73 E1 already reconciled to defer to §1.5)
**Profile field:** `[spec]` peer_id note
**Your guess:** Derive the Ed25519 peer_id from the §1.5 canonical-form table —
`hash_type = 0x00` identity-multihash, digest = raw public-key bytes — wire form
`Base58(key_type || hash_type || digest)`. IGNORE the historical §7.4 SHA256(pubkey)
skeleton.
**Rationale:** CONFIRMED in spec-data/v7.75 (§1.5 line 459). On this snapshot the v7.73
E1 erratum has ALREADY reconciled §7.4 to defer to §1.5 — so this is no longer a
contradiction, just a settled fact. Baked in proactively because the conformance corpus
uses opaque digests (a wrong construction passes S2 and only blows up at the S4
handshake — the cycle Zig/OCaml burned).
**Escalation:** note (no longer an open spec ambiguity on v7.75; recorded as a settled
trap pre-resolved in the profile so S3/S4 do not regress it).

> **S4 CORRECTION (A-PL-010a):** the `key_type` byte was WRONG. The peer
> shipped `key_type = 0x00` for Ed25519; the Go oracle `@75c532e` rejected it at the
> very first handshake check —
> `hello_peerid_valid FAIL: invalid peer_id "…": authentication failed: unsupported
> key type 0x00`. The §1.5 key registry codes Ed25519 = **0x01** (and Ed448 = 0x02);
> only the `hash_type` is 0x00 (identity-multihash, raw-key digest). The cohort
> (Ruby `KEY_TYPE_CODES = {ed25519:1, ed448:2}`, OCaml, …) all use 0x01. Fixed in
> `ec_identity.pl:peer_id_of_pubkey/2` → `ec_peerid_format(1, 0, Digest, _)`. This is
> EXACTLY the "passes S2, blows up at the S4 handshake" cycle this entry warned about
> — the corpus uses opaque digests so S2/S3 (53/53 type-registry, 11/11 loopback) were
> all GREEN with the wrong byte because both loopback peers shared the same wrong
> derivation; only the cross-impl oracle caught it. Lesson reinforced: peer_id
> key_type must be validated against the oracle, not just self-consistency.

---

## A-PL-017: SWI named-alias mutexes leak under connection churn — use ANONYMOUS mutexes (NEW, S4)
**V7 section:** §7b concurrency / §4.10 resource bounds
**Finding:** the transport created a NAMED-alias mutex per connection
(`mutex_create(conn7_pend)`). A named global mutex persists for the process lifetime
and is never GC'd; under the oracle's connection-churn probe (`concurrency.t2_2`,
100+ connect→close cycles) the host exhausted the named-mutex table and
`mutex_create` began throwing `No permission to create mutex 'connN_pend'`, killing
serve threads → `t2_1_sustained_load` dropped 2057/10000 requests and `t2_2` failed
to connect. Switching to ANONYMOUS mutexes (`mutex_create(-Id)` with an unbound arg,
reclaimable) + explicit `mutex_destroy` at connection teardown (`io_destroy/1`) made
concurrency 5/5 (t1_2/t1_3/t2_1/t2_2 PASS; t1_1 the informational no-speedup WARN).
**Resolution:** per-connection mutexes are anonymous + destroyed on teardown; only
process-lifetime singletons (`ec_peer_outctr`) use a named alias.
**Escalation:** note (SWI resource fact; a logic-paradigm-specific footgun the
OO/functional peers don't hit because their lock objects are GC'd value objects).

## A-PL-018: the §6.11 reentry seam must be a MODULE-QUALIFIED closure term (NEW, S4)
**V7 section:** §6.11 / §6.13(b) outbound reentry, §7a dispatch-outbound
**Finding:** the transport handed the dispatcher an outbound seam as the unqualified
term `outbound_via(IO)`; the dispatcher (`ec_peer`) invokes it `call(Outbound, Req,
Resp)`. SWI resolves an unqualified `call/N` goal in the CALLER's module — so
`outbound_via/3` was looked up in `ec_peer` (where it doesn't exist) →
`existence_error(procedure, ec_peer:outbound_via/3)`, surfacing as `dispatch-outbound`
returning 503 `no_outbound_seam` (the §6.11 reentry probe `concurrency.t1_2` +
`origination.dispatch_outbound_reentry`). Fix: hand the seam as the MODULE-QUALIFIED
term `ec_transport:outbound_via(IO)` so `call/3` pins resolution to `ec_transport`.
Same class as A-PL-009 (the cross-module callback footgun) but for a TERM passed
across modules rather than a meta-predicate argument — `:- meta_predicate` fixes the
arg case; an explicit module qualifier fixes the term-closure case.
**Resolution:** seam terms crossing a module boundary carry their module qualifier.
With the fix: `t1_2_concurrent_reentry` PASS (8/8 concurrent reentries) and
`origination.dispatch_outbound_reentry` PASS over real 2-peer TCP vs the Go reference.
**Escalation:** note (recorded so S5/maintainers keep the qualifier on the seam).

---

## S2 SPIKE RESULTS — bounded codec spike, empirical resolution

> Container BUILT (`entity-core-keystone/prolog-toolchain`, swipl 9.2.9 on
> fedora:43, image-OpenSSL 3.5.4). Minimal `cbor.pl` spike under
> `spike-s2/` exercised ONLY the two resistant vector classes against the
> v7.71 ECF corpus (`conformance-vectors-v1.diag`; ECF corpus byte-identical
> v7.56→v7.71 per MANIFEST). Result: **20/20 byte-exact PASS** (14 float.* +
> 6 map_keys.*). No vector doctored — map_keys.4 expected bytes are parsed
> verbatim from the diag hex at runtime.

### A-PL-008 — RESOLVED (positive)
fedora:43 ships `swi-prolog 9.2.9` (version flag 90209) — ON the 9.2.x stable
line. No source-build needed. OpenSSL in image: 3.5.4.

### A-PL-002 — RESOLVED **NEGATIVE** (the surprise; escalate)
SHA-256/384 via `crypto_data_hash/3` (algorithm(sha256)/algorithm(sha384)):
**PRESENT and working** — confirmed exact digests. BUT the predicted Ed25519
predicates **DO NOT EXIST**. `library(crypto)` in swipl 9.2.9 exports NO
ed25519_* predicates at all (`ed25519_new_key/sign/verify` → existence_error).
Full exported signature surface is only: `ecdsa_sign/4`, `ecdsa_verify/4`,
`rsa_{sign,verify}/4`, `crypto_curve_{generator,order,scalar_mult}` (and these
curves reject `ed25519`/`prime256v1`/`secp256k1` by name — type_error
crypto_curve), plus hashing/HKDF/encrypt. **There is NO native Ed25519 path,
not even a generic EVP route.** The profile's "native floor" assumption is
WRONG: the §9.1 signature floor (Ed25519 sign/verify) is **NOT reachable in
SWI-Prolog without FFI.** This is a harder finding than S1 predicted — S1
expected only *Ed448* to need FFI.

### A-PL-003 — RESOLVED (Ed448 absent, as predicted, but now moot)
`ed448_new_key` also existence_error. Ed448 absent — corroborates
A-OC-002/A-ZIG-002 a 4th time. But A-PL-002 subsumes it: BOTH curves need FFI,
so the entire signature surface (not just agility) is an FFI obligation.

### A-PL-004 — RESOLVED: prediction PARTIALLY held; weaker than expected
The two resistant classes hit **byte-exact** (20/20). HOW they got there:
- **map_keys (canonical ordering):** the predicted shape is exactly what was
  needed — a DCG cannot sort its own output, so the encoder runs `cbor_value`
  as a *function* per key (`once(phrase(...))`), `predsort`s on the encoded key
  byte-lists (length-then-lex; SWI `compare/3` on code lists IS byte-wise
  lexicographic — a clean win), then re-splices. The sort is imperative
  scaffolding wrapped around the DCG, but it is SMALL and readable (~30 lines).
  The byte-string-vs-text key case (map_keys.5) and the length-prefix boundary
  (map_keys.4) both fell out correctly. **Idiom cost here: LOW-MODERATE.**
- **float (shortest-float ladder):** the prediction HELD HARD. SWI exposes NO
  float→IEEE-754-bits primitive (no `float_to_bits`, no hex-float format dir),
  so the f64 bit pattern is reconstructed ARITHMETICALLY (sign/biased-exp/
  52-bit frac via `log/floor` + exact rational frac), and f16/f32
  representability is tested by manual half/single bit-assembly + exact
  round-trip. ~112 lines, ENTIRELY imperative bit/branch arithmetic with zero
  DCG content — "C with `:-`". Annotated split in the spike file: **18 [IMP]
  vs 6 [DCG]** predicate annotations; the float block is 100% [IMP].
  **Idiom cost here: HIGH — this is the antithesis of the relational idiom.**

Net A-PL-004: canonical CBOR is byte-achievable in Prolog, but the
shortest-float side condition is pure imperative IEEE-754 scaffolding (the
prediction was correct); map-key ordering is more tractable than feared (mild
scaffolding around a genuine DCG). The idiom survives for *structure* and
*ordering* but collapses entirely for *float minimization*.

## Blocking-severity items: NONE

No item blocks the S1 exit (profile fully populated, no TBD-blocking — only
`repository_url` empty, TBD-on-first-publish, same as OCaml/Elixir/CL). A-PL-002 /
A-PL-003 / A-PL-008 / A-PL-009 are S2 verification tasks (gated by the Containerfile
build assertions); A-PL-001 is the go/defer verdict (operator decision, not a blocker).

---

---

## S2-FFI RESULTS — FFI codec + crypto binding, EMPIRICAL

> The codec/crypto floor is now sourced over the C-ABI (libentitycore_codec, ABI
> v1.1, impl `c 0.1.0 / ecf-c-abi 1.1 / spec-data v7.71 / libsodium 1.0.22`) via a
> SWI foreign-predicate shim (`c/ec_codec_pl.c` → `ec_codec_pl.so`, loaded with
> `use_foreign_library/1`; no external `ffi` pack). GATE: **69/69 wire-conformance
> byte-identical + 10/10 crypto KAT**, in-container, swipl 9.2.9 / fedora:43 /
> OpenSSL 3.5.4. Corpus pinned: v7.71 `conformance-vectors-v1.cbor` sha256
> `41d68d2d…a052` (matches MANIFEST).

### A-PL-009 — RESOLVED (corpus provenance confirmed)
The vendored v7.71 `conformance-vectors-v1.cbor` sha256 is `41d68d2d717f84e195d46
ec002fce6b8729742026256e72dc7a3a8b6c0c6a052` — byte-identical to the v7.71 MANIFEST
pin (ECF corpus unchanged v7.56→v7.71, as MANIFEST claims). No v7.74/v7.75
test-vectors directory exists yet; v7.71 is the latest vendored corpus and the gate
target. (Caveat carried to S4: the Go oracle stamp is v7.75-class; the *codec* corpus
is v7.71 and unchanged — confirm at S4 the oracle agrees on these 69 wire bytes.)

### A-PL-005 — RESOLVED (determinism discipline holds; one reporting nuance)
Every public codec predicate is `det`/`semidet`: `findall/3` over `ec_encode_ecf`,
`ec_sha256`, `ec_content_hash_prefixed`, `ec_ed25519_keygen`, etc. yields EXACTLY ONE
solution — the wire is a function, no choice point leaks. NUANCE: `deterministic/1`
called immediately after a foreign call inside an `(If->Then)` can report `false`
even when the single-solution invariant holds — a SWI foreign-call frame-teardown
reporting artifact, NOT a real leaked CP. SWI has NO "deterministic" registration
flag (only `PL_FA_NONDETERMINISTIC` opts INTO retry); flag 0 = deterministic, which
is what the shim uses. The `once/1` wrappers in `ec_codec.pl` are the explicit guard
at the public surface. Authoritative check = single-solution findall, which passes.

## A-PL-011: public ec_content_hash_with_format REJECTS forward-compat format codes the corpus still pins (NEW)

**V7 section:** §4.1a content_hash format codes (ENTITY-CBOR-ENCODING); C-ABI §4.1a
**Profile field:** `[codec]` content_hash surface
**Finding:** conformance vector `content_hash.4` pins a `format_code = 128` (0x80,
multi-byte LEB128) content_hash with REAL canonical bytes `8001 ‖ <SHA-256 digest>`.
But the PUBLIC C-ABI `ec_content_hash_with_format` only supports codes 0x00/0x01 and
returns `EC_DECODE_ERROR (unsupported_content_hash_format)` for 0x80 — so the public
ABI alone CANNOT reproduce the pinned bytes. The C-ABI's own conformance harness
sidesteps this by calling the INTERNAL `cc_content_hash` (format_code is just a
LEB128 prefix over the SHA-256 body; never enters the hashed body), which is NOT an
exported symbol. **Resolution (the peer's correct move):** COMPOSE the prefixed hash
from public symbols — `ec_content_hash` gives `0x00 ‖ digest`; swap the 1-byte `0x00`
prefix for `ec_hash_format_code_encode(128)` = `80 01`. Implemented as
`ec_content_hash_prefixed/4` in `ec_codec.pl`. content_hash.4 then passes byte-exact.
**Class:** a "test-vector pins behavior the public ABI deliberately rejects" seam —
the forward-compat code is representable on the wire but not a supported *hashing*
selection. Every FFI peer that drives content_hash.4 through the public ABI (rather
than an internal symbol) hits this; worth surfacing to arch as an ABI-surface note.
**Escalation:** arch (the public `ec_content_hash_with_format` contract vs the corpus
forward-compat vector) + note for the other FFI peers.

## A-PL-012: Ed448 (>32B pubkey) peer_id digest = SHA-256(pubkey), NOT raw key — §1.5 size-cutoff (NEW, corroborates A-PL-010 boundary)

**V7 section:** §1.5 canonical-form table — identity-multihash 32-byte size cutoff
**Profile field:** `[spec]` peer_id construction
**Finding:** A-PL-010 baked in "Ed25519 peer_id digest = the RAW 32-byte pubkey
(hash_type 0x00 identity-multihash)". That holds ONLY for keys ≤ 32 bytes. The Ed448
pubkey is 57 bytes, EXCEEDS the identity-multihash cutoff, so its peer_id digest is
`SHA-256(pubkey)` under `hash_type 0x01` ("SHA-256-form") — confirmed against agility
pin `KEY-TYPE-ED448-1` (`3dR1gAppfHXSGMvPRuAfYkkt4P2C1fvnFYpxPBSQP8RLs4` =
`Base58(0x02 ‖ 0x01 ‖ SHA256(pubkey))`). Passing the raw 57-byte key as digest yields
the WRONG base58. The agility KAT pins both the Ed448 pubkey/sign/verify (RFC 8032
byte-exact via the C-ABI vendored curve448) AND this peer_id construction.
**Resolution:** S3 peer_id construction MUST branch on pubkey length vs the §1.5
cutoff — identity-multihash (raw) for ≤32B (Ed25519), SHA-256-form for >32B (Ed448).
The C-ABI `ec_peerid_format` is digest-agnostic (it just LEB128-prefixes + base58s
key_type‖hash_type‖digest); the peer chooses the digest. Baked into the agility KAT
now so S3/S4 do not regress it.
**Escalation:** note (settled construction rule; recorded so S3 handshake/identity
does not rediscover it — the same class of trap A-PL-010 pre-resolved for Ed25519).

---

---

## S3 RESULTS — peer machinery + the relational core, EMPIRICAL

> Two Prolog peers talk over real loopback TCP through the full §6.5 dispatch
> chain. GATE: **type-registry 53/53 byte-identical + two-peer loopback smoke
> 11/11**, in-container (prolog-toolchain, swipl 9.2.9 / fedora:43), sealed-offline
> (`--network=none`, loopback only). S2 codec regression unbroken (69/69 + 10/10
> KAT). Full report: status/PHASE-S3.md.

### A-PL-006 — RESOLVED (the failure-vs-exception boundary; the genuinely-Prolog finding)
**Does any V7 error path want relational FAILURE (backtrack) rather than a thrown
term?** Answer: a clean TWO-CHANNEL split that the verdict semantics dictate.
- **Relational failure IS the dominant "deny" channel** in the §5.5 chain walk and
  is idiomatic: a link that doesn't satisfy `single_link_self_ok`/`link_attenuates`
  simply FAILS, and `\+ verify_capability_chain(...)` reads that failure directly as
  `authz_deny`. No `good` flag, no `return DENY` — *failure is denial*, the relational
  reading the spec's "valid iff …" invites. Cleaner than the cohort's boolean-flag walks.
- **The ONE path that needs a distinct channel** is the §5.5 unresolvable-grantee 401
  carve-out: it must surface as **401**, distinct from a 403 authz denial. Relational
  failure would collapse it into "denied" (403), so it is a THROWN term
  (`ec_capability(unresolvable_grantee)`) caught at the dispatcher → 401 (mirrors CL's
  condition). Prolog failure is mono-valued ("no") — it cannot say "no, specifically
  401-no", so a verdict whose HTTP-class must DIVERGE from its neighbors needs a
  non-failure channel.
- **Finding:** NOT "all terminal throws" (the S1 expectation). It is: failure for the
  dominant deny, a thrown marker only where the status class must diverge. The
  logic-paradigm analogue of the CL conditions/restarts probe.
**Escalation:** research (paradigm-fit landscape signal).

### A-PL-007 — VALIDATED (store-race safety)
The §3.9 store is the clause DB (`content_fact/3` + `tree_fact/3`); every RMW
(`store_bind`/`store_unbind`) runs inside `with_mutex/2` keyed per StoreId. The 8-way
request_id demux exercised concurrent dispatch + store writes with no corruption.

## A-PL-013: C-ABI ec_encode_ecf treats `data` as OPAQUE — the data-value canon is the caller's (NEW)
**V7 section:** §4.1 ECF encode; C-ABI codec.c (`ev_preencoded`)
**Finding:** `ec_encode_ecf(type, data)` canonicalizes only the OUTER `{data,type}`
entity map; the nested `data` value is wrapped as opaque pre-encoded bytes
(`ev_preencoded`) and NOT re-canonicalized. So an FFI peer MUST hand the data value to
the ABI *already in canonical CBOR* (minimal ints, length-then-lex map-key ordering).
"FFI the codec" does NOT eliminate a canonical-CBOR obligation at the data-value layer.
**Resolution:** the peer owns a canonical CBOR value codec (`ec_cbor.pl`) for the
data-value layer; the C-ABI still owns entity framing + content_hash + crypto. The
53/53 type-registry byte-diff is the proof the Prolog data-value canon matches the
cross-impl encoder.
**Escalation:** arch + note for the other FFI peers (the public-ABI contract delegates
data-value canonicalization to the caller; every FFI peer building entity data through
`ec_encode_ecf` carries this obligation).

## A-PL-014: framed binary TCP I/O is the irreducibly-imperative floor ("C with :-") (NEW, paradigm)
**V7 section:** §1.6 TCP length-prefix framing
**Finding:** `read_frame`/`write_frame` (read-exactly-N + 4-byte BE length over a
binary stream) are procedural by nature — the predicate arrows are punctuation, not
logic. As predicted in the handoff, this is the most imperative part of the peer. It is
the same imperative floor every peer has; Prolog does not make it worse, just visibly
procedural. (No idiom claim here — flagged as the expected non-relational pocket.)
**Escalation:** note (paradigm-fit landscape signal; expected, not a problem).

## A-PL-015: SWI module-meta-call — cross-module callbacks need meta_predicate (NEW, adoption hazard)
**V7 section:** absent (toolchain/idiom)
**Finding:** a closure passed across a thread/module boundary and invoked via `call/N`
resolves in the CALLEE's module unless the receiving predicate is declared
`:- meta_predicate`. Two real bugs hit this: the transport serve goal
(`serve_goal(Responder)` constructed in the test module, called in `ec_transport`) and
the store emit consumer (`on_tree_event` in the test module, called in `ec_store`) both
silently resolved in the wrong module — `existence_error` surfacing as a 10s-timeout
hang and a 500. Fix: `:- meta_predicate start_listener(3,+,-)` and
`register_*_consumer(+, 1)`.
**Escalation:** note (the cross-module-callback footgun a logic-paradigm peer phrases
differently from the OO/functional peers; record so S4/S5 maintainers don't reintroduce).

## A-PL-016: SWI global variables are THREAD-LOCAL — shared counters belong in the clause DB (NEW)
**V7 section:** §7b concurrency
**Finding:** `nb_setval`/`nb_getval` (and `b_*val`) are per-thread. A request-id counter
set on one thread and read on a per-connection/dispatch thread, or an emit counter
updated by the dispatch worker, must live in the SHARED clause DB (`assertz`/`retract`
under a mutex), not in global vars. The 8-way demux failed 0/8 until the request-id
counter moved to a `req_counter/2` dynamic predicate.
**Resolution:** shared mutable state lives in the clause DB (consistent with the
store-as-clause-DB idiom, A-PL-007); global vars are only safe for thread-confined state.
**Escalation:** note (SWI concurrency fact; recorded so the pattern is not regressed).

---

## S5 RESULTS — packaging + idiom-findings synthesis, EMPIRICAL

> Packaging artifacts filed (pack.pl, README, LICENSE, CHANGELOG, CI workflow) +
> the human-readable conformance report + the architecture review + THE
> idiom-findings synthesis (status/IDIOM-FINDINGS-SYNTHESIS.md — the deliverable).
> Regression re-ran GREEN in-container: S2 69/69 + 10/10 KAT, S3 53/53 + 11/11, S4
> 653·291P/269W/0F/93S @ 75c532e (`failed == 0`). No prior-phase regressions.

## A-PL-019: SWI pack `version` grammar is dotted-NUMERIC only — no pre-release channel (NEW, S5)
**V7 section:** absent (toolchain/packaging, S5/S11)
**Profile field:** `[packaging].pack_file`, `[publishing]`
**Finding:** SWI's pack version validator `prolog_pack:is_version/1` is
`split_string(V,".","",Parts), maplist(number_string,_,Parts)` — every dot-separated
component MUST parse as a number. So it REJECTS `0.1.0-pre`, `0.1.0pre`, `0.1.0_pre`,
`0.1.0-alpha.1`, `0.1.0-1` (ALL INVALID — verified empirically in-container, swipl
9.2.9); only the bare dotted **`0.1.0`** is VALID. SWI has NO pre-release channel at
all — STRICTER than SemVer AND stricter than RubyGems (which at least accepts the
dotted `0.1.0.pre`, A-RUBY-010) AND than ASDF (also dotted-integer-only, A-CL-010,
but the same class). This is the THIRD cohort ecosystem whose version grammar
disagrees with the SemVer dash, and the strictest of the three.
**Resolution:** `pack.pl` carries the parseable `version('0.1.0')`; the `0.1.0-pre`
pre-release LINE lives in CHANGELOG.md + README.md, NOT in pack.pl. A future
promotion to `0.1.0` needs no pack.pl change — only the docs drop the `-pre`.
**Escalation:** operator (recorded for future promotions; the SWI analogue of
A-CL-010 / A-RUBY-010).

## A-PL-006: ANSWERED + developed (the genuinely-Prolog finding — S5 synthesis)
**V7 section:** §5.2 verdicts / §5.5 chain / N2/N3 decode rejection
**Finding (final form, see IDIOM-FINDINGS-SYNTHESIS.md §2):** the protocol's verdict
semantics fit a TWO-CHANNEL error model. Relational FAILURE is the dominant,
idiomatic "deny" channel — a §5.5 link that doesn't satisfy the relation simply
fails, and `\+ verify_capability_chain(...)` reads that failure directly as
`authz_deny` (no boolean flag, no `return DENY`). The ONE path that needs a distinct
channel is the §5.5 unresolvable-grantee 401 carve-out: it must surface as 401,
distinct from a 403 deny, and Prolog FAILURE IS MONO-VALUED — failing means "no", it
cannot carry "no, specifically the 401 kind". So it is a THROWN term
(`ec_capability(unresolvable_grantee)`) caught at the dispatcher → 401. The boundary
is NOT the S1 guess ("floor = throw, query = fail"); it is **"deny = fail,
status-class-DIVERGENCE = throw"** — and the interesting boundary lives in the authz
verdict layer, exactly where the logic idiom is strongest. The logic-paradigm
analogue of the CL conditions/restarts probe.
**Escalation:** research (paradigm-fit landscape signal — tells the team that
401-vs-403 in §5.5 is a genuine *kind* distinction, carried out-of-band from the deny
path in any implementation).
