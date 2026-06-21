# entity-core-protocol-ruby — Spec Ambiguity Log

Every guess the agent makes goes here (S3 discipline). Items escalate to
architecture as proposal candidates via `research/stewardship/`. **No silent
guesses.** Prefix `A-RUBY-NNN` (Ruby peer #12).

Note: peers #1–11 already surfaced and (mostly) resolved a large set of
*spec-level* ambiguities (peer-id §7.4/§1.5, 401/403 §5.2a, format_code, hex-case
§3.4/§3.5, §4.10 403→400 chain-depth, A-JAVA-010 `data`-shape, …). Those are spec
facts now folded into v7.75 (the snapshot this peer reads), not re-litigated per
language. This log records **Ruby-specific** guesses plus any **new** spec gap
this peer surfaces. Cross-references to shared findings use their original ids.

---

## A-RUBY-001: codec strategy = native; CBOR hand-rolled (no Ruby gem does ECF)

**V7 section:** ENTITY-CBOR-ENCODING.md (ECF canonical form), §4.7 (construct-vs-decode)
**Profile field:** `[codec].strategy`, `[codec].cbor_library`
**Your guess:** `native` strategy with a **hand-rolled** canonical CBOR
encoder/decoder. No Ruby CBOR gem delivers the full ECF contract: `cbor` (C ext)
emits insertion-order maps / no float-min / accepts tags; `cbor-canonical` gives
RFC-7049 §3.9 length-first ordering (the right axis) but is encode-only with no
float minimization and no recursive tag-6 decode rejection; `cbor-deterministic`
targets RFC-8949 bytewise ordering (the WRONG order for ECF). Hand-roll the
canonical layer (length-then-lex on encoded key bytes, shortest-float incl. f16,
recursive major-type-6 rejection, full uint64/nint range, verbatim raw-byte
`data` N4).
**Rationale:** The A-005 pattern, now 12-for-12: a faithful ECF codec owns the
canonical layer regardless of library. Hand-rolling is simpler than gluing
`cbor-canonical`'s encode half to a custom decoder + custom float pass, and keeps
the zero-runtime-gem-dependency story. Ruby's arbitrary-precision `Integer` (no
uint64 head-form trap) and ASCII-8BIT `String` byte buffers make it clean.
**Escalation:** **operator** — design decision, no spec impact. Spike the
`map_keys` + `float` vectors at S2 before the full build (the load-bearing risk).

---

## A-RUBY-002: Ed448 native via stdlib `openssl` (overturns the ffi default) — verify bundled OpenSSL has Ed448 at S2

**V7 section:** §1.5 / §7.3 multikey (key_type 0x02 = Ed448); crypto-agility higher bar (v7.67)
**Profile field:** `[codec].ed448_library`
**Your guess:** Source Ed448 **natively** from stdlib `openssl`
(`OpenSSL::PKey.generate_key("ED448")`, `sign(nil, msg)`/`verify(nil, sig, msg)`,
57-byte seed / 114-byte sig, PureEdDSA) — the SAME generic PKey surface as
Ed25519, **no FFI** (contrast OCaml A-OC-002's hybrid-FFI Ed448). OpenSSL 3.x
(Debian bookworm in `ruby:3.4.4-slim-bookworm`) provides Ed448.
**Rationale:** This replicates the Elixir/Haskell native-full-agility result on a
3rd native-crypto substrate (Ruby stdlib openssl). One crypto source, fewer deps,
strictly larger reach than libsodium/RbNaCl (which lacks Ed448).
**Risk / verification:** the *bundled* OpenSSL build must actually enable Ed448.
The Containerfile asserts `OpenSSL::PKey.generate_key("ED448")` round-trips at
BUILD time (fails loudly otherwise), and the byte-pin is verified against the
agility corpus at S2. fedora/debian OpenSSL 3.x ships Ed448, so this is expected
to pass; flagged here because it is the one crypto-reach assumption.
**Escalation:** **operator** — resolved-pending-S2-byte-verify; no spec impact.

**S2 RESOLUTION:** **RESOLVED — Ed448 native, byte-verified.** The
container build-time assertion passed (`crypto ED448 OK (sig 114B)`), and the S2
agility run byte-matches the v7.67 pins: Ed448 seed→pubkey (`2601850d…3b0e00`),
peer_id (`3dR1gApp…P8RLs4`), the `system/peer` ECF data bytes + SHA-256-form
content_hash (`002785b3…0748`), and the 114-byte signature over the fixture
message (`0aff7a36…33400`). The bundled Debian-bookworm OpenSSL 3.x ships Ed448;
**no FFI**. Closed.

---

## A-RUBY-003: stdlib `openssl` EdDSA exact API + raw-key method availability — confirm in-container at S2

**V7 section:** n/a (impl detail); §1.5 identity derivation (seed→pubkey)
**Profile field:** `[codec].ed25519_library` / `ed448_library`
**Your guess:** Use the generic PKey EdDSA form: `OpenSSL::PKey.generate_key(alg)`
/ `OpenSSL::PKey.new_raw_private_key(alg, seed)` for key construction, `sign(nil,
msg)` / `verify(nil, sig, msg)` with an explicit **nil** digest (PureEdDSA), and
`raw_private_key` / `raw_public_key` for the 32-byte (Ed25519) / 57-byte (Ed448)
raw key material §1.5 needs.
**Rationale:** This is the documented modern Ruby openssl API; `raw_private_key`/
`raw_public_key` / `generate_key`(string-alg) / `new_raw_private_key` require the
**openssl gem ≥ 3.0**, which Ruby 3.4 bundles. The seed→pubkey derivation §1.5
needs is `new_raw_private_key(alg, seed).raw_public_key`.
**Resolution path:** confirm the exact method names + raw-key round-trip against
the pinned Ruby 3.4.4 / OpenSSL 3.x in `containers/ruby-toolchain` at S2 (the
Containerfile already round-trips sign/verify; S2 additionally confirms
`raw_private_key`/`raw_public_key` and `new_raw_private_key`). If a method spelling
differs in the bundled openssl version, adjust the crypto shim at S2 (no spec
impact — Ed25519/Ed448 are deterministic, so byte-conformance is unaffected).
**Escalation:** **operator** — impl detail, no spec impact.

**S2 RESOLUTION:** **RESOLVED.** Confirmed in-container against Ruby
3.4.4 / OpenSSL 3.x: keys are imported from raw seeds via
`OpenSSL::PKey.new_raw_private_key(alg, seed)` (and `new_raw_public_key(alg, pub)`
for verify-only); signing/verifying use `sign(nil, msg)` / `verify(nil, sig, msg)`
with an explicit `nil` digest (PureEdDSA); raw key material via `raw_private_key`
/ `raw_public_key` (32 B Ed25519, 57 B Ed448). The §1.5 seed→pubkey derivation is
`new_raw_private_key(alg, seed).raw_public_key`. The crypto shim
(`lib/entity_core/signature.rb`) uses exactly these; Ed25519 + Ed448 raw-key
round-trips pass in the codec unit suite. Closed (no spec impact —
deterministic curves, byte-conformance unaffected).

---

## A-RUBY-006: shortest-float / f16 — Ruby `Array#pack` has no half-float code

**V7 section:** ENTITY-CBOR-ENCODING.md Rule 4 / Rule 4a (float minimization +
special floats)
**Profile field:** `[codec].cbor_library` (the S2 float spike)
**Your guess:** Hand-encode f16 from the IEEE-754 binary64 bits rather than rely
on a pack format. `pack`/`unpack` only offer `g` (f32) and `G` (f64) — there is
**no half-float directive** — so `enc_float` decomposes via
`[f].pack("G").unpack1("Q>")`, checks the unbiased exponent is in `[-14, 15]`
(silent overflow-to-Inf guard) AND the low 42 mantissa bits are zero (exactness),
then assembles the 16-bit half with `pack("n")`. f32 uses `pack("g")` with an
exact-round-trip + all-ones-exponent guard. NaN/+Inf/-Inf/-0.0 take their fixed
Rule 4a f16 bytes. Decode rebuilds f16 with `Math.ldexp` (normals + subnormals)
and surfaces specials as native `Float::NAN` / `±Float::INFINITY`.
**Rationale:** Same ladder shape as the native siblings (Elixir `::float-16` bit
syntax, the BEAM f16-overflow probe), implemented against Ruby's available
primitives. All 14 `float` vectors pass first-try, incl. the
`65503→f32 / 65504→f16` boundary and the 2^15+ large-f16 cases that broke cbor2's
C extension.
**Escalation:** **operator** — impl detail, no spec impact. RESOLVED at S2.

---

## A-RUBY-004: concurrency = thread-per-connection under the GVL; Mutex-guarded store; Ractors declined

**V7 section:** §4.8 (store-safety / data-race = crash), §4.9 (resilience under load), §6.11 (reentrant request_id demux), §7b concurrency gate
**Profile field:** `[async]` (`threaded` / `thread-per-connection` / `mutex-guarded`)
**Your guess:** Meet §4.8/§4.9/§6.11 with **one Ruby `Thread` per connection**
(the single writer for that socket), a **Mutex/Monitor-guarded** shared store
(the §3.9 CAS put is a single critical section), and a `pending {request_id =>
waiter}` map + `ConditionVariable` for the §6.11 reentrant demux — the
threaded-peer shape (same as OCaml's reader-thread + Hashtbl + condvar). Set
**TCP_NODELAY** on every socket (§7b throughput). Decline **Ractors**.
**Rationale + honest GVL accounting:** MRI's GVL serializes Ruby bytecode (no
parallel Ruby execution) BUT is **released during blocking IO** — so
thread-per-connection is genuinely concurrent for this **IO-bound** peer, adequate
for §7b without worker pools/fibers. The GVL does **not** make compound
read-then-write atomic, so explicit Mutex locking is still required for §4.8
store-safety (a real correctness point, not boilerplate). Ractors give true
parallelism (no shared GVL) but impose a share-nothing object model that fights
the shared store and remain experimental — the wrong tool at core; noted as the
parallelism escape hatch. TCP_NODELAY per the Zig lesson (Nagle = the small-frame
req/resp throughput killer).
**Escalation:** **operator** — design decision, flagged for review (the GVL
trade-off + Ractor-decline are the Ruby-specific concurrency calls). No spec
impact; no dependency (all stdlib `socket`/`thread`).

**S3 RESOLUTION:** **RESOLVED — validated end-to-end.** The
thread-per-connection peer (one reader `Thread` per socket, each inbound EXECUTE
on its own `Thread`, §6.11 demux via a `pending {request_id => Waiter}` map +
`ConditionVariable`, per-connection write `Mutex`, **TCP_NODELAY** on every
socket) drives the two-peer loopback **11/11 GREEN**, including the 8-way
request_id demux (N7) — ran 8× with no flakiness. The Mutex-guarded store's
indivisibility is proven by a 64-thread CAS-from-absent race that yields
**exactly one winner** (`test/peer_test.rb`) — confirming the GVL does NOT make
the compound read-then-write atomic and the explicit `Mutex` is load-bearing.
Ractors stayed declined (not needed for this IO-bound peer). Closed.

---

## A-RUBY-007: matrix root_cap §3.6 cap-token shape — byte-confirmed (positive)

**V7 section:** §3.6 (capability-token CBOR shape); crypto-agility matrix (v7.67)
**Profile field:** n/a (peer-layer obligation deferred from S2)
**Resolution:** The 3 S2-deferred `root_cap` gates (`matrix.M2/M3/M6.root_cap`)
are now byte-green on the first attempt. The cap token is
`{granter:<A home-format hash>, grantee:<B SHA-256 hash>, grants:[{handlers:
{include:[]}, operations:{include:[]}, resources:{include:["system/validate/
matrix/*"]}}], created_at:0, expires_at:0}` (map fields ordered by the codec's
length-then-lex sort); its content_hash uses the ACTIVE negotiated format
(SHA-256 in all three vectors), and peer A signs the 33-byte content_hash. Both
the **content_hash AND the signature** match the v7.67 pins across the Ed448
granter (M2), the SHA-384 home identity (M3), and the combined cross-key +
cross-hash case (M6). This corroborates the Elixir A-ELX-005 result on the 2nd
independent peer to pick these up — the optional-field convention (parent omitted
when nil) is byte-stable.
**Escalation:** **operator** — positive confirmation; no spec gap. RESOLVED.

---

## A-RUBY-008: §9.5 type-registry — S3 seeds a minimal subset (full 53 at S4)

**V7 section:** §9.5 (core type floor)
**Profile field:** n/a
**Your guess:** S3 publishes a small `system/type` seed (`CoreTypes::SEED`) so
the type tree exists for resolution; the FULL 53-type §9.5 floor (render-from-
model, byte-diffed against `type-registry-vectors-v1`) lands at S4 with the
`type_system` oracle category. The smoke gate does not fetch types, so the
minimal seed is sufficient for S3.
**Rationale:** Mirrors the cohort (C#/TS/Java A-*-008): the 53-type registry is
the heaviest S4-specific render surface and is gated by an oracle category, not
the wire smoke. No point byte-pinning it before the S4 vectors are available.
**Escalation:** **operator** — phase-scoping decision, no spec impact.

**S4 RESOLUTION:** **RESOLVED — full 53-type §9.5 floor seeded,
53/53 byte-match.** Published render-from-shapes: each type's `TypeDefinition`
shape is vendored (`lib/entity_core/data/core_type_floor.rb`) dumped byte-exact
from the Go reference registry @75c532e (throwaway `cmd/dump-floor` mirroring
`cmd/internal/validate/typesystem.go`: `RegisterCoreTypes` + the validator
augmentation — Hello/Authenticate/tree get/put/listing `ReflectType` + the
`OverrideField` corrections). `CoreTypes.floor_entities` **decodes each shape
with the Ruby peer's own S2-green decoder** and re-materializes the entity via
`Entity.make`, so the content_hash is recomputed by the Ruby codec (NOT ingest-
the-served-bytes); it asserts at boot that each recomputed hash equals the
oracle's pinned hash. All 53 byte-match → `validate-peer` `type_system` floor
fetch+match **53/53 PASS**, `types_all_present` PASS. Non-floor `compute/*`
vocabularies stay unpublished (matched-if-present WARN, never a core FAIL).
Closed.

---

## A-RUBY-009: deferred-gate count split + absent v7.75 test-vector snapshot

**V7 section:** n/a (corpus / brief bookkeeping)
**Profile field:** `[spec].codec_corpus` ("v7.75")
**Observation 1 (gate count):** The S3 brief stated "4 root_cap cap-token §3.6
shapes + 3 registry-interpretation decode_rejects". The actual v7.71 agility
corpus carries **3 `matrix_flow` root_cap + 4 `decode_reject`** (7 total). The
per-kind split is transposed in the brief; the 7 deferred gates themselves are
the same set and all now pass. Non-blocking — recorded so the next reader is not
surprised by the 3/4 split.
**Observation 2 (vectors):** `shared/test-vectors/` ships v7.56 / v7.70 / v7.71
only; there is no `v7.75/` snapshot, so the suite runs against the vendored
**v7.71** corpus (default in `test_helper`). The profile asserts the ECF +
agility encodings are byte-identical v7.73→v7.75 (SHA-verified in the MANIFEST),
so the codec is wire-stable and the v7.71 run is authoritative for the codec
axis; the S4 `validate-peer` run is the live superset that closes the version
question regardless.
**Escalation:** **operator** (count note) / **research** (a v7.75 vector
snapshot would let the suite name its corpus version honestly). No spec impact.

---

## A-RUBY-005: RubyGems id `entity_core_protocol` (snake_case, no `_ruby` suffix)

**V7 section:** n/a (packaging)
**Profile field:** `[publishing].package_id`
**Your guess:** Register on RubyGems as `entity_core_protocol` (peer id
`entity-core-protocol-ruby` is keystone naming; a gem is implicitly Ruby, so the
redundant suffix is dropped — mirrors the Elixir Hex-id reasoning). `require`
path `entity_core`; top namespace `EntityCore`.
**Rationale:** RubyGems ids are idiomatic snake_case; the `<lang>` suffix in the
keystone peer id is a multi-repo disambiguator a single-ecosystem registry
doesn't need.
**Escalation:** **operator** — confirm availability/non-squatting at S5; fall
back to `entity_core_protocol_ruby` if taken. No spec impact.

**S5 RESOLUTION:** **resolved-pending-operator-id-check.** The
gemspec ships id `entity_core_protocol` (snake_case, no `_ruby` suffix);
`gem build` + `Gem::Specification#validate` pass in-container. RubyGems is a
real upload registry (`gem push`), with **no** Maven-Central-style reverse-DNS
namespace gate — the only registry obligation is confirming the id is
non-squatted before first `gem push` (operator). Fall back
`entity_core_protocol_ruby` if taken. Closed pending that one-time check.

---

## A-RUBY-010: RubyGems pre-release version spelling — dotted `0.1.0.pre`, not SemVer-dash `0.1.0-pre`

**V7 section:** n/a (packaging)
**Profile field:** `[publishing]` / the gemspec `version`
**Surfaced at:** S5 packaging.
**Finding:** the cohort release line is written `0.1.0-pre` in prose. RubyGems,
however, treats a literal `-` in a version string as a `.pre.` separator, so
`Gem::Version.new("0.1.0-pre")` canonicalizes to the **malformed `0.1.0.pre.pre`**
(the dash → `.pre`, then the literal `pre` appended). The RubyGems-idiomatic
pre-release spelling is the **dot-separated `0.1.0.pre`** — canonicalizes to
itself, `.prerelease?` is true, and `gem install` hides it from default
resolution (consumers need `--pre` / an explicit pin, which is the correct
behavior for an unpromoted peer).
**Your guess / resolution:** set `EntityCore::VERSION = "0.1.0.pre"` (the gem
coordinate) and carry the cohort `0.1.0-pre` label in CHANGELOG/README/prose.
**Verified in-container** (Ruby 3.4.4 / RubyGems 3.6.7):
`Gem::Version.new("0.1.0-pre").to_s == "0.1.0.pre.pre"` (malformed) vs
`Gem::Version.new("0.1.0.pre").to_s == "0.1.0.pre"` + `.prerelease? == true`;
`gem build` emits `entity_core_protocol-0.1.0.pre.gem` and `spec.validate` passes.
**Cohort note:** this is the **exact distant-idiom shape as Common Lisp's
A-CL-010** (ASDF's dotted-integer-only `:version` rejecting `0.1.0-pre`) — the
second cohort ecosystem whose version grammar disagrees with the SemVer-dash,
against the SemVer-suffix-accepting majority (Maven `-pre`, opam, build.zig.zon,
package.json, mix.exs, Cargo). On promotion to `0.1.0` the suffix disappears, so
this note only applies to the pre-release line.
**Rationale:** RubyGems handles pre-releases natively — but via the dotted form,
not the SemVer dash. Using the dash would publish a mis-canonicalized version.
**Escalation:** **operator** — packaging note, no spec impact; recorded so a
future promotion re-applies the spelling.

---

_No blocking-severity items. S1 exit criteria met: profile fully populated (no
TBD-blocking), rationale written, container authored + specified (build
verification deferred to first build / S2 per the S1 no-build boundary). A-RUBY-002
(Ed448 native — expected pass, byte-verify at S2) and A-RUBY-003 (openssl API
spelling — confirm in-container at S2) are the two items that touch the next phase;
neither blocks S1. No NEW spec-level ambiguity surfaced — Ruby reads the complete
v7.75 snapshot and corroborates the inherited cohort findings (peer-id §1.5,
401/403 §5.2a, §4.10 resource_bounds, A-JAVA-010 `data`-shape) rather than
re-litigating them._

**S2 UPDATE:** A-RUBY-002 (Ed448 native) and A-RUBY-003 (openssl
raw-key API) **both RESOLVED** with real bytes against the in-container Ruby
3.4.4 / OpenSSL 3.x — Ed448 ships natively, no FFI. A-RUBY-006 logged + resolved
(the f16 / `Array#pack`-has-no-half-float spike). Still no NEW spec-level
ambiguity, no blocking items. ECF corpus 69/69, agility 25 byte-pins — S2 exits
green. The 7 S3-deferred agility gates (cap-token §3.6 root_cap shape + the
key/hash registry `decode_reject` interpretations) are peer-layer obligations,
not codec gaps._

**S4 UPDATE:** A-RUBY-008 (full 53-type §9.5 floor) **RESOLVED** —
seeded render-from-shapes, 53/53 content_hash byte-match vs the Go reference
@75c532e; `validate-peer --profile core` = `Result: PASS`, machine-verified
`summary.failed == 0` (653 total · 291 P / 268 W / 0 F / 94 S). origination-core
3/3 (incl `dispatch_outbound_reentry` over real 2-peer TCP). **No NEW spec-level
ambiguity at S4** — the peer corroborated the inherited cohort findings live
against the oracle rather than surfacing anything new. No blocking items.

**S5 UPDATE:** One NEW item, **packaging only — A-RUBY-010**
(RubyGems treats `0.1.0-pre` as `0.1.0.pre.pre`; idiomatic spelling is dotted
`0.1.0.pre`; verified in-container) — the Ruby analogue of CL's A-CL-010, owner
operator, no spec impact. A-RUBY-005 (gem id) resolved-pending the operator's
one-time non-squatting check at first `gem push`. **No ⚑ arch asks from this
peer** — the honest cohort-fit result is a **dry well**: by the 12th peer the
ratified-in-v7.75 findings (peer-id §1.5, 401/403 §5.2a, §4.10 resource_bounds,
the §1.1 A-JAVA-010 `data`-shape, lowercase address-space hex) are read as text
and corroborated live against the oracle, not re-litigated. The contribution is
idiom breadth + convergence evidence (first dynamic/scripting peer; native-full-
agility on a 3rd substrate via stdlib openssl, zero FFI; the 12th independent
`send`-reflection dispatch arrival; arbitrary-precision-`Integer` int story), not
a new finding. Gem builds + validates clean (`entity_core_protocol-0.1.0.pre.gem`,
zero runtime deps). No blocking items. **S5 publish-ready; parked at `0.1.0-pre`.**
