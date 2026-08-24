# entity-core-protocol-odin — Spec Ambiguity Log

Every guess made during generation, per PROMPT-CONSTANTS. Format: one `A-ODIN-NNN`
entry per decision. **Escalation** routes to arch (spec clarification), research
(profile needs a field), or operator (local decision). No blocking-severity items
at S1 exit.

---

## A-ODIN-001: Codec strategy = native hand-rolled despite a canonical-aware stdlib

**Spec section:** ENTITY-CBOR-ENCODING.md (ECF canonical rules)
**Profile field:** `[codec].strategy`, `cbor_library`
**Guess:** Hand-roll the full canonical codec; use `core:encoding/cbor` only as a
float-ladder cross-check, not as the codec.
**Rationale:** `core:encoding/cbor` is canonical-*aware* (f16 ladder + deterministic
int/float) but its map sort is bytewise (not ECF's length-then-lex) and it has no
decode-side major-type-6 tag reject. Bending it to length-first + tag-reject is
more work than a faithful hand-roll (the A-005 pattern). Keeps the codec fully in
our control for byte-exactness.
**Escalation:** operator — local decision (consistent with the whole cohort).

## A-ODIN-002: Ed448 deferred (core:crypto has no Ed448)

**Spec section:** §1.5 key_type 0x02 (crypto-agility higher bar)
**Profile field:** `[codec].ed448_library`
**Guess:** Defer Ed448; ship the Ed25519+SHA floor only.
**Rationale:** `core:crypto` has `x448` (ECDH) but not the Ed448 signature scheme
(verified absent). Future path: hybrid-FFI via `libentitycore_codec` (`ec_ed448_*`)
bound with `foreign import` as an opt-in sub-package. Does not affect the
Ed25519/ECF floor. Same posture as Zig/C/C++/Ada.
**Escalation:** operator — local decision; revisit when agility enters scope.

## A-ODIN-003: Raw-thread concurrency; manual §7b store-safety

**Spec section:** §4.8 / §6.11 / §7b
**Profile field:** `[async]`
**Guess:** One reader thread per connection (`core:thread`); explicit `sync.Mutex`
around the store + §3.9 CAS; `{request_id => waiter}` + `sync.Cond` demux.
**Rationale:** Odin has no actor/CSP/STM substrate — raw OS threads only. So
store-safety is enforced manually (the Zig/CL class) and the §6.11 handler-outbound
demux is a correlation-map tax, not free. This is a structural property of the
runtime, not a spec ambiguity — recorded for the effort estimate + the peer layer.
**Escalation:** operator — local decision.

## A-ODIN-004: Native pure-Odin crypto floor is unaudited (core:crypto self-declares)

**Spec section:** §1.5 (Ed25519), §HASH-FORMAT (SHA-2)
**Profile field:** `[codec].ed25519_library`, `sha256_source`
**Guess:** Use native `core:crypto/ed25519` + `core:crypto/sha2` for the floor,
despite the crypto README's "not received independent third-party review" note.
**Rationale:** Native is the faithful, self-contained default and the more
interesting corroboration (a fresh RFC-8032 implementation re-deriving the same
signatures). The KAT accept-path unit + the wire-conformance/validate-peer oracles
gate the actual bytes, so any RFC-8032 deviation fails loudly rather than shipping
silently. A libsodium-via-`foreign import` fallback is a drop-in if an operator
requires an audited floor.
**Escalation:** operator — local decision (audited-crypto policy call); note for
adopters in the matrix row.

## A-ODIN-006: Integer value model — u64 pattern, head-form derived (S2)

**Spec section:** §3.2 / §4.1 Rule 1
**Profile field:** `[idiom].native_fixed_width_int`
**Guess:** Model `Ec_Uint`/`Ec_Nint` as a distinct `u64` carrying the FULL bit
pattern (nint stores `n` where wire value = `-1 - n`), and DERIVE the CBOR head
form from the value at encode time rather than storing a head-form tag.
**Rationale:** The corpus only exercises up to 2⁶³-1 (int.10) on the wire, but the
fixed-width-int class MUST prove `[2⁶³, 2⁶⁴-1]` (profile). A single `u64` covers
it natively; the minor-27 (8-byte-arg) head is a value artifact, not a stored
property — so the head-form self-test is a unit over the encoder, and no `head_form`
field leaks into the model. Same arrival as Zig's `uint`/`nint: u64`.
**Escalation:** operator — local decision (no spec ambiguity; the range is spec-fixed).

## A-ODIN-007: content_hash construction serialises caller format_code (S2)

**Spec section:** §4.7 construction-vs-verification asymmetry (v7.73)
**Profile field:** n/a (derived from spec)
**Guess:** The construction path (`content_hash`) emits `varint(format_code)` for
WHATEVER code the caller supplies and hashes with SHA-256 for every code except
0x01 (→ SHA-384); it does NOT gate on the registry.
**Rationale:** content_hash.4 pins a synthetic `format_code = 128` with a SHA-256
digest and a 2-byte varint prefix — the §4.7 forward-compat construction half. The
registry gate lives on the VERIFY side (peer layer, S3, → `unsupported_content_hash_format`),
not here. Derived directly from §4.7, byte-confirmed by content_hash.4; recorded so
the S3 verify path doesn't mistakenly re-gate construction.
**Escalation:** none — spec is explicit (§4.7). Logged for the S3 boundary.

## A-ODIN-008: Base58 big-int via byte-wise long division (no core:math/big) (S2)

**Spec section:** §1.5 peer-id
**Profile field:** `[codec].base58_library = "hand-rolled"`, `bignum_available`
**Guess:** Hand-roll Base58 encode/decode with byte-wise base-256⇄base-58 long
division rather than pull in `core:math/big`.
**Rationale:** The conformance digests are 33-34 bytes — the classic streaming
long-division Base58 (Bitcoin alphabet, leading-zero→'1') is exact, allocation-light
(temp_allocator scratch, freed on every path), and avoids a bignum dependency the
floor doesn't otherwise need. `core:math/big` stays reserved for a future ≥2⁶⁴
arithmetic arm (profile), not the peer-id path. peer_id.1/.2/.3 pass byte-identical.
**Escalation:** operator — local decision.

## A-ODIN-005: Peer numbering / matrix index provisional

**Spec section:** n/a (process)
**Profile field:** `[language].tier`
**Guess:** Label the tier descriptively (`corroboration-T3`) rather than claim a
global peer index.
**Rationale:** Odin + Crystal are built on this machine while Julia + Nim build on
another branch concurrently; a hard-coded `peer-NN` would collide at merge. Final
index reconciles at merge.
**Escalation:** operator — local decision (merge-time reconciliation).

## A-ODIN-009: Store carries its own allocator (cross-thread consistency) (S3)

**Spec section:** §4.8 (store-safety under concurrent dispatch)
**Profile field:** `[async].store_safety = "manual-mutex"`
**Guess:** The in-memory `Store` pins ONE `mem.Allocator` at init and uses it for
every internal clone (content keys, tree keys/values, entity copies) — NOT the
calling thread's `context.allocator`.
**Rationale:** §4.8 dispatch runs on OS threads whose default `context.allocator`
differs from the main thread's (Odin gives each spawned thread a fresh context). A
store keyed to the calling thread's context would clone entities under thread-local
heaps, then double/bad-free at `store_destroy` on the main thread (caught by
`mem.Tracking_Allocator`: "Bad free"). Pinning one allocator, guarded by the store
Mutex, makes the store thread-safe regardless of which dispatch thread mutates it.
This is a RAW-THREAD-runtime property, not a spec ambiguity — recorded as a durable
no-GC-peer lesson (the actor/STM peers never hit it; the thread/image peers must).
**Escalation:** operator — local decision (language-runtime discipline).

## A-ODIN-010: Type-def slice literals rendered in place (lifetime) (S3)

**Spec section:** §9.5 (core type floor render-from-model)
**Profile field:** n/a (Odin language semantics)
**Guess:** Each `Type_Def` (with `fields: []Field` / `layout: []string` compound
literals) is rendered to ECF + bound into the store IMMEDIATELY within its
declaring statement, rather than collected into a `[dynamic]Type_Def` and rendered
later.
**Rationale:** An Odin slice compound literal (`[]Field{...}`) used inline is
backed by a stack temporary that dies at the end of the statement; storing the
`Type_Def` and reading its `fields` later reads freed stack memory (ASan:
allocation-size-too-big from a corrupted string length). Rendering in place keeps
the backing array live. Same class as the "cannot return a slice compound literal
from a proc" rule — a fresh-syntax trap the generator now knows. Purely mechanical;
the rendered bytes are byte-identical to the Go vector set (unit-proven).
**Escalation:** operator — local decision (language-semantics trap, no spec impact).

## A-ODIN-011: §7a `value` passed through, not re-wrapped (S3)

**Spec section:** §7a.1 (dispatch-outbound reentry)
**Profile field:** n/a (derived from spec + cohort)
**Guess:** In `dispatch-outbound`, the caller's `value` field IS the outbound
params entity data — wrap it once as `primitive/any{value}` and pass through; do
NOT re-wrap as `{value: {value: …}}`.
**Rationale:** Re-wrapping double-wraps, so the downstream echo's `result.value`
returns a map instead of the sent value (the keystone §7b t1_2 lesson the cohort
hit). Matches the reference behavior; the origination category is extension-gated
(SKIP under `--profile core`), so this is exercised by the §7a `--validate` probes.
**Escalation:** operator — local decision (spec-derived, cohort-confirmed).
