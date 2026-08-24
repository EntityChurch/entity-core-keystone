# entity-core-protocol-crystal — Spec Ambiguity Log

Every guess made during generation, per PROMPT-CONSTANTS. Format: one `A-CRY-NNN`
entry per decision. **Escalation** routes to arch (spec clarification), research
(profile needs a field), or operator (local decision). No blocking-severity items
at S1 exit.

---

## A-CRY-001: Codec strategy = native hand-rolled (no canonical CBOR shard)

**Spec section:** ENTITY-CBOR-ENCODING.md (ECF canonical rules)
**Profile field:** `[codec].strategy`, `cbor_library`
**Guess:** Hand-roll the full canonical CBOR codec in pure Crystal rather than
consume any shard.
**Rationale:** No Crystal CBOR shard provides ECF's canonical guarantees —
`arestifo/crystal-cbor` (the de-facto shard) targets RFC 7049, emits no
shortest-float/float16, iterates maps in insertion order (not length-then-lex),
and silently *skips* major-type-6 tags on decode (opposite of the required
reject); `cbor.cr` is abandoned. Hand-rolling is faithful and simpler (the A-005
pattern, 29th confirmation). This is also the deliberate Ruby-overfit probe.
**Escalation:** operator — local decision (consistent with the whole cohort).

## A-CRY-002: Ed448 deferred (libsodium has no Ed448)

**Spec section:** §1.5 key_type 0x02 (crypto-agility higher bar)
**Profile field:** `[codec].ed448_library`
**Guess:** Defer Ed448; ship the Ed25519+SHA floor only.
**Rationale:** The chosen Ed25519 route (direct libsodium C binding) has no Ed448,
and no Crystal shard implements Ed448 (shards.info "ed448" → zero results). The
documented future path is hybrid-FFI via `libentitycore_codec` (`ec_ed448_*`) as
an opt-in sub-library. Does not affect the Ed25519/ECF conformance floor. Same
posture as C/C++/Ada/PHP/Zig ("deferred").
**Escalation:** operator — local decision; revisit when agility enters scope.

## A-CRY-003: Ed25519 via direct libsodium C binding (not a shard, not stdlib)

**Spec section:** §1.5 (Ed25519 signatures)
**Profile field:** `[codec].ed25519_library`
**Guess:** Bind libsodium directly in-process via `lib LibSodium`/`fun` rather
than use `sodium.cr`, `monocypher.cr`, or a pure-Crystal shard.
**Rationale:** Crystal stdlib `OpenSSL` has no PKey/Ed25519 surface (verified
absent). Among the routes: `sodium.cr` is stale (2021); `monocypher.cr` defaults
to a non-RFC-8032 BLAKE2b variant; the pure-Crystal shard is unaudited. A direct
libsodium binding is audited (libsodium), is a system lib (no shard dep to pin),
and keeps the peer self-contained — the Ada/C/C++/PHP "native — libsodium" row.
**Escalation:** operator — local decision.

## A-CRY-004: SHA-384 via OpenSSL::Digest (no native stdlib Digest::SHA384)

**Spec section:** agility hash family (SHA-384 for the §HASH-FORMAT content-hash
family, independent of the signature curve)
**Profile field:** `[codec].sha256_source`
**Guess:** SHA-256/512 from native stdlib `Digest`; SHA-384 from
`OpenSSL::Digest.new("SHA384")`.
**Rationale:** Crystal stdlib has native `Digest::SHA256`/`SHA512` but no
`Digest::SHA384`; the OpenSSL by-name digest is the stdlib-available route.
SHA-384 is agility-only — the SHA-256 *floor* is fully native. Byte-verify against
the agility corpus at S2 if/when agility is exercised.
**Escalation:** operator — local decision.

## A-CRY-005: Fiber-per-connection, single-thread default (MT preview not used)

**Spec section:** §4.8 / §4.9 / §6.11 / §7b
**Profile field:** `[async]`
**Guess:** One fiber per accepted connection on the default single-OS-thread
scheduler; explicit `Mutex` only under `-Dpreview_mt`.
**Rationale:** Crystal's CSP fibers yield on blocking IO, so a fiber-per-conn peer
is genuinely concurrent for the IO-bound workload — adequate for §7b. Multithread
mode is still preview in 1.20 (default-on targeted 1.21) → not used at core; store
is fiber-safe between yield points on the single thread. The §6.11 demux is a
`{request_id => Channel}` pending map.
**Escalation:** operator — local decision; revisit when `-Dpreview_mt` lands
default-on (1.21) and the store needs the mutex unconditionally.

## A-CRY-007: Map keys are arbitrary EcValues (incl. byte strings), not String

**Spec section:** ENTITY-CBOR-ENCODING.md §4.1 Rule 2 / §7.2 / corpus `map_keys.5`,
`nested.4`, `envelope.2`
**Profile field:** `[idiom].data_is_arbitrary_ecf`, `byte_slices_for_wire`
**Guess (S2, non-blocking):** Model the ECF map as `::Hash(EcValue, EcValue)` — the
KEY type is the full tagged union, not `String`. Byte-string keys (major 2) and text
keys (major 3) are distinct static types (`Bytes` vs `String`) and the length-then-lex
key sort operates on the ENCODED key bytes, so a byte key can legitimately sort before
a longer text key (`map_keys.5`: `43 6b6579` < `68 746578745f6b6579`). Envelope
`included` maps and hash-keyed maps carry 33-byte byte-string keys (`nested.4`,
`envelope.2`).
**Rationale:** The corpus pins byte-keyed maps directly; a `String`-keyed model (the
naive Ruby-encoding-tag read) cannot represent them on Crystal where `String` is
UTF-8-validated. Confirmed byte-identical against all three byte-key vectors.
**Escalation:** operator — local modeling decision; not a spec ambiguity (the spec is
unambiguous, this records the Crystal-substrate consequence). Also logged: the
`EntityCore::Hash` content-hash module name shadows stdlib `Hash` inside the namespace,
so the generic map type is written `::Hash(...)` throughout — a naming-collision note
for future modules under `EntityCore`, not a spec matter.

## A-CRY-008: Core-type floor = 53 types, render-from-shapes (vendored Go dump)

**Spec section:** V8 §9.5 / §9.5a (core type floor)
**Profile field:** n/a (S3 peer surface)
**Guess (S3, non-blocking):** Publish exactly the 53-type core floor at
`/{peer}/system/type/{name}`, rendered by DECODING the vendored Go-dumped ECF
`data` (hex) with THIS peer's S2 codec and re-materializing a `system/type`
entity — then ASSERTING the recomputed content_hash equals the oracle's pinned
`CoreTypeFloor::CONTENT_HASH` at bootstrap. Extension vocabularies (compute/*,
content/*, …) are intentionally NOT published under `--profile core`.
**Rationale:** The keystone render-from-model pattern (single-source-of-truth in
code, Go-golden as a byte-exact drift target), not "emit these bytes to hit the
check." A codec divergence surfaces immediately as a content_hash mismatch. The
53 shapes are the Ruby peer's vendored floor (same Go source dump); `type_system`
scored 108-pass / 0-FAIL, confirming byte-identity. Mirrors the Ruby/Zig peers.
**Escalation:** operator — local decision (cohort convention).

## A-CRY-009: §1.4 path-flex rejects C0 control chars (incl. NUL) in segments

**Spec section:** V8 §1.4 (path validation) / CORE-TREE-PATH-FLEX-1
**Profile field:** n/a (S4 peer bug fix)
**Guess (S4):** `Peer.path_flex_ok?` rejects any path segment containing a C0
control character (`c.ord < 0x20`), i.e. NUL and friends, in addition to the
space check ported from the Ruby peer.
**Rationale:** The ONE genuine S4 FAIL — `core_tree_path_flex_1` sub-pin
`reject_null_byte` — showed the peer accepting `.../with\x00null` with 200. The
Ruby-ported `path_flex_ok?` checked space only. A NUL byte is not valid in any
path segment (§1.4); the broader C0 rule is the safe superset. Re-run → PASS.
This is a shared-with-cohort validation refinement, not a spec ambiguity.
**Escalation:** operator — local decision; the spec is unambiguous.

## A-CRY-010: §4.8 store-safety is STRUCTURAL on the single-thread scheduler

**Spec section:** V8 §4.8 (store data-race safety under concurrent dispatch)
**Profile field:** `[async].store_safety = single-thread-default`
**Guess (S3, non-blocking):** No `Mutex` guards the in-memory store at core.
Every mutating store method (`bind`/`put_entity`/`bind_cas`/`unbind`) is pure
in-memory CPU with NO fiber-suspension point, so under Crystal's DEFAULT
single-OS-thread cooperative scheduler a compound read-then-write executes
atomically w.r.t. other fibers by construction (fibers only yield at blocking IO
/ Channel / sleep / Fiber.yield — never mid-computation).
**Rationale:** The profile-declared posture (A-CRY-005). §4.8 is satisfied
structurally, not by a lock; `concurrency` scored 5/5 PASS. Under `-Dpreview_mt`
(NOT used at core) each mutating section would need an explicit `Mutex` (the
raw-thread posture) — documented in `store.cr` and revisit-flagged for 1.21.
**Escalation:** operator — local decision; revisit when preview_mt lands default-on.

## A-CRY-006: Peer numbering / matrix index provisional

**Spec section:** n/a (process)
**Profile field:** `[language].tier`
**Guess:** Label the tier descriptively (`corroboration-T3`, Ruby-overfit check)
rather than claim a global peer index.
**Rationale:** Crystal + Odin are built on this machine while Julia + Nim are
built on another branch concurrently; a hard-coded `peer-NN` would collide at
merge. Final index reconciles when the branches merge.
**Escalation:** operator — local decision (merge-time reconciliation).

## A-CRY-011: Graceful SIGTERM/SIGINT handler required on the preview fiber scheduler (S4)

**Spec section:** §4.9 (resilience — don't crash), §7b (transport); runtime, not wire
**Profile field:** `[async]` (CSP fibers, single-thread default)
**Guess (S4 fix, non-blocking):** The host traps `SIGTERM`/`SIGINT` and closes the TCP
listener (breaks the accept loop → `Host.run` returns → clean exit); `run-s4.sh` reaps the
host with a graceful `kill -TERM` + wait-for-exit (hard `-KILL` only as a >5s fallback).
**Rationale:** The S4 harness reaps the host by signal. WITHOUT a handler, Crystal 1.20's
**preview** Execution-Contexts scheduler could be interrupted mid-schedule by the default
signal action, surfacing an intermittent `Thread#execution_context cannot be nil`
(NilAssertionError) — observed ~1 run in ~15 under repeated concurrent load, and it produced
NO Summary line (so it could corrupt a verdict, not just teardown). The host binary alone
never crashes; the crash only appeared under the harness's kill-based reap. After the fix:
**0 crashes / 20 consecutive full `--profile core` runs** (independently re-verified). This is
a **durable cross-language peer-build lesson**, not a spec ambiguity: a fiber-scheduler peer
on a preview scheduler needs a graceful signal handler or it flakes under a kill-based
harness (the analogue of the Zig TCP_NODELAY finding). Revisit if Crystal 1.21 stabilizes the
Execution-Contexts scheduler.
**Escalation:** operator — local runtime-hardening decision; noted for the durable-lessons
digest (a fiber/preview-scheduler substrate hint for future peers).
