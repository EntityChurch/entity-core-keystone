# entity-core-protocol-elixir — Spec Ambiguity Log

Every guess the agent makes goes here (S3 discipline). Items escalate to
architecture as proposal candidates via `research/stewardship/`. **No silent
guesses.** Prefix `A-ELX-NNN` (Elixir peer #4).

Note: peers #1-3 already surfaced and (mostly) resolved a large set of
*spec-level* ambiguities (A-OC-001..010, F-series). Those are spec facts, not
re-litigated per language; this log records **Elixir-specific** guesses plus any
**new** spec gap this peer surfaces. Cross-references to the shared findings use
their original ids.

---

## A-ELX-001: spec-data snapshot stops at v7.72, spec HEAD is v7.74 (folded)

**V7 section:** §4.6 (v7.73 nonce-echo), §6.13/§6.9a/§6.10/§7a (v7.74 extensibility + bootstrap + conformance handlers)
**Profile field:** `[spec]`
**Your guess:** Pin profile + codec to the v7.72 snapshot (codec corpus v0.8.0 — byte-identical CBOR/type specs). Treat the v7.73 + v7.74 folds as **peer-layer** (S3+) work, resynced against the folded proposal text exactly as peers #1-3 did — they too reached v7.74 conformance with snapshots that lagged HEAD. S1/S2 (profile + codec) are wire-unaffected, so they proceed on v7.72 with no risk.
**Rationale:** The codec specs (`ENTITY-CBOR-ENCODING.md`, `ENTITY-NATIVE-TYPE-SYSTEM.md`) did not change v7.71->v7.72 and the v7.73/v7.74 changes are peer-protocol (authenticate/dispatch/bootstrap/conformance), not wire-format. Blocking S1 on a not-yet-authored snapshot would stall the peer for an S2-ownership input.
**Escalation:** **arch / research** — spec-data is architecture's to author (S2); a v7.73 and/or v7.74 verbatim snapshot is needed for peer #4 to reach documented parity rather than building against living proposal text. Until it lands, S3 mirrors the C#/TS/OCaml peer-layer build against the folded proposals. Non-blocking for S1/S2.

---

## A-ELX-002: Ed448 native via OTP `:crypto` — **RESOLVED (S2, byte-verified)**

**V7 section:** §1.5 / §7.3 multikey (key_type 0x02 = Ed448); crypto-agility higher bar (v7.67)
**Profile field:** `[codec].ed448_library`
**Your guess:** Source Ed448 natively from OTP `:crypto` (`crypto:sign(eddsa, none, Msg, [Seed, ed448])` etc.), same backend as Ed25519 — NOT via the C-ABI FFI that OCaml needed.
**Resolution:** Byte-verified end-to-end against the v7.71 agility corpus at S2. The Ed448 signature (114 B) over the locked fixture message is **byte-identical** to the RFC-8032 cross-impl pin; the seed→pubkey (57 B), §1.5 SHA-256-form peer-id, and system/peer content_hash all match; SHA-384 rehash matches. 28/28 agility crypto byte-pins green **from the default build, no FFI** — the headline contrast with OCaml A-OC-002 (which had to source Ed448 over the C-ABI). The LANDSCAPE ffi default is overturned on evidence.
**Escalation:** **operator** — resolved, fully native, no spec impact.

---

## A-ELX-003: `:crypto` EdDSA exact arity/atom spelling — **RESOLVED (in-container)**

**V7 section:** n/a (impl detail)
**Profile field:** `[codec].ed25519_library` / `ed448_library`
**Your guess:** Use the option-list EdDSA form with an explicit `:none` digest: `crypto:sign(eddsa, none, Msg, [Seed, Curve])`, `crypto:verify(eddsa, none, Msg, Sig, [Pub, Curve])`, `crypto:generate_key(eddsa, Curve, Seed)`.
**Resolution:** Confirmed functionally against the pinned OTP 27.3.4 in `containers/beam`. Round-trip verified for BOTH curves: ed25519 (pub 32B, sig 64B) and ed448 (pub 57B, sig 114B) — sign/verify pass, tamper rejects, seed->pubkey derivation returns `{Pub, Seed}`, and ed25519 re-signing is deterministic (same seed+msg → identical sig). The assumed arity is correct; no codec-shim adjustment needed at S2. (Also empirically closes **A-ELX-002**: Ed448 native works end-to-end, no FFI.)
**Escalation:** **operator** — resolved, no spec impact.

---

## A-ELX-004: Hex package id `entity_core_protocol` (snake_case, no `_elixir` suffix)

**V7 section:** n/a (packaging)
**Profile field:** `[publishing].package_id`
**Your guess:** Register on Hex as `entity_core_protocol` (the peer id `entity-core-protocol-elixir` is keystone naming; a Hex package is implicitly BEAM, so the redundant suffix is dropped). OTP app atom `:entity_core_protocol`.
**Rationale:** Hex ids are idiomatic snake_case; the `<lang>` suffix in the keystone peer id is a multi-repo disambiguator that a single-ecosystem registry doesn't need.
**Escalation:** **operator** — confirm availability/non-squatting at S5; fall back to `entity_core_protocol_elixir` if taken. No spec impact.

---

## A-ELX-005: matrix `root_cap` §3.6 cap-token construction — **RESOLVED (S3, byte-verified)**

**V7 section:** §3.6 (capability-token shape) / agility SEEDS.md §2.3-§2.5 (home-vs-active format, RFC-8032 deterministic signature target)
**Profile field:** n/a (peer-layer construction)
**Your guess:** The 3 deferred matrix `root_cap` gates (M2/M3/M6) — left as S3 by every prior peer (C# PHASE-S4-BLOCK3 item 9; OCaml/TS never computed them) — were built fresh from SEEDS.md: `granter` = peer A's HOME-format identity hash as a **raw `system/hash` byte string** (SingleSig arm of the `granter` union, NOT a `{type,hash}` wrapper map), `grantee` = peer B's SHA-256 identity hash, `grants` fixed, `created_at: 0` and `expires_at: 0` PRESENT, **`parent: null` ⇒ field ABSENT** (optional-absent, not encoded null). Cap-token content_hash under the ACTIVE format (SHA-256); A signs the cap-token's 33-byte wire content_hash.
**Resolution:** All 6 derived gates (content_hash + signature × M2/M3/M6) matched the locked cross-impl pins **byte-identical on the first attempt** — across both the cross-key (Ed448 granter) and cross-hash (SHA-384 home identity hash, SHA-256 active cap) axes. This is the first independent verification of the `root_cap` pins by any keystone peer; it corroborates the §2.4 home-vs-active discipline and pins the optional-field convention (`parent` absent when null; `expires_at: 0` emitted). 35/35 agility gates green, 0 deferred.
**Escalation:** **operator / research** — resolved; a positive cross-peer corroboration worth recording (the prior peers' deferral left these pins unverified outside the cohort). No spec change.

---

## A-ELX-006: BEAM concurrency model — process-per-connection + GenServer store + selective-receive reentry (§4.8 / §6.11)

**V7 section:** §4.8 (inbound concurrent with outbound), §6.11 (reentrant transport + request_id demux), §9.4 (impl-defined delivery)
**Profile field:** `[async]` (`processes` / `otp-genserver`)
**Your guess:** The OCaml peer met §4.8/§6.11 with one reader **thread** per connection + a `pending` Hashtbl + a condition variable + a write mutex. Elixir maps this onto the **actor model** as the profile mandates: (1) the content store + entity tree is a single `GenServer` (`EntityCore.Store`) — all access serialized through it, so concurrent per-request dispatch is race-free without locks, and the §3.9 CAS put is a single atomic call (`bind_cas`, vs OCaml's non-atomic read-then-write); (2) one `Connection` process per socket is the SINGLE WRITER (responses + outbound requests serialize without a mutex); (3) the `system/protocol/connect` handshake is handled INLINE in the connection process (mutates per-connection state, never originates outbound) while every other EXECUTE is dispatched on a **separate spawned process** (§4.8) so a §6.13(b) outbound await never stalls the reader; (4) the §6.11 demux is a `pending: %{request_id => caller_pid}` map + a `receive` in the dispatch process (the BEAM idiom for the condvar wait), woken by the reader routing the correlated EXECUTE_RESPONSE.
**Rationale:** Pure profile-idiom translation (S6/S8): the wire behavior is identical to the threaded peers; the concurrency *mechanism* is the most distant of the four peers (no shared mutable state, no locks — message passing + a serializing GenServer). The single-writer connection process subsumes OCaml's `write_mutex`; selective `receive` subsumes the condition variable.
**Escalation:** **operator** — design decision, flagged for review (the actor placement is new vs the threaded reference peers). No spec impact; no new dependency (all OTP stdlib).

---

## A-ELX-007: emit consumer delivery — sync-inline-in-GenServer vs async, a forward seam (§6.10 / §9.4)

**V7 section:** §6.10 (emit pathway), §6.8a (impl-defined context), §9.4 (delivery is impl-defined)
**Profile field:** `[async]` (delivery model is unspecified there)
**Your guess (S3, deliberate):** Emit consumers run **synchronously, inline, inside the `EntityCore.Store` GenServer's `handle_call`** (`emit_tree`/content-consumer `Enum.each` during `do_bind`/`do_put`) — the same sync-inline shape as the OCaml/cohort stores. For a `--profile core` peer this is **fully inert**: zero consumers are registered, so no event is delivered and there is no hazard. **S3 is correct and unaffected.**
**The forward seam (track for emit/compute, NOT a current bug):** the actor model surfaces a delivery decision the threaded peers (Go/Rust/Py/OCaml) get to defer. Because the Store is a single serializing GenServer, once an *extension* registers a real consumer: (1) a consumer that **re-enters the Store** (e.g. `Store.get_at` from inside its callback) **deadlocks** — the GenServer is blocked running the consumer while the consumer calls the same GenServer; (2) a **slow** consumer stalls *all* peer-wide tree access for its duration. The threaded peers don't hit this — their store has no serializing owner, so a re-entrant consumer just runs. This is the cost-side of the lock-free race-freedom guarantee (the benefit-side of [[A-ELX-006]]).
**Preferred resolution (when the emit-consumer surface is built):** deliver **asynchronously** — `send` the §6.10 event to consumer *processes* rather than invoking a fn inline in the Store loop. This is the idiomatic BEAM shape, gives back-pressure/isolation for free, removes both hazards, and is explicitly permitted by §9.4 (delivery impl-defined). Decide this deliberately at emit-consumer build time rather than inheriting sync-inline by accident — compute dispatches through the same §6.6 path, so this is a compute-readiness seam too.
**Escalation:** **operator / arch** — design fork, non-blocking for core. No spec change needed (§9.4 leaves delivery open); flag is that the BEAM forces the choice earlier than the threaded peers.

---

_No blocking-severity items. S1 + S2 + S3 exit criteria met. A-ELX-002/003/005 resolved in-session (byte-verified); A-ELX-006 is an idiom design note; A-ELX-007 is a forward emit-delivery seam (inert at core). A-ELX-001 (peer-layer spec-data snapshot lags HEAD; the S3 peer layer was built against the folded v7.73/v7.74 proposal text, mirroring peers #1-3) and A-ELX-004 (Hex id) remain open and non-blocking. No NEW spec-level ambiguity surfaced at S3 — the peer layer ported cleanly from the §5/§6 reading that peers #1-3 already validated; Elixir corroborates the inherited findings (A-OC-007 §7.4/§1.5 peer-id, A-OC-008 401/403, A-011/A-013 conformance-handler coupling) rather than re-litigating them._
