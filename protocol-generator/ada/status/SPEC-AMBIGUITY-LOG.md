# entity-core-protocol-ada — Spec Ambiguity Log

> Discipline: every guess goes here; no silent guesses (S3). Items escalate to
> architecture/research via `research/stewardship/`. Ada is **peer #10** — the
> safety-critical / strong-typing member, bringing the two most-distant idiom axes left
> in the batch (tasks + protected objects + rendezvous; design-by-contract). Entries are
> prefixed `A-ADA-` to namespace from the prior peers' logs.
>
> **Honest framing:** the spec-discovery well is DRY — 8+ independent prior peers found no
> new defect on the v7.75 surface. The current-state menu items below are INHERITED-SETTLED
> (peer_id §1.5, hex-case, 401/403 trichotomy, A-JAVA-010 data-model, 400-chain-depth,
> resource_bounds, concurrency) and are PRE-RESOLVED here so S2–S5 inherit them correctly,
> NOT re-discovered. No new blocking-severity ambiguity surfaced at S1. The Ada-distinct
> entries (A-ADA-002 Ed448 defer, A-ADA-003 hex-case-pin, A-ADA-004/005 build/publish,
> A-ADA-006 concurrency-shape) are local/idiom decisions, not spec defects.

---

## Phase coverage so far: **S1 (profile)**

No new spec defect surfaced at S1. The §1.5/§7.4 peer-id contradiction and the unspecified
hex-case are PRE-EXISTING, multi-peer-corroborated findings; they are recorded here as
pre-resolved (with the arch escalation re-stated for the peer-id one) so the Ada peer
inherits the settled resolution. The Ada idiom axes (protected-object store, contract
aspects) map CLEANLY onto V7 — a spec-tightness signal, not a finding.

---

## A-ADA-001: peer_id construction — §1.5 canonical-form table, NOT §7.4 (PRE-RESOLVED, settled)

**V7 section:** §1.5 (canonical-form table) vs the stale §7.4 / §1.5-skeleton pseudocode.
**Profile field:** `[codec].ed25519_library` (raw-pubkey note); arch/PROFILE-RATIONALE.md
"peer_id construction".
**Your guess:** Derive the Ed25519 peer_id from the **§1.5 canonical-form table** —
`hash_type = 0x00` identity-multihash, digest = the **raw public key bytes** (no SHA-256).
IGNORE the stale §7.4 `SHA256(public_key)` / `hash_type = 0x01` form.
**Rationale:** Verified directly in `spec-data/v7.75` — `ENTITY-CORE-PROTOCOL-V7.md`
**line 459** declares `0x01 Ed25519 → 0x00 identity-multihash … The digest IS the
public_key (v7.64)`. The v7.73 closeout (§E1) reconciled §7.4 (parameterized over
`key_type`, deferring to the §1.5 table) precisely because its pseudocode was the stale
SHA-256 form. Five+ prior spec-first peers corroborated (Zig A-ZIG-001, OCaml A-OC-007,
CL A-CL-002, Java A-JAVA-004, …) — **SETTLED**. The S2 opaque-digest corpus would NOT catch
a wrong construction; it only blows up at the S4 `401 identity_mismatch` handshake — so
baking the §1.5 form in proactively dodges that debug cycle. libsodium returns the raw
32-byte pubkey directly (no point extraction), so construction is trivial.
**Escalation:** arch — re-stated (already escalated by 5+ peers; this is a corroboration,
not a new finding). Non-blocking for Ada.

## A-ADA-002: Ed448 / SHA-384 deferred to the agility overlay (libsodium gap; core floor unaffected)

**V7 section:** §7.67 crypto-agility higher bar (Ed448 `0x02`, SHA-384 `0x01`); §9.1 floor.
**Profile field:** `[codec].ed448_library`, `[codec].sha256_source`.
**Your guess:** v0.1 covers the **§9.1 CORE FLOOR (Ed25519 + SHA-256) ONLY**, fully
provided by libsodium. The Ed448 + SHA-384 **agility higher bar is DEFERRED**; when taken
it comes via the `libentitycore_codec` C-ABI agility surface (OCaml precedent) or an
OpenSSL `curve448` + SHA-384 binding (`openssl-devel` is in the base image), NOT libsodium.
**Rationale:** libsodium has **no Ed448**, and ships **SHA-256 + SHA-512 only (no
SHA-384)** — the SAME gap OCaml (A-OC-002, C-ABI Ed448) and Zig (A-ZIG-002, flat gap) hit.
The canonical core gate (576 · 0F · 89 skip) does **not** require Ed448/SHA-384, so the
defer is non-blocking for the core floor.
**Escalation:** operator — local crypto-sourcing decision for the optional agility overlay
(mirrors OCaml's opt-in `entitycore_agility` sub-lib stance). Non-blocking for the core
floor.

## A-ADA-003: hex-case — emit LOWERCASE explicitly (Ada hex builtins default UPPERCASE) (PRE-RESOLVED)

**V7 section:** §3.4/§3.5 tree-path keys; §6.9a policy paths; §1.5 content_hash hex
rendering (hex-case is NOWHERE stated normatively — the A-CL-009 finding).
**Profile field:** `[naming].hex_case`, `[idiom].hex_lowercase_pinned`.
**Your guess:** The codec's hex helper MUST emit **lowercase `a-f`** via a custom
nibble→char table — NEVER `Integer'Image`, the `16#..#` based-literal form, or
`Ada.Text_IO.Integer_IO` with `Base => 16` (all of which emit UPPERCASE in Ada).
**Rationale:** The §3.4/§3.5/§6.9a tree-path keys are **case-sensitive string keys** keyed
by lowercase hex (matching the Go oracle's `hex.EncodeToString`). Ada's hex builtins
default UPPERCASE, so an uppercase helper passes Ada-to-Ada loopback but **404s** against
the lowercase oracle — EXACTLY the A-CL-009 trap (CL's `~x` defaulted uppercase and broke
the register/revocation paths). **The CL log explicitly names Ada hex builtins as carrying
this same risk.** Pinned proactively.
**Escalation:** arch (re-stated, non-new) — V7 SHOULD state hex-case explicitly (lowercase)
for the case-sensitive tree-path keys; A-CL-009 already escalated this. Local fix is the
lowercase helper. Non-blocking.

## A-ADA-004: build = gprbuild + hand-rolled test runner (no Alire deps; no AUnit)

**V7 section:** absent (toolchain choice).
**Profile field:** `[build]`, `[testing]`.
**Your guess:** Use **gprbuild** against a committed `.gpr` (no Alire registry resolve) and
a **hand-rolled** test/conformance runner (no AUnit). Alire is the optional S5 distribution
channel only.
**Rationale:** The core peer has no Alire crate deps (libsodium C binding + hand-rolled
CBOR/base58/varint), so gprbuild builds fully offline under `--network=none` — the
lightest-supply-chain story (Zig/Elixir/Java tier). AUnit is a separate dep and the
conformance harness is "load fixture → assert bytes", which needs no framework (the
Zig/OCaml/CL hand-rolled-harness precedent).
**Escalation:** operator — local toolchain decision.

## A-ADA-005: Alire crate publish (S5) requires crate-index submission

**V7 section:** absent (packaging).
**Profile field:** `[publishing]`.
**Your guess:** Publishing the `entity_core_protocol` Alire crate is the optional S5 step;
`repository_url` is TBD until the first publish (the Alire community crate-index PR gates
publish).
**Rationale:** Same shape as Java's Maven-Central namespace gate (A-JAVA-005) — a
publish-time registry submission, deferred to S5. Non-blocking for S1–S4.
**Escalation:** operator — deferred to the S5 registry step.

## A-ADA-006: concurrency shape (one-task-per-conn vs bounded pool) decided at S3

**V7 section:** §4.8 (store safety), §4.9 (resilience), §6.11 (reentrancy), §7b (gate).
**Profile field:** `[concurrency]`.
**Your guess:** Fix the **protected-object store** now (§4.8 maps onto a protected object —
language-enforced mutual exclusion). Defer the task topology (one-task-per-connection vs a
bounded task pool with a request queue) to S3; set TCP_NODELAY on accepted sockets; if a
bounded pool is used, keep socket I/O per-task / non-blocking.
**Rationale:** The store-safety mechanism is the load-bearing §4.8 decision and is fixed
now (the cleanest cohort story — the Zig/CL store-race fall-overs are structurally
unrepresentable behind a protected object). The exact task topology is an S3 implementation
choice (mirrors the Java A-JAVA-003 / OCaml A-OC-003-revised deferral), recorded so S3 does
not re-litigate silently.
**Escalation:** operator — S3 implementation decision.

## A-ADA-007: resource_bounds (§4.10) — 413 payload / 400 chain-depth / 503 conn-flood (PRE-RESOLVED)

**V7 section:** §4.10(a)/(b)/(c) (v7.75 floor MUSTs + the (c) SHOULD); §5.5 chain depth.
**Profile field:** `[error_model]` (`Payload_Too_Large_Error`, `Chain_Depth_Exceeded_Error`).
**Your guess:** r1 over-payload → **`413 payload_too_large`** (default 16 MiB) + keep
serving; r2 over-deep delegation chain → **`400 chain_depth_exceeded`** (default 64) — MUST
be **400, NOT 403**; r3 connection flood → `503 too_many_connections` / clean close or an
honest WARN (§4.10(c) is a SHOULD). S3 builds the ~15-line §4.10(b) chain-depth STRUCTURAL
pre-check (walk parents, no signature work, max = 64, BEFORE the authz walk).
**Rationale:** Verified directly in `spec-data/v7.75` — lines 1933–1935 (the MUSTs + the
(c) SHOULD), 1950–1951 (the status-code table: `payload_too_large` 413,
`chain_depth_exceeded` 400 "non-authz by design"), 4036 + 4092 (the §9.1 floor + the
`resource_bounds` category). `chain_depth_exceeded` is 400 because a too-deep chain is
structural excess, not an authz denial — all prior peers needed the structural pre-check,
and the 403→400 change was net-new for ALL peers in the v7.75 re-run.
**Escalation:** none (settled in v7.75). Pre-resolved so S3 inherits it correctly.

## A-ADA-008: §5.2 verdict trichotomy — 401 / 403 / 401-unresolvable (PRE-RESOLVED)

**V7 section:** §5.2 `verify_request`; §5.2a verdict-to-status enumeration.
**Profile field:** `[error_model]` (`Authentication_Error` → 401, `Authorization_Error` → 403).
**Your guess:** Map the §5.2 verdict to the five-peer-convergent trichotomy: **401**
(authn failure) / **403** (authz denial) / **401** (identity unresolvable).
**Rationale:** spec-data/v7.75 §E2 records the v7.73 fold of the three-way `ALLOW` /
`AUTH_DENY` / `AUTHZ_DENY` verdict + the §5.2a verdict-to-status enumeration; five prior
peers (C# F20, OCaml A-OC-008, Rust + Python concurrence, …) converged. SETTLED.
**Escalation:** none (settled). Pre-resolved.

## A-ADA-009: entity `data` is an arbitrary ECF value, NOT a map (A-JAVA-010 inherited; PRE-RESOLVED, load-bearing for Ada)

**V7 section:** §1.1 (entity `data`).
**Profile field:** `[data_model]` (`ecf_value_model = "discriminated-record-variant"`,
`entity_data_is_arbitrary_ecf = true`).
**Your guess:** Model `data` as a **general ECF value** — a **discriminated record / tagged
variant** over the full ECF value space — from the start, NOT an `Ada.Containers` map.
**Rationale:** A-JAVA-010 (the silent-500 trap): a map-only `data` model passes S2/S3 green
then **500s on the first scalar-data entity** at the live S4 gate, because §1.1 `data` is
an arbitrary ECF value (scalar / array / map / …), not necessarily a map. Ada's strong,
static typing makes this **especially** load-bearing — a map-only field is a type-level
commitment the compiler accepts and only the oracle catches. The codec's ECF value type IS
this discriminated type; an entity's `data` is one such value. Pinned now so S2/S3 build
the right type from the start.
**Escalation:** none (inherited-settled from Java). Pre-resolved — the single decision most
likely to bite at S4 if gotten wrong, hence flagged prominently.

---

## Phase coverage added: **S2 (codec)**

No NEW spec defect surfaced at S2 — consistent with the dry well. The 10 inherited-settled
items held exactly as pre-resolved; A-ADA-002 (Ed448/SHA-384 defer) confirmed as the
libsodium gap (core floor unaffected). One small Ada-specific engineering note logged
below (A-ADA-010); it is a local toolchain decision, not a spec defect.

## A-ADA-010: float-validity-check suppression in the codec (Ada-specific; engineering note)

**V7 section:** ENTITY-CBOR-ENCODING.md §4 (float canonicalisation; specials NaN/±Inf/-0.0
are first-class ECF values).
**Profile field:** absent (toolchain/compiler behaviour).
**Your guess:** Disable compiler-inserted validity checks (`pragma Validity_Checks (Off)`
+ `pragma Suppress (Validity_Check)`) in exactly the two codec bodies that traffic in raw
float bits (`Entity_Core.Codec.Cbor`, `Entity_Core.Codec.Value`), and do NOT use `-gnatVa`
project-wide.
**Rationale:** GNAT's validity model treats IEEE-754 special floats (NaN, ±Inf) as
"invalid data" the moment a value is produced via `Ada.Unchecked_Conversion` (the bit-exact
float encode/decode path) or returned from a function — raising `Constraint_Error` on
perfectly canonical wire bytes (the `float.5`/`float.6`/`float.7` corpus vectors). Special
floats are legitimate, normative ECF values, so blanket float-validity checking is
incorrect for a faithful codec. The suppression is scoped to the two float-bit bodies only;
the design-by-contract `Pre`/`Post`/`Type_Invariant` aspects remain LIVE under `-gnata`
(the suppression touches validity checks, not assertion/contract checks). This is the Ada
analogue of "don't let a language's default float handling corrupt canonical bytes" — the
same class as the cbor2 float16 lesson (W1/W2), reached from the other direction (Ada is
too strict about floats, not too lossy).
**Escalation:** operator — local compiler-configuration decision; non-blocking, conformance
is unaffected (69/69 byte-identical with the suppression in place). No spec action needed.

---

## S1 exit status

**No blocking-severity items.** A-ADA-001/003/007/008/009 are PRE-RESOLVED inherited-settled
items (recorded so S2–S5 inherit them); A-ADA-002 (Ed448 defer) is the agility higher bar,
non-blocking for the §9.1 core floor; A-ADA-004/005/006 are local toolchain/build/publish/
concurrency-shape decisions. No new spec defect surfaced at S1 — consistent with the dry
well, and the Ada idiom axes (protected-object store, contract aspects) map cleanly onto V7,
a spec-tightness signal. **S1 PASS.**

## S2 exit status

**No blocking items.** S2 (codec) added only A-ADA-010 (an Ada-specific float-validity
compiler note, non-blocking, conformance-neutral). The inherited-settled items
(A-ADA-001/003/007/008/009) were exercised and held; A-ADA-002 (Ed448/SHA-384 defer)
confirmed against libsodium 1.0.22 (the core floor needs only Ed25519 + SHA-256, both
present). ECF wire-conformance is **69/69 byte-identical, 0 FAIL**. **S2 PASS.**

---

## Phase coverage so far: **S3 (peer machinery)**

The dry well held at S3 — no NEW spec defect surfaced. The peer surface mapped
cleanly onto V7 under the Ada idioms (tasks + protected objects + design-by-
contract). The two-direction loopback against the Go reference (`a053670`)
is GREEN with zero spec disagreement. The one S3 decision deferred from S1
(A-ADA-006 task topology) is resolved below; the rest are honest, non-spec
implementation notes (logged because they could bite a future reader, not
because they are defects).

## A-ADA-006 (RESOLVED at S3): task topology = ONE TASK PER CONNECTION

**V7 section:** §4.8 (store safety), §4.9 (resilience), §6.11 (reentrancy), §7b (gate).
**Profile field:** `[concurrency]` (the S1 profile fixed the protected-object store and
deferred the topology to S3).
**Resolution:** **one TASK per connection** (accept loop spawns a `Reader_Task` per
accepted socket; the dialer spawns one client-side), NOT a bounded task pool with a
request queue.
**Rationale:** GNAT maps tasks to OS threads, so a blocking socket read in one
connection's task does NOT stall any other connection — the §7b cooperative-pool-
starvation trap (the Swift `read()`-on-a-bounded-pool 60s stall) is sidestepped
STRUCTURALLY, not by a backpressure knob. The §4.8 store-safety is already the protected
object, so the connection tasks share no unsynchronized state; the §6.11/N7 demux and the
shared-stream write serialization are themselves protected objects (`Demux_Table`,
`Write_Guard`). This is the simplest topology satisfying N6 + N7 for a `--profile core`
peer — the per-connection-reader shape OCaml/Zig/CL/Java converged on, reached here via
Ada's first-class tasks. A bounded pool was rejected: it would have to keep socket I/O
per-task/non-blocking to dodge the §7b trap, buying nothing for the core profile.
**Escalation:** none — a resolved local idiom decision (mirrors A-JAVA-003 /
A-OC-003-revised). Non-blocking; the topology is recorded so S4/S5 do not re-litigate it.

## A-ADA-011 (note, non-defect): EXECUTE `params` is an ENTITY wire-form, not a bare map

**V7 section:** §3.2 (EXECUTE params), §4.1 (connect operations).
**Observation:** the Go reference puts the `params` of an EXECUTE as the **wire form of an
ENTITY** (`{type, data, content_hash}` — `Params: ecf.Encode(authEntity)`), NOT a bare
data map. The §3.5 proof-of-possession signature target at authenticate is therefore the
**authenticate ENTITY's content_hash**, and the responder MUST materialize `params` as an
entity (and read its `data` fields + recompute its hash) rather than reading fields off the
top level of the params map. A first cut that read `key_type`/`nonce`/`public_key` off the
params map top level got `nonce-not-found → 401` against the Go client; materializing
params first (the `Params_Entity` helper) fixed it and matched the cohort.
**Why logged:** not a spec defect (V7 §3.2 does say params is an entity-shaped value) — but
it is a SHARP, easy-to-miss wire detail that a peer author reading the §4.1 handshake at the
"params has a nonce field" altitude can get wrong, and it only shows up at the live oracle
(Ada-to-Ada loopback would pass with EITHER convention). Recorded as a peer-author caution.
**Escalation:** none — implementation note; the §3.x text is adequate, the trap is altitude.

## A-ADA-012 (note, cohort-consistent): default-policy seed grants double the discovery floor

**V7 section:** §4.4 (initial grant), §6.9a (seed policy).
**Observation:** the §6.9a default policy entry is seeded with `grants = discovery_floor`,
and `Derive_Seed_Grants` returns `floor ++ matched-policy-grants`, so an authenticated peer
whose policy resolves to the `default` entry receives the discovery floor TWICE (the Go
`probe-peer` display shows grant[0..3] = floor·2). This is SEMANTICALLY a no-op (grants
union; a duplicate grant changes no authz verdict) and is BYTE/behaviour-consistent with the
Java precedent (which seeds the same default-entry grants and unions identically). The Go
reference shows the floor once.
**Why logged:** honest disclosure of a cosmetic divergence in the GRANT LIST PRESENTATION
(not the authz outcome). It does not affect any verdict, the smoke 404, or the S4 gate (the
oracle checks authz behaviour, not grant-list cardinality). A future tidy would have the
default entry carry only the NON-floor scope (empty for the non-open case, the wildcard for
`--debug-open-grants`) so the union yields the floor once.
**Escalation:** none — cosmetic, cohort-consistent, non-blocking.

## S3 exit status

**No blocking items, no new spec defect.** A-ADA-006 RESOLVED (one task per connection).
A-ADA-011/012 are honest implementation notes (a wire-altitude caution + a cosmetic
cohort-consistent grant-list duplication), neither a spec defect nor a behaviour bug. The
substrate floor is baked in (413-on-length-prefix; the one structural 400-chain-depth
pre-check, 400≠403, pre-check-before-authz-walk, unreachable-parent-stays-403; TCP_NODELAY;
resilience-on-malformed-frame). The §4.8 protected-object store makes the store-race
structurally unrepresentable — the centerpiece result. Two-direction loopback against the
Go reference (`a053670`) GREEN; S2 codec regression unbroken (69/69 + 37/37). **S3 PASS.**

---

## Phase coverage: **S4 (conformance)** — `validate-peer --profile core` PASS, 0 FAIL (cohort baseline `b30a589`: 576·0F·89S)

### A-ADA-013 (RESOLVED) — cohort oracle is `b30a589`, not `62044c5` (off-by-one-commit)

**V7 section:** §4.9/§4.10/§9.1 (resource bounds), §9.0 (core profile).
**Observation:** at `entity-core-go @ 62044c5`, the oracle's `coreProfileCategories`
(`cmd/internal/validate/profile.go`) folds `concurrency` into core but NOT
`resource_bounds` — so a CLEAN `git archive 62044c5` build's `--profile core` auto-skips
`resource_bounds` → the Ada peer scores **574·0F·90S**, whereas the cohort scorecard is
uniformly **576·0F·89S**.
**Resolution (verified read-only from oracle source; corroborated by the live S4 re-run):**
the cohort scorecard's "62044c5" label is **off-by-one-commit**. The real v7.75 cohort
oracle is the immediate child **`b30a589`** ("v7.75: pair §9.0 drift gate post-arch-fold;
resource_bounds enumerated"), which adds `catResourceBounds: true` to
`coreProfileCategories` (line 46 of `profile.go`, joining `catConcurrency: true`). Building
the oracle from `b30a589` (READ-ONLY `git archive`, no oracle modification, peer NOT
rebuilt) and re-running `--profile core` gives the true cohort number **576·0F·89S**,
machine-verified `summary.failed == 0`, with `resource_bounds` now ACTIVE in core:
r1 `payload_too_large` PASS · r2 `400 chain_depth_exceeded` PASS · r3 connection-flood WARN.
`b30a589` is clean and an ancestor of the later clean cohort commits.
**Additional evidence retained:** the clean `62044c5` run (574·0F·90S) + the standalone
`-category resource_bounds` GREEN (same r1/r2/r3) — `b30a589` simply folds that standalone
GREEN into the headline core run. Binary gate (`Result: PASS`, 0 FAIL) holds across all of
`62044c5` (574), `62044c5` + opt-in resource_bounds, and `b30a589` (576).
**Outcome:** RESOLVED — no doctoring, no peer change; the only correction was selecting the
correct cohort baseline commit `b30a589` as the certification oracle. Both the §4.10(b) 400
`chain_depth_exceeded` pre-check and the §4.9/§9.1 413 payload cap behave exactly as the cohort.

### Discovery-well status at S4: DRY (as predicted)

No new spec DEFECT surfaced. Every one of the ~7 iteration fixes (params-navigation,
53-type registry, §6.11 reentry, cap configure/revoke, §10.1 register, §3.9 CAS, §1.4
path-flex, deletion-marker filter, §4.5/§4.7 negotiation/agility, F12 nonce) was a
peer-implementation completion derived spec-first from V7 + the `62044c5` oracle's own check
sources — none was a spec ambiguity. The Ada idiom axes (protected-object store +
one-task-per-connection + a reentry-only child task) produced the same 0-FAIL fixed point as
the cohort, with concurrency genuinely 5/5 (the store-race the C sibling hit is structurally
unrepresentable here). **S4 PASS — no new blocking ambiguity; A-ADA-013 RESOLVED (cohort
oracle = `b30a589`, 576·0F·89S).**

---

## Phase coverage: **S5 (publish)** — log FINALIZED (every item owner + escalation tagged)

No new spec defect at S5 (docs/packaging phase). One packaging item (A-ADA-005, Alire crate publish)
is the deferred operator step; all other items carry their final owner + escalation status below. The
log is closed for v0.1 — every entry has a named owner; nothing blocks release.

### Final disposition table (owner + escalation)

| Item | Owner / escalation | Status | One-line |
|---|---|---|---|
| **A-ADA-013** | ⚑ mainline/arch | RESOLVED (in-peer) | cohort oracle is `b30a589`, not `62044c5` (off-by-one); `b30a589` folds `resource_bounds` into core → 576·0F·89S (clean `62044c5` → 574·0F·90S); verified read-only + live re-run, no doctoring, peer not rebuilt — scorecard label should take the one-commit fix. |
| **A-ADA-001** | ⚑ arch | RESOLVED (in-peer) | §7.4-vs-§1.5 peer-id; N-th spec-first corroboration; resolved via §1.5 identity-multihash (raw pubkey, `hash_type=0x00`); baked at S1. |
| **A-ADA-003** | ⚑ arch | RESOLVED (in-peer) | hex-case unspecified; Ada hex builtins default UPPERCASE (the A-CL-009 trap, CL log named Ada); pinned proactively (lowercase nibble→char table). |
| **A-ADA-008** | ⚑ arch | RESOLVED (in-peer) | §5.2 401/403/401-unresolvable trichotomy; multi-peer-convergent; mapped from the exception lattice at the dispatcher boundary. |
| **A-ADA-011** | implementation note (no escalation) | RESOLVED (in-peer) | EXECUTE `params` is an ENTITY wire-form (`params.data.entity`); biggest S4 fix cluster; NOT a spec defect (§3.2 adequate), a wire-altitude trap. |
| **A-ADA-010** | operator | RESOLVED (in-peer) | GNAT `-gnatVa` flags IEEE float specials as invalid on canonical bytes; validity checks scoped-suppressed in the two float-bit codec bodies (contract aspects stay live); conformance-neutral. |
| **A-ADA-007** | none (settled v7.75) | RESOLVED | resource_bounds 413 / 400-not-403 / WARN; §4.10(b) structural pre-check before authz walk; pre-resolved + held. |
| **A-ADA-002** | operator | DEFERRED (non-floor) | Ed448/SHA-384 agility higher bar; libsodium gap (OCaml/Zig company); §9.1 floor needs only Ed25519+SHA-256; overlay via C-ABI / OpenSSL curve448, NOT libsodium. |
| **A-ADA-005** | operator | DEFERRED (S5 step) | Alire crate publish; `alr publish` needs a crate-index submission (sets `origin`/`repository_url`); Alire `version` accepts `-pre` directly (contrast A-CL-010). |
| **A-ADA-006** | none | RESOLVED (S3) | task topology = one task per connection (GNAT tasks → OS threads; no cooperative-pool starvation); protected-object store fixed at S1. |
| **A-ADA-004** | operator | RESOLVED | build = gprbuild against the committed `.gpr` (no Alire resolve) + hand-rolled test runner (no AUnit); lightest-supply-chain, fully offline. |
| **A-ADA-012** | none | RESOLVED (cosmetic) | default-policy seed grants double the discovery floor in the GRANT-LIST PRESENTATION (no authz-verdict effect; cohort-consistent with Java). |

### S5 exit status

**No new blocking items; log finalized.** The discovery well held DRY across S1–S5, as the honest
framing predicted — no genuinely-new spec defect from the Ada idiom axes. The arch-bound bundle is
A-ADA-001/003/008 (standing corroborations, ⚑ arch) + A-ADA-013 (⚑ mainline/arch — the oracle-label
correction, the most actionable item); the deferred-operator items are A-ADA-002 (Ed448/SHA-384
agility, non-floor) and A-ADA-005 (Alire publish, S5 step); the rest are resolved-in-peer. Every item
has a named owner. **S5 PASS — ambiguity log finalized, all items owner-tagged, no release blocker.**
