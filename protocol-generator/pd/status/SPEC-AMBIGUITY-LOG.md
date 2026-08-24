# Pure Data peer — SPEC-AMBIGUITY-LOG

Findings surfaced while building the Pd peer (#33). Substrate-quirk findings (`A-PD-*`) are local
notes; a genuine **spec** ambiguity/defect escalates to `research/stewardship/` as a
`HANDOFF-TO-ARCH-*.md` (never a cross-repo edit). Per the framing in `COMPLETENESS-ROADMAP.md`, this
probe is **not** a spec-discovery bet — the value is robustness + the reactive-mismatch
characterization — so `A-PD-*` rows are expected to be substrate quirks, not spec gaps.

Legend: 🟡 open · 🟢 resolved · 🔺 escalated (spec)

---

## A-PD-001 🟢 — Pure Data is not packaged in fedora:43 (toolchain, not spec)

`dnf search puredata` / `pd` / `pure-data` → no matches; only fedora/updates/openh264 repos. The
handoff's `dnf install puredata` assumption is wrong. **Resolved:** source build, pinned tarball
`0.55-2` (SHA `2b9cda30…`), **core-only** (`make -C src`; the `extra/` DSP externals break on modern
gcc's `sqrt` prototype and aren't needed). See `containers/puredata-toolchain/Containerfile`.

## A-PD-002 🟢 — `[netreceive]` reply targeting under multiple concurrent connections (§6.11) — RESOLVED (transport moved into `[ecodec]`)

Stock `[netreceive -b]` is bidirectional (a list to its inlet is written back over TCP — proven at
S1). **Open:** with multiple concurrent client sockets on one `[netreceive]`, does `send` address a
specific socket or broadcast to all? entity-core §6.11 requires per-connection reply targeting. Read
`src/x_net.c netreceive_send` closely at S3 and test empirically with 2+ simultaneous connections;
if stock `send` can't target a single socket, that IS the transport finding (decide: a per-socket
demux authored on the canvas, or fall back to an `iemnet [tcpserver]` external — log the decision).
The concrete face of the concurrency-shape stress in PHASE-S1.

**Update (S3.13): this is the peer's characterized substrate limit — the last 3 `--profile core`
fails.** After driving `--profile core` to **188 P / 5 F**, the residual failures cluster on the
single-global connection state: `resource_bounds` **r1_payload_over_limit** (the peer DOES cap frames
at 16 MiB — `ECODEC_MAX_FRAME` — and closes on oversize, which §4.10(a) allows as "coded frame OR
close"; but "**keeps serving**" fails — after the oversize close the global `g_rbuf`/phase state is
dirty, so the *next* connection's handshake degrades), **r2_chain_depth_over_limit** (cascades — "handshake
failed before chain-depth probe"; also wants 400 `chain_depth_exceeded` where the walk's depth guard
returns 403), and **r3_connection_flood** (SHOULD — admission bound under 256-connection churn). All three
are the §6.11 single-threaded reactive-substrate limit: per-connection state (nonce/phase/buffer) is a
single global, and there is no cooperative-yield between connections (cf. the TurboWarp #32 lesson — a
serial drain drops responses under churn). The fix is the per-connection-demux + cooperative-yield
rework (per-socket state off `[netreceive]`'s "from" outlet or an `iemnet [tcpserver]`), a substantial
canvas sub-project — and r3 (SHOULD) may remain partly substrate-bound single-threaded. This is the
reactive-paradigm characterization the Pd probe exists to produce, not a spec gap.

**RESOLVED (transport rework, 2026-07-15).** Read `src/x_net.c` at the source level (per the
"prove a negative" discipline): stock `[netreceive]`'s `netreceive_send` **broadcasts** every reply to
all `x_nconnections` (a `for` loop over `x_connections[i]` → `netsend_dosend`), and binary mode carries
**no per-connection source id** — so a conformant multi-connection peer is genuinely impossible on stock
Pd transport. **Sockets are an explicitly-legitimate FFI seam** (FLOW-DESIGN: bytes/maps/sockets/crypto/
store), so the transport moved INTO `[ecodec]`: one listening socket (`net_listen`, via `sys_addpollfn`),
a **per-connection** receive buffer + §1.6 frame assembler + issued nonce, an admission cap
(`EC_MAX_CONN`, pause-accepting → OS ECONNREFUSED), an idle-connection reaper (close a socket open >2s
that never sent a byte), and **reply-targeting to the originating fd** (`conn_send_all`, no broadcast).
The §6.5/§5.2/§6.6 dispatch stays on the canvas — a completed frame is copied to `g_rbuf` and the
existing decode→route→ladder cascade is kicked synchronously, so per-request transient globals stay
single-owner-safe. Result: **`resource_bounds` r1 + r2 PASS, r3 WARN** (kept-serving, §4.10(c) SHOULD),
and `concurrency.t2_2_connection_churn` **PASS**. The rework also un-blocked ~35 previously-unreachable
probes (negotiation/format-agility gaps, all since fixed). See `A-PD-015`.

## A-PD-016 🟢 — second-truncated mint timestamps make same-scope re-mints CONTENT-HASH IDENTICAL → one revoke kills the session cap (durable, cross-language)

A content-addressed token is `{grants, grantee, granter, created_at}`. With `created_at` stamped
from `time(NULL)*1000` (second precision), two mints of the SAME scope for the SAME grantee within
one second are byte-identical → **same content hash → the same capability**. The oracle's
`revoke_happy_path` probe then revoked a freshly-requested token whose hash collided with the
§4.4 **session floor cap**, and every later category 403-cascaded (isolated category runs stayed
green — only the full-profile marathon, where the capability category runs early on a long-lived
session, exposed it). **Fix:** ms-precision wall clock (`clock_gettime(CLOCK_REALTIME)`) at every
mint site. **Durable lesson:** on a content-addressed protocol, mint-timestamp precision is a
CORRECTNESS parameter, not a formatting choice — any peer whose clock stamps coarser than the
oracle's re-mint cadence will alias tokens. (The C peer's `ec_now_ms()` avoided this implicitly;
nothing in the spec says so explicitly — candidate for a GUIDE-CONFORMANCE note.)

## A-PD-017 🟢 — the open-grants seed needs the ABSOLUTE all-peers resource form; bare `*` cannot cover foreign namespaces (§5.5a consequence)

The degenerate `default → *` seed with `resources: ["*"]` looks universal but §5.5a makes bare `*`
GRANTER-LOCAL (`/{granter}/*`) — so the `universal_address_space` probes' writes into a FOREIGN
namespace (`/{fixturePeer}/system/validate/uas/*`) had no covering grant and the whole category
skipped ("connection grants do not cover"). The seed must carry BOTH forms:
`resources: {include: ["*", "/*/*"]}`. A consequence of the §5.5a bare-star ruling that any peer
implementing an open-access/debug seed hits; the Go `-open-access` peer covers it internally.

## A-PD-015 🟢 — the transport rework un-blocked ~35 probes; 5 were real gaps (fixed), the rest are the gated writable-peer scaffold — CLOSED 2026-07-15: writable peer landed, `--profile core` **Result: PASS**

**Close-out:** the writable-peer sub-project shipped — dynamic store + §6.3 `tree:put` (CAS,
listing filter, deletion markers) + §1.4 canonical store keys (foreign namespaces preserved
absolute) + §6.13(a) register/unregister five-write + §6.2 capability revoke/configure/delegate +
§5.2 step-4 revocation + the §7a validate scaffold (`EC_VALIDATE`: echo + dispatch-outbound §6.11
reentry) + the `EC_OPEN_GRANTS` seed + `EC_NAME` persistent identity + §3.6/§5.5 M3/M4/M6 K-of-N
multisig accept. Gate: **682 · 287P/299W/0F/96S — Result: PASS @ cc1970f**, 0 fail-counting skips
(96 = §9.0 extension carve-outs); origination-core 3/3 via `run-origination-core.sh`; all 10
offline KAT/regression targets green. Historical context below.

The classic "conformance-green can be vacuous" / unmasking lesson, at the transport layer. With the
single-global `[netreceive]` transport, the oracle's multi-connection probing corrupted state or timed
out, so ~35 probes never ran (`--profile core` total 592). The per-connection transport (A-PD-002) let
them run (total 627). Of the newly-exercised probes, **5 were real pre-existing gaps** — the hello never
advertised `hash_formats`/`key_types`, no disjoint-format/keytype reject, no `unsupported_key_type` at an
unknown `key_type` (§4.5/§4.7) — **all now fixed**. Net this session: `--profile core` **F 5 → 0**
(219 P / 304 W / **0 F** / 104 S @ cc1970f).

**Remaining to a cohort-matching `Result: PASS` (0 fail-counting skips):** the gate categories are
`connectivity / encoding / type_system / origination / resource_bounds / concurrency / §10.1 register /
§7a` (CONFORMANCE-MATRIX). Three still SKIP because the peer is **read-only** (implements `tree:get`,
not the write surface the cohort peers run with):

1. **`concurrency` t1_1/t1_2/t1_3/t2_1** — need the peer run with the `--validate` scaffold
   (`system/validate/*` handlers incl. `dispatch-outbound`) **and write grants** (`--open-access` /
   `--debug-grants`): the probes `tree:put system/validate/concurrency/*` and get **403** (no write
   grant) / find `system/validate/dispatch-outbound` absent. (`t2_2_connection_churn` already **PASS** —
   the multi-connection transport.)
2. **`handlers.core_register_*`** — the §6.13(a) handlers-handler `register`/`unregister` five-write
   behavioral contract (manifest + types + grant + grant-signature + interface). The peer resolves the
   handler but does not execute the writes.
3. **`origination` §7a** — reference-peer-gated; a single-peer `run-s4` honest-SKIPs it (run via
   `run-origination-core.sh`), so it is allow-listable, but §7a `dispatch-outbound` reentry is the same
   scaffold item as concurrency t1_2.

These are one coherent sub-project: **make the peer writable** (`tree:put` into `g_store`) + the
`system/validate/*` conformance handlers + an open-access/validate grant mode + the §10.1 register
five-write. The extension-category skips (query/compute/attestation/… + the extension handler-interface
probes) are legitimately `-allow-skip`'d for a core peer. Not a spec gap — a build-scope roadmap item.

## A-PD-003 🟡 — Pd atoms are 32-bit floats: no native u64 / byte-buffer (integer head-form)

Pd's atom is a 32-bit float; it cannot hold a u64 wire integer exactly, nor a byte buffer. Per the
cross-language "integer head-form is a fixed-width artifact" lesson, but taken to the limit: the peer
carries large ints + buffers **inside opaque C-external handles**, never as Pd atoms. Confirm at S2
that no wire-int or length value is ever materialized as a bare Pd float on a path where precision
matters (esp. the §1.6 4-byte-BE length prefix — 32-bit float loses precision above 2²⁴, and frame
lengths can exceed that; the length math must live in the C external or be handled as 4 separate byte
atoms, never a single float). **Load-bearing** — flag any path that round-trips a length through one
float atom.

## A-PD-008 🟢 — ephemeral process identity — RESOLVED (EC_NAME persistent keypair, 2026-07-15)

`[ecodec]` now loads the Ed25519 seed from `~/.entity/peers/$EC_NAME/keypair` (the entity-core PEM:
base64 of a 32-byte seed — the Go `--name` / peer-manager convention) when `EC_NAME` is set,
deriving the pubkey via `ec_ed25519_seed_to_pubkey`; absent the env var it falls back to the
ephemeral keygen. `run-s4.sh` provisions the cohort's deterministic `0x11×32` seed as
`conformance`, which is what lets the multisig accept-path probe (`valid_2of3_peer_signed_accepted`)
co-sign AS the peer — closing the last conditioned skip (multisig 11/11).

## A-PD-006 🟢 — placeholder handler tree — RESOLVED (dynamic store + manifest entities, 2026-07-15)

**Close-out:** the real writable store landed in `[ecodec]` (a bind/tombstone list keyed by §1.4
canonical store keys — local bare-relative, foreign `/{peer}/rest` preserved absolute). The §6.6
walk now resolves handlers by ENTITY TYPE from the store (`system/handler` manifest entities bound
at pattern paths), so runtime-registered handlers dispatch identically to the bootstrap five
(§6.13(a) dispatch uniformity). Dynamic binds shadow the static bootstrap tables; a tombstone
shadows a static binding with "unbound". Historical context below.

`[ecodec] tree_get` currently matches a hardcoded set of core handler locations (§6.2:
`system/{tree,handler,type,capability,protocol/connect}`), NOT peer-scoped, NOT populated from a real
content store. Enough to prove the §6.6 walk discriminates known handler prefixes from unknown paths
(→ 404). The real entity tree + content store — keyed by full path incl. peer_id, bootstrapped from
identity — replaces it when the §4.1 handshake lands the peer's identity. Until then paths are matched
bare (no peer_id prefix). Not a spec issue; a build-order note.

**Update (S3.6):** the §6.5 ALLOW path now serves REAL data. A minimal store holds the 8
MUST-populate primitive type entities (`system/type/primitive/*`), and `tree_get_serve` implements the
§6.3 `system/tree:get` handler (listing on trailing `/`, entity at exact path, 404 otherwise). Oracle
`type_system.types_listing_available` + `handlers.handlers_listing_available` PASS (real
verify→resolve→perm-allow→result). Still bare-path (no peer_id prefix); still a placeholder for the
*walk's* handler set (`ecodec_tree_get`). The remaining broadening is the rest of the 53-type floor +
real `system/handler` manifest entities (for `handler_*_present` / interface-type checks) + peer-scoped
keying — the type-registry sub-project proper.

**Update (S3.7): the 14-type bootstrap floor is now populated, rendered natively.** The store
(`g_store[]` in `ecodec.c`) is a **data table of type definitions** + one canonical encoder
(`emit_typedef_data`/`emit_fields`/`emit_fspec`) — the durable "render natively, Go vectors as a
byte-exact drift target" lesson, in C. Beyond the 8 primitives it now holds `system/hash` (extends
`primitive/bytes`, `format_code`+`digest` layout), the two meta-types (`system/type`,
`system/type/field-spec`), the three string-address types (`system/tree/path`, `system/type/name`,
peer-id under both names — see A-PD-012), and the structural root `entity` (§3.1.1). Oracle
`-category type_system` climbed **17 P -> 30 P**: every new type greens its `_fetch` **and** `_match`
(byte-exact vs the Go rendering — the meta-types too, proving canonical length-then-lex ordering is
right), except `type_system_type_field_spec_match`, an expected non-gating **WARN** (A-PD-013). Adding
the remaining core/protocol/supporting types (§8/§9/§10 — the other ~170) is now mechanical table
rows, not new code. connectivity 22/22 + authz 4P/2F/2S held.

## A-PD-012 🔺 — spec names the peer-identity type two ways (`system/identity/peer-id` vs `system/peer-id`)

Escalated as SPEC-FINDINGS-LOG **F33**. ENTITY-NATIVE-TYPE-SYSTEM.md v0.8.0 names the peer-identity
address primitive inconsistently: the bootstrap definition (§1 L19, §4.4 table row 14, §4.8, §2.7
rationale; used as a `type_ref` at L639/L1082) calls it **`system/identity/peer-id`**, but §10.1
`system/peer` (L1453) + Appendix B (L2399) reference **`system/peer-id`** for the same concept — and
the reference oracle's ratified-core set carries only `system/peer-id` (no `identity/` probe). Both
names are live `type_ref`s in one spec version. **Peer decision (spec-faithful, not oracle-chasing):**
register the type under **both** names (`g_store` binds `system/type/system/identity/peer-id` AND
`system/type/system/peer-id`, each `{name, extends:"primitive/string"}`) so every spec `type_ref`
resolves; this also greens `type_system_peer_id_fetch`/`_match` as a side effect of being *more*
spec-complete. Arch picks the canonical name. Secondary: §4.4 says "14 bootstrap types" but the table
lists 15 rows (row 15 = `entity`) — an off-by-one folded into F33.

**Update (S3.8) — the divergence is systemic: `ENTITY-NATIVE-TYPE-SYSTEM.md` Appendix B is STALE
vs the primary `ENTITY-CORE-PROTOCOL.md` `:=` definitions.** Populating the full core type floor
surfaced that Appendix B disagrees with the primary protocol doc (and the oracle, built from it) on
several core types: `core/envelope.root` / `system/protocol/execute.params` /
`.../execute/response.result` are **`core/entity`** in the primary doc (§3.1/§3.2/§3.3) but
**`primitive/any`** in Appendix B; `connect/hello.peer_id` + `connect/authenticate.peer_id` are
**`system/peer-id`** in the primary doc but **`system/identity/peer-id`** in Appendix B (the same F33
naming split — the oracle uses `system/peer-id` *everywhere*, never `identity/peer-id`);
`system/envelope` **extends `core/envelope`** (primary §3.1 "structurally identical to
system/protocol/envelope") but Appendix B spells out duplicated `{root, included}` fields; and
`system/handler/manifest` **extends `system/handler/interface`** (§3.7) which Appendix B omits. The peer
is authored from the **primary doc** (spec-faithful; the oracle `_match` confirms byte-exact). Folded
into F33: Appendix B should be regenerated from the `:=` definitions. Result: **all core `type_system`
`_fetch`+`_match` probes pass under `--profile core`**.

## A-PD-014 🟢 — populating the type store unmasked 6 vacuously-passing capability-chain probes (methodology)

The "conformance-green can be vacuous" lesson, third instance in this peer (after A-PD-009 cohort-of-one
and A-PD-010 dead-ALLOW-path). Populating the core type floor flipped **6 `security`-category probes
PASS→FAIL** under `--profile core`: `chain_no_delegation_denied`, `chain_max_delegation_ttl_denied`,
`chain_mid_link_expiry_denied`, `chain_per_link_temporal_denied`, `chain_content_hash_substitution`,
`captok_form_dispatch_minted_pl_presented_xpeer` — all **multi-link capability-chain** validations
(§5.5/§5.7). **This is NOT a security regression.** The peer never implemented full chain-walk caveat
enforcement (grep confirms: zero `no_delegation`/`max_delegation`/per-link-temporal enforcement code —
the only mentions are the *type definitions* added this session); its §5.2 ladder validates the
**single presented cap** (signature, grantee, temporal, scope) but does not walk the delegation chain.
The 6 probes were passing **by accident** — the peer denied their requests for an *incidental* reason
(the target type path 404'd, or the cap resource was out of scope), which happened to match the
expected "MUST be denied". Once the target types resolve (this session) and the caps are in-scope, the
working §5.2 ladder authorizes → 200 → the probe honestly reveals the peer never enforced §5.5/§5.7
chain caveats. The honest FAIL is strictly better than the vacuous PASS. **Fix (real conformance work,
next):** implement the §5.5/§5.7 multi-link chain walk — delegation caveats (`no_delegation`,
`max_delegation_ttl`, `max_delegation_depth`), per-link temporal validity, and content-hash-substitution
detection — alongside the `system/capability:request` handler (A-PD-011). Net this session: `--profile
core` F 105→34; these 6 are the honest face of an always-present gap, not new breakage.

## A-PD-013 🟢 — the oracle's `system/type/field-spec` bakes in the extension `constraints` field (open-type-tolerable)

Not a spec defect and not a peer bug — a confirmation the core/extension boundary works. The oracle's
`type_system_type_field_spec_match` reports a **non-gating WARN**: "1 structural difference
(open-type-tolerable): field 'constraints': optional locally, missing remotely (spec:
array_of(core/entity)?)". The reference peer's `system/type/field-spec` definition carries an extra
optional `constraints` field; our core-only render omits it, per §4.3 ("Value constraints... defined by
the type extension (EXTENSION-TYPE.md). Core type definitions describe structure only"). Adding
`constraints` would render an **extension** field inside a **core** type — a §4.3 violation — so we do
NOT. The oracle's own `_match` treats the omission as open-type-tolerable (§2.4) and only WARNs; that
WARN is the correct, spec-faithful outcome for a `--profile core` peer. Logged so a future reader
doesn't "fix" the WARN by importing the extension field.

## A-PD-007 🟢 — Pd `[route]` de-wraps a lone symbol into a bare selector (substrate)

Reusable Pd finding (reactive-patch substrate quirk, not spec). `outlet_anything(out, "prefix", 1,
&sym)` → `[route prefix]` strips the selector and emits the remaining lone symbol as a **bare-selector
message** (0 args), so a downstream `[msg tree_get $1(` fails with "$1: argument number out of range"
and the object sees "bad arguments". A `[print]` shows the symbol fine (masking the bug). **Fix:**
insert `[symbol]` (or `[list]`) between the `[route]` outlet and the `$1` consumer — it re-wraps the
bare selector into a proper `symbol` message so `$1` reads it. Verified. Carry this into every
route→$1 path (`prefix`→`tree_get`, `treetype`→`[sel]`). One more instance of the reactive substrate's
message-typing friction (cf. A-PD-004).

**Recurred a 3rd time (S3.6), now a hard rule.** The §6.5 op-switch (`dispatch_op`→`[sel get]`) failed
with `select: no method for 'get'` — `[route]` handed the bare selector `[get(` to `[sel get]`, which
can't match it. Same `[symbol]`-coercion fix. **Durable rule: ANY `[route]` outlet feeding a `[sel]`,
a `[symbol]` right-inlet store, or a `$1` message MUST pass through a `[symbol]` first** (the left
inlet coerces a bare-selector anything into a real `symbol`). This is now the single most-recurring
authoring trap in the peer — three instances (walk `tree_get`, walk perm-handoff, op-switch). The
`build/pd-validate.py` structural check does not catch it (it is a message-*type* mismatch, not a
wiring error); the tee + a `post()` on the receiving seam method is how each instance was found.

## A-PD-009 🟢 — cohort-of-one clients validated a non-conformant envelope shape (methodology, not spec)

The canonical "conformance-green can be vacuous" lesson, caught the moment the **real `validate-peer`
oracle** first drove the peer (S4 step 1, `run-s4.sh -category connectivity`). Both `[ecodec]` (decode
+ emit) and every hand-rolled Python test client (`test/*-roundtrip.py`) serialized the **wire
envelope** as a full entity triple `{type:"system/protocol/envelope", data:{root,included},
content_hash}`. They agreed with each other, so all five S3 gates (decode/response/treewalk/hello)
passed — a **cohort of one**. The spec was never ambiguous: §1.1's wire-format example and §3.1 show
the on-wire envelope is the **bare `{root, included}` data map** — the root *entity inside* is a full
`{type,data,content_hash}` triple, but the envelope's own type/content_hash are **elided on the wire**
(§3.1 transport optimization: envelope content_hash "NOT REQUIRED... during transport"). The real Go
peer sends exactly `{root, included?}` (and omits `included` entirely when empty). Our decoder rejected
that with `no_env_type`.

**Fix:** decode reads `root` at top level (map_pos 0), no env-type/env-data lookup; emit frames the
`{root, included}` map directly, dropping the `wb_entity` envelope-triple wrapper; all Python clients
build/parse the bare map. Response payloads shrank (e.g. hello 328→243 B). After the fix hello passes
the oracle clean. **The lesson (not the fix) is the payoff:** a hand-rolled differential is only as
good as its most-conformant party — the higher-bar live oracle is what makes S4 non-vacuous. (Minor
open Q: we emit `included:{}` explicitly where the reference omits it when empty; the oracle accepts
both, and the envelope isn't hashed on the wire, so this is tolerated — revisit if a canonical-form
check ever flags it.)

## A-PD-005 🟢 — Pd external can't statically link the non-PIC distro libsodium.a (toolchain)

Building `ecodec.pd_linux` (a shared object) against the self-contained static
`libentitycore_codec.a` fails: the bundled distro `libsodium.a` objects are non-PIC
(`relocation R_X86_64_PC32 … can not be used when making a shared object; recompile with -fPIC`).
**Resolved:** link the SHARED `libentitycore_codec.so` instead (built PIC, exports only `ec_*` via
the export.map version script, libsodium privately localized), with a `$ORIGIN` rpath so the shipped
pair (`ecodec.pd_linux` + `libentitycore_codec.so`) is self-locating in Pd's `-path` dir. The same
seam shape the tcl peer uses (rpath to the codec build). See `Makefile` `external` target.

## A-PD-004 🟡 — reactive-mismatch: encoding a stateful state machine without `await`

Not a spec ambiguity — a paradigm-characterization finding (the probe's payoff). Pd has no `await`;
sequential multi-step protocol logic becomes explicit state held in `[int]` cells, consulted on each
inbound message event, with feedback loops back into those cells.

**First concrete data point (§1.6 frame assembler, `src/frame-assembler.pd`):** a header→body read
that is ~3 lines imperatively (`read(4); len=be32(); read(len)`) took **~24 Pd objects** on the
canvas: two `[int]` state cells (phase, expected-count), a decrement-test-store feedback loop
(`[int]→[- 1]→[t f f]→` store + `[==0]`), right-to-left `[trigger]` ordering to sequence
append-before-count, and event-driven header→body transition via the async `[ecodec] buf_read_len`
→ `[route]` round-trip. The **counting/phase state machine is genuinely legible** on the canvas (it
IS the §1.6 algorithm, visible) — but the cost is the trigger-ordering discipline and that "sequence"
is expressed as data-cell mutation, not control flow. Verified byte-exact (single + back-to-back
frames reset correctly) against real `pd`. The §4.1 handshake lifecycle (connect→hello→authenticate→
established) will be the larger instance of this same shape — the concurrency-taxonomy third shape
(single-thread reactive message-graph). Document the legible-vs-collapsed ratio as the spine grows.

## A-PD-010 🟢 — decomposing the §6.6 walk + check_permission onto the canvas surfaced a dead ALLOW path (substrate/methodology)

Composing the §5.2 authz ladder + §6.6 tree-walk + check_permission into `src/main.pd` surfaced a
**latent bug that every DENY probe masked**: `authz_check_perm` was firing at *every* walk prefix
(with the wrong/empty handler pattern), so `perm_ok` was effectively always 0 — **no request could
ever be authorized; the entire ALLOW path was dead.** All four DENY paths still passed (they deny
before/at perm), so a folded "authz works" claim would have shipped a peer that authorizes nothing.

Two substrate causes, both rooted in A-PD-007 (`[route]` de-wraps a lone symbol into a bare
selector-only *anything* message, e.g. `[system/tree(`):
1. **Fan-out race.** Feeding the matched prefix to a hold-symbol *and* the `tree_get` chain from one
   `[route]` outlet let Pd's depth-first fan-out reach `found` (and bang the holder) *before* the
   prefix was stored → the holder emitted empty. Fixed with a `[t a a]` forcing store-before-query.
2. **`[symbol]` inlet asymmetry.** `[symbol]`'s **left** inlet coerces the bare-selector anything
   `[system/tree(` into a real `symbol system/tree` (this is how the walk's `tree_get` gets its
   arg at all); its **right** (store) inlet rejects it (`inlet: expected 'symbol' but got
   'system/tree'`). So the perm-handoff holder must be fed from the *converted* output of the walk's
   symbol, not from `[route]` directly.

**Verified via an oracle-driven tee** (`build/tee-capture.py` in front of `pd` on an alt port +
`post()` on the perm rung) showing perm firing once per resolved probe with the correct handler.
**The lesson is the payoff** (the keystone doctrine, made concrete a third time after Node-RED #31 /
TurboWarp #32): folding the verify→resolve→permission sequence hides real defects; decomposing it
into visible canvas rungs + testing the ALLOW path (not just DENY) is what exposed a peer that
authorized nothing. A DENY-only test surface is vacuous for an authz primitive.

## A-PD-011 🟡 — authz category `delegate_grant`/`scope_exceeds` assume the target handler resolves (§6.5 order vs full-profile probe)

`validate-peer -category authz` pins `delegate_grant` → 403 `capability_denied` and `scope_exceeds`
→ 403 `scope_exceeds_authority`. Both assume the request's target handler **resolves** so that
`check_permission` (or the §6.2 handler's own scope check) fires and DENYs. A **core** peer that
does not implement those handlers is spec-faithful to return, per the §6.5 dispatch order
(resolve-handler **before** check_permission):
- `delegate` → `system/role` (an EXTENSION-ROLE handler) unresolved → **404 `not_found`**;
- `scope_exceeds` → `system/capability:request` resolves *as a known prefix* and the presented cap
  **does** authorize `request system/capability` → `perm_ok=1` → dispatch → **501 `not_implemented`**
  (the scope-exceeds check lives *inside* the unimplemented §6.2 handler).

So the two probes are **full-profile / extension-adjacent**, not core-ladder-reachable: the §5.2
verify ladder is complete and correct, but the (status, code) they pin only materializes once the
`system/role` and `system/capability:request` handlers exist (the real store + handler sub-project,
A-PD-006 / next leg). Not escalated — §6.5 is unambiguous that handler resolution (404) precedes
check_permission (403); the probes simply presuppose an extension-equipped peer. Revisit when the
capability handler lands: `scope_exceeds` should then flip 501→403 `scope_exceeds_authority`, and
`revoked_*` (currently SKIP — their cap-`request` setup 400s without the handler) become reachable.
