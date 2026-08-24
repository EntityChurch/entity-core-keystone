# SPEC-AMBIGUITY-LOG — entity-core-protocol-asm-x86_64

Ambiguities, decisions, and findings surfaced building the x86-64 assembly peer. `A-ASM-*`
entries are peer-local decisions/findings; anything that reads as a genuine *spec* defect
(not a substrate mapping choice) is promoted to `research/stewardship/SPEC-FINDINGS-LOG.md`
and, if normative, a `HANDOFF-TO-ARCH-*.md`. Severity: `decision` (recorded, non-blocking) /
`info` (finding, non-blocking) / `blocking` (halts the dependent phase).

| ID | Sev | Phase | Title |
|---|---|---|---|
| A-ASM-001 | decision | S1 | Assembler = GAS/AT&T; link via `cc` driver + `-no-pie` |
| A-ASM-002 | decision | S1 | Ed448 / SHA-384 agility deferred (not in the core floor) |
| A-ASM-003 | decision | S1 | Concurrency = single-threaded epoll event loop, not clone-threads |
| A-ASM-004 | info | S1 | "FFI the whole codec" still requires a hand-rolled envelope/data-map CBOR reader+writer |
| A-ASM-005 | info | S3 | validate-peer's concurrent/lingering connections make a blocking accept loop head-of-line block (concurrency is required even for non-concurrency categories) — see A-ASM-003 |
| A-ASM-006 | decision | S3 | Type/handler bootstrap entities served from a byte-exact harvested `.rodata` store (no data model to reflect over) |
| A-ASM-007 | info | S3 | Unknown operations must still get a prompt error response — a silent no-reply head-of-line-blocks validate-peer ~20 s per probe |
| A-ASM-008 | info | S3 | 16-byte stack alignment before any call reaching the FFI (SSE) — a non-leaf asm handler must push an odd register count |
| A-ASM-009 | info | S3 | Byte-diff compare returned in `%eax` must be sign-tested as 32-bit, not zero-extended into `%rax` (else negatives read positive) |
| A-ASM-010 | info | S3 | An over-cap inbound frame must be drained + answered (413), never close the connection — a mid-stream close cascades broken-pipe to every later probe on a multiplexed connection |
| A-ASM-011 | info | S3 | `--profile core` multiplexes most stateful probes onto ONE long-lived connection → per-fork `.bss` state suffices for same-connection put→get/register; no MAP_SHARED/epoll needed for the core gate |
| A-ASM-012 | info | S3 | Multisig (§3.6 M3) accept needs full structural validation (threshold ≥ 2, 2 ≤ threshold ≤ N, N ≥ 2, distinct signers, null parent, local peer ∈ signers) or it regresses the 10 reject probes that currently pass fail-closed |
| A-ASM-013 | info | S3 | A `system/handler` **dispatch** entity `{interface:<path>}` at the bare pattern path (distinct from the interface entity at `system/handler/<pattern>`) is what the §6.2 N2/N5 `dispatch_type`/`interface_ref` checks read; publishing built-ins per fork closes them. Publishing `system/handler/system/validate/dispatch-outbound` is the oracle's `--validate` gate for both §7a checks |
| A-ASM-014 | info | S3 | **CORRECTS A-ASM-013's premise.** §7a.2a concurrent reentrant dispatch-outbound is NOT out of reach for a blocking fork peer: the reentry is on ONE socket (the validator plays peer B), so a single-threaded loop that routes inbound frames by root type (request vs `…/execute/response`) + a `pending_tab` demux of echo replies by `request_id` handles all N pipelined dispatches with no threads/epoll. `--profile core` = Result: PASS |
| A-ASM-015 | info | L2 | Native canonical-CBOR codec ports cleanly to asm (61/61); but F6 `bare_value` identity does NOT exercise key-sort — the vacuous-green trap |
| A-ASM-016 | info | L2 | f16 **subnormal input** decode is a documented reject-gap (no corpus vector) |
| A-ASM-017 | info | L2 | Full 71-vector ECF corpus green on native asm codec (crypto-only FFI, symbol-verified) |
| A-ASM-018 | info | L2 | Corpus `signature` vectors sign the entity's **ECF bytes**, NOT its content_hash (cf. §7.3) |

---

## A-ASM-001 — Assembler + link mode (decision, S1)

**Decision.** GAS (AT&T syntax, binutils `as`) over NASM: binutils is already in the
toolchain (zero new dependency), consistent with the ecosystem's minimal-dependency stance.
Link via the `cc`/gcc **driver** (crt0 + `__libc_start_main` initialize libc before the asm
`main`), not bare `ld` — the codec `.so` needs a fully-initialized libc, and driving startup
by hand from a bare `_start` is fragile for zero Level-1 benefit. `-no-pie` (absolute
addressing for `.bss`/`.data`; PIE/PIC is a later hardening). Static `.a` link and a
freestanding `_start` are documented Level-2 alternatives. Full rationale in
`arch/PROFILE-RATIONALE.md`. Non-blocking.

## A-ASM-002 — Agility (Ed448 / SHA-384) deferred (decision, S1)

**Decision.** The C-ABI exposes `ec_ed448_*` + `ec_sha384`, but agility is
validated-not-required and NOT in the `--profile core` floor (the whole cohort defers it).
Level-1 FFIs only the Ed25519 + SHA-256 floor. When agility enters scope it is a pure
additional FFI surface (no new asm logic — the same `call` pattern with the longer buffers).
Does not affect the conformance floor. Non-blocking.

## A-ASM-003 — Concurrency model (decision + S3 finding, staged)

**S1 decision.** Single-threaded `epoll` readiness loop over non-blocking sockets, not
`clone(2)` kernel threads + futex. Hand-managing thread stacks/TLS/futex in asm is
materially harder than an epoll loop, and `--profile core` needs interleaved progress (no
head-of-line blocking), not parallelism. `TCP_NODELAY` set (§7b).

**S3 finding (empirical, load-bearing).** A single-threaded **blocking** accept loop
**head-of-line blocks** under `validate-peer`: the oracle opens **concurrent / lingering**
connections (e.g. `handshake_replay_cross_connection` holds connection A open while probing
B; `tcp_connect` connects without sending). A blocking peer stuck in `read` on an idle
connection never accepts the next → the hello probe times out even though the hello
response itself is byte-correct (proven: works through a serializing tee-proxy, fails
direct). **The concurrency requirement is real even for the non-`concurrency` categories.**

**S3 stopgap (shipped).** `fork(2)` per accepted connection: each connection gets its own
process, so no head-of-line blocking. This unblocked the **stateless** hello path — 5
connectivity checks PASS. **Limitation:** fork gives each connection a private address
space, so a **shared store** (tree put on one connection visible to get on another;
revocations; registered handlers) is NOT yet shared. The **stateful** categories therefore
need the S1-intended model: single-process **epoll** with an in-process store, or
fork + `MAP_SHARED` store + a futex. Epoll is the plan (keeps the store trivially shared).
Staged: fork now (stateless categories green), epoll refit before the stateful ones.
Non-blocking on the phase.

## A-ASM-004 — Level-1 FFI still needs hand-rolled envelope/data-map CBOR (info, S1)

**Finding (generator-robustness, not a spec defect).** The intuitive reading of "Level 1 =
FFI the entire codec" is that no CBOR is hand-written. That is **false**: the C-ABI's unit
of decode/encode is the *entity* (`ec_decode_entity` → type+data+orig slices;
`ec_encode_ecf`; `ec_content_hash`), plus crypto/peer-id/base58/envelope-hash helpers. The
**envelope** map (`{root, included}`) and the EXECUTE/RESPONSE **`data`** map
(`{request_id, uri, operation, params, author, capability, resource}`) are bare
canonical-CBOR maps owned by the model layer — the FFI never decomposes them. So the asm
peer hand-rolls a minimal canonical-CBOR map **reader + writer** for that layer even at
Level 1: read head+argument, iterate map pairs, fetch value-by-text-key, read
text/bytes/uint/nested; emit uint/text/bytes/array-header/map-header. The hard canonical
parts (shortest-float ladder, recursive major-type-6 tag-reject, general length-then-lex
key sort) stay behind the FFI — the peer emits only small fixed-shape maps with keys
written in pre-sorted order. Documented so the next substrate/FFI peer scopes it correctly
(the same boundary applies to any FFI peer, but higher-level languages hide it inside their
model libraries; asm makes it explicit). Non-blocking; see
`arch/WIRE-SURFACE-REFERENCE.md` §"The Level-1 FFI boundary".

## A-ASM-006 — Type/handler bootstrap store is harvested byte-exact (decision, S3)

**Decision.** The `--profile core` `type_system` (400 checks / 199 type entities) and the
static `handlers` interface checks are served as `system/tree` **get** results from an
embedded read-only store (`src/typestore.s`, generated by `tools/gen-typestore.py` from
`reference/typestore/*.bin`). In a language peer the type registry is *rendered* by
reflecting over the peer's own data model (keystone "render natively, don't ingest bytes"
lesson); **assembly has no data model to reflect over**, so that lesson does not transfer —
the bootstrap entities are captured **byte-exact** from the reference `entity-peer` (oracle
`cc1970f`) through the frame-tee (`tools/teeproxy.c`), then embedded verbatim and re-served.
The store is `.rodata`, so it is shared across the fork-per-connection workers for free — no
epoll/shared-store refit is needed to serve read-only bootstrap entities (that refit is only
required for *mutable* cross-connection state: capability request/configure/revoke, tree
put, handler register).

**Caveat (ADR-0012).** Byte-harvesting from the reference is **cohort-consistent, not
independent** — it demonstrates the asm peer's transport + tree-get + canonical-response
machinery end-to-end, but the *type-definition bytes* are the Go reference's, not
independently derived. This is the sanctioned approach for a substrate with no model layer;
the independent signal lives in the transport/codec/handshake interior, not in the type
vocabulary. Non-blocking.

## A-ASM-007 — Unknown operations must respond, never drop (finding, S3)

**Finding (load-bearing).** A handler that silently returns without writing a response frame
does **not** merely fail the check — it makes `validate-peer` block on its per-operation
read deadline (~20 s observed for `capability` probes), which cascades into whole-suite
timeouts (a bare 60 s `-timeout` never finishes). The dispatch **catch-all** now emits a
`501 not_implemented` (echoing `request_id`) for every unrecognized operation, turning
multi-second hangs into sub-millisecond fast-fails and making the full `--profile core`
sweep run in ~350 ms. Side effect: probes the reference *honest-SKIPs* (e.g. some
`core_register_*`) become fast FAILs on this peer instead of allowlisted skips — an honest
trade (a fail we can see beats a hang we can't). Non-blocking.

## A-ASM-008 — Stack alignment before FFI calls (finding, S3)

**Finding.** SysV requires `%rsp ≡ 0 (mod 16)` at a `call` site (so the callee entry sees
`≡ 8`). A hand-authored non-leaf handler that reaches the codec FFI (`ec_content_hash` et al.
use aligned SSE) must therefore push an **odd** number of registers at entry (entry `%rsp ≡
8`; an odd push count restores `≡ 0` at its call sites). A handler that pushed nothing (or an
even count) silently faulted the FFI on a `movaps` — the child died with no response, which
presented as "get never answered". Caught for `serve_tree_get` (1 push) and
`check_hello_negotiation` (3 pushes). Non-blocking.

## A-ASM-009 — 32-bit sign in byte-diff compare (finding, S3)

**Finding.** `mcmp33` returns the first differing byte's signed difference in `%eax`
(`movzbl … ; sub`). A negative diff (e.g. `-199 = 0xFFFFFF39`) has bit 31 set, so
zero-extended into `%rax` it reads as a **large positive** value — a `test %rax,%rax; jle`
then makes the wrong canonical-sort swap decision for ~half of random hash byte-pairs. The
bug is *data-dependent*: it surfaced as an **intermittent** `encoding.ecf_key_ordering` fail
(the `included` map keys are content hashes that vary per run with the timestamp/nonce).
Fixed by testing the 32-bit `%eax`. Lesson: sign-test byte-diff results at their native
width. Non-blocking.

## A-ASM-010 — Over-cap frame must drain + 413, never close (finding, S3)

**Finding (load-bearing).** `conn_serve` originally **closed** the connection on any frame
over the 64 KiB bring-up cap (`ja .Lcs_done`). `--profile core` multiplexes many categories
onto one long-lived connection; a single legitimate **264 KiB tree-put** frame mid-stream
tore that connection down, and *every later probe on it* — all 6 `authz` checks + the
`peer_canonicalization` ones — then failed not on logic but with `write: broken pipe`. The
symptom (broken pipe, deterministic-in-full-run but absent standalone) masqueraded as a
concurrency bug and as authz logic bugs; it was neither. Fix: raise `b_req` to the 16 MiB
§9.1 payload cap so real frames are read and dispatched, and for a genuinely over-cap frame
**drain its body from the socket** (keep the stream framed) and answer `413
payload_too_large` while keeping the connection open (§4.10(a) "keeps serving"). Lesson: a
peer must never let one frame's size tear down a connection that carries others. Non-blocking.

## A-ASM-011 — Per-fork `.bss` state suffices for the core gate's stateful probes (finding, S3)

**Finding (re-scopes A-ASM-003).** The prior handoff framed the remaining stateful ops
(tree put→get, capability configure/revoke, handler register/unregister,
peer_canonicalization configure) as needing the epoll / `MAP_SHARED` + futex refit so state
is shared *across connections*. But `--profile core` runs those probes **on one
long-lived connection**, which is served by a **single fork** — so an in-process store in
`.bss` (private to that fork, but persistent across every frame of the connection) is
sufficient for the core gate. The cross-connection shared store is only needed for probes
that deliberately put on connection A and get on connection B (not in the `--profile core`
floor). This makes the write-op handlers materially cheaper than the staged A-ASM-003 refit
implied: a per-fork append store + `put`/`get`-from-store + `register`, no MAP_SHARED/epoll.
Non-blocking; re-scopes the next-pieces list.

## A-ASM-012 — Multisig accept needs full M3 structural validation (finding, S3)

**Finding.** The peer currently fail-closes every map-form (multi-granter) `granter` → 403,
which *passes* all 10 `multisig` **reject** probes for free. Adding the one **accept**
(`valid_2of3_peer_signed_accepted`) therefore cannot be a bare K-of-N signature count: it
must re-impose every §3.6 M3 rule the fail-closed path was implicitly enforcing, or those 10
rejects regress. Harvested reject shapes fix the rules precisely: reject `threshold == 0`,
`threshold == 1` (multisig threshold MUST be ≥ 2), `threshold > N`, `N == 1` (N MUST be ≥ 2),
duplicate signers; plus `non_null_parent` and `local_not_in_signers`. The accept is a 3-of-N
token with `threshold == 2`, distinct signers including the local peer, null parent, and
≥ threshold valid distinct-signer Ed25519 signatures over the token content_hash. Deferred:
self-contained but higher-risk than its 1-check payoff; do it with the reject corpus as a
regression harness. Non-blocking.

**Resolved (session 3).** Implemented as `verify_multisig_granter` — all M3 rules above +
K-of-N distinct-signer verification; the 10 rejects held while the valid 2-of-3 accepts.
multisig 11/11.

## A-ASM-013 — Handler dispatch entities + the §7a `--validate` scaffold boundary (finding, S3)

**Finding (dispatch entities).** The §6.2 handler-normalization checks
(`handler_{connect,tree,capability}_{dispatch_type,interface_ref}`) do **not** read the
interface entity at `system/handler/<pattern>`; they read a separate **dispatch** entity — a
bare `system/handler` entity `{interface:"system/handler/<pattern>"}` stored at the **bare
pattern path** (`system/tree`, `system/protocol/connect`, `system/capability`). Its `interface`
field is the `interface_ref` (N5); the absence of `expression_path` makes `dispatch_type` =
native (N2). A "pre-normalization peer" that serves only interface entities skips these. Fix:
seed the 3 built-in dispatch entities into the per-fork store at `conn_serve` start (they are
static and tiny; `.bss` is per-fork so there is no cross-connection accumulation). Closed all 6.

**`--validate` gate.** The two §7a checks — `validate_echo_dispatch` (§7a.1) and
`t1_2_concurrent_reentry` (§6.11 + §7a.2a) — both reported "target peer not run with
`--validate`" even though the peer *is*. The oracle's `--validate` detection is a **get of
`system/handler/system/validate/dispatch-outbound`**: our peer 404'd it (the earlier seed
published `system/validate/echo`, the wrong handler), so both skipped. Publishing the
dispatch-outbound handler interface (+ echo) flips the gate; `validate_echo_dispatch` then
passes on the existing verbatim `echo`.

## A-ASM-014 — §7a reentry is one-socket, single-thread-tractable (finding, S3 — corrects A-ASM-013)

**Correction.** A-ASM-013 (and PHASE-S3 draft) claimed `t1_2_concurrent_reentry` needed an
epoll/async refit a blocking fork peer can't provide. **Wrong.** The reentry round-trip is on
the SAME connection: the validator sends N (=8) `system/validate/dispatch-outbound` requests
(pipelined), and for each our peer must originate an outbound `echo` EXECUTE back to the target
peer — which *is the validator, acting as B*, on that same socket — then return the echoed value.

A single-threaded blocking fork handles this with **no threads and no epoll**: `conn_serve`/
`dispatch` route each inbound frame by its root type — a `system/protocol/execute/response`
frame is a reply to one of our outbound echoes, everything else is a request. `serve_dispatch_
outbound` builds+signs the echo EXECUTE (a 5-entry sorted `included`: our peer + our PoP
signature + the `reentry_capability`/`reentry_granter`/`reentry_cap_signature` handed to us in
`params`), writes it to the connection, and records `{echo_rid → dispatch_rid}` in a pending
table without replying. When the echo reply arrives, `handle_dispatch_response` matches its
`request_id` to the pending dispatch and emits the deferred 200. Because the validator sends all
8 dispatches before any echo reply, the frames arrive in a clean order the sequential loop
consumes directly; the pending table is the only state needed. Result: **`--profile core` =
Result: PASS, 583·0F**, matching the reference on every check it passes. The takeaway: "assembly
can't do X" is almost never the real constraint — the fork *architecture*'s apparent limit
dissolved once the reentry was seen as one-socket demux rather than cross-thread concurrency.

## A-ASM-015 — Native canonical-CBOR ports cleanly to asm; but bare_value identity ≠ key-sort coverage (info, L2)

**Finding (L2 discovery bet, positive).** The canonical-CBOR core — the part L1 kept behind
the FFI (A-ASM-004) — expresses byte-exactly in hand-written x86-64 asm. `src/codec.s`
implements the C-ABI F6 hook `ec_encode_bare_value` as a recursive-descent **transcoder**
(decode one value → re-derive canonical form → re-emit): RFC 8949 Rule 1 integer/length
minimization, the **Rule 4/4a shortest-float f16/f32/f64 ladder** (incl. NaN→`f97e00`,
±Inf→`f97c00`/`f9fc00`, ±0, and the 65503→f32 vs 65504→f16 boundary), definite-length only,
and a **recursive major-type-6 tag REJECT at every depth** (N2). Result: **61/61** of the
Class-A + tag_reject corpus (`make diff`), byte-identical to the 3-way-locked
(Go×Rust×Python) golden vectors. The float ladder — the single hardest canonical primitive —
went green on the first assemble. This retires the ISA-MAP's "can asm express the
canonical-CBOR invariants byte-exact?" for everything except key-sort (below).

**Honesty caveat (ADR-0012 + the "conformance-green can be vacuous" lesson).** The F6
`bare_value` differential is *identity-on-canonical-input*: it feeds each vector's already-
canonical golden bytes through decode+re-encode and checks the output reproduces them. That
rigorously exercises the ladder and minimization (a wrong choice diverges from golden), **but
it does NOT exercise length-then-lex map key SORTING** — the corpus `map_keys` inputs are
pre-sorted, so emitting map entries in input order passes them vacuously. M1 `codec.s`
therefore emits maps in **input order** and makes **no canonical-sort claim**. The sort is
load-bearing in the real ECF encoder (`ec_encode_ecf`/`ec_content_hash`), where
`content_hash.3`'s data map `{"z":1,"a":2,"bb":3,"aaa":4}` is UNSORTED and its golden hash is
over the canonical sorted form — that is the correct, non-vacuous place to implement + prove
the sort (next: M2, with the content_hash differential). Likewise `bare_value` does not
enforce minimal-head-on-*input* (non-canonical input isn't in this corpus). Non-blocking;
scopes M2.

## A-ASM-016 — f16 subnormal input decode is a documented reject-gap (info, L2)

**Finding.** `f16_to_f64` (decoding an input half-float to re-run the ladder) handles zero /
normal / ±Inf / NaN but **rejects f16 subnormals** (`EC_DECODE_ERROR`) rather than decode
them. No corpus vector is an f16 subnormal, so this is unobserved; a reject (not a silent
mis-decode) is the fail-safe. To be a fully general canonical encoder it must normalize
subnormals (bsr + shift); deferred to M1b with a synthetic vector. Non-blocking.

## A-ASM-017 — Full 71-vector ECF corpus green on the native asm codec (info, L2 — M2 complete)

**Result.** The **entire** ECF conformance corpus passes on the hand-written x86-64 asm codec,
with only Ed25519 + SHA-256 behind the FFI (the L2 boundary):

| Category | n | Native surface (asm) | FFI |
|---|---|---|---|
| float/int/map_keys/length/primitive/nested/envelope | 56 | `ec_encode_bare_value` transcoder | — |
| tag_reject | 5 | recursive major-6 reject | — |
| content_hash | 4 | `ec_content_hash{,_with_format}` = native ECF (sorted) + FFI sha256 | sha256 |
| peer_id | 3 | `ec_peerid_format` = native base58 + LEB128 varint | — |
| signature | 3 | native `ec_encode_ecf` (sorted) + FFI ed25519 sign | ed25519 |

Plus 4 synthetic unsorted→canonical vectors (key-sort proof). Run: `make diff` → 71 corpus +
4 synthetic, 0 FAIL.

**Non-vacuous (symbol-verified).** `codec.o` and `libentitycore_codec` both export
`ec_content_hash` / `ec_encode_ecf` / `ec_peerid_format`; `nm bin/diff` confirms these resolve
to **T** (our .o, linked first), while `ec_sha256` / `ec_ed25519_sign` are **U** (imported
from the .so). So the differential exercises OUR asm codec, not the library's — the base58,
canonical encode, and key-sort are genuinely under test. This is **corroboration** (ADR-0012):
a native transcode of the same canonical rules, cross-checked against the 3-way-locked corpus,
not an independent spec. **Not yet peer-integrated** (M3): the live peer still calls the FFI
codec; the CONFORMANCE-MATRIX gains an L2 row only when `run-s4.sh --profile core` is 0-FAIL on
the native-codec-linked peer.

## A-ASM-018 — Corpus signature vectors sign the ECF bytes, not the content_hash (info, L2)

**Finding (spec-clarity, surfaced by the differential).** The ECF corpus's `signature`
category signs the target entity's **canonical ECF bytes** — `ed25519_sign(seed, ECF({type,
data}))` — determined empirically (the golden 64-byte sigs matched signing the ECF, and did
**not** match signing the 33-byte content_hash nor the 32-byte digest; sign/verify round-trips
independently, isolating this to message choice). This is a **different construction** from the
*protocol* signature in `ENTITY-CORE-PROTOCOL.md` §7.3, which signs the **content_hash** ("Sign
full hash bytes: format code + digest") for authenticate/capability entities. Both are
legitimate — the corpus tests the lower-level "canonical-encode-then-sign" codec primitive; the
protocol wraps it over the content_hash — but an implementer reading only §7.3 and assuming
"signatures sign the content_hash" will fail the corpus `signature` vectors. signature.2's
unsorted data `{z:1,a:2}` additionally confirms the key-sort must reach the signed ECF (our
native sorted `ec_encode_ecf` matches; the FFI encoder fed unsorted data did not). Worth a
one-line spec note distinguishing the two signature constructions; flagged for arch review, not
a defect. Non-blocking.
