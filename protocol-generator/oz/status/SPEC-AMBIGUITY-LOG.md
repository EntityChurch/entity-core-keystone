# entity-core-protocol-oz — spec-ambiguity log

Per PROMPT-CONSTANTS: every unauthorized guess lands here. Prefix `A-OZ-…`.
Severity: 🟢 resolved/benign · 🟡 open, non-blocking · 🔺 arch-worthy.

## A-OZ-001 🟢 — Oz integers are bignum: the uint64 head-form boundary is free

**V7 section:** §1 integer tower / head forms
**Profile field:** `[codec] numeric_model`
**Resolution:** verified live at S1 and re-asserted in every mozart-toolchain
image build (GO-gate self-test): `2^63 + (2^64-1) = 27670116110564327423` exact,
`(2^64-1)+1 = 2^64` exact. Oz is in the bignum class (Elixir/Python/Ruby row of
the durable lesson) — the full `[2^63, 2^64-1]` range carries with no fixed-width
artifact. No per-run self-test tax; the image build carries the probe.

## A-OZ-002 🟢 — floats carried as IEEE bit patterns; no VM float arithmetic on the wire path

**V7 section:** §1 float tower (mt7 f16/f32/f64, shortest-form ladder)
**Profile field:** `[idiom] float_as_bits`
**Your guess:** the tagged value rep carries mt7 values as their exact 64-bit
IEEE-754 pattern (a bignum int), never as an Oz float. Encode/decode + the
f64→f32→f16 shortest-form ladder + NaN/inf canonicalization are pure integer
bit logic (div/mod arithmetic — Mozart has no bitwise ops).
**Rationale:** Mozart exposes no float-bits primitive and its inf/NaN semantics
are unprobed; core protocol logic never needs a float's numeric value, so
refusing to leave the bit domain removes an entire trap class (the Rexx A-RX-002
hand-roll, minus the decimal↔binary conversion risk).
**Escalation:** none — local design decision, conformance-gated.

## A-OZ-003 🟡 — TCP_NODELAY unreachable from Open.socket (§7b menu item)

**V7 section:** §7b transport menu ("set TCP_NODELAY on raw-socket peers")
**Profile field:** `[async] tcp_nodelay`
**Your guess:** run without it; document as substrate-unreachable.
**Rationale:** `Open.socket` exposes no setsockopt surface; the RPM ships no
headers so a native-functor shim would demand the full source build S1 rejected.
Moving the socket into the co-process daemon to gain setsockopt would forfeit the
paradigm axis (native Oz transport). On the sealed in-container loopback used for
conformance, Nagle has nothing to delay (no MTU-size writes, loopback RTT ≈ 0);
S4 empirically confirms latency-sensitive categories (concurrency t2_*) pass.
**Escalation:** research — a profile-field candidate ("tcp_nodelay:
unavailable-in-runtime" as a legitimate value for VM-sealed substrates; precedent
for any future peer whose runtime hides the socket).

## A-OZ-004 🟢 — daemon framing: binary length-prefix replaces ecnet's hex-over-FIFO

**V7 section:** absent (implementation seam)
**Profile field:** `[codec] strategy` (ffi-hybrid-coprocess)
**Your guess:** the entity-codec-daemon speaks binary frames over stdin/stdout
(`op:u8 ‖ len:u32be ‖ payload`, reply `status:u8 ‖ len:u32be ‖ payload`), one
reply per request in order; vocabulary = ecnet's crypto subset + NOW + RND.
**Rationale:** ecnet's hex-over-FIFO armor existed because Regina's FIFO line
reads lose bytes across pipe-read boundaries (A-RX-011); Open.pipe is byte-exact
(S1-proven), so the armor is pure overhead here. Vocabulary kept 1:1 with ecnet
so the convention stays one family. Documented in src/daemon/DAEMON-PROTOCOL.md.
**Escalation:** research — DAEMON-PROTOCOL.md is the reusable convention doc the
handoff asked for ("design once, document as the entity-codec-daemon convention").

## A-OZ-005 🟢 — Oz: the empty string `""` IS `nil`; two S3 bugs, both crash-class

**V7 section:** n/a (substrate finding — a durable Oz lesson, not a spec gap)
**Profile field:** n/a
**Finding:** in Oz an empty char-list `""` is literally `nil` — the same value as
the empty list. Two distinct S3 dispatch bugs both traced to this:

1. **§6.6 resolution dropped the leading slash.** `resolve_handler` split an
   absolute path `/{peer}/system/tree` into segments `["", "{peer}", "system",
   "tree"]` and rebuilt prefixes with a fold whose "first element" sentinel was
   `Acc == nil`. The first *real* segment (`""`, the part before the leading `/`)
   IS `nil`, so the sentinel never advanced and the leading `/` was silently
   dropped — every prefix lookup missed and EVERY authenticated dispatch returned
   `404 handler_not_found`. Fix: seed the fold with the head segment and append
   `/‖S` for the tail (never test a segment for `== nil`).
2. **A root/empty-target listing hung the request 20s.** `system/tree:get` with an
   empty resource target (`""`, the universal-root listing) hit `{List.last ""}`
   = `{List.last nil}`, which *raises* — and the raise was not `entityCore`, so it
   escaped the dispatcher's narrow catch, killed the worker thread, and left the
   request unanswered until the oracle's 20s deadline (which then cascaded into a
   budget-exhaustion failure of every later category). Fix: guard empty/`"/"`
   targets as root listings BEFORE any `List.last`, AND broaden the dispatcher's
   catch to `[] _ then 500` so no bug can ever silently drop a request (§4.9(c)).

**Durable lesson:** on a substrate where `"" == nil`, (a) never use `== nil` as a
"first iteration"/"no value yet" sentinel over string data, and (b) a request
dispatcher MUST catch *all* exceptions (not just the codec's own condition family)
and map to 500 — an uncaught host-language exception in a per-request worker thread
is indistinguishable from a hang and violates deliver-or-signal. Both are generator-
robustness findings (they'd bite any future list-substrate peer), not spec defects.
**Escalation:** research — candidate SUBSTRATE-TAKEAWAYS note (list-substrate
sentinel + dispatcher catch-all).

## A-OZ-006 🟢 — §6.11 reentry on a dataflow substrate needs no correlation pump

**V7 section:** §6.11 transport reentry contract
**Profile field:** `[async] request_demux` / `dataflow_demux`
**Outcome (the paradigm claim, validated):** the S1 watch-item — "Open.pipe
blocking under concurrent handler outbound + t2_2 connection churn" — resolved
cleanly. The demux collapses into a **single dataflow variable per pending
request**: the reader thread reads ALL frames on a connection and routes them
(response frames bind the pending var; request frames each dispatch in their OWN
worker thread), so a handler that originates an outbound EXECUTE (§6.13(b)) just
`{Send Writer …}` then `{Wait Var}` — the reader binds `Var` when the correlated
`EXECUTE_RESPONSE` arrives, and never blocks on dispatch, so reentry cannot
deadlock. concurrency t1_2 (M=8 reentry), t2_1 (sustained load), t2_2 (churn, 4.6s)
and origination `dispatch_outbound_reentry` all PASS. The correlation-map tax the
thread/async peers pay (and the serial-drain yield the single-threaded reactive
peers pay — Pd/Scratch) is **absent** here: the variable IS the demux. This is the
distinct §7b data point Oz was built to produce.
**Escalation:** none — the fourth §7b shape's payoff, recorded for
SUBSTRATE-TAKEAWAYS.

## A-OZ-007 🟢 — unsupported key_type detected from the peer_id varint prefix (AGILITY-UNKNOWN-1)

**V7 section:** §4.6 (SHOULD reject unknown key_type with 400) / §4.5 negotiation
**Profile field:** n/a (cohort-settled trap, re-confirmed here)
**Finding:** the oracle's AGILITY-UNKNOWN-1 presents an `authenticate` whose
`key_type` *string* is unremarkable but whose claimed `peer_id` carries an
unsupported `key_type` (0xFD) in its LEB128 varint prefix. Deriving the expected
peer_id from the public key assuming Ed25519 and comparing yields `401
identity_mismatch` — but the spec wants `400 unsupported_key_type`. Fix: decode the
claimed peer_id's varint `key_type` (Peerid.parse) and treat any value ≠ 0x01 as an
unsupported key_type (the Rexx A-RX precedent). **Escalation:** none — settled.
