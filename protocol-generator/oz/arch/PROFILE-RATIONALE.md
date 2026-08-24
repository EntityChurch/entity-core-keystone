# entity-core-protocol-oz — profile rationale

Audit trail for the S1 profile choices. Peer target `oz` (Oz 3 / Mozart 2.0.1) —
the dataflow-variable concurrency probe, the fourth structural §7b shape.
S1 feasibility evidence: `research/evaluations/oz-io-viability.md` §S1 (2026-07-15,
GO); build plan: `docs/status/HANDOFF-2026-07-15-oz-io-s1-go.md`.

## Why the release RPM, not a source build

Mozart 2's source build is the risk the viability doc flagged (LLVM-based VM +
a Scala bootstrap compiler). S1 proved it never materializes: the 2018-09 release
RPM `mozart2-2.0.1-x86_64-linux.rpm` installs on fedora:43 via plain `dnf install`;
its only repo deps are glibc/libstdc++ basics + tcl/tk 8.6 (still packaged). tk
belongs to `ozwish` (the GUI) alone — `ozemulator`, which `oz`/`ozc`/`ozengine`
shell out to, links no tk and no boost. Pinned by SHA-256
(`d7b0fee5…ae04`), fetched fresh at image build, fail-closed on mismatch. At ~7.8
years old the S11 30-day cool-down is satisfied by years; upstream is dormant, so
the pin is effectively permanent.

## Codec strategy: hand-rolled canonical CBOR in pure Oz + co-process crypto

**CBOR native.** No Oz CBOR library exists (the A-005 pattern, unbroken). Even if
one did, no platform CBOR lib gives ECF's canonical guarantees (the durable
cross-language lesson) — the canonical layer is hand-written everywhere. Oz's
substrate is *good* at this: integers are arbitrary-precision (verified live at
S1: `2^63 + (2^64-1)` exact; re-asserted in every image build by the GO-gate
self-test), so the CBOR integer tower and the uint64 boundary are free — no
head-form fixed-width trap, no head-form self-test tax beyond the baked GO-gate
probe. Bytes travel as lists of ints 0..255, the native currency of
`Open.socket`/`Open.pipe`, both proven byte-clean incl 0x00/0xFF.

**Floats as bit patterns (A-OZ-002).** Mozart has no primitive to view a float's
IEEE bits, and its float exception/rounding semantics for inf/NaN are untested
territory. Instead of probing them, the codec *never does float arithmetic on the
wire path*: a decoded mt7 value is carried in the tagged rep as its exact IEEE-754
bit pattern (a bignum int), and the shortest-form ladder (f64→f32→f16
representability) plus NaN/inf handling are pure integer bit logic —
dropped-mantissa-zero checks and exponent-range checks via div/mod arithmetic
(Mozart has no bitwise integer operators; div/mod on bignums is exact). This is
the Rexx A-RX-002 lesson made cheaper: Rexx had to *reach* IEEE bits from decimal
values; Oz just refuses to leave the bit domain at all. Core protocol logic never
needs a float's numeric value.

**Crypto via the `entity-codec-daemon` co-process.** Mozart ships zero crypto and
the RPM ships zero headers, so the native-functor C++ FFI route would demand the
full source build we avoided. The seam is a small C co-process
(`src/daemon/eccodecd.c`) linking `libentitycore_codec`, spawned by the peer via
`Open.pipe` and spoken to over stdin/stdout. The command vocabulary is Rexx
`ecnet`'s crypto subset (SHA256/SHA384/PUB/SIGN/VERIFY + ED448 variants + NOW +
RND), re-framed: `ecnet` armored payloads as hex over FIFOs because Regina's FIFO
line reads lose bytes; `Open.pipe` is byte-exact (S1-proven), so the daemon speaks
binary length-prefixed frames instead (documented once in
`src/daemon/DAEMON-PROTOCOL.md` as the entity-codec-daemon convention). Unlike
`ecnet` the daemon owns **no sockets** — Oz listens natively; delegating the
transport would forfeit the paradigm axis (the wrapper-guard, applied to
concurrency instead of visuals).

**NOW/RND through the daemon.** Oz's `Time.time` is second-granular; A-PD-016
made ms-precision mint timestamps a *correctness* parameter (same-second
same-scope mints alias content hashes → revoke kills the session cap). The daemon
serves `NOW` from `clock_gettime(CLOCK_REALTIME)` in ms, and `RND` from
/dev/urandom for keygen.

## Concurrency: dataflow-thread-per-connection + port agents

The paradigm bet, stated so S4 can falsify it:

- **§6.11 demux is a dataflow variable.** A handler-originated outbound request
  registers `ReqId → V` (V unbound) and the worker `{Wait V}`s; the connection's
  reader thread binds V when the correlated EXECUTE_RESPONSE arrives. Out-of-order
  replies need nothing extra — each reply binds its own variable. The demux
  machinery every thread/async peer paid for (the correlation-map tax) collapses
  into the variable itself.
- **§4.8 store-safety is NOT free on this substrate** — dataflow variables
  synchronize producers with consumers, not mutators with each other. Shared
  mutable state (content store, grant/revocation table, connection registry,
  per-connection write queue, the daemon pipe) is each owned by a **port agent**:
  `{NewPort Stream}` + one consumer thread folding state over the stream, requests
  carrying dataflow variables for replies. That is actor-shape serialization built
  from the dataflow primitives themselves (a port's stream is a dataflow list).
  The peer uses **no locks** (Oz has them; the probe is that dataflow + ports
  suffice).
- **Blocking I/O discipline (§7b).** Mozart VM threads are preemptive and
  lightweight; each blocking read sits in its own thread (one reader per
  connection, one daemon agent), so there is no bounded cooperative pool to starve
  (the Swift lesson does not transfer). The S1 watch-item — `Open.pipe` blocking
  under concurrent handler outbound + t2_2 connection churn — is tested early at
  S4 by design.
- **TCP_NODELAY is unavailable** (A-OZ-003): `Open.socket` exposes no setsockopt
  surface and the RPM ships no headers to add one. Logged, not silenced; on the
  in-container loopback conformance run Nagle never engages (no delayed-ACK
  interaction at loopback RTT). The §7b menu item is recorded as
  substrate-unreachable.

## Error model, naming, layout

Native Oz exceptions (`try/catch` on record values) — the codec raises
`entityCore(kind:… detail:…)` records, caught at the request boundary and mapped
to §6.12/§5.2 status envelopes, fail-closed. Naming follows the language's own
rules (uppercase-initial variables/procedures, lowercase atoms) and the CTM/
library style: one functor per file, records as the aggregate unit, tagged records
for wire values (`int(N) float64(Bits) bytes(L) text(L) arr(L) map(Pairs) bool(B)
null` + the `absent` atom — Oz strings are char-code lists indistinguishable from
byte lists, so mt2-vs-mt3 intent is explicit in the rep, the Tcl/Rexx lesson).

## Testing / publishing

No living Oz test framework or package registry exists (MOGUL is defunct) — the
hand-rolled-harness + git-tarball pattern (Rexx/COBOL precedent). Conformance is
the corpus + the oracles, per the standard.
