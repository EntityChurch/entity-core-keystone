# entity-core-protocol-rexx — Spec Ambiguity Log

Per PROMPT-CONSTANTS: every guess is logged here, no silent guesses. `A-RX-NNN`.
Severity: **blocking** (stops a phase) / **non-blocking** (proceed with a flagged
best-guess) / **finding** (candidate spec-precision issue → arch).

Status at end of S1: **no blocking items.** The number-model probes (A-RX-001/002/003)
are the reason this peer exists — carried into S2 as the things to prove. Library +
substrate confirmations (A-RX-005/008) were resolved at the S1 container build.

---

## A-RX-001: integer tower on a decimal substrate (native big-endian, FREE uint64)

**V8 section:** ENTITY-CBOR-ENCODING §major-types 0/1 (int), §head minimal-argument
**Profile field:** `[idiom] int_is_decimal_native`, `[codec] numeric_model`
**Your guess (CONFIRMED at S1):** `D2C(n, len)` produces an len-byte BIG-ENDIAN
character string (network order — free), and `C2D(bytes)` decodes to an exact decimal
integer. With `NUMERIC DIGITS 40` the full uint64 boundary `[2^63, 2^64-1]` is exact
(no fixed-width trap), reached via DECIMAL bignum (vs Tcl/Python platform bignum, vs
C#/Zig fixed-width). Verified in-container: `2**64-1` → `FFFFFFFFFFFFFFFF` → round-trip.
**Escalation:** **operator — RESOLVED at S1.** No spec question; a clean native mapping.

## A-RX-002: NO binary float type — every IEEE bit hand-computed in decimal (THE PROBE)

**V8 section:** ENTITY-CBOR-ENCODING §float shortest-form ladder (f16/f32/f64), §mt7
**Profile field:** `[idiom] no_binary_float_type`, `[codec] cbor_library`
**Your guess:** Rexx has NO IEEE float type and NO built-in to read/write IEEE bits
(unlike EVERY prior peer, incl. Tcl's `binary format R/Q`). The encoder computes
sign / biased-exponent / 52|23|10-bit mantissa from a decimal value using decimal
arithmetic (`*2**k`, integer division, `D2C`), lays the bytes big-endian, and the
decoder inverts (`C2D` the fields → reconstruct the decimal value via `mantissa *
2**(exp)` with `NUMERIC DIGITS` high enough). The shortest-float ladder (does this
value round-trip through f16/f32 exactly?) is decided by an exact decimal comparison.
The half-float leg has no shortcut (as everywhere). This is the deepest hand-roll in
the cohort.
**Escalation:** **finding-candidate** — S2 proves whether the spec's float determinism
(shortest-form selection, canonical NaN 0x7e00, ±Inf, ±0) is exactly reproducible from
a decimal base, or whether any float vector is under-specified in a way that a
decimal↔IEEE peer surfaces (e.g. a value whose shortest-form is ambiguous without a
stated rounding mode). Expected: tight; peer computes the bits exactly. THE probe.

## A-RX-003: int-vs-float intent (numeric shimmer, decimal edition)

**V8 section:** ENTITY-CBOR-ENCODING §mt0/1 (int) vs §mt7 (float)
**Profile field:** `[idiom] numeric_intent_seam`
**Your guess:** The peer marks int-vs-float intent EXPLICITLY at value construction (a
tagged rep, as Tcl), and NEVER infers the major type from the string form.
`DATATYPE(x,'W')` classifies the STRING as a whole number, but "1" and "1.0" are both
numerically integral and the spec-intended type is a field property, not a value
property. Same root as A-TCL-003 but on a decimal tower.
**Escalation:** **finding-candidate** — as A-RX-002; S2 confirms every numeric core
field's int-vs-float kind is spec-fixed. Expected: tight; peer carries intent.

## A-RX-004: byte-string-native — LENGTH is byte length (NO char-vs-byte trap)

**V8 section:** ENTITY-CBOR-ENCODING §byte (mt2) / text (mt3) strings
**Profile field:** `[idiom] byte_string_native`
**Your guess (CONFIRMED at S1):** A Regina string IS a byte string (byte-oriented, no
Unicode type), so `LENGTH` already returns the wire BYTE count — the A-TCL-002
char-length trap does NOT arise here. byte-vs-text (mt2 vs mt3) INTENT is still carried
explicitly in the tagged rep (a string alone cannot say which major type). Verified:
`LENGTH("hello") = 5`.
**Escalation:** **operator — RESOLVED at S1** on the length seam; the byte-vs-text tag
is the same explicit-tag discipline as Tcl (no side-channel).

## A-RX-005: crypto via a C external-function extension (no native Rexx crypto)

**V8 section:** §9.1 crypto floor (Ed25519 + SHA-256)
**Profile field:** `[codec] ed25519_library`, `[layout] ffi_binding`
**Your guess (CONFIRMED at S1):** Regina has no crypto. Bind `libentitycore_codec` via
a C external-function extension using Regina's SAA API (`rexxsaa.h`, present per
regina-rexx-devel), exposing `ec_sha256/384` + `ec_ed25519_{seed_to_pubkey,sign,verify}`
as Rexx functions (`rxfuncadd`-loaded). Same FFI-hybrid shape as COBOL/Tcl.
**Escalation:** **research — S2 build gate.** The C-ext compile + `rxfuncadd` load + a
KAT is the S2 confirm.

## A-RX-006: f16 half-float leg (hand-rolled bit arithmetic on decimals)

**V8 section:** ENTITY-CBOR-ENCODING §float ladder (f16/f32/f64)
**Profile field:** `[idiom] d2c_c2d_codec`
**Your guess:** No format helper for any width; f16/f32/f64 are ALL hand-rolled from
decimal (A-RX-002). There is no left-shift operator — use `*2**k` / `X2D`/`D2X` +
`BITAND`/`BITOR`. Subnormals + the shortest-form minimization are decimal decisions.
**Escalation:** **operator — local decision.** Verified by the `float` test vectors at
S2 (the highest-value S2 spike, harder than Tcl's since even f32/f64 are hand-rolled).

## A-RX-007: empty string cannot be the "absent" sentinel

**V8 section:** n/a (representation)
**Profile field:** `[error_model] absent_sentinel`, `[idiom] empty_string_trap`
**Your guess:** Absence is a tagged marker; a present value is always a non-empty
tagged list/stem. The empty string is a legitimate wire value (empty mt2/mt3), so it
cannot double as absent (same resolution as Tcl A-TCL-007 — the tag carries presence).
**Escalation:** **operator — local decision.**

## A-RX-008: RxSock NOT packaged with fedora Regina → sockets via the C ext (RESOLVED)

**V8 section:** §8 transport (TCP), §4.8 concurrency
**Profile field:** `[async] socket_source`, `[deps] regina`
**Your guess → RESOLVED at S1 (pivot):** The S1 plan assumed Regina's RxSock library
for TCP. The container build DISPROVED it: fedora:43 `regina-rexx` ships only RexxUtil
(`libregutil`) + `librxtest*`; `rxfuncadd 'SockLoadFuncs','rxsock',…` → rc 60, and
`find` shows no `librxsock`. **Resolution:** fold BSD sockets into the SAME C
external-function extension that carries crypto (the COBOL `netshim.c` pattern) —
`EcNetListen/Accept/Connect/Send/Recv/Select/Close/Nodelay` as Regina external
functions. One C ext = crypto + net. Cleaner than a missing dependency; the peer's
single-threaded `EcNetSelect` loop gives structural §7b store-safety.
**Escalation:** **research — RESOLVED at S1 container build.** The C-ext socket path is
confirmed at S3 (a two-peer loopback).

---

## S2 resolutions (2026-07-11)

Recorded as the S2 codec ran to full-corpus green (69/69; container
`rexx-toolchain:latest`, Regina 3.9.6).

- **A-RX-002 (no binary float — THE probe) — CLOSED as corroboration.** The
  decimal-only substrate encodes/decodes every IEEE float vector exactly (14/14): the
  f16/f32/f64 shortest-float ladder, canonical NaN 0x7e00, ±Inf, ±0 are all computed
  in decimal arithmetic (`%`=shift-right, `//`=mask, `*2**k`=shift-left, `D2C`), and
  the codec round-trip stays in IEEE-bit-space (a decoded float is stored as its f64
  pattern; encode narrows). No spec-precision finding — the deepest hand-roll in the
  cohort holds. A-RX-001 (native big-endian int, free uint64) and A-RX-003 (int-vs-
  float intent carried explicitly) close likewise.
- **A-RX-005 — RESOLVED (pivot to a helper binary).** fedora Regina 3.9.6 does NOT
  load a dynamic external-function library via `rxfuncadd` (rc 60 even for the
  built-in `regutil`; `strace` shows no dlopen). But `ADDRESS SYSTEM cmd WITH INPUT
  STEM / OUTPUT STEM` works. So crypto crosses the C-ABI via a standalone `eccrypto`
  helper binary over a hex stem-pipe (line-oriented hex is binary-safe) — still
  FFI-hybrid, at the process boundary. The SAA C-extension (`entitycore_rexx.c`) was
  written first and discarded when `rxfuncadd` proved non-functional.

### Banked Regina lessons (durable — carry to any future Rexx work)

- **A-RX-009: no EXPRESSION subscripts.** A compound-variable tail must be a plain
  symbol: `idx.j` works, `idx.(j-1)` does NOT — Regina mis-parses the assignment as a
  shell COMMAND (`IDX.: command not found`), silently corrupting the value. Compute the
  tail into a variable first (`jm = j - 1; idx.jm`). (Cost us the map-sort on the first
  spike run.)
- **A-RX-010: SYNTAX does not propagate across a CALL.** Regina catches a SYNTAX
  condition only in the SAME routine that raised it (or, for an untrapped one, at the
  MAIN program level) — a caller's `SIGNAL ON SYNTAX` does NOT trap a syntax raised in
  a callee (an untrapped callee syntax is effectively swallowed and the caller
  continues). So the codec reject/unwind is the classic-Rexx **RC-flag** (`EC.!OK`
  checked at each recursion/consume boundary), NOT an exception. This also means the
  S3 dispatch maps a codec reject by testing `EC.!OK`, not by trapping — simpler.
- **A-RX-008 UPDATE (S3 socket plan).** Since `rxfuncadd` is dead (A-RX-005), the S3
  transport cannot be a C external-function ext either. A per-invocation helper binary
  can't hold a persistent listening socket + per-connection state across calls. So S3
  sockets use a **persistent `ecnet` co-process daemon** that owns the real sockets +
  the `select()` loop, driven by the Rexx peer over two named pipes (FIFOs): the peer
  `charout`s commands (listen/send/close) and `linein`s events (accept/data/closed) —
  Regina does stream I/O to FIFOs natively. C owns I/O + select; Rexx owns the protocol
  brain. The single Rexx thread + the daemon's select give structural §7b store-safety.

## S3 resolutions (2026-07-11)

Recorded as the S3 peer machinery ran to green (self-test 31/31, two-peer loopback smoke
8/8; container `rexx-toolchain:latest`, Regina 3.9.6). The peer machinery itself is a
faithful port of the language-agnostic protocol layers (§5 capability, §6.5 dispatch,
§6.9 bootstrap, the MUST handlers) — now proven a third time (after Tcl/COBOL). All the
S3 friction, and the durable findings, are in the TRANSPORT.

- **A-RX-008 — CLOSED (the co-process daemon is proven).** `ext/ecnet.c` owns the
  sockets + `select()` + §1.6 de-framing; the Rexx peer drives it over the two FIFOs.
  Two non-obvious corrections were required to make it robust, each banked below.

## A-RX-011: `ADDRESS SYSTEM` fork/exec CORRUPTS an open Regina FIFO read (THE finding)

**V8 section:** §8 transport / §9.1 crypto (impl-substrate interaction, not a spec defect)
**Severity:** finding — durable Regina lesson, resolved at S3.
**What happened:** with the evt FIFO open for reading, ANY `ADDRESS SYSTEM` — even a bare
`address system 'true'`, and both the `WITH INPUT/OUTPUT STEM` form and a plain redirect
— **desyncs Regina's FIFO read buffer**: the next read returns payload bytes as if they
were a fresh length/line, and framing is lost from there on. Confirmed with a minimal
harness (a C writer + a Regina reader that does an `ADDRESS SYSTEM` between exact-count
reads → desync; remove the `ADDRESS SYSTEM` → 100% clean). The mechanism is that Regina
flushes/repositions its open streams around a subprocess spawn, and a FIFO is not
seekable → the buffered-but-unconsumed bytes are dropped.
**Consequence:** the S2/COBOL-shape **eccrypto subprocess crypto is incompatible with the
FIFO transport** — the peer cannot spawn the crypto helper while it is serving.
**Resolution:** **fold the §9.1 crypto INTO the `ecnet` daemon** (it links
`libentitycore_codec`). The networked peer's SHA/Ed25519/now/random cross the C-ABI over
the SAME cmd/evt FIFO channel — a `SHA256`/`SIGN`/`VERIFY`/`NOW`/`RND` command answered by
an `R <hex>` event, which the crypto call demuxes out of the event stream (deferring any
interleaved network `FRAME`/`ACCEPT`/`CLOSED` events to `EC.!EVQ` for the main pump). No
subprocess spawn ever happens while the FIFO is open. The OFFLINE code paths (the S2 codec
conformance + the S3 foundation self-test) do NOT open a FIFO, so `ADDRESS SYSTEM` is safe
there — they keep the eccrypto helper via a `EC.!CRYPTO_VIA = helper|daemon` mode switch.
**Escalation:** operator — RESOLVED at S3. A pure impl-substrate lesson (no spec question);
the highest-signal transport finding in the cohort, unique to a peer whose C bridge is a
subprocess rather than a linked extension.

### Banked S3 transport lessons (durable — carry to any Rexx co-process work)

- **A-RX-012: the daemon must be FULLY non-blocking on every write.** A blocking event
  write + a blocking command read deadlock both processes when both FIFOs fill during a
  burst. The daemon keeps an outbound queue for the evt FIFO AND a per-connection output
  queue for each socket, both drained only on `select` write-readiness (sockets set
  `O_NONBLOCK`); it never blocks anywhere → deadlock-free.
- **A-RX-013: Regina FIFO reads lose data; read EXACT byte counts, not lines.** Both
  `linein` and char-at-a-time `charin` drop bytes across a pipe-read boundary under load.
  Frame the daemon→peer channel as `<8-hex-len><bytes>` and read it with a
  `charin(stream,,N)` loop (a single large `charin(,,N)` can still short-read, so loop
  until exactly N). Exact-count reads are reliable; newline-delimited reads are not.

## S4 resolutions (2026-07-11)

Recorded as the S4 conformance gate ran to green (`--profile core` **682·0F @ cc1970f**:
291P/295W/0F/96S, 0 fail-counting skips; origination-core 3/3). The peer machinery was
correct on a fresh peer from the first run — every category passes in isolation. The real
S4 work was **resilience under sustained load** (the §4.9/§4.10 watch-items), which surfaced
one genuine, spec-relevant finding.

## A-RX-014: a core peer MUST NOT persist inbound request-auth signatures (unbounded)

**V8 section:** §4.9 / §4.10 (resource bounds) — spec-relevant finding + impl fix.
**Severity:** finding — a resource-exhaustion vector; escalate to arch.
**What happened:** `_ingest_signatures` (peer.rex), run on EVERY inbound envelope during
dispatch, both `Store_PutEntity`'d the `system/signature` entity AND `Store_Bind`'d it at
`/{signer_pid}/system/signature/{targethex}`. A request signature is **unique per request**
(a fresh `request_id` → fresh signed bytes → fresh content hash), so this grew the content
store AND the tree path list (`EC.!SPATHS`) by one **per inbound request** — growth driven
purely by request traffic, with no bound. Two failure modes under the `t2_1` 10 000-request
sustained flood: (1) the peer ballooned ~6 MB → ~117 MB; (2) `Store_Listing` walks `SPATHS`
via `Lst_Item` (O(i) each = **O(n²)** over the accreting list), so once `SPATHS` held 10 000+
paths every later listing-touching op (`universal_address_space` foreign-namespace listing,
`peer_canonicalization`, and the tail categories) hung for the full 20 s per-request cap —
which looked like a whole-peer wedge but was per-op.
**Resolution:** ingest only the signer **peer** entities (bounded — distinct peers dedup by
content hash; chain resolution `Cap_ResolveGranterPeerId` may fall back to the store for
them). Do NOT persist or tree-bind the per-request signature entities: `Cap_VerifyRequest`
verifies signatures straight from the envelope's `included`, never from the store, so
nothing is lost. Post-fix the store/tree no longer grow with request volume, the O(n²)
listing disappears, and the full run dropped 8m34s → 3m40s.
**Escalation:** **arch** — the spec should state explicitly (under §4.9/§4.10) that inbound
request/capability authentication signatures are verified-and-discarded, NOT persisted into
the queryable signature tree; only explicitly PUBLISHED signatures (via tree.put) are
retained. An implementer following "ingest signatures so they're resolvable" naively
persists request-traffic ephemera — a DoS amplifier. (Latent adjacent item, not fixed:
`Store_Listing`'s O(n²) `Lst_Item` walk is fine at conformance path counts but should become
an indexed/stem walk before large trees — noted, YAGNI for the gate.)

### Banked S4 lessons (durable)

- **§4.10(c) admission: a hard connection cap == the flood size is the worst outcome.** The
  daemon's `EC_MAXCONN` was 256, exactly the `r3_connection_flood` burst → the daemon
  accepted all 256 then hard-closed the 257th keep-serving probe = the oracle's
  "accepted-all-then-fell-over" FAIL. Raising it to **512** (> flood + probe; < FD_SETSIZE
  1024; per-conn buffers malloc'd lazily) makes the peer keep serving → the §4.10(c) SHOULD
  scores **external-delegation WARN** (not gated). A hard cap can never reach the PASS
  (self-bounded-and-keeps-serving) outcome because the flood holds every slot during the
  probe — external delegation is the reachable clean result for a fixed-cap daemon.
- **The FIFO co-process makes this the cohort's slowest peer; `-timeout` is the knob.** Every
  §9.1 crypto op crosses a FIFO (A-RX-011: no in-process shim), ~17 ms/request. The default
  60 s oracle budget is eaten by `concurrency` (10 000 requests) alone. Set `-timeout 10m`
  (dart uses 5m, prolog 180s for the same reason). The test explicitly gates on the 20 s
  per-request cap, not wall-clock — "a slow language passes by being correct."
- **`EC.!EVQ` must be an O(1) queue.** The deferred-event queue was a packed-list (O(n) per
  op); rebuilt as a head/tail stem ring. Not the wedge root cause but a real burst hazard.
- **Regina nests `/* */` comments — comment TEXT must not contain a literal `/*`.** A header
  comment mentioning `system/validate/*` opened an unterminated NESTED comment that swallowed
  code and surfaced as an "unmatched quote" error thousands of lines downstream in the
  concatenated program. (Cost one debug cycle on `bin/peer.rex`.)
- **Debugging hygiene: run the gate ALONE.** A concurrent second heavy podman container (an
  orphaned build stuck 2 h) starved a peer-under-test into 20 s timeouts indistinguishable
  from a real wedge. `podman ps` for orphans before trusting a wedge; the single-container
  repro is ground truth.
