# RT-13b Part-B / RT-13a — cohort write-concurrency class declarations

**Date:** 2026-07-27 · **Owner:** keystone (this is the grading seam arch assigned us) ·
**Bar:** `entity-system-architecture/docs/status/VECTOR-SPEC-2026-07-27-RT-13b-frame-write-atomicity.md` §4.1
**Read at pins:** keystone `fc445a8`+ · `entity-core-protocol` `c32d2c5` · `entity-core-go` `af8a582`

Arch's §4.1 pins a graded per-class bar (R / M / S) and gives keystone one uniform check with
teeth: **verify the declared class matches the peer's actual write-concurrency model**, so a peer
cannot declare the cheap class to dodge the stress test. This file is that verification for the
generated cohort — the declaration and the check in one place, because keystone is both the peer
author and the grader here and separating them would be theatre.

> **Axis note.** This covers keystone's **generated cohort** only. The ground-up trio
> (`entity-core-{go,rust,py}`) is a different axis with its own Part-B artifacts; the classes below
> say nothing about them, and a same-language row here is a different codebase that merely shares a
> language name.

## Method — how the class was determined (not asserted)

For each peer, two questions, answered from source rather than from the profile's self-description:

1. **Are frame writes reachable from ≥2 concurrent contexts?** Evidence = the presence (or
   structural absence) of a per-connection write-serialization primitive in the transport layer.
   A peer that carries a write lock is admitting ≥2 writer contexts; a peer with one event loop and
   one writer has nothing to lock.
2. **Is a race detector available on the substrate?** This is what splits R from M, per arch's own
   language lists (`Go -race`, `Rust/TSan` → R; `c, cpp, ada, fortran, forth, odin, zig, asm-*,
   riscv64…` → M). Note this is arch's *list*, not a capability claim: TSan exists for C/C++/Zig,
   but arch classed those M and grading uniformly matters more than relitigating the line.

**Status of this table.** The class column is a *declaration with cited evidence*, not a passed
bar. Part B is only satisfied when the artifact each class owes (last column) exists and passes.
**No peer in this cohort has submitted its Part-B artifact yet** — that work is open, and this file
is the input to it, not a substitute for it.

## Class S — single writer by construction (structural attestation, no stress test)

The §4.1 predicate: *the single-writer claim is checkable from source (no thread/task writes frames
concurrently)*. Every row here has **no write-serialization primitive in transport**, and that
absence is the evidence — on these substrates there is nothing to serialize.

| Peer | Structural reason | Evidence |
|---|---|---|
| `typescript` | one Node event loop; writes are `socket.write` on the loop thread | no write lock in `src/transport/` |
| `dart` | single-threaded event loop per isolate; no shared memory across isolates | `profile.toml` `store_safety = "event-loop-confinement"` |
| `php` | single-thread `stream_select` event loop | `profile.toml` `concurrency_model = "single-thread stream_select event loop"` |
| `nim` | one event thread; explicitly "no concurrent writer" | `src/store.nim` header |
| `crystal` | fiber-per-connection on the default single thread | `profile.toml` `store_safety = "single-thread-default"` |
| `tcl` | single-threaded event loop (the language's headline model) | `profile.toml` §concurrency |
| `apl` | single-threaded select/poll loop | `profile.toml` — "SINGLE-THREADED SELECT/POLL LOOP" |
| `forth` | gforth single-threaded; no portable in-image threading | `profile.toml` §concurrency |
| `rexx` | classic Rexx single-threaded, no native concurrency | `profile.toml` — resolved at S1 |
| `smalltalk` | all green processes on ONE native OS thread (cooperative) | `profile.toml` §concurrency |
| `fortran` | single network reactor | `profile.toml` §concurrency |
| `pd` | single-threaded reactive canvas | `profile.toml` `concurrency_shape = "single-thread-reactive"` |
| `sql` | single host thread owns the socket | `profile.toml` `store_safety = "structural (single host thread)"` |
| `datalog` | host-serialized; Datalog side is a stateless fixpoint | `src/host.rs` header |
| `asm-x86_64`, `asm-arm64`, `riscv64` | single-threaded fork + request/response frame router; no threads, no epoll | `CONFORMANCE-MATRIX.md` §1 asm note; no write lock in `src/` |
| `wasm-wat` | no fork, no threads at Level 1 | `profile.toml` header |
| `rust-wasm`, `rust-wasm-wasmtime` | single-threaded poll loop; the reentry seam collapses to a synchronous pump | `src/main.rs` header |
| `swift` | `actor` isolation — the connection actor is the only writer | `profile.toml` `concurrency_primitive = "actor"` |
| `elixir` | the connection process **is** the single writer (responses and outbound both route through it) | `lib/entity_core/connection.ex` header |
| `oz` | per-connection WRITER port serializes; dataflow variables, no shared mutable state | `profile.toml` §concurrency |
| `io` | per-connection FIFO writer queue on one event loop (cooperative yield) | `profile.toml` `coroutine_write_lock = true` |
| `node-red`, `turbowarp` | single-threaded JS runtimes | exploratory probes, not deployable peers |

**Two rows need a caveat, not a clean pass.** `oz` and `io` carry a *queue* rather than a lock: the
writer is single but frames are enqueued from multiple logical contexts. That still satisfies §6.11
a′ (one drainer, whole frames), but the structural attestation must name the queue as the
serialization point — "it's single-threaded" alone under-describes it. `io` in particular already
has a frame-write history (`A-IO-002` is the failure shape the whole vector spec cites), so its
attestation should be written against that scar, not around it.

## Class M — ≥2 writer contexts, no race detector (deterministic test + serialization-point citation)

The §4.1 predicate: *(a) a ≥2-writer test checking **emitted-stream** framing, (b) a real resolvable
serialization symbol, (c) no frame-write path bypasses it*. Column 3 is the symbol the attestation
must cite; column 4 is what is still missing.

| Peer | Serialization point (cited symbol) | Evidence | Owes |
|---|---|---|---|
| `c` | per-connection write mutex | `src/peer_internal.h` | deterministic ≥2-writer test + bypass spot-check |
| `cpp` | `write_mu_` (`std::lock_guard`) | `src/transport.cpp` | same |
| `ada` | protected `Write_L` object | `src/entity_core-protocol-transport.ads` | same |
| `odin` | `write_mu: sync.Mutex` | `src/transport.odin` | same |
| `cobol` | single-writer mutex over the FFI shim (OS threads via pthread) | `profile.toml` | same |
| `prolog` | `WriteMutex` in `conn_state/2` | `prolog/ec_transport.pl` | deterministic ≥2-writer test |
| `ocaml` | `write_mutex : Mutex.t` | `src/transport.ml` | same |
| `julia` | `write_lock::ReentrantLock` | `src/transport.jl` | same |
| `lean` | `writeMutex : Std.Mutex Unit` | `src/EntityCore/Transport.lean` | same |
| `zig` | `write_mutex: std.Thread.Mutex` (`Io.writeFramed`) | `src/transport.zig:42,60-61` | deterministic ≥2-writer test + bypass spot-check — **no longer a hold, see below** |
| `common-lisp` | `write-lock` (`sb-thread:make-mutex`), locked in `write-framed` | `src/peer-transport.lisp:21,28-30` | same — **no longer a hold, see below** |
| `haskell` | `ioWriteLock :: MVar ()` | `src/EntityCore/Transport.hs` | same |
| `unison` | `ioWriteLock : MVar ()` | `src/Transport.u` | same |
| `java` | per-connection write lock (virtual threads) | `Transport.java` | same |
| `kotlin` | per-connection write lock | `Wire.kt` | same |
| `csharp` | `_writeLock = new SemaphoreSlim(1, 1)` | `PeerConnection.cs` | same |
| `ruby` | per-connection write `Mutex` | `lib/entity_core/transport.rb` | same |
| `python` | `self._write_lock = threading.Lock()` | `peer/transport.py` | same |

**Both named holds are resolved (2026-07-28) — the prior scan was a false negative, not a peer
defect.** The 2026-07-27 pass grepped `wire.zig` / `profile.toml` and stopped there; the real
primitive was one file over in both peers, confirmed by reading source directly (per the
prove-a-negative discipline in AGENTS-STANDARD.md — an absence claim from a partial grep is exactly
how this kind of false gap gets filed):

- **`zig`**: `wire.zig`'s doc comment ("the caller serializes concurrent writes") pointed at
  `transport.zig`, which the prior scan didn't open. `Io.writeFramed` (`src/transport.zig:56-62`)
  locks `write_mutex: std.Thread.Mutex` (declared `:42`) around every call to `wire.writeFrame` — and
  a cohort-wide grep for `wire.writeFrame(` / `writeFramed(` (`src/`) shows the **only** call site of
  the former is inside the latter. No bypass. This is a real, resolvable symbol every frame write
  passes through — Class M, not a gap.
- **`common-lisp`**: same shape. `peer-transport.lisp:21` declares `(write-lock (sb-thread:make-mutex
  :name "write"))`; `write-framed` (`:28-30`) wraps the one call to `write-frame` in
  `(sb-thread:with-mutex ((io-write-lock io)) ...)`, and both of `write-framed`'s own call sites
  (`:50`, `:94`) go through it. `write-frame` (`peer-wire.lisp:32`) has no other caller. Class M,
  cleanly — the "unclassifiable" state is retracted.

Both rows moved into the Class M table above with their cited symbols. Neither still owes anything
beyond what every other Class M row owes: the deterministic ≥2-writer test.

## The `oz` / `io` queue attestations (closing the two named caveats)

Both confirmed structurally, not merely re-asserted:

- **`oz`**: `NewWriter` (`src/transport.oz:76-85`) opens one Oz `Port`/stream pair per connection and
  spawns exactly one thread that `{ForAll S proc {$ Payload} {Sock write(...)} end}` — draining the
  port's stream in arrival order. A cohort grep for `Sock write` in `oz/src/` finds **one** call
  site, inside that thread. Every response/outbound path (`transport.oz:107,127,154`) reaches the
  socket only via `{Send Writer Payload}` into the port — never directly. So the "queue" is the Oz
  Port itself: multiple logical senders, one draining thread, whole frames only. Attestation: *the
  per-connection `Writer` port (`NewWriter`, `transport.oz:76`) is the single writer; `{Send Writer
  _}` is the only path to the socket, verified by exhaustive call-site search.*
- **`io`**: the `Conn` prototype's per-connection `wbuf` (`Transport.io:81` `_sendFrame`, drained by
  `_flushWrites` at `:94-102`) is the queue — multiple call sites append frames (the ordinary response
  path and the §6.11 reentry path both call `_sendFrame`), and `_flushWrites` is the only place bytes
  reach the socket for a `Conn`. The one other `asyncStreamWrite` call site (`Transport.io:276`)
  belongs to the unrelated `Session` prototype (the outbound test-dialer client), not `Conn` — a
  different object playing a different role, not a bypass of the same connection's writer. Attestation:
  *`Conn`'s per-connection `wbuf` + `_flushWrites` (`Transport.io:81-102`) is the single point frames
  reach the socket; the `Session` object at `:273` is a distinct client-side connection and does not
  share `Conn`'s write path.* This is written against `io`'s own scar (`A-IO-002`), as the predecessor
  handoff asked: the fix that closed that history is the same `wbuf`/`_flushWrites` pairing cited here.

Both `oz` and `io` are Class S with a named, verified serialization point (a port and a buffer,
respectively, standing in for a lock) — not a downgrade to Class M, since there is still exactly one
writer; the caveat was about *naming* the queue, which is now done.

## Class R — ≥2 writer contexts, race detector available

| Peer | Detector | Serialization point | Owes |
|---|---|---|---|
| `go` | `go test -race` | `writeLock sync.Mutex` (`src/peer/transport.go`) | a ≥2-writer test under `-race` asserting **frame-boundary integrity of the emitted stream**, not demux timing, + the CI invocation proving `-race` was on |
| `rust` | TSan / Miri | `write_lock` guarding the cloned write half (`src/peer/transport.rs`) | same shape |

**Closed (2026-07-28).** Both now have the assertion, not just the mechanism:

- `go`: `protocol-generator/go/src/peer/transport_concurrency_test.go`,
  `TestConcurrentWritersFrameBoundaryIntegrity` — 16 goroutines call `writeFramed` concurrently over
  a `net.Pipe`; a single sequential reader decodes each frame and asserts request_id↔status pairing
  (a torn/interleaved write produces either an undecodable frame or a mismatched pair — the exact
  corruption shape a byte-splice leaves). `go test -race -run TestConcurrentWritersFrameBoundaryIntegrity ./peer/...`
  passes clean. **Verified non-vacuous**: temporarily bypassing `writeLock` in `writeFramed`
  reproduced the failure (an unattributed goroutine panic from a corrupted read after the test body
  moved on) before the lock was restored — the test does have teeth, not just green-by-construction.
- `rust`: `protocol-generator/rust/src/peer/transport/tests.rs`,
  `concurrent_writers_frame_boundary_integrity` — same shape (16 `std::thread`s, one sequential
  reader on a real loopback `TcpListener`/`TcpStream` pair since `std` has no `net.Pipe` equivalent).
  `cargo test --offline transport::tests` passes clean (run inside `rust-toolchain` — the crate's
  MSRV 1.96 exceeds the host's 1.94.1). **Verified non-vacuous**: bypassing `write_stream`'s mutex
  (writing via an unlocked `try_clone()` of the stream) reproduced `Codec(TrailingData)` decode
  failures — the exact corruption signature — in 2 of 3 runs before the bypass was reverted.
- Both still owe "the CI invocation proving `-race`/a sanitizer was on" — these tests exist and pass
  today but nothing yet gates a future regression on running them under a detector in CI. Noted, not
  closed; a `make check`/CI wiring task, not a source-level one.

## RT-13a (§4.8 store-safety incl. refcounts) — scope

RT-13a is behavioural only on manual-memory substrates, so it is invisible on most of the table
above. The reachable set in this cohort is `c`, `cpp`, `ada`, `fortran`, `forth`, `odin`, `zig`,
`asm-x86_64`, `asm-arm64`, `riscv64`, `cobol`. `c` already carries the fix (`A-C-009`). Every other
member owes the same §4.1 M/S-shaped artifact at the storage layer rather than the wire layer.

**RT-13a cannot be inferred from a Go/Rust/Python result**, on either axis: those substrates are
GC/ARC and satisfy it trivially by construction. A three-way GREEN on the trio is silent about
RT-13a, and the silence must not be read as a pass — it validates first at the 43-peer run, on the
rows above.

## What this file is not

It is not a Part-B submission. **Status as of 2026-07-28**: the two named holds (`zig`,
`common-lisp`) are resolved (Class M, real symbols cited, see above), the two named caveats (`oz`,
`io`) are closed (Class S, the queue named and verified), and Class R (`go`, `rust`) has its
deterministic test written and independently verified non-vacuous. **Still open**: every Class M
row's own ≥2-writer test + bypass spot-check (`c`, `cpp`, `ada`, `odin`, `zig`, `cobol`,
`common-lisp`, `prolog`, `ocaml`, `julia`, `lean`, `haskell`, `unison`, `java`, `kotlin`, `csharp`,
`ruby`, `python` — 18 peers, none submitted yet; the `go`/`rust` tests above are the template:
N concurrent writers over a real or in-memory duplex, one sequential reader asserting per-frame
decode + field-pairing integrity, verified non-vacuous by a temporary bypass), and RT-13a's storage-
layer artifact on the manual-memory peers below (`c` already done). Until the Class M list clears,
RT-13b is **unverified cohort-wide on those 18** — a state, not a pass.
