# Oz/Mozart & Io viability — dataflow-variable concurrency + prototype-based OO

**Question.** Are Oz (Mozart) and Io real peer substrates, and what distinct axis does each add?
Companion to `../PARADIGM-MAP.md`. Both were flagged there as medium-priority candidates.

**Short answer.** Both are **NATIVE-for-I/O + seam-for-crypto** (like our alien-substrate peers) — real
peers are possible. Each adds one genuinely distinct axis:
- **Oz** → a *fourth structural concurrency model* (dataflow variables) for the §7b taxonomy.
- **Io** → the *pure prototype-based object model* — the one object model we haven't probed.

The real risk for both is **toolchain availability**, not paradigm fit — both are low-maintenance
runtimes, so the S1 feasibility gate is "does it build + can it listen on a socket in a fedora:43
container," not "does the paradigm work."

---

## Oz / Mozart

**Runtime — where it runs.** The **Mozart Programming System** (Mozart 2, LLVM-based) is a full VM +
runtime for Oz — REPL, script runner, standard library. It's the teaching vehicle of *Concepts,
Techniques, and Models of Computer Programming* (van Roy/Haridi), the canonical multi-paradigm text.
**Native I/O:** Mozart ships socket/file modules (`Open`, `Socket`), so — unlike SQL/Datalog/Brainfuck —
**Oz can listen on a TCP socket itself.** CBOR + Ed25519/SHA have no native lib → **seam via the C++ FFI
to `libentitycore_codec`** (the standard hybrid pattern). So: **NATIVE peer, crypto/CBOR seam.**

**The distinct axis — dataflow variables.** Oz's defining feature is the **single-assignment dataflow
variable**: a thread that reads an unbound variable *blocks until another thread binds it* — synchronization
is automatic, no locks, no explicit channels. This is **declarative concurrency**: a fourth structural
§7b store-safety shape distinct from everything in the cohort —

| Concurrency model | Cohort peers | Mechanism |
|---|---|---|
| Actor-isolation | Swift, Elixir | no shared mutable state |
| STM transactions | Haskell | optimistic retry |
| CSP channels | Go | message-passing over channels |
| threads + lock | C, Zig, Java, … | manual mutual exclusion |
| **dataflow variables** | **Oz (gap)** | **read-blocks-until-bound; automatic** |

The §6.11 handler-outbound demux and §7b store-safety would be expressed via dataflow synchronization —
a genuinely new data point for "how does each substrate satisfy no-serialization + store-safety."

**Verdict:** real peer, **HYBRID-FFI**, medium priority — the concurrency axis is the payoff. **Risk:**
Mozart 2's maintenance is thin; verify it builds headless in-container before committing (the S1 gate).

**What it looks like** (dispatch fan-out, illustrative):
```oz
% each inbound request handled in its own lightweight thread; Result is a dataflow variable
thread Result = {Dispatch Req} end          % blocks consumers until bound
{Socket send({Encode Result})}              % consumer auto-waits on Result — no lock
```

---

## Io

**Runtime — where it runs.** Io (Steve Dekorte) is a small **prototype-based** language; the reference
implementation is a compact C interpreter (`io`), embeddable, with an addon system. **Native I/O:** the
`Socket`/networking addon gives TCP (historically libevent-backed), so **Io can listen itself.** CBOR +
crypto → **seam via a C addon / the C-ABI codec.** So again: **NATIVE peer, crypto/CBOR seam.**

**The distinct axis — pure prototype-based OO.** Io has **no classes** — every object is `clone`d from a
prototype, inheritance is differential (delegation up the proto chain), and *everything is a message
send* (like Smalltalk, but prototypal). This is the **one object model the cohort hasn't probed**: we
have class-based (Java/C++/Ruby/…), pure message-passing-class (Smalltalk), and prototype-*in-JS* (but we
cover JS as TypeScript, which is class-flavored). Io is the *pure* prototype language. Its dispatch —
handler resolution walking the proto/delegation chain — is a novel rendering of the §6.6 tree walk.

**Verdict:** real peer, **HYBRID-FFI**, medium priority — the prototype object model is the payoff.
**Risk:** Io is low-activity; the Socket addon's build health in-container is the S1 gate.

**What it looks like** (prototype dispatch, illustrative):
```io
Handler := Object clone                       // base prototype
TreeHandler := Handler clone                  // differential inheritance via clone
TreeHandler handle := method(req, ...)        // message-send dispatch
resolved := registry resolveFor(req path)     // walks the delegation chain
resolved handle(req)
```

---

## Both, in one line

Neither is a stunt — both author the full interior natively and only seam crypto/CBOR, exactly like the
alien-substrate cohort. Oz buys a new **concurrency** axis; Io buys a new **object-model** axis. The only
real question is **toolchain viability in-container**, which is the honest S1 GO/NO-GO for each. Priority:
below the mainstream completeness picks (Scala/Objective-C) and below the high-interest SQL/Datalog, but
above pure catalog rows — each teaches one genuinely new substrate lesson.

---

## S1 gate results (2026-07-15) — BOTH GO

The "toolchain viability in-container" question this doc left open was answered by live probes
(capped `fedora:43` podman containers, the standard `PODMAN_RUN_CAPS` ceilings). Both passed the
full gate: headless boot + TCP listen/accept + **byte-identical echo incl `0x00`/`0xFF`**.

### Oz / Mozart — GO

- **Acquisition:** the release **`mozart2-2.0.1-x86_64-linux.rpm`** (2018-09, S11-clean by years)
  installs on fedora:43 via plain `dnf install` — its only repo deps are glibc/libstdc++ basics +
  **tcl/tk 8.6** (still packaged in fedora:43). tk belongs to `ozwish` (the GUI ELF) alone;
  `oz`/`ozc`/`ozengine` are shell scripts over `ozemulator`, which links **no tk and no boost**
  (boost is static). No source build needed — the LLVM/Scala-bootstrap build risk this doc
  flagged never materializes.
- **Headless:** `ozc -c hello.oz && ozengine hello.ozf` works with no display.
- **Sockets:** `Open.socket` bind/listen/accept/read/write — byte-identical TCP echo incl
  `0x00`/`0xFF` (`read(list:)` yields byte ints; writing the same list back is byte-clean).
- **The paradigm axis works headless:** `thread Y = X + 1 end` blocks on unbound `X`, resumes on
  bind (`Y=42`) — dataflow variables live under `ozengine` with no OPI/emacs.
- **Crypto/CBOR seam = co-process, not native-functor FFI:** the RPM ships **zero headers**, so
  the C++ native-functor route would demand a full mozart2 source build (the risk we avoided).
  Instead: **`Open.pipe` co-process daemon** (the Rexx `ecnet` precedent) — proven byte-clean
  through `0x00`/`0xFF` against a spawned child. The daemon wraps `libentitycore_codec`.

### Io — GO (with one upstream surprise)

- **Upstream pivot (the headline S1 finding):** IoLanguage/io **master is now a WebAssembly/WASI
  port** — the native build (DynLib/AddonLoader/addons) is frozen at the **`2026.04.20-native-final`**
  tag (commit `e5024305`, S11-clean ~3mo), and the addon repos (incl. Socket) were **archived the
  same day**. Pins are therefore *permanent*: the native line will never move again. (The WASM
  pivot itself is a data point for the assembly team's WASM track — upstream Io now targets
  wasmtime.)
- **Core build:** CMake build on fedora:43 needs
  `-DCMAKE_C_FLAGS="-std=gnu11 -Wno-incompatible-pointer-types -Wno-implicit-function-declaration
  -Wno-int-conversion"` — GCC 15's C23 default hard-errors 2018-era C (the same modern-gcc
  friction class as Pd's `extra/`). With those flags: clean build, `io -e` headless OK
  (v. 20260302).
- **Socket addon (the real risk, resolved manually):** `eerie` (the package manager) does not
  bootstrap usably from the frozen tree — but the addon builds **by hand** exactly like any seam
  artifact: clone `IoLanguage/Socket` (`e348c23`, 2018-06), hand-write the ~30-line generated-style
  `IoSocketInit.c` (the `DynLib call("Io<Name>Init", context)` convention from `AddonLoader.io`),
  `gcc -shared` against the installed io headers + `-levent`, install the
  `{_build/dll/libIoSocket.so, io/, protos, depends}` layout at `~/.eerie/base/addons/Socket`
  (already on `Addon searchPaths`). `-include assert.h` needed (implicit-decl → undefined
  `assert` symbol otherwise).
- **Sockets:** `Server`/`Socket` accept + coroutine read/write — byte-identical TCP echo incl
  `0x00`/`0xFF`.
- **One behavioral quirk to carry into the peer build:** a client **half-close (FIN with the
  socket kept readable)** tears the connection down before the pending write flushes — the echo
  is lost. Full-duplex request/response traffic (what validate-peer does — connections stay open)
  is unaffected; just never design a flow that answers after peer-FIN.
- **Crypto seam viability is already demonstrated:** the manual Socket build IS the pattern for
  the `EntityCodec` C addon over `libentitycore_codec` — same init convention, same compile
  shape. No co-process needed; Io's C-addon FFI is first-class.

**Net:** both are real, cheap builds — no toolchain wall. Oz's build effort concentrates in the
co-process seam protocol + expressing §6.11/§7b in dataflow threads (the payoff axis); Io's in
the EntityCodec addon + prototype-chain dispatch (§6.6 as delegation, the payoff axis).

## Cross-references
- Whole-territory map: `../PARADIGM-MAP.md`
- Concurrency taxonomy (§7b shapes): `../SUBSTRATE-TAKEAWAYS.md`
- Build queue: `../COMPLETENESS-ROADMAP.md`
