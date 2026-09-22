# PROFILE-RATIONALE — entity-core-protocol-asm-x86_64

Why each S1 profile choice was made. The asm peer is a **substrate probe**, not a
language-idiom probe: it exists to document how the protocol maps onto the extreme end
of the substrate axis — a machine with no runtime, no allocator, no types, no error
model, no strings, only registers + memory + `syscall`. Expected spec-discovery yield is
**low** (the wire-touching axes are saturated by the 30-peer cohort); the payoff is
**generator-robustness + substrate-dynamics**, and the honest framing is cohort-consistent
corroboration, not independent convergence (ADR-0012).

## Codec strategy = FFI (Level 1)

Assembly has no library ecosystem: no CBOR, no Ed25519, no SHA-2, no base58 — nothing.
This is precisely the `gap → hybrid-FFI` end of the crypto-availability spectrum, taken
to its limit: **everything** is FFI'd, not just Ed448. The C-ABI (`libentitycore_codec`,
C-ABI 1.1) exposes the entire codec + crypto behind the SysV AMD64 calling convention, so
Level-1 FFIs all of it and hand-authors only the machine's own logic. A ground-up asm
codec (Level 2) and a fully-pure crypto build are documented later stretches, not this
build's scope.

**Scope caveat surfaced during S1 (A-ASM-004):** "FFI the whole codec" does NOT eliminate
hand-rolled CBOR. The C-ABI decomposes *entities* (`ec_decode_entity`, `ec_encode_ecf`,
`ec_content_hash`) but not the *envelope* map (`{root, included}`) nor the EXECUTE/RESPONSE
`data` map (`{request_id, uri, operation, params, author, capability, resource}`). Those
are bare canonical-CBOR maps owned by the peer's model layer, so the asm peer hand-rolls a
minimal canonical-CBOR map **reader + writer** for that layer even at Level 1. The
shortest-float ladder, recursive tag-reject, and general key-sort stay behind the FFI
(everything entity-shaped goes through `ec_encode_ecf`); the peer only emits small,
fixed-shape maps whose keys it writes in pre-sorted order. See
`arch/WIRE-SURFACE-REFERENCE.md`.

## Assembler = GAS / AT&T (A-ASM-001)

GAS ships with `binutils`, which is already in every toolchain image (and pinned in
`containers/c-toolchain`), so it is the **lowest-dependency** choice — consistent with the
ecosystem's "system toolchains, minimal dependencies" stance (AGENTS-STANDARD). NASM is
more readable (Intel syntax) but would add a `dnf` dependency for zero correctness gain.
GAS's AT&T syntax (`src, dst` order, `%`-registers, `$`-immediates, size suffixes) is the
tradeoff; it is well-trodden and the assembler is the reference tool for the SysV ABI on
Linux. Decision: **GAS**.

## Link mode = dynamic via the `cc` driver, `-no-pie` (A-ASM-001)

Two sub-decisions:

1. **`cc`/gcc as the link driver, not bare `ld`.** `libentitycore_codec.so` is
   dynamically linked against libc (with libsodium statically + privately linked inside
   it). If the peer entry were a freestanding `_start`, we'd have to initialize libc's TLS
   / errno / constructors by hand before any FFI call could safely touch libc — fragile.
   Letting `cc` supply `crt0` + `__libc_start_main` means the C runtime initializes libc
   fully before our asm `main` runs. The peer is still **written in assembly** — every line
   of logic is in `.s` files; we merely use the standard system startup + link driver, as
   any hand-authored asm program on Linux does. Transport is still raw `syscall`s (the
   substrate-research point), even though libc is now linkable.

2. **`-no-pie`.** Hand-authored asm using absolute addressing for `.bss`/`.data` symbols is
   the simplest correct model at Level 1. PIE/PIC (RIP-relative everywhere, GOT/PLT
   discipline) is a documented later hardening, not a Level-1 requirement.

A fully freestanding `_start` (no crt, no libc) is noted as a Level-2 purity option — but
since the codec `.so` needs libc regardless, it buys little at Level 1. Static linking the
`.a` (self-contained ELF) is a documented alternative to dynamic; dynamic is simpler to
iterate against and chosen for the build loop.

## Error model = errno (register status + branch)

There is no language error model to choose — the machine offers status codes in registers
and conditional branches, nothing else. The C-ABI returns `int32_t` in `%rax`
(`EC_OK=0 … EC_INTERNAL_ERROR=-99`); protocol verdicts are integers. At the dispatch
boundary the asm maps `{C-ABI status, protocol outcome}` → the §5.2a/§6.12 status codes
carried in the response envelope. This is the `errno` taxonomy taken to the bare metal.

## Concurrency = single-threaded epoll event loop (A-ASM-003)

Two options: (a) kernel threads via `clone(2)` + a futex mutex on the shared store, or
(b) a single-threaded `epoll(7)` readiness loop. Chose **(b)**: hand-managing thread
stacks / TLS / futex wake in asm is materially harder and more error-prone than an epoll
readiness loop, and the `--profile core` concurrency category needs *interleaved progress*
across connections (no head-of-line blocking), not true parallelism. §4.8/§6.11
inbound-concurrent-with-outbound is satisfied structurally by the loop; full
handler-initiated origination (`dispatch-outbound` live) is reference-peer-gated and
honest-SKIPs on a single-peer run. §7b throughput floor is `TCP_NODELAY` via `setsockopt`
(the Zig lesson: Nagle/delayed-ACK on small frames, not compute, is the bottleneck).

## Memory = static .bss + bump-over-mmap + FFI'd arena

The extreme end of the no-GC axis. Decoded entity bodies live in an FFI'd `ec_arena_t`
(`ec_arena_{new,reset,free}`) that the codec owns; the peer `ec_arena_reset`s per request.
The peer's own working buffers (frame read buffer, response build buffer, store slots,
connection state) are a static `.bss` region carved at assemble time, with a hand-rolled
bump allocator over an `mmap`'d region for anything variable-sized. Manual, by definition.

## Toolchain pins (S11)

- `binutils 2.45.1-4.fc43` — `as` (GAS) + `ld`; fedora:43 stock, matches
  `containers/c-toolchain`. Provides the AT&T assembler; no LLVM/NASM.
- `gcc 15.2.1-7.fc43` — **link driver only** (no peer C is compiled); fedora:43 stock,
  matches `containers/c-toolchain`.
- `glibc` — fedora:43 stock; loaded because the codec `.so` needs it; the peer touches it
  only implicitly (crt startup). Transport is raw syscalls.
- `libentitycore_codec` — `entity-core-codec-ffi-c`, C-ABI 1.1; a repo artifact
  version-pinned by `ec_impl_info()`, not a distro package.

All are ≥ 30 days old at authoring (they match the already-shipped `c-toolchain` pins);
the FFI target is a committed repo build output, not a registry pull, so no registry
cool-down applies.

## Spec pin

`v0.8.0 / V8` snapshot (`shared/spec-data/v0.8.0`), corpus `conformance-vectors`
(71 vectors), oracle `cc1970f` (fingerprint `8261a033…`). Core wire byte-unchanged
v7.75→v7.77→V8. Expected `--profile core` result: **0-FAIL** (~292·0F like the recent
cohort), as corroboration.
