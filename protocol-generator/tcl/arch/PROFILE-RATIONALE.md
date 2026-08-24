# entity-core-protocol-tcl — Profile Rationale (S1)

Audit trail for each major `profile.toml` decision. One section per choice.
Authored 2026-07-10 from the V8 spec-data + Tcl-ecosystem research, no prior
peer's profile ported. Companion to `profile.toml` and `status/PHASE-S1.md`.

## Why Tcl at all — the probe thesis

Tcl is the first **Everything-Is-A-String (EIAS)** peer. Every value is,
canonically, a string; the typed internal representations (`int`, `double`,
`bytearray`, `list`, `dict`) that a `Tcl_Obj` caches are guaranteed by the
language to be indistinguishable from the string. That is the exact opposite of
what a canonical binary wire format needs: ECF demands, for every value, **one
unambiguous CBOR major type** — mt2 byte-string ≠ mt3 text-string, mt0/1 int ≠
mt7 float.

The cohort's peer-selection compass (LANDSCAPE §"Runtime-shared families";
CONFORMANCE-MATRIX §5) marks the **string/encoding model** as the least-saturated
wire-touching axis — the one most likely to still yield a spec-precision finding.
Swift probed grapheme-vs-scalar and converged null; COBOL probed fixed-width
PIC/COMP-3. Tcl probes the axis from the other extreme: a value model with **no
intrinsic type at all**. The thesis is that this forces the byte-vs-text and
length-in-bytes seams into the open (A-TCL-001/002), and either surfaces a real
ambiguity or demonstrates that the spec is already tight enough to force the peer
to carry type explicitly — which is itself a clean, reportable answer.

## Codec strategy: ffi-hybrid (hand-rolled CBOR + C-ABI crypto)

Two independent facts, one per half of the codec:

- **CBOR → hand-rolled, pure Tcl.** No Tcl CBOR package offers ECF canonicality
  (length-then-lex map ordering on encoded key bytes, shortest-float ladder,
  major-type-6 tag rejection, raw-byte fidelity) — the A-005 pattern all seven
  native-codec peers hit. And Tcl is genuinely *good* at the byte assembly:
  `binary format`/`binary scan` do network-order integers (`Iu`/`Wu`/`Su`) and
  IEEE `f32`/`f64` (`R`/`Q`) natively. So the encoder's engine is native; only the
  f16 half-float leg is hand-rolled bit arithmetic (A-TCL-006, as on every peer).
  Hand-rolling here is not a workaround — it is where the entire paradigm probe
  lives, so it is the point of building this peer.

- **Crypto → C-ABI over `cffi`.** There is no Ed25519 anywhere in Tcl or Tcllib.
  Tcllib ships `sha256`/`sha1`/`md5` (pure-Tcl, correct, slow) and `aes`/`des`,
  but no EdDSA; `tcltls`/`tls` wraps OpenSSL for TLS *transport* only, exposing no
  general EVP/Ed25519 surface. So — unlike Prolog, which *discovered* its crypto
  gap at S2 — Tcl's signature floor is a known FFI obligation from S1. We bind
  `libentitycore_codec` (`ec_ed25519_*`, `ec_sha256/384`, `ec_ed448_*`) through
  `cffi`, the modern libffi-based declarative FFI. SHA also crosses the C-ABI for
  one consistent crypto surface; Tcllib `sha256` is retained only as the documented
  FFI-free SHA-floor fallback.

Net shape = **COBOL's**: a competent native value-codec plus the C-ABI for crypto
it cannot do. This is *not* "ffi everything" (Prolog's landing zone) — the whole
CBOR/base58/varint value layer is native Tcl. It IS the same FFI-hybrid class the
matrix tracks (native floor + C-ABI crypto), so the shipped default peer depends on
`libentitycore_codec` being present, exactly like COBOL/Prolog.

## Integer model: native bignum (free full range)

Tcl 8.5+ carries arbitrary-precision integers (libtommath). So the uint64/nint
head-form range is free, no fixed-width self-test needed — Tcl joins the
CL/Elixir/Prolog/Python/Ruby bignum class, opposite the OCaml int63 / C# ulong /
TS bigint / Zig u64-trap fixed-width class. One less trap than the systems peers;
the interesting numeric risk is instead **which** major type an untyped numeric
value takes (A-TCL-003), not its range.

## Concurrency: single-threaded event loop (structural store-safety)

Tcl's idiomatic network-server model is the reactor: `chan event $sock readable`,
`vwait`, non-blocking channels. One thread, cooperative — the same structural
shape as the PHP `stream_select` peer and Dart's per-isolate loop. §7b store-safety
comes for free: one event thread serializes all store mutations, so the store is
plain Tcl dicts with no lock. §6.11 outbound-dispatch reentry is a plain event-loop
turn — no cross-thread demux, no correlation-map tax, no deadlock risk (contrast
COBOL's hand-built poll-slot pump). This corroborates the PHP/Dart "reentry is free
on an event loop" result on a **third** event-loop substrate.

The `Thread` package (real share-nothing OS threads + `thread::send`) is a genuine
actor alternative but is out of scope for the core peer (A-TCL-008): the event loop
is more idiomatic for a network peer and needs no `tsv` discipline.

## Error model: Tcl 8.6 try/throw/trap

Modern Tcl has structured exceptions — `throw {ENTITY_CORE <KIND> ...} msg` sets a
machine-readable `-errorcode` list matched by `try { } trap {ENTITY_CORE ...} { }`.
That is the idiomatic surface (superseding bare `error`/`catch`) and the natural
analogue of the C#/TS/Java exception peers. The codec throws on N2/N3 hard rejects;
in-band absence returns a tagged value. Note the EIAS wrinkle (A-TCL-007): the empty
string is a real wire value, so it cannot be the "absent" sentinel — absence is a
tagged dict `{present 0}`.

## Naming, build, packaging, testing

- **Naming**: lowercase procs (`snake_case`), `::entity::core::*` namespaces as the
  module unit, ensemble subcommands for the public surface — the core-Tcl/Tcllib
  idiom, not camelCase.
- **Build**: interpreted, no compile gate. "Build" is sourcing `pkgIndex.tcl` + a
  `package require` smoke. No cargo/dotnet analogue; TEA is only for C extensions,
  and we have none (crypto is a runtime `cffi` binding to a prebuilt `.so`).
- **Testing**: `tcltest` — bundled in base Tcl, the ecosystem standard. Unlike the
  OCaml/CL/Zig peers there is no dependency-minimization reason to hand-roll: the
  standard framework is already zero-supply-chain.
- **Packaging**: Tcl has no dominant registry. Publish = a git repo with a working
  `pkgIndex.tcl`; Tcllib inclusion is a later review-gated step. The git-indexed
  model, like SWI packs / Quicklisp.

## Version choice: Tcl 9.0 preferred, 8.6 fallback

Tcl 9.0 (2024-09) is full-Unicode/UTF-8 internal with 64-bit sizes and a cleaner
byte-vs-string boundary — which makes the two headline probes (byte-vs-text,
length-in-bytes) crisper than 8.6's UCS-2-ish internals. Both are well over the S11
30-day floor. The fallback to 8.6.15 (the long-stable line) is taken only if
fedora:43 packages 8.6 rather than 9.0, or if the pinned `cffi` targets 8.6 — both
confirmed at S2 (A-TCL-004). The codec logic is version-agnostic; only the internal
string model differs, and the peer always drives wire encoding through explicit
`encoding convertto/convertfrom utf-8` rather than the interp's system encoding.

## Honest "does this idiom map?" verdict

**Lean GO, with the probe as the payoff.** Unlike Prolog (where S1 flagged a real
risk that the declarative idiom might not survive byte-exact framed I/O), Tcl's
event-loop + `binary` command are a *good* fit for a network codec — the mechanics
are not in doubt. The open question is narrower and sharper: whether EIAS forces
the peer to smuggle type information through side channels in a way that reveals a
spec gap, or whether the spec's explicit major-type discipline cleanly obliges the
peer to carry an explicit tagged value model (the expected outcome). Either result
is worth the build; the second is the corroboration the type-registry lesson
("render natively from the data model, don't infer") predicts, now stress-tested on
a substrate with no types to reflect.
