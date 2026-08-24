# The Cryptography Landscape — what 46 substrates taught us about the state of crypto libraries

**What this is.** entity-core requires every peer to do the same two things: Ed25519 sign/verify and
SHA-256. That is a deliberately boring, universally-available floor. Building 46 peers across 46
substrates meant asking 46 language ecosystems *"how do you do Ed25519?"* and writing down the honest
answer each time.

The result is an accidental survey — a cross-section of how the world's language ecosystems actually
provision cryptography in 2026. It is not a security audit and makes no claim about the correctness or
strength of any library named. It is a **provisioning** map: what exists, what it rests on, and where
the gaps fall.

**Sources.** Every row is drawn from a built, measured peer — `CONFORMANCE-MATRIX.md` §1 (the per-peer
codec/crypto columns) and each peer's `protocol-generator/<lang>/profile.toml` + `status/`. Nothing
here is from memory or from a library's marketing.

> **Honesty note, and it matters for this document specifically.** These 46 peers are
> **keystone-generated** — they share a generation lineage. Where this document says "N peers use
> library X," that is a statement about *what the ecosystem made available to us*, which is real and
> independently checkable. It is **not** 46 independent engineering teams converging on X. See
> `CONFORMANCE-MATRIX.md` and the README's independence section.

---

## 1. The headline: 46 peers, ~10 distinct Ed25519 implementations

The single most surprising result of the sweep. Forty-six substrates — spanning six decades of language
design, from COBOL to Unison — reach the *same* Ed25519 floor, and when you trace each one down past
the language binding to the code that actually multiplies points on a curve, they collapse onto roughly
**ten distinct implementations.**

| Underlying implementation | Reached by | Peers |
|---|---|---:|
| **libsodium** (C) | directly (`C`, `C++`, `Ada`, `Crystal`, `Nim`, `Julia`), via a platform extension (`PHP` ext-sodium), via a managed wrapper (`C#`/NSec), **and beneath all 17 C-ABI FFI peers** | **~25** |
| **OpenSSL** (C) | `Python` (`cryptography`), `Ruby` (stdlib `openssl`), `Elixir` (OTP `:crypto`) | 3 |
| **BoringSSL** (C) | `Swift` (swift-crypto on Linux) | 1 |
| **JDK SunEC** | `Java`, `Kotlin` | 2 |
| **ed25519-dalek + sha2** (pure Rust) | `Rust`, `rust-wasm`, `rust-wasm-wasmtime`, and the Rust build of `libentitycore_codec` | 3 (+ABI) |
| **@noble** (pure TS/JS) | `TypeScript`, `Node-RED`, `TurboWarp` | 3 |
| **crypton** (Haskell, audited C-backed) | `Haskell` | 1 |
| **mirage-crypto-ec + digestif** (OCaml) | `OCaml` | 1 |
| **ironclad** (pure Common Lisp) | `Common Lisp` | 1 |
| **`std.crypto`** (pure Zig) · **`core:crypto`** (pure Odin) · **`crypto/ed25519`** (pure Go) · **`cryptography_plus`** (pure Dart) · **UCM builtins + hand-written keygen** (Unison) | one each — the from-scratch in-language tier | 5 |

**The concentration is the finding.** More than half the cohort — every peer that links libsodium
directly, plus every peer that reaches crypto through the C-ABI codec, which itself links libsodium in
its C build — rests on **one C library**. A language's apparent crypto independence is frequently a
binding depth away from the same `libsodium.so` its neighbours use.

This is not a criticism of libsodium, which is excellent and is popular for good reasons. It is an
observation about **supply-chain shape**: the diversity you see at the language layer is substantially
thinner at the primitive layer, and a survey that counts languages will badly overstate it. If you are
reasoning about correlated failure — a CVE, a packaging change, a platform that won't ship it — the
number that matters is ~10, not 46.

## 2. The five provisioning tiers

Every language ecosystem lands in one of five tiers. The S1 profile phase classifies each target onto
this ladder *before* any code is authored, because the tier determines the peer's whole shape — whether
it ships dependency-free, whether it needs an FFI seam, and whether crypto agility is reachable at all.

| Tier | What it means | Peers |
|---|---|---|
| **1 — language stdlib** | Ed25519 + SHA-2 in the box, zero dependencies | `Go` · `Zig` · `Odin` · `Ruby` · `Unison`* |
| **2 — platform / runtime crypto** | the runtime provides it (OS, VM, or extension) | `Elixir` (OTP) · `Java` · `Kotlin` (JDK SunEC) · `Python` · `PHP` · `C#` |
| **3 — audited third-party native lib** | a real library in the language's own package ecosystem | `Haskell` · `OCaml` · `Rust` · `TypeScript` · `Swift` · `Dart` |
| **4 — native-pure-language** | implemented from scratch *in the language itself*, no C | `Common Lisp` (ironclad) · `Odin` · `Dart` · `Zig` · `Unison` |
| **5 — gap → hybrid-FFI** | no viable in-language provider; crypto crosses the C-ABI | `Lean` · `Prolog` · `COBOL` · `Tcl` · `Rexx` · `Fortran` · `Forth` · `Smalltalk` · `APL` · `Oz` · `Io` · `SQL` · `Datalog` · `Pure Data` · `asm-x86_64` · `asm-arm64` · `riscv64` |

\* Unison is a special case worth its own section — see §4.

Tiers 1–4 ship a **self-contained peer**. Tier 5 is why `libentitycore_codec` and the whole
`ffi-generator/` arm exist: seventeen substrates cannot reach Ed25519 in-language on any reasonable
timeline, and rather than declare them out of scope we gave them a language-agnostic C contract to
consume. **The FFI layer is not a shortcut — it is the thing that makes the long tail of the language
landscape reachable at all.**

Note that tier 5 is *not* the same as "obscure." `Prolog` is there because SWI-Prolog's
`library(crypto)` has no Ed25519 — a mature, widely-used language with a serious crypto library that
simply does not carry this curve. `Lean` is there by choice: its peer proves its core in Lean and
deliberately puts crypto behind the ABI rather than trusting a hand-rolled proof-adjacent
implementation.

## 3. Ed448 — where the map tears, and why the tear is not about languages

The spec's crypto-**agility** tier asks for Ed448 and SHA-384 alongside the Ed25519 + SHA-256 floor.
Agility does not gate `--profile core`; a peer that defers it WARNs rather than FAILs. That design
choice turns out to be load-bearing, because **Ed448 is where the cohort splits, and it splits along a
line no language designer drew.**

**Who has native Ed448 today — 5 peers:**

| Peer | Provider | Notes |
|---|---|---|
| `Haskell` | crypton | `Crypto.PubKey.Ed448` — the first native-full-agility peer in the cohort |
| `Elixir` | OTP `:crypto` | free with the BEAM; OpenSSL underneath |
| `Common Lisp` | ironclad | **pure Lisp** — no C anywhere in the path |
| `Python` | `cryptography` | OpenSSL underneath |
| `Ruby` | stdlib `openssl` | OpenSSL underneath |

**Who can reach it through a managed library — 3 peers:** `C#` (BouncyCastle), `Java` (JDK /
BouncyCastle), `TypeScript` (`@noble`).

**Everyone else defers.** And when you read the deferral reasons in the matrix, the same parenthetical
appears over and over:

> *deferred (libsodium has no Ed448)*

`C`, `C++`, `Ada`, `Crystal`, `Nim`, `Julia`, `PHP`, `COBOL` — and, transitively, every FFI peer whose
codec is the C build — are blocked on Ed448 for exactly one reason: **the C library their ecosystem
settled on does not implement that curve.** Not because the language can't. Not because the peer
authors ran out of time. Because libsodium made a scope decision.

**The C-ABI makes this concrete in the cleanest possible way.** `libentitycore_codec` has two
interchangeable implementations, both building the same `.so` with the same header:

- `entity-core-codec-ffi-rust` — links `ed448-goldilocks`. **Carries Ed448.**
- `entity-core-codec-ffi-c` — links libsodium 1.0.22. **Ed448 deferred**, and the spec says why in as
  many words: *"an implementation MAY return `EC_INTERNAL_ERROR` for the `ec_ed448_*` symbols if it has
  not yet bound an Ed448 provider (**libsodium has none**)."*

Two implementations of one contract, byte-identical on the 71-check differential, differing on exactly
one primitive — and the difference is inherited wholesale from the C library each chose. A tier-5 peer's
agility story is therefore decided not by its language at all, but by **which build of the codec it
happens to link.**

**The generalizable lesson.** When a protocol specifies a primitive, the real question is not *"can
languages do this?"* It is *"has the small set of C libraries that the world's languages actually bind
to decided to implement it?"* Ed25519 is everywhere because libsodium, OpenSSL, and BoringSSL all ship
it. Ed448 is scarce because one of those three declined. **Language diversity does not buy primitive
diversity** — the binding layer is wide, the implementation layer is narrow, and a spec that requires
something outside the narrow layer partitions the ecosystem along a line drawn years earlier by a
handful of library maintainers.

This is precisely the argument for making agility a WARN and not a gate. Had we gated `--profile core`
on Ed448, we would have excluded roughly three quarters of the cohort — and the exclusion would have
measured library scope, not peer quality.

## 4. Unison — the case that broke the tier ladder

Every tier-5 peer above reaches crypto by crossing the C-ABI. Unison **cannot**: it is a managed runtime
with no C-FFI hatch. The escape valve that seventeen other substrates used is *structurally unavailable*.
That forced a fifth classification the ladder didn't have — **managed-runtime-no-C-FFI** — where agility
can only ever be pure-language or deferred.

It also produced the sharpest single crypto finding of the whole sweep, and it is one worth internalizing
if you ever port a protocol to an unfamiliar runtime:

**A runtime can ship sign and verify and still ship no key derivation.**

UCM exposes `crypto.Ed25519.sign.impl` and `crypto.Ed25519.verify.impl`. It exposes no keygen. Worse,
`sign.impl` takes the public key as an *argument* — so there is no way to recover it from the seed
through the API. Producing an identity therefore required implementing Ed25519 key derivation **from
scratch, in pure Unison**: arithmetic in GF(2²⁵⁵−19) on base-2¹⁶ limbs, twisted-Edwards scalar
multiplication, and point compression.

Two durable rules came out of it:

1. **At S1, probe for keygen specifically** — not "is Ed25519 present." Presence of sign/verify tells
   you nothing about whether you can mint an identity.
2. **On such a substrate, treat the public key as part of the identity** — derive it once and carry it.
   Exposing a `sign(seed, msg)` convenience silently makes every signature pay a full keygen.

## 5. Two more things the sweep taught us

**Canonical CBOR is harder to source than cryptography.** This is genuinely counterintuitive and it is
the most reliably reproduced result in the project. Ed25519 is available in some form to most of the
cohort. **Canonical-ECF CBOR is available to none of it.** No platform library suffices — not Rust's
`ciborium`, not .NET's `System.Formats.Cbor`, not Haskell's `cborg`, not Julia's `CBOR.jl`, not Odin's
canonical-*aware* `core:encoding/cbor`. Every single peer hand-rolls the shortest-float ladder,
recursive major-type-6 tag rejection, and length-then-lex key sorting on top of whatever it had. A
mature ecosystem will hand you elliptic-curve signatures and leave you to write your own deterministic
serializer. That asymmetry is why the FFI codec exists and why a from-spec C codec was a reasonable
thing to build.

**Execution mode is part of the crypto contract on interpreted substrates.** §5.2 verifies *every*
request — two Ed25519 verifies per request, deliberately, for forwardability and content-addressed
caching. On any compiled substrate that is microseconds and invisible. On an interpreted one it
dominates everything: WasmEdge's interpreter runs one verify in **~9 ms**; its JIT runs the same verify
in **~84 µs** — a 109× difference that is the entire margin between passing and timing out on the
§6.11 sustained-load probe. For `wasm-wat` the JIT flag is therefore not a tuning knob, it is part of
the peer's documented conformance contract. The tempting fix — cache the auth verdict per connection —
is specifically forbidden by the oracle, which flips an author signature on a warm connection and
expects a 401. Per-request verification is mandatory; if your substrate is slow at it, that is a
substrate problem to solve, not a check to route around.

## 6. What we would tell someone provisioning crypto for a new peer

1. **Ask for keygen, sign, verify, and SHA-2 separately.** They are not a package, and Unison proves the
   gaps are real.
2. **Trace your library down to the primitive.** "My language has a crypto package" usually means "my
   language binds libsodium." Know whether you are adding diversity or a fourth wrapper around the same
   C.
3. **Check Ed448 before you promise agility.** If your provider is libsodium, the answer is no today,
   and no amount of language-side work changes it.
4. **Budget more for canonical serialization than for signatures.** Every peer in this cohort did.
5. **On an interpreted or managed runtime, measure a verify before designing the request path** — and
   check whether a C-FFI hatch exists *at all* before assuming it is your fallback.

## See also

- `CONFORMANCE-MATRIX.md` §1 — the per-peer codec / crypto floor / agility columns this document
  summarizes; the authoritative source for any single peer.
- `ffi-generator/c-abi/spec/` — the C-ABI contract, its two implementations, and the `ec_ed448_*`
  validated-not-required language quoted in §3.
- `research/PEER-ATLAS.md` — the whole cohort mapped by substrate axis, of which crypto is one.
- `research/SUBSTRATE-TAKEAWAYS.md` §2 — crypto-as-a-spectrum in its operational form.
- `AGENTS.md` → "Durable cross-language lessons" — the per-case operational version of these rules.
