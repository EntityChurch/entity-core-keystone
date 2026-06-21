# entity-core-protocol-ada — Profile Rationale

Audit trail for every major S1 profile choice. Ada is **peer #10** (canonical order;
parallel cohort with the C peer), and the **safety-critical / strong-typing** member of
the batch. It carries the two most-DISTANT idiom axes remaining — **tasks + protected
objects + rendezvous** concurrency and **design-by-contract** — neither exercised by any
prior peer. Each choice below was derived from the V7 spec-data/v7.75 snapshot + Ada/GNAT
ecosystem research, **not** ported from the prior nine peers. Where a value matches a
prior peer it is by **independent arrival** from V7 + the Ada/GNAT toolchain.

## Why Ada is a worthwhile probe — and the honest caveat

The spec-discovery well is **dry**: 8+ independent prior peers found no new defect on the
v7.75 surface, and the wire-touching axes (integer/float/crypto/string) are saturated.
The bar for this peer is therefore a **clean, complete, correct S1 profile that lets
S2–S5 reach 576 · 0 FAIL · 89 skip GREEN** — not a hunt for invented ambiguities.

That said, Ada brings genuinely-new idiom axes:

- **Concurrency** — Ada's **tasks + protected objects + rendezvous** is a first-class,
  in-language concurrency model. No prior peer used it (the cohort spanned BEAM actors,
  STM, GHC green threads, raw OS threads, JVM virtual threads, goroutines, cooperative
  async). The §4.8 data-race-safe store maps *naturally* onto a **protected object** —
  language-enforced mutual exclusion, no lock to forget. This is the centerpiece finding.
- **Design-by-contract** — `Pre`/`Post`/`Type_Invariant`/`Predicate` aspects (Ada 2012+),
  compiler/runtime-checked. The static-rigor analogue of Zig's error sets and Java's
  checked exceptions, via a mechanism no prior peer had.
- **Strong typing** makes the A-JAVA-010 `data`-model decision *pointed*: modeling
  `data` as a discriminated variant (not a map) is a type-level decision the compiler
  enforces.

If anything genuinely new surfaces in this batch, it most plausibly comes from here — but
it is **gravy, not the goal**, and is logged honestly only if real.

## Codec strategy: native (libsodium-C-binding crypto, hand-rolled canonical CBOR)

`research/LANDSCAPE.md` places Ada in the distant-idiom backlog. Research lands it as
**native**, the same A-005 pattern every prior native peer hit, in two halves:

1. **No Ada CBOR library gives ECF canonicality** — and the Ada ecosystem has no mature
   canonical-CBOR library at all. Even a general-CBOR Ada lib would leave the
   ECF-specific guarantees — **RFC-7049 length-FIRST then lexicographic** map-key ordering
   on encoded key bytes (which DIFFERS from RFC-8949 §4.2 bytewise ordering), the
   shortest-float ladder (incl. f16), recursive major-type-6 tag rejection, full
   uint64/nint range, and raw-byte fidelity — entirely to the peer. This is the
   reality-check-on-native rule (PHASE-S1-PROFILE): "native" means the primitives +
   crypto are native, not that canonicality is free. So **hand-rolling the canonical
   layer is the faithful AND simpler path**. Ada's strong typing +
   `Ada.Streams.Stream_Element_Array` / `Interfaces.Unsigned_8` make a tight byte-walking
   encoder/decoder idiomatic.

2. **Crypto is NOT native to Ada's predefined library** (no Ed25519/SHA-256 in the
   stdlib). It is sourced via a **libsodium binding over Ada's strong C interop**
   (`Interfaces.C` + `pragma Import, Convention => C`) — the cleanest, most-audited crypto
   source for Ada (a thin, well-typed binding, not a re-implementation). libsodium is
   already in the base image (`libsodium-devel`).

`ffi` (consume `libentitycore_codec` over the C-ABI) is the documented fallback and is
**not expected**: the canonical CBOR hand-roll is small and well-understood across nine
prior peers, and the libsodium binding already supplies native crypto, so a full FFI codec
buys nothing. **Codec spike at S2** (PHASE-S1 mandate): push the `map_keys` + `float`
v7.71 vectors through the hand-rolled encoder and assert byte-identity before the full
build — the load-bearing canonical risk (length-then-lex ordering + shortest-float f16).

Net: the **core peer has ONE runtime dependency** — system libsodium (a universal, audited
shared library), via a thin C binding. CBOR + base58 + varint are hand-rolled; no Alire
crates. This ties Zig/Elixir/Java for the lightest supply-chain in the cohort, achieved
here via the distro toolchain + a system crypto library.

## CBOR: hand-rolled (no Ada library)

As above. The encoder appends to a growable byte buffer
(`Ada.Streams.Stream_Element_Array` or a bounded/unbounded byte vector); the decoder is
index-walking over a `Stream_Element_Array` slice. The canonical rules are owned in-code:
length-then-lexicographic map ordering on encoded key bytes, the shortest-int and
shortest-float ladders, definite lengths only, recursive major-type-6 tag rejection.
**Ada advantage (no unsigned trap):** Ada has native **modular (unsigned) integer types**
(`Interfaces.Unsigned_64`), so the full uint64 head-form range is native — *unlike* the
C# `ulong` / Java `long` trap (no native unsigned) that those peers had to work around
with `compareUnsigned`. The codec uses `Interfaces.Unsigned_8/16/32/64` for wire scalars.

## Crypto: libsodium via Interfaces.C (Ed25519 + SHA-256)

The §9.1 floor needs only **Ed25519 + SHA-256**, both provided by libsodium:
`crypto_sign_seed_keypair` (seed→keypair), `crypto_sign_detached` /
`crypto_sign_verify_detached` (sign/verify), `crypto_hash_sha256` (content hash). The
binding is a thin Ada spec over the libsodium C ABI (`pragma Import, Convention => C`),
RFC-8032-deterministic by the algorithm. **Ada-specific advantage over the Java peer's
crypto wrinkle:** libsodium returns the **raw 32-byte public key directly** from
`crypto_sign_seed_keypair` — there is **no point-encoding extraction step** (contrast the
JDK EdEC `(sign-bit, y-coordinate)` point the Java peer had to decode). So the raw-pubkey
the §1.5 identity-multihash peer_id needs is in hand immediately.

## Ed448 / SHA-384: deferred to the agility overlay (libsodium gap; core floor unaffected)

The crypto-agility **higher bar** (v7.67: key_type Ed448 `0x02`, content_hash_format
SHA-384 `0x01`) is **not reachable from libsodium** — libsodium has **no Ed448** and ships
**SHA-256 + SHA-512 only (no SHA-384)**. This is the SAME gap OCaml (A-OC-002, sourced
Ed448 over the C-ABI) and Zig (A-ZIG-002, a flat gap) hit. **Default position for v0.1:
the §9.1 CORE FLOOR (Ed25519 + SHA-256) only, which libsodium fully covers — the Ed448 +
SHA-384 agility higher bar is DEFERRED.** When taken, the agility overlay comes via the
`libentitycore_codec` C-ABI agility surface (the OCaml precedent) or an OpenSSL
`curve448` + SHA-384 binding (`openssl-devel` is already in the base image; likely the C
peer's route too) — **not** from libsodium. The core gate (576 · 0F · 89 skip) does **not**
require Ed448/SHA-384, so this defer is non-blocking. Logged **A-ADA-002**.

## Base58 + varint: hand-rolled

Both are small and dependency-free. Base58 (Bitcoin alphabet, encode+decode, ~80 lines)
for peer_id; multicodec-style LEB128 varints (`Interfaces.Unsigned_64` + shift/mask) for
the format-code / key-type / hash-type framing (§7.3). Hand-rolling dodges two Alire deps
and matches the dependency-minimization stance (the cohort precedent).

## Error model: exceptions + design-by-contract (the static-rigor seam)

Ada's idiomatic error mechanism is the **exception** (`raise` / `exception` handler) with
user-defined exceptions per failure class — the C#-family shape — **paired** with the
distinctive Ada seam: **design-by-contract**. `Pre`/`Post`/`Type_Invariant`/`Predicate`
aspects (Ada 2012+), enforced by the compiler/runtime, guard the INTERNAL invariants: a
`Content_Hash` is exactly 32 bytes (`Type_Invariant`), a canonical buffer is well-formed
(`Post` on the encoder), a `Peer_Id` is a valid multihash. This is a compiler/runtime-
checked rigor seam **no prior peer exercised** — the static analogue of Zig's error sets
and Java's checked exceptions, via a different mechanism. **SPARK formal proof is OUT OF
SCOPE for v0.1** (noted, not used): the contract aspects are used as **runtime-checked
guards**, not discharged as proofs (SPARK is plausible future work but overkill for v0.1).
Protocol-status failures map an exception subtype → status code at the dispatcher boundary:
`Codec_Error` → 400 `non_canonical_ecf`; `Authentication_Error` → 401;
`Authorization_Error` → 403; `Chain_Depth_Exceeded_Error` → **400** (not 403, §4.10(b));
`Payload_Too_Large_Error` → 413. Hierarchy in `profile.toml [error_model]`.

## Concurrency: tasks + protected objects + rendezvous (the centerpiece — distinct from every prior peer)

THE standout idiom axis. Ada has **first-class, in-language** concurrency:

- **Tasks** — the unit of concurrency (≈ a thread, but a language construct with
  rendezvous entries).
- **Protected objects** — data + the operations that serialize access to it, with
  condition-synchronization via **entry barriers** (a monitor, in the language).
- **Rendezvous** — synchronous task-to-task entry calls.

This is structurally distinct from every prior cohort shape (BEAM actors, STM, GHC green
threads, raw threads, JVM virtual threads, goroutines, cooperative async).

**§4.8 data-race-safe store → protected object.** The content store + tree index live
inside a **protected object** (or sharded protected objects): reads are protected
*functions*, writes are protected *procedures*. Mutual exclusion is enforced **by the
language** — no lock to forget, no map to race. The protected object *is* the data-race-
safety guarantee §4.8 demands, and it is the **cleanest store-safety story in the cohort**:
the two store-race fall-over bugs that drove §4.8 into the v7.75 floor (Zig double-free,
CL read-race — see `concurrency-gate-7b-results`) are **structurally unrepresentable**
behind a protected object. Recorded in `[concurrency].store_safety = "protected-object"`.

**§4.9 resilience / §6.11 reentrancy.** One **task per connection** (or a bounded task
pool fed by a request queue); the request_id ↔ continuation correlation (N7) is a
protected-object demux map. Inbound-concurrent-with-outbound (N6/N7) is the natural Ada
task shape. **Cooperative-pool caveat (the brief's "no blocking syscalls on a cooperative
pool"):** GNAT maps Ada tasks to OS threads, so a blocking socket read in one task does
not stall others under one-task-per-connection; but if a bounded pool is used, socket I/O
must stay per-task / non-blocking. **TCP_NODELAY** is set on accepted sockets (the Zig
§7b finding — disable Nagle so small `EXECUTE_RESPONSE` frames flush promptly). The codec
(S2) is pure/synchronous; concurrency enters at the peer (S3). The protected-object store
is fixed now; one-task-per-conn vs bounded-pool is an S3 decision (A-ADA-006).

## Data model: discriminated variant for the ECF value (A-JAVA-010, made pointed by strong typing)

**A-JAVA-010 inherited and made load-bearing here.** §1.1 entity `data` is an **arbitrary
ECF value — NOT necessarily a map.** A map-only model passes S2/S3 green then **500s on the
first scalar-data entity** at the live S4 gate (the silent-500 trap). Ada's strong, static
typing makes this decision *especially* consequential: `data` MUST be modeled as a
**general ECF value** from the start — a **discriminated record / tagged-type variant**
over the full ECF value space (uint, nint, bytes, text, array, map, bool, null, float,
simple; tag rejected), **NOT** an `Ada.Containers` map. The codec's ECF value type IS this
discriminated type, and an entity's `data` field is one such value. Modeling `data` as a
map would be a type-level mistake the compiler would happily accept and that only the live
oracle would catch. Recorded in `[data_model]`; this is the single decision most likely to
bite at S4 if gotten wrong, so it is pinned now.

## peer_id construction: §1.5 canonical-form table, NOT §7.4 (verified in spec-data/v7.75)

The profile **mandates** deriving the Ed25519 peer_id from the **§1.5 canonical-form
table** — `hash_type = 0x00` identity-multihash, digest = the **raw public key bytes** (no
hash) — and **ignoring the stale §7.4 / §1.5-skeleton `SHA256(public_key)` form**.
**Verified directly in `spec-data/v7.75`:** `ENTITY-CORE-PROTOCOL-V7.md` **line 459** (the
§1.5 canonical-form table) declares `0x01 Ed25519 → 0x00 identity-multihash … The digest
IS the public_key (v7.64)`. The v7.73 closeout (header §E1) records that §7.4 was
reconciled (parameterized over `key_type`, deferring to the §1.5 table) precisely because
its pseudocode was the stale SHA-256 form. **Five+ prior spec-first peers (Zig A-ZIG-001,
OCaml A-OC-007, CL A-CL-002, Java A-JAVA-004 …) corroborated this — it is SETTLED.** Baking
the §1.5 form in proactively dodges the `401 identity_mismatch` handshake failure that S2's
opaque-digest corpus would NOT catch (a wrong construction passes S2 and only blows up at
the S4 handshake). libsodium hands back the raw 32-byte pubkey directly, so the
construction is trivial here. Pre-resolved in the ambiguity log (A-ADA-001).

## Resource bounds (§4.10) + the 400-chain-depth structural pre-check (verified in spec-data/v7.75)

The v7.75 `resource_bounds` category gates §4.10, now a §9.1 floor MUST (verified in
spec-data/v7.75, lines 1933–1935, 1950–1951, 4036, 4092):
- **r1 — max inbound payload (MUST):** over-`max_payload` → **`413 payload_too_large`**
  (default 16 MiB, informative) + keeps serving; reject before fully buffering/decoding
  where the transport allows (allocation-safety, the §4.9 no-crash class).
- **r2 — max capability-chain depth (MUST):** over-`max_chain_depth` →
  **`400 chain_depth_exceeded`** — **MUST be 400, NOT 403** (a too-deep chain is structural
  excess, not an authz denial; 403 would conflate "too deep" with "you lack the
  capability"). Default 64 (informative). S3 must build the **~15-line §4.10(b) chain-depth
  STRUCTURAL pre-check** (walk parents, no signature work, max = 64, BEFORE the authz walk)
  — all prior peers needed it.
- **r3 — connection flood (SHOULD):** `503 too_many_connections` or a clean close, or an
  honest WARN — §4.10(c) is a SHOULD with an external-layer carve-out (admission is
  systemd/proxy/OS-fd territory; scored WARN, not FAIL).

These map onto the Ada error model (`Payload_Too_Large_Error` → 413,
`Chain_Depth_Exceeded_Error` → 400) and are pre-resolved in the ambiguity log (A-ADA-007).

## §5.2 verdict trichotomy: 401 / 403 / 401-unresolvable (verified in spec-data/v7.75)

The §5.2 `verify_request` verdict is the five-peer-convergent **401 (authn) / 403 (authz)
/ 401-unresolvable** trichotomy (spec-data/v7.75 §E2 records the v7.73 fold of the three-way
`ALLOW` / `AUTH_DENY` / `AUTHZ_DENY` verdict + the §5.2a verdict-to-status enumeration).
Settled; pre-resolved (A-ADA-008).

## Naming: Ada-native Mixed_Case_With_Underscores — and the hex-case pin

Ada identifiers are **case-insensitive**; the idiomatic rendering (GNAT / Ada Quality &
Style Guide) is `Mixed_Case_With_Underscores` for types, subprograms, variables,
constants, packages, and enum literals (Ada has **no** screaming-snake idiom — constants
are Mixed_Case too, unlike Java/C). File names follow the GNAT default (unit name
lowercased, `.` → `-`: `entity_core-protocol.ads`). **HEX-CASE PIN (the A-CL-009 lesson
applied PROACTIVELY — load-bearing for Ada):** all external string/byte hex rendering MUST
be **lowercase** to match the Go oracle (`hex.EncodeToString`) and the cohort. **Ada's hex
builtins DEFAULT to UPPERCASE** — `Integer'Image`, the `16#..#` based-literal form, and the
common `Ada.Text_IO.Integer_IO` `Base => 16` output all emit `A-F`. The §3.4/§3.5 tree-path
keys (`system/signature/{hash}`, `system/capability/revocations/{hash}`) and §6.9a policy
paths are **case-sensitive string keys** keyed by lowercase hex; an uppercase hex helper
passes Ada-to-Ada loopback but **404s** against the lowercase oracle — EXACTLY the
A-CL-009 trap CL hit (its `~x` defaulted uppercase), and the **CL log explicitly names Ada
hex builtins as the same risk**. **PIN:** the codec's hex helper emits lowercase `a-f` via
a custom nibble→char table, NEVER `Integer'Image` / `Integer_IO` with `Base => 16`.
Recorded in `[naming].hex_case` and `[idiom].hex_lowercase_pinned`; logged A-ADA-003.

## Build / test / packaging: gprbuild + hand-rolled runner + Alire (optional S5)

**gprbuild** (with a GNAT project file, `entity_core_protocol.gpr`) is the
toolchain-native Ada build system (the gcc-gnat companion driver; Alire's `alr build`
wraps it). Chosen **over** Alire-as-the-build-driver to keep the container **offline +
dependency-minimal**: the core peer has **no Alire crate dependencies** (crypto =
libsodium C binding, CBOR/base58/varint hand-rolled), so gprbuild against a committed `.gpr`
needs no registry resolve at all — the dnf-installed GNAT + gprbuild + libsodium-devel are
the whole toolchain, and the dev loop runs fully offline under `--network=none`. The
**test/conformance runner is hand-rolled** (a small Ada main that loads the normative
fixture vectors and asserts byte-identity) rather than **AUnit** (the Ada xUnit), which is
a separate Alire/library dep — the cohort's dependency-minimization stance (Zig/OCaml/CL
hand-rolled their harness) applies cleanly, and "load fixture → assert bytes" needs no
framework. **Alire** (the Ada Library Repository) is noted as the ecosystem package
registry and the optional S5 distribution channel (crate `entity_core_protocol`,
lowercase_with_underscores), but is NOT required for the core build (A-ADA-004, A-ADA-005).

## License: Apache-2.0 (S9 default)

The FSF-GNAT *compiler* is GPL-with-runtime-exception, but the toolchain license does not
bind the **generated peer** — the repo's Apache-2.0 default stands for the output (explicit
patent grant retained). No override.

## Toolchain pins (S11)

> **S2 pin re-capture.** The NVRs below were captured by `rpm -q` inside the
> built `ada-toolchain` image (`/opt/ada-toolchain-versions.txt`). Two S1-draft values were
> corrected: `gcc-gnat`/`gcc` `-2.fc43` → the real Fedora 43 release `-7.fc43`, and
> libsodium `1.0.20` → `1.0.22-1.fc43` (fedora:43 ships only 1.0.22; conformance-neutral —
> the high-level `crypto_sign_*` / `crypto_hash_sha256` APIs are byte-identical between the
> two). See `status/PHASE-S2.md` for the capture.

- **GNAT (FSF GCC-Ada) — `gcc-gnat-15.2.1-7.fc43`.** GCC 15.2
  (~10 months old at authoring) — comfortably clears the ≥30-day
  cool-down. GNAT 15.2 has full Ada 2012/2022 + contract-aspect support (the
  `Finalizable` aspect and other 2022 features landed in GCC 15). The Fedora 43 distro
  channel is a **reviewed vendor channel** (Fedora's packaging/review, the OS-package
  analogue of the .NET/Temurin feeds), so the exact NVR pin stands for reproducibility and
  the age floor is cleared by the release dates. Chosen over an AdaCore Alire-distributed
  GNAT (`gnat_native`) or a from-source build because the distro package **matches the
  fedora:43 base exactly**, needs no tarball/sha juggling, and keeps the toolchain
  consistent with the base image's existing `gcc`/`gcc-c++`/`libsodium-devel`.
- **gprbuild — `gprbuild-25.0.0-5.fc43`** (dnf-installed alongside gcc-gnat). Exact NVR
  captured at the S2 build from the image's dnf metadata. Distro channel, same rationale.
- **libsodium `1.0.22-1.fc43`** — Ed25519 + SHA-256. Fedora 43 ships **only** 1.0.22
  (`libsodium-devel-1.0.22-1.fc43`; already in `containers/base/Containerfile`). System
  shared library, consumed via an `Interfaces.C` binding. **No Ed448 / no SHA-384**
  (agility-overlay-only; A-ADA-002). The `openssl-devel-3.5.4-3.fc43` headers are present
  for the deferred agility overlay only, not the core floor.
- **Fedora 43** — the base image OS and the toolchain channel; matches
  `containers/base/Containerfile`.
- **No Alire crates.** No CBOR/base58/varint/test-framework packages — all hand-rolled.

## Spec version: read v7.75, codec corpus v0.8.0

Profile + (future) peer derive from `spec-data/v7.75` (the latest snapshot — the
current-state menu items were verified directly in it at S1, see PHASE-S1.md). The codec
uses the `test-vectors/v0.8.0` corpus (the latest test-vectors snapshot) because
`ENTITY-CBOR-ENCODING.md` is **byte-stable across v7.71→v7.75** (no wire-format change in
the v7.72–v7.75 folds — resilience/resource-bounds are peer-layer, not codec; the cohort
SHA-verified the byte-stability). So the v0.8.0 corpus is valid at v7.75. The canonical core
gate at v7.75 is **`validate-peer --profile core` = 576 · 0 FAIL · 89 skip** (includes the
`concurrency` + `resource_bounds` categories). The §7a validate handlers + §7b
concurrency/resilience gate come from GUIDE-CONFORMANCE.md + the generator menu (NOT
spec-data); Ada picks them up at S3/S4.
