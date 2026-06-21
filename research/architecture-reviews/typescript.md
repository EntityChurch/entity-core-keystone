# Architecture review — entity-core-protocol-typescript

Running dev log for the **second** generated peer. Composition choices, the
C#→TypeScript idiom deltas, and the standing input to architecture. Companion to
`csharp.md` (peer #1). The thesis this peer tests: **does a faithful peer#1→peer#2
port, into a structurally different runtime, reach the same oracle fixed point?**
The answer, at S4, is **yes — identically.**

---

## Headline (S4)

`validate-peer --profile core` (oracle `cb54f5b`, v7.72 §9.0):
**`552 total · 269 pass · 194 warn · 0 fail · 89 skip` → PASS.**

This is the **byte-for-byte same scoreboard** the C# peer reached after a multi-block
S4 grind (nonce-echo, multisig, type registry, handler interface, the §9.0 carve-out
triage, the F21/F22 oracle-bug round-trip). TypeScript reached it on the **first**
validate-peer run, **zero code fixes**. The only S4 work was scaffolding
(`test/host.ts`, `run-s4.sh`) and closing the one precursor (A-006).

That delta — peer #1 needed iteration + two oracle-bug escalations to *discover* the
core verdict; peer #2 *inherited* it — is the keystone working exactly as designed.
The hard-won knowledge (what's core, what's extension over-demand, which status codes,
the §9.0 profile) is now encoded in the reference peer and the findings log, and the
second peer pays none of that cost.

## Why C# was the architectural template (and it held)

Per the user's read: C# and TypeScript are close enough — both broadly-used,
gradually-typed-ish OO/structural languages that have converged in idiom over the
years — that the C# peer's *structure* (file decomposition, the §6.5 dispatch chain,
the Layer-1 chain verifier, the handler/dispatcher boundary, the N4–N8 invariant
placement) ports almost 1:1. It did. The port was **file-for-file**, not a
re-derivation from V7. **Payoff signal: zero new spec ambiguities surfaced at S3 or
S4** — the same §5.5 chain verdict, §6.5 order, §4.1 leg-ordering, and §9.0 core/
extension split survived the runtime change with no semantic surprises. That is
evidence the reference peer's behavior is genuinely **spec-shaped**, not C#-shaped:
if it had encoded a C#-ism as protocol, the TS port would have forced a divergence and
the oracle would have caught it. Neither happened.

## The cross-language deltas (where the runtime *did* force a translation)

These are the points a future profile/generator must know are *idiom*, not protocol —
the seams where "same behavior" required different machinery:

| Concern | C# (peer #1) | TypeScript (peer #2) | Same behavior because |
|---|---|---|---|
| Integer surface | `ulong`/`long` | **`bigint` end-to-end** (R1) | full u64 range, no 2⁵³ truncation; codec minimal-length identical |
| Wire bytes | `byte[]` / `Span` | `Uint8Array` | N4 verbatim splice preserved both sides |
| Handshake ordering | `TaskCompletionSource` | **`Deferred<T>`** (promise + external resolve) | JS continuations are always async → §4.1 leg-ordering automatic |
| Concurrency guards | `SemaphoreSlim`, `ConcurrentDictionary` | **promise-chain mutex, `Map`** | single-threaded event loop has no preemption between `await`s → the C# locks *collapse*, not port |
| Inbound framing | `Stream` + `ReadExactlyAsync` | **async generator over `node:net` chunks** | the one Node-coupled corner; codec/crypto stay pure-JS, browser-portable |
| CBOR codec | `System.Formats.Cbor` (Ctap2) | **hand-rolled zero-dep core** (A-005) | `cborg` can't type-distinguish float `1.0` from int `1`; a faithful ECF value model must carry an explicit float node anyway |
| Crypto | NSec (libsodium) + BouncyCastle Ed448 | **`@noble/curves` + `@noble/hashes`** | RFC 8032 determinism → byte-identical signatures on fixed seeds |

The load-bearing observation for architecture: **every one of these is a library/
runtime idiom the *profile* owns (S6), and none of them touched protocol semantics.**
The spec surface and the idiom surface stayed cleanly separated across two very
different languages. That's the cleanest possible evidence for the three-layer prompt
design (constants / phase / profile).

## What the peer is composed of

L1–L4 + foundation over the S2 codec, ~4.4k lines: `model` (Entity 3-field wire /
2-field hashable N4, Envelope N5), `identity` (peer-id §1.5/§7.65, system/peer v7.65
projection), `capability` (Scope/GrantEntry/Token + multi-granter, Attenuation §5.6/
§5.7, the deterministic Layer-1 ChainVerifier §5.5/§5.10), `store` (CAS + listing
§3.9), `handlers` (connect §4 / tree §6.3 / capability §6.2, HandlerRegistry §6.6
tree-walk), `dispatch` (the §6.5 chain), `transport` (FrameCodec §1.6, reader-loop
demux N6/N7, §4.1 handshake both directions), `types` (the 53-type core registry).

## S4 conformance read (all core checks green)

Per-category: connectivity 22/22 · encoding 6/6 · type_system 108/302 (194 warn =
non-floor types, **0 core fail**) · handlers 25/57 (32 skip ext) · capability 12/12 ·
tree_operations 25/56 (31 skip EXTENSION-TREE) · security 22/23 · multisig 10/10 ·
universal_address_space 8/8 · peer_canonicalization 7/7 · format_agility 10/10 ·
crypto_agility 4/4 · negotiation 4/4 · authz 6/8 (2 skip ROLE).

- **A-006 (type registry) — 53/53 byte-identical first run.** The single biggest "did
  the port preserve the bytes?" risk. It did: every core type's ECF render is byte-for-
  byte the Go render. This is *why* type_system landed clean — the precursor de-risked
  the category before the live run.
- **F23 (new) — `origination` is outside `--profile core`.** Our own lifecycle gate
  doc (`PHASE-S4-CONFORMANCE.md`) lists origination as "required for v0.1, extension-
  free"; the v7.72 §9.0 oracle auto-allowlists it as extension-only. Proven by running
  it under the full profile with the Go `entity-peer` as `-reference-peer`: the
  outbound-dispatch legs (`reference_connect`/`reference_ready`) pass; the rest is
  ASYNC §1 / NETWORK §10 extension over-demand. Peer is correct; **our doc is stale**
  (it predates the §9.0 profile). → fix the keystone lifecycle doc, no V7 change.

## What this teaches architecture (the feedback)

1. **The core-profile (F18) is validated by a second, independent peer.** The §9.0
   `--profile core` machinery — F18's ask — now yields a clean machine PASS for two
   structurally-different peers with no hand-maintained scoreboard. The §9.0 profile is
   doing its job. (Arch: F18 can move toward closed once the profile is blessed as the
   canonical core gate; F23 asks the keystone to retire its hand-listed gate in favor
   of it.)
2. **No new V7 ambiguity from a second language.** Two peers, two runtimes, one spec
   read — and the second surfaced *zero* new spec gaps. Either the spec is genuinely
   tight at the core surface, **or** peer#2-from-peer#1 derivation is too conservative
   to stress new corners (it inherits peer #1's interpretations wholesale). Both are
   true and worth stating: the *convergence* is strong evidence of spec tightness, but
   the *next* peer should be derived **spec-first in a distant idiom** (a non-OO, non-
   exception language — Rust/Haskell/Erlang) to actually re-probe the spec rather than
   re-confirm the C# reading. That is where the next ambiguities will come from.
3. **The idiom/protocol seam is clean.** Every cross-language delta above lived in the
   profile layer; none leaked into protocol behavior. Strong support for the three-
   layer prompt split and for letting the profile (not the agent, S6) own library/async/
   error-model choices.

## Packaging & publishing review (npm)

Reviewed ahead of S5 (we are **not** publishing yet — see the cross-language
publishing-seam review for the seam decision).
npm specifics for this peer:

- **Consumable artifact ≠ this dir.** A published package is `dist/` (compiled JS +
  `.d.ts`) + README + LICENSE. **Concrete gap:** `package.json` has no `files`
  allowlist, so `npm pack` today would ship `src/`, `test/`, `status/`, `run-s4.sh` —
  the whole workspace. S5 adds `files: ["dist"]` + an `exports`/`types` map. ESM-only
  (`"type": "module"`).
- **Publish path (S11-aligned):** **OIDC trusted publishing** from GitHub Actions —
  no `NPM_TOKEN`, npm CLI ≥ 11.5.1, `id-token: write`, cloud runner. **Provenance is
  auto-generated** (profile `provenance = true` satisfied with no flag) **iff the repo
  is public.** That public-repo requirement is the forcing function behind the seam
  question.
- **Naming (A-002):** `@entity-core/protocol` (needs the free `@entity-core` org;
  cleaner, pairs with a future per-repo lift) vs unscoped `entity-core-protocol-
  typescript`. Open.
- **Consumer story:** `npm install … && import { Peer }`. Differentiator vs peer #1:
  codec + crypto are **pure-JS → browser-portable**, so a browser bundle is a viable
  later artifact (the consumable-data-library use case from S1).
- **Account/signup:** npmjs.com, 2FA mandatory; configure the trusted publisher
  pointing at the repo+workflow. No long-lived secret stored.

## S5 watch list (next — when/if we publish)

README (lead with "this is generator output — to contribute, work in the keystone;
to try the protocol in your ecosystem, here you go") + license (Apache-2.0, S9) +
CHANGELOG (pin **spec version** + conformance report, not source — S8) + the `files`
allowlist + npm scope (A-002) + profile `cbor_library` note (A-005) + Podman CI.
Lockfile + S11 pins already in place. No conformance work remains for v0.1.

*Append the next phase below.*
