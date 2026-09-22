# A superseded corpus duplicate answered for a year, and the peers that transcribed it passed

**Date:** 2026-09-02
**From:** entity-core-keystone
**Spec:** `ENTITY-CORE-PROTOCOL` §4.5a item 1a (`system/peer` is floor-pinned)
**Corpus:** `crypto-agility`, `agility-vectors.cbor` `b5484e84…` (current) vs `8e7c5232…` (retired)
**Status:** four peers fixed and re-measured · one predicted-failing and unmeasurable here · one
spec-behaviour gap left open and named

---

## One sentence

Removing a version-stamped **duplicate** of the crypto-agility corpus — a job that looked like
directory-naming hygiene — exposed that the duplicate's *vector semantics* had been superseded
upstream, that two peers were computing a `system/peer` `content_hash` the spec forbids, and that
two more peers were passing the same defect **because they had transcribed the retired values into
their own source** instead of loading the corpus.

## What made it invisible

`protocol-generator/shared/test-vectors/` held both `v0.8.0/agility-vectors-v1.cbor` (`8e7c5232…`)
and `crypto-agility/agility-vectors.cbor` (`b5484e84…`). The second is byte-identical to
architecture's current fixture. The first is a **retired** copy of the same corpus, and the peers'
harnesses still pointed at it.

**Nothing failed while both existed.** Every peer reading the old path got the old bytes and agreed
with them. The de-versioning required by `GUIDE-CONFORMANCE.md` §5.1 — *"a corpus is identified by
its name, never by a version stamp"* — is what forced the two into one, and the disagreement
appeared on the first run afterwards.

This is the standing **stale-input** class with a new carrier. Every prior instance in this repo was
a stale *artifact* (a `.wasm` older than its source, a reverify overlay older than the census it
overrode, a tracked report a pin behind). This one is stale **vendored data**, and it is worse in one
specific way: an old build artifact is at least *derived* from something in the tree, so a rebuild
reconciles it. A vendored corpus reconciles with nothing — it is authoritative by construction, and a
second copy of it is a second authority.

## What actually changed upstream

Measured by diffing the two `.diag` files, not by reading either changelog:

| | Retired | Current |
|---|---|---|
| `hash-format-sha-384.2` | asserts the re-hash **succeeds**, pinning `012e64bbde…3eef5a69` | asserts the construction is **refused** |
| `matrix.M3.peer_a.content_hash` | `0166f421…` (49 B, SHA-384 form) | `00af37ab…` (33 B, floor) |
| `matrix.M6.peer_a.content_hash` | `01ef28f9…` (49 B, SHA-384 form) | `00848e20…` (33 B, floor) |
| Ed448 seed width | 58 B | 57 B (RFC 8032) |
| `0xAA` fixture pubkey | 63 B | 64 B |

The cause is one rule. **`system/peer` is the one type with no home format**: §4.5a item 1a pins the
identity entity to the ECFv1-SHA-256 floor unconditionally, because its data is wholly recoverable
from the public peer-id, so an entity nobody fetches to learn its hash cannot be hold-and-fetch.
Every identity reference therefore resolves floor-form — including `granter.hash` for M3 and M6.

Upstream's own note on the retired vector is the sharper half, and it is quoted here because it names
a failure shape rather than a value:

> This vector previously asserted the OPPOSITE — that the rehash succeeds, pinning
> `canonical_content_hash 012e64bbde…` — and stayed green only because the verifier hand-built the
> entity instead of routing through the constructor that would have refused it. **A fixture that
> exercises a forbidden construction and passes by bypassing the code that forbids it certifies the
> opposite of the rule** (`GUIDE-CONFORMANCE` §2.4a failure shape).

## The measurement

| Peer | Reads the corpus? | Before | After |
|---|---|---|---|
| `elixir` | yes, by path | **FAIL** 2 gates (M3.A, M6.A) | PASS — 28 tests, 0 failures |
| `ruby` | yes, by path | **FAIL** 2 gates (M3.A, M6.A) | PASS — 37 runs, 71 assertions, 0 failures |
| `ocaml` | **no — transcribed** | **PASS 25/25** | PASS 24/24 (one assertion withdrawn) |
| `csharp` | **no — transcribed** | **PASS** | PASS 23/23 |
| `haskell` | yes, by path | not measurable here | **predicted FAIL**, see below |

`elixir` and `ruby` each reported the same two gates with the same values —
`got 0166f421…, want 00af37ab…` — i.e. **the peers were computing the SHA-384 form**. The fix in both
is the same three lines: stop threading `home_content_hash_format` into the `system/peer` hash and
pin it at the floor.

## The part worth carrying: a transcribed pin makes a harness compare the peer to itself

`ocaml` and `csharp` do not load the corpus. They carry hand-transcribed constants — including
`012e64bbde…`, `0166f421…` and `01ef28f9…`, all three retired. Both peers **passed**, `ocaml` at a
confident `RESULT: PASS (25/25)`, while carrying the *identical* defect that made `elixir` and `ruby`
fail.

They passed because the peer computed the SHA-384 form and the test expected the SHA-384 form. That
is not a conformance check; it is a **self-consistency check**, and this repo has met that shape
before in a completely different place — `oracle-bootstrap.sh` once compared an installed oracle's
provenance against itself and printed *"matches BOTH … nothing to do"* three lines after warning that
the digest differed from the committed pin. The rule was written then and applies verbatim here:
**always name the authority side of a comparison, and be suspicious of any equality test whose two
operands derive from the same source.**

The corollary is the operational one: **a transcribed pin is a copy with no gate on it.** A peer that
loads the corpus re-reads ground truth on every run and gets corrected for free the moment upstream
moves. A peer that transcribes ground truth into its own source froze it at transcription time, and
nothing in the tree re-checks the copy — not `make lint`, not `validate-peer`, not the corpus's own
sha-pin, because the peer never opens the file the pin protects.

## What is left open, named rather than folded into the win

- **`haskell` is predicted to fail and was not measured.** Its `AgilitySpec` reads
  `canonical_content_hash` from `hash-format-sha-384.2` — a field the inverted vector **no longer
  has**. The prediction is a source read, not a measurement, and is labelled as such. It is
  unmeasured because the `ghc-toolchain` image cannot resolve the test-suite's own dependencies
  (`hspec`, `HUnit`, `QuickCheck`) offline *or* online — `cabal` reports
  `repoContextWithSecureRepo: unknown repo`. **That is a container-recipe gap, and it means
  `haskell`'s S2 test-suite has no runnable gate on this host at all**, which is a finding in its own
  right and larger than this one.
- **The negative half is not implemented anywhere.** `GUIDE-CONFORMANCE` §2.4a requires the refusal
  to be asserted, and the current vector asks for exactly that. No peer in this cohort refuses
  `build_peer(… , home = SHA-384)` for a `system/peer`; they all still construct it. The four fixed
  harnesses now assert the floor form and **do not** assert the refusal, and each says so in a
  comment at the site. Writing the refusal is a peer-behaviour change (the constructor must reject a
  non-floor home format for one type), not a test edit, and is deliberately not faked — a
  half-implemented rule that emits a plausible value reads as done.
- **`validate-peer` never covered any of this.** The crypto-agility corpus is not part of
  `--profile core`, so all four peers were, and remain, `756 · 0F`. **No published conformance number
  moves.** This is a second axis, and it was red on two peers while the gated axis was green.

## Enforcement

1. **One copy of a vendored corpus, ever.** A second copy under any name is a second authority.
   `protocol-generator/shared/test-vectors/README.md` records the vendor pins and every retired
   digest, so a supersession is visible as a changed digest rather than as two directories.
2. **Prefer loading the corpus to transcribing it.** Where a peer must transcribe (no CBOR decoder at
   the layer under test), the transcription site must name the corpus artifact it came from, so the
   next reader can diff it. All four fixed peers now do.
3. **When a corpus moves, re-run the peers that LOAD it and the peers that TRANSCRIBE it — the second
   group is the one that will not tell you.**
