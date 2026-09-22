# Conformance vector corpora

Three corpora live here, one directory each. **A corpus is identified by its NAME, never by a
version stamp** — `GUIDE-CONFORMANCE.md` §5.1 (MUST, revised 2026-08-22): the directory is named
for what the corpus tests, artifacts are `<subject>-vectors.{diag,cbor}` with no `-v1`, and each
corpus's `CHANGELOG.md` stands in for a version integer. A conformance citation names
`(spec-version, corpus-name, artifact sha256)`.

| Corpus | Kind | Authored by |
|---|---|---|
| `ecf-conformance/` | canonical, normative | architecture — vendored byte-identical |
| `crypto-agility/` | canonical, normative | architecture — vendored byte-identical |
| `type-registry/` | **derived** drift target | keystone, harvested from the reference peer |

**The third is a different kind of thing.** Keystone does not author canonical bytes (S5). The first
two are byte-for-byte copies of `entity-core-protocol` `specs/test-vectors/`, changelogs included —
**do not edit anything under them**, including the `CHANGELOG.md`, or the copy stops being a copy.
`type-registry/` is ours: harvested from `entity-core-go`'s registry as a render/diff target, not a
normative pin, and it carries its own changelog explaining the difference.

This file is keystone's own note *about* the vendors — the place for provenance that is true of our
copies rather than of the upstream corpora.

---

## Current pins

| Artifact | sha256 |
|---|---|
| `ecf-conformance/conformance-vectors.cbor` | `9695b1f1d939cfdfdd4297f8ad32122d424b1ec180cfae74c92d509d88f7c6dc` |
| `ecf-conformance/conformance-vectors.diag` | `da521d67aa8193a3bf9acd232088d8515d50333f0294c65a5df3b45f46a1a87b` |
| `crypto-agility/agility-vectors.cbor` | `b5484e84dd2cddfa7d3cc8a041deba92cb29615aedb2180e31d8b6910ac5b648` |
| `crypto-agility/agility-vectors.diag` | `c4f52b1a8aaf057e7209352b53f7db469c6dc73b32bb297779b7a2228e5fca90` |
| `crypto-agility/SEEDS.md` | `2e031952de24da54f7e8411f404eb48e2d11e29211a77d7f0270ee15c87d87cb` |
| `type-registry/type-registry-vectors.cbor` | `7ae1021d0e58b704a2528ff346f09c6fd037f01766b73286b99f1ca56d9c6d48` |
| `type-registry/type-registry-vectors.diag` | `1b0ddf3a91cdeec3e085da195497904c32d775d49201940dbaf13ff09883a880` |
| `type-registry/type-registry-shapes.json` | `15cc691705373e63198b4f6fd6a72d27ae46339f21ea67e35987c483ca481b29` |

## Retired pins — recorded on purpose

**Retiring a pin means recording its content identity, not just its successor.** These digests are
cited in our own published prose (`CONFORMANCE-MATRIX.md`'s F29/F30 re-vendor note names
`41d68d2d…`), and the only place they had ever been written down was the `v0.8.0/MANIFEST.md` that
the de-versioning retired. Deleting that file would have made a published citation unresolvable —
the same defect the oracle-pin work fixed for `retired_ref*`, one directory over.

| Retired | Superseded by | What it was |
|---|---|---|
| `41d68d2d…` (ECF `.cbor`) | `9695b1f1…` | the 69-vector corpus, before F29/F30 |
| `987672147c90…` (ECF `.diag`) | `da521d67…` | ditto |
| `71015b729b205f39e29750e632a136844fe7da3f9e37800e870d14bf87086544` (ECF `.diag`) | `da521d67…` | the 71-vector `.diag` under its old filename; two header comment lines only |
| `8e7c5232f64bee83d628679f930c771e4e49f2f1e37d19e41e0d7838e31f982e` (agility `.cbor`) | `b5484e84…` | **superseded content, not a rename** — see below |
| `6d423cc6fe83bae099ce0172a360ca7d10ff2faf7d1f4d19894d0ffb26b877ae` (agility `.diag`) | `c4f52b1a…` | ditto |
| `be0aa1b7ddfed340c38ae3d4bb9a34ad9882ae925d3c7c31ed0c5370685e4bb5` (`agility-SEEDS.md`) | `2e031952…` | ditto |
| `2737f0259e8f775097e7b8809ea477808368bdb786f6f770c958bcc0101dbf28` (type-registry `.diag`) | `1b0ddf3a…` | two header comment lines only |

## The de-versioning was NOT a rename, and the difference is the whole finding

The obvious reading of this migration is "the same bytes moved to better-named directories." That is
true of the **ECF** corpus — `.cbor` byte-identical across the move, `.diag` differing in two header
comment lines — and it is **false of crypto-agility**, which had been re-vendored upstream with
changed vector *semantics* while a second, superseded copy sat here under the old name.

What actually changed, measured by diffing the two `.diag` files rather than by reading either
changelog:

- **`HASH-FORMAT-SHA-384-2` was inverted.** It used to assert that re-hashing the fixture
  `system/peer` under `content_hash_format = 0x01` **succeeds**, pinning
  `012e64bbde…3eef5a69`. `ENTITY-CORE-PROTOCOL` §4.5a item 1a pins the `system/peer` identity
  entity to the ECFv1-SHA-256 floor **unconditionally**, so that construction cannot exist. The
  vector now asserts the **refusal**. Upstream's own note on it is worth quoting, because it names
  the failure shape: the old vector *"stayed green only because the verifier hand-built the entity
  instead of routing through the constructor that would have refused it. A fixture that exercises a
  forbidden construction and passes by bypassing the code that forbids it certifies the opposite of
  the rule."*
- **M3/M6 `expected_peer_a_content_hash` became floor-form.** `0166f421…` → `00af37ab…` and
  `01ef28f9…` → `00848e20…`. Same cause: every identity reference resolves floor-form.
- Ed448 seed widths and the `0xAA` fixture pubkey were corrected (58 → 57 B, 63 → 64 B).

**A stale duplicate of a corpus is worse than no copy, because it answers.** Nothing failed while
both existed: the peers reading the old path got the old bytes and passed. Only removing the
duplicate makes the disagreement visible.

## Consequence for peers that transcribe pins instead of loading the corpus

`ocaml` and `csharp` carry hand-transcribed agility KATs rather than reading the `.cbor`. Both assert
all three retired values above, so both currently pin a `system/peer` `content_hash` under SHA-384 —
a construction §4.5a item 1a forbids. **Neither is caught by `validate-peer`**: the agility corpus is
not part of `--profile core`, so both peers are `756 · 0F` with the defect present. Tracked as a
finding; see `research/stewardship/SPEC-FINDINGS-LOG.md`.

The general form: **a transcribed pin is a copy with no gate on it.** A peer that loads the corpus
re-reads ground truth on every run; a peer that transcribes ground truth into its own source froze it
at transcription time and nothing re-checks the copy.

## The latent-bug lesson (carried from the retired `v0.8.0/MANIFEST.md`)

Phase 2 of the agility corpus caught a Go bug: `[]string(nil)` encoded to CBOR `null` via the
serializer's default, where spec-canonical is `{include: []}` → `0x80`. It stayed latent because
handshake capabilities are self-signed and verified against *received* bytes — nothing re-encodes a
capability cross-impl until a byte-pin round-trip forces independent re-derivation.

**Class: an idiomatic-language serializer default silently overriding spec-canonical encoding.**
Empty list vs null, omitted vs present-empty, map-key ordering defaults. The byte gate is the only
thing that catches it, and every new impl should be checked for the same class rather than assumed
clear because its unit tests pass.

*(The `AUTHZ-*` matrix the retired manifest also carried is not a byte-fixture set and was never
vendored here — those seven vectors assert `(status, code)` pairs and live in architecture's
`GUIDE-CONFORMANCE.md` §9 `(k)–(q)`, driven by `validate-peer`. Cited, not copied.)*
