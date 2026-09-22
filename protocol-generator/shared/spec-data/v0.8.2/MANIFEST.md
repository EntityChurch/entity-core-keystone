# spec-data v0.8.2 — Snapshot Manifest

**Spec version:** Entity Core Protocol **0.8.2**. `ENTITY-CORE-PROTOCOL.md` carries `**Version**: 0.8.2` on line 3 (verified in this snapshot, not assumed).
**Snapshot type:** verbatim copy of the authoritative normative spec files — **no paraphrase, byte-for-byte** (S2). Verified by hashing the source blob and comparing before acceptance.

> **RE-SYNCED 2026-08-30 to the PUBLISHED 0.8.2, and the correction is worth stating plainly:
> this directory previously held the PRE-RELEASE draft of 0.8.2, not the released artifact.**
> It was taken from `entity-core-protocol` `dev` at commit `106834c` on 2026-08-21. The 0.8.2
> release was cut afterwards (`release: cut 0.8.2 — strip the arch-managed fourth component,
> and cite by content never by SHA`), and that cut changed `ENTITY-CORE-PROTOCOL.md`.
>
> **The delta is one line and carries no normative content:** a §3.13 parenthetical had three
> `entity-core-{rust,py,go}` dev commit SHAs (`1152d35`, `ad0ef98`, `a02ab5e`) removed by the
> release scrub. `ENTITY-CBOR-ENCODING.md` and `ENTITY-NATIVE-TYPE-SYSTEM.md` were already
> byte-identical to the published form and did not move.
>
> **Why it mattered anyway.** This file claimed a byte-for-byte copy of the authoritative spec
> and pinned SHA-256s of bytes that existed in no published artifact, so "our v0.8.2" and
> "0.8.2" were different objects — and the snapshot publishes (`protocol-generator/**` ships
> undeclared), so we were shipping three dev SHAs that resolve for no outside reader. That is
> the [ADR-0012] Amendment 1 defect, in the file whose whole purpose is fidelity to an upstream
> artifact. The old provenance record below cited a `dev` commit for the same reason.
>
> **On the in-place edit.** `AGENTS.md` holds each `<version>/` immutable once stamped, with
> amendments going to a new subdirectory. That rule governs spec **amendments** — a changed
> spec gets a new version directory. The spec did not change here; we copied from the wrong
> ref, and the directory claimed to be v0.8.2 while not being it. Immutability protects a
> correct pin from shifting under a reader, not a mis-stamped one from being corrected.
> Operator-authorized, 2026-08-30.
>
> **The three copies now agree byte-for-byte** — this snapshot, `entity-core-protocol`
> published `master`, and `entity-core-formalization` `spec-data/v0.8.2/`. Formalization
> vendored from published `master` and cited by content from the start; this snapshot now
> matches their method as well as their bytes.
**Supersedes for new work:** `v0.8.0/` (kept in place as a point-in-time pin, as every prior snapshot is). Peers re-target on next rebuild — there is no forced migration, and **no peer in this repo has yet been regenerated against this snapshot** (see "Status" below, and `CONFORMANCE-MATRIX.md`).

**Authorized by** `entity-system-architecture` `ROUTING-2026-08-21-l` §1 (the final pin) and re-verified by `ROUTING-2026-08-21-m` §1. Directory named for the version, per `-l` §2 — **not** `v0.8.0.1`; the fourth component is an arch-managed in-flight signal and is stripped at release.

## Provenance

| Field | Value |
|---|---|
| Source repo | `entity-core-protocol` (sibling; public source mirror) |
| Source path | `specs/` |
| Source ref | published **`master`** — the released 0.8.2 |
| Method | `git show master:specs/<file>` into the snapshot path; each output hashed and compared against the source blob before acceptance. All three matched. |
| Read at | 2026-08-30 (re-sync; originally 2026-08-21 from `dev`) |

**Cited by content, not by commit** ([ADR-0012] Am. 1). The superseded record named
`106834cc5bde47884046d5a5088d629f44ae0c5f` on `dev`. Published commits are authored fresh at
the release boundary ([ADR-0027]), so a `dev` SHA resolves for no outside reader — the SHA-256
table below is the anchor, and it is the same table `entity-core-formalization` records.

**Note on the previous snapshot's provenance.** `v0.8.0/MANIFEST.md` names source repo `entity-core-architecture` at commit `a8c63bc`, path `V8/entity-core-protocol/specs/`. **That commit is dead in both trees** and the path names a layout that no longer exists — a public-mirror history rewrite, arch's, never routed to us (`-l` §5). `v0.8.0`'s *content* is unaffected (its three SHA-256s still verify against the files in that directory); only its provenance line is unresolvable. The pin above resolves.

## Files (the three authoritative normative inputs)

| File | Spec version | SHA-256 |
|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` | **0.8.2** | `6e7e0ca1594099294f89853caef79d8a0a6e851cce70ac297216e125cdc8e4e9` |
| `ENTITY-CBOR-ENCODING.md` | 1.5 | `0826504a82ad4db96da1044c4e67a8103f870160862fb62955562ee5e74d25b9` |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | 4.2.1 | `64c526210a6908d0d248321178b7216816a24530c308d8aa47d08c9d40da70e5` |

All three recomputed from published `master` at the 2026-08-30 re-sync and matched the source blobs byte-for-byte; the two unmoved files still match arch's independently-computed table in `-l` §1 / `-m` §1. `ENTITY-CORE-PROTOCOL.md`'s hash moved `4be521f7…` → `6e7e0ca1…` at the re-sync (the release scrub — see the note at the top), and `6e7e0ca1…` is the value `entity-core-formalization` independently recorded. Verify integrity: `sha256sum -c` against this table, or diff against the source repo at the pinned commit.

## What's different from v0.8.0

**Measured in this tree** (`diff v0.8.0/<f> v0.8.2/<f> | grep -cE '^[<>]'`), which independently reproduces arch's `-m` §1 count of 197 / 29 / 40:

| File | vs v0.8.0 | Changed lines | Version label |
|---|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` | changed (`ff8e7666…` → `6e7e0ca1…`) | **197** | 0.8.0 → **0.8.2** |
| `ENTITY-CBOR-ENCODING.md` | changed (`fc57a85c…` → `0826504a…`) | **29** | 1.5 (unmoved) |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | changed (`de86fa7e…` → `64c52621…`) | **40** | 4.2.1 (unmoved) |

**The span is `entity-core-protocol` `43484b0..106834c`, and the following characterization is arch's** (`-m` §1), carried here as routed rather than re-derived — the line counts above are ours, the attribution below is theirs:

- the **0.8.1 amendments** — F37 `system/peer-id`, F40 id-scope grammar, RT-6 401, continuation TTL 8×
- the **hash-width lock**
- §3.13's `reason` / `last_error` / `failing_since`
- the **CAP-1…CAP-7 capability cluster** and **CAP-6a ingest**
- the **three-valued dispatch authority**
- the version cut itself

**F37 is our own finding**, absorbed upstream 2026-07-27 at `85e8738`: `system/identity/peer-id` → `system/peer-id`. Our `v0.8.0` snapshot predates its own acceptance because nobody told us. Arch ranks it the #1 place to expect peer movement (`-l` §3), scoped to **`pd`, three files, one peer** — measured in our tree by arch, not estimated. `pd` is maintenance tier **M3**, so it is **not** in this release's re-run: a known, named, one-peer debt that does not gate.

### §5.2's `(normative, 0.8.2)` tags are correct as written

`ROUTING-2026-08-21-j` §3.4 reported the three `(normative, 0.8.2)` tags in §5.2's dispatch pseudocode as residue from a reverted version cut, and told us to read them as "landed in the window the fourth component records." **That report is withdrawn by `-l` §2, and it was wrong in direction** — those rules were authored *for* 0.8.2 and the version header was reverted out from under them. The tags were **ahead of** the header, not left behind by it. As of `106834c` they are simply correct, and nothing was edited to make them so. Recorded here explicitly because the withdrawn caveat would otherwise have been carried into this manifest and outlived its own truth.

## Conformance scaffolding NOT in this snapshot (read before generating)

Unchanged from `v0.8.0`: the **§7a conformance test-handlers** (`system/validate/echo`, `system/validate/dispatch-outbound`), the **§7b concurrency gate**, the **§4.10 `resource_bounds` validate-peer probe**, and the **generator-menu defaults** live in `GUIDE-CONFORMANCE.md` (non-normative, differently owned) + the keystone generator menu — **not in these three files**. A generated peer derives its **protocol surface** (including the §4.8/§4.9/§4.10 floor MUSTs) from this snapshot, but its **conformance scaffolding + generator defaults** from the guide + menu.

**The guide is now pinned, and that open item is closed.** It stays out of `spec-data/` (non-normative, arch-owned, different lifecycle) — but "operator-carried" meant *unpinned*, and our generated peers derive their whole conformance scaffolding from it, so a generation was not reproducible. Pinned separately here:

| Field | Value |
|---|---|
| File | `GUIDE-CONFORMANCE.md` |
| Source repo | `entity-system-architecture`, path `guides/` |
| SHA-256 | `7d59fee6d0bfb3ce34bf02b76d9253ce16c2f94366168ae20082106fac83f2dd` |
| Status label | **Draft** |
| Content last moved at | `f3e81e2` |

**The hash is the anchor, not the commit.** Arch re-pinned this to their HEAD (`48aae2a`) after `-l` quoted `26e1868`; **the bytes are identical across all three** — the file has not been touched since `f3e81e2`. Verified in this session by hashing the live file. **A peer generated against a `Status: Draft` guide should say so** — which argues for the pin, not against the guide.

## Status in this repo

**This snapshot is pinned, not yet consumed.** No peer has been regenerated against `v0.8.2` as of the release measured in `CONFORMANCE-MATRIX.md`; the M1 re-run for this release measured peers **as generated against `v0.8.0`** against the **`c1b0708` oracle**. That is a deliberate, recorded gap, not an oversight — the oracle is what gates the wire, and the snapshot delta reaching a peer is a regeneration question with its own cadence. `pd`'s F37 debt above is the one known, named consequence.
