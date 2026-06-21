# spec-data v0.8.0 — Snapshot Manifest

**Spec version:** Entity Core Protocol **0.8.0** (V8). ENTITY-CORE-PROTOCOL.md `**Version**: 0.8.0`. (V7 was 0.7.77; "V8" / 0.8.0 is the release cutover.)
**Snapshot type:** verbatim copy of the authoritative normative spec files — **no paraphrase, byte-for-byte** (S2).
**Supersedes for new work:** `v7.75/` (kept in place as a point-in-time pin; v7.74/v7.72/v7.71/v7.70/v7.56 likewise). All peers after the V8 release cutover target this version; new peers derive spec-first against it. Existing peers re-target on next rebuild — there is no forced migration.

## ⚠ File rename + version line (read first)

- The core protocol spec is now **`ENTITY-CORE-PROTOCOL.md`** — de-versioned. Prior snapshots (v7.75 and earlier) carried it as `ENTITY-CORE-PROTOCOL-V7.md`. The "V7" was an artifact of the source revision folder; the published spec is identified by its `**Version**` field, not by a version baked into the filename. Generator profiles / tooling that open the file by basename update it when they re-target this snapshot.
- The protocol **version is `0.8.0` (V8)**. The prior line was `0.7.77` (V7, written "7.77"). The folded increments that closed the V7 line (0.7.76 verdict-determinism; 0.7.77 identifier-naming normalization) are carried under their V7 labels in the spec's change history.

## What's different from v7.75 (tight)

| File | vs v7.75 | Why |
|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` (was `-V7.md`) | **changed** (`057dc8eb…` → `ff8e7666…`) | Two folded increments + the V8 cutover + release-prep. **0.7.76** — capability-verdict determinism: the evaluation timestamp is sampled **once per verdict** and is a Layer-1 input (§5.10 / §5.2); the verdict is a pure function of the chain and `t`. **0.7.77** — identifier-naming normalization (kebab namespaces = type paths / operations / enum values; snake_case data keys = fields / error codes); `STYLE-NAMING-CONVENTIONS.md` is now a binding companion; 9 straggler type-paths renamed snake→kebab — **almost all extension-side** (EXTENSION-TYPE constraint kinds, EXTENSION-CONTENT frame-limit check); the only core-spec touch is the `system/peer-id` type-ref. **Core wire contract byte-unchanged** (no map-key renames; `--profile core` unaffected). **V8 cutover:** `**Version**` stamped `0.8.0`. **Release-prep (cosmetic, no surface change):** file de-versioned/renamed; cross-references normalized to `.md` form; dev-process dates, amendment-provenance tags, impl-archaeology, bare V7 self-naming, and citations to unpublished working docs stripped — published specs ship clean. |
| `ENTITY-CBOR-ENCODING.md` | **changed** (`8324742c…` → `fc57a85c…`) | **Normative content unchanged since v7.75** (version label stays **1.5**). Bytes differ only from release-prep: internal cross-references re-pointed to the renamed `ENTITY-CORE-PROTOCOL.md`, two dev-process dates + a design-doc citation stripped + Appendix-E/guide cross-ref paths corrected to the V8 layout. No codec / wire change. |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | **changed** (`5292fe59…` → `de86fa7e…`) | **Normative content unchanged since v7.75** (version label stays **4.2.1**). Bytes differ only from release-prep: cross-references re-pointed to the renamed spec, one date + two working-doc citations stripped. No type-system change. |

**No wire-format change. No new error/status code.** The substantive protocol delta closing the V7 line was 0.7.76 verdict-timestamp determinism (a Layer-1-input clarification) + 0.7.77 naming normalization (extension-side type-paths; core wire byte-unchanged). The C# codec corpus carries forward untouched (no CBOR change).

## Conformance scaffolding NOT in this snapshot (read before generating)

Unchanged: the **§7a conformance test-handlers** (`system/validate/echo`, `system/validate/dispatch-outbound`), the **§7b concurrency gate**, the **§4.10 `resource_bounds` validate-peer probe**, and the **generator-menu defaults** (recommended bounds 16 MiB / 64; store data-race-safety; TCP_NODELAY on raw-socket peers; no-blocking-syscall-on-cooperative-pool) live in `GUIDE-CONFORMANCE.md` (non-normative) + the keystone generator menu — **not in these three files**. A generated peer derives its **protocol surface** (including the §4.8/§4.9/§4.10 floor MUSTs) from this snapshot, but its **conformance scaffolding + generator defaults** from the guide + menu. (Open item to arch: whether to fold GUIDE-CONFORMANCE into the spec-data set or keep it operator-carried. Current default: operator-carried.)

## Provenance

| Field | Value |
|---|---|
| Source repo | `entity-core-architecture` (sibling) |
| Source path | `V8/entity-core-protocol/specs/` (**new** — the V8 published surface; prior snapshots sourced from `docs/architecture/v7.0-core-revision/core-protocol-domain/specs/`) |
| Source git commit | `a8c63bc` |

## Files (the three authoritative normative inputs)

| File | Spec version | SHA-256 |
|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` | 0.8.0 | `ff8e76660fd1e64677a9f26495bc73a337bb70a2378ee79b37fe2b1a6861c1a5` |
| `ENTITY-CBOR-ENCODING.md` | 1.5 | `fc57a85cfca759e75cf54795cb36af5cb5b60e1c289440a2db54a123007711cb` |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | 4.2.1 | `de86fa7ef92a8d0f4794bdc23a497e1ad5016d7e78db3f3b948055c0f745bad3` |

All three SHA-256 differ from the v7.75 snapshot. For CBOR + type-system the change is **release-prep only** (rename-propagation in cross-refs + date stripping); their normative content is identical to v7.75.

Verify integrity: `sha256sum -c` against this table, or diff against the source repo at the pinned commit.
