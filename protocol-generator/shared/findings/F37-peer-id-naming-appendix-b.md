# HANDOFF-TO-ARCH — F37: peer-identity type-name split (§4.8 vs §10.1/Appendix B) + Appendix B staleness vs the primary `:=` definitions

**Date:** 2026-07-15 · **Finding:** F37 (`research/stewardship/SPEC-FINDINGS-LOG.md`); surfaced
as **A-PD-012** (`protocol-generator/pd/status/SPEC-AMBIGUITY-LOG.md`, S3.7–S3.8)
**Owner:** `arch` (spec-body reconciliation) · **Severity:** documentation-reconciliation debt
(two live `type_ref` names for one primitive; a consolidated appendix disagreeing with the
normative source) · **Blocks:** nothing
**Lineage:** same class as **F32** (body text not back-propagated across an amendment), on a
*type name* rather than a status code
**Spec surface:** ENTITY-NATIVE-TYPE-SYSTEM.md @ `spec-data/v0.8.0`

> Keystone cannot edit `spec-data/**` (immutable, boundary). Request for arch to reconcile on its
> own schedule; no local patch was made. Derived from the spec (primary `:=` definitions), with
> the oracle's ratified-core set as corroboration only.

## The name split

The peer-identity address primitive (`primitive/string`-extending, Base58 peer id) carries **two
names within one spec version**:

| Name | Where |
|---|---|
| `system/identity/peer-id` | §1 intro (L19) · §4.4 bootstrap table row 14 (L409) · §4.8 heading + body (L508–526) · §2.7 rationale · used as `type_ref` at L639 (`system/peer` example) + L1082 (`connect/hello`) |
| `system/peer-id` | §10.1 `system/peer` (L1453) · Appendix B (L2399) · **the oracle's entire ratified-core set** (fetch/match probes at `system/type/system/peer-id`; no `identity/` probe exists) |

A peer registering only the §4.8 bootstrap name leaves the §10.1/hello `type_ref`s dangling and
404s the oracle's `type_system_peer_id_fetch`. The Pd peer (and the safe pattern for any peer)
binds **both** names so every spec `type_ref` resolves — a workaround, not a resolution.

**Secondary, same table:** §4.4 says "The complete set of **14** bootstrap types" but the table
enumerates **15 rows** (row 15 = `entity`, §3.1.1).

## Appendix B is systemically stale vs the primary `:=` definitions

The peer-id split is one facet: Appendix B (the consolidated reference) disagrees with the
primary ENTITY-CORE-PROTOCOL.md `:=` definitions (which the oracle is built from) on at least:

- `core/envelope.root` / `system/protocol/execute.params` / `.../execute/response.result`
  rendered **`primitive/any`**; primary doc (§3.1/§3.2/§3.3) + oracle use **`core/entity`**.
- `connect/hello.peer_id` / `connect/authenticate.peer_id` rendered **`system/identity/peer-id`**;
  primary doc + oracle use **`system/peer-id`**.
- `system/envelope` spelled out with duplicated `{root, included}` fields; primary doc has it
  **extend `core/envelope`**.
- Omits that `system/handler/manifest` **extends `system/handler/interface`** (§3.7).

## The ask

1. **Pick ONE canonical name** for the peer-identity primitive and reconcile all `type_ref`s +
   the §4.4 bootstrap table to it (the oracle + §10.1 have de-facto settled on `system/peer-id`);
   if both must coexist, say so normatively (alias).
2. Fix the §4.4 "14" → 15 count (or drop `entity` from the table if intended).
3. **Regenerate Appendix B from the primary `:=` definitions** so the consolidated reference
   stops disagreeing with the normative source — same doc-reconciliation shape as F32.

## Disposition

**Not a peer bug** — the Pd peer authored from the primary doc and greens all core `type_system`
`_fetch`+`_match` under `--profile core` (682·0F @ `cc1970f`), binding both names defensively.
**Not a spec-logic defect**; a naming/count/appendix reconciliation debt. Does not block any
phase; every future peer pays the dual-bind tax until reconciled.
