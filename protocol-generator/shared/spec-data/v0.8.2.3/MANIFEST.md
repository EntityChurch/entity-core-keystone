# spec-data v0.8.2.3 — Snapshot Manifest

**Spec version:** Entity Core Protocol **0.8.2.3**. `ENTITY-CORE-PROTOCOL.md` carries `**Version**: 0.8.2.3` on line 3 (verified in this snapshot, not assumed).
**Snapshot type:** verbatim copy of the authoritative normative spec files — **no paraphrase, byte-for-byte** (S2). Each file was hashed from the source blob and compared against the written copy before acceptance; all three matched.

**Supersedes for new work:** `v0.8.2/` and `v0.8.0/` (both kept in place as point-in-time pins, as every prior snapshot is).

**Authorized by** `entity-system-architecture` `ROUTING-2026-09-01-a` §1 — *"You are clear to regenerate. Target `0.8.2.3`, `entity-core-protocol` `a544743`."* Directory named for the version the spec header carries. Per `-m` §2 we do **not** vendor a `v0.8.3/`: the fourth component is an arch-managed in-flight signal that the operator strips and renames at the release cut.

## Provenance, and one thing that is different from every snapshot before it

| Field | Value |
|---|---|
| Source repo | `entity-core-protocol` (sibling) |
| Source path | `specs/` |
| Source ref | **`dev`** at `a544743` — see below |
| Method | `git show a544743:specs/<file>` into the snapshot path; each output hashed and compared against the source blob before acceptance. All three matched. |
| Read at | 2026-09-01 |

**This snapshot is vendored from an UNRELEASED line, and that is a deliberate change of method
worth stating rather than leaving for someone to notice.** The `v0.8.2` re-sync of 2026-08-30 was
taken from published `master`, and its manifest argues at length for why that mattered. `0.8.2.3`
is not on `master` — `master` is still the released `0.8.2`, and the fourth component exists
precisely so core text can move without cutting a release. So there is **no published artifact to
vendor from**, and there will not be one until the operator names the number at the cut.

The consequence is that the SHA-256 table below is not merely the preferred anchor here, it is the
**only** one: `a544743` is a `dev` commit, [ADR-0027] authors published commits fresh at the release
boundary, and this directory publishes (`protocol-generator/**` ships undeclared). The commit is
recorded above as an internal build coordinate and is **not** citable in anything published — the
same discipline `tools/oracle-pin.env` applies to the oracle's `ref`.

## Files (the three authoritative normative inputs)

| File | Spec version | SHA-256 |
|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` | **0.8.2.3** | `f899b8ea6e9be64b2018e12ebf7c5824de779accad1b63c5a204a78aa3c76527` |
| `ENTITY-CBOR-ENCODING.md` | 1.5 | `74ace6c2bf24ded8d6962c889150b27a8de2b862a2425f10042e19dcdec09fe4` |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | 4.2.1 | `2cec31bb751c6876bc0e461b549c2a1cb5af52e4be5f69f1d52edc59397e22bd` |

Verify integrity: `sha256sum -c` against this table, or `git show a544743:specs/<file> | sha256sum`
in the sibling while that ref still resolves.

## What's different from v0.8.2

Measured in this tree (`diff v0.8.2/<f> v0.8.2.3/<f>`), against the **published** `0.8.2` this
directory's predecessor holds:

| File | vs v0.8.2 | Changed lines | Version label |
|---|---|---|---|
| `ENTITY-CORE-PROTOCOL.md` | changed (`6e7e0ca1…` → `f899b8ea…`) | **50** | 0.8.2 → **0.8.2.3** |
| `ENTITY-CBOR-ENCODING.md` | changed (`0826504a…` → `74ace6c2…`) | **19** | 1.5 (unmoved) |
| `ENTITY-NATIVE-TYPE-SYSTEM.md` | changed (`64c52621…` → `2cec31bb…`) | **2** | 4.2.1 (unmoved) |

Three amendments landed in this window, and **only two of them reach a generated peer**:

### 0.8.2.1 — FM-1: a pre-hello `authenticate` had two answers in one table

§4.7 row 6 pinned the input to `401 invalid_nonce`; row 10's parenthetical claimed the same input
as an out-of-order operation at `400 connection_sequence_error`. **Ruled `401 invalid_nonce`** — a
captured `authenticate` replayed onto a fresh connection *is* this input, so it is an authentication
failure, not a malformed request. §4.2's ordering MUST gained the status and code it had always
lacked, row 10's example was narrowed, and §4.7 is now stated as authoritative for the connect-time
`(status, code)` pair.

**This is our own finding, measured on the wire.** `entity-core-formalization` found the
contradiction and censused the cohort by source, flagging it as unmeasured; we built the probe and
measured 45 of 46 (`protocol-generator/shared/findings/prehello-authenticate-wire-census.md`).
Their source census was right on all 34 peers it committed to and we resolved the other 11. The
substantive addition was that **a 38–6 majority was 6 decisions and 38 fall-throughs** — 38 peers
answer `invalid_nonce` pre-hello *and* post-hello, because they never model the pre-hello case at
all. The ruling went the way of the majority, but not on the strength the raw tally implied.

### 0.8.2.2 — PD-1: a foreign-namespace request had a MUST with no code anyone could find

§1.4 always required refusing an inbound EXECUTE naming another peer's namespace, at
`400 invalid_request` — but `invalid_request` appeared **exactly once in the whole specification,
inside that MUST**. Not in §3.3's status vocabulary, not in §8.3's table, not in §5.2a, not in
§9.1, and no conformance check read it. Meanwhile §6.2 defined `404 handler_not_found` as *"no
handler is registered at the dispatch path"* — a description a foreign path satisfies on its face.
Implementers picked the code the specification explained. **The rule had nowhere for the agreement
to live**, which is why 40 of our 46 peers refused with the wrong code and the rest resolved
locally.

`invalid_request` is now declared in §3.3 and §8.3, enumerated as a **pre-dispatch** row in §5.2a
(neither auth-class nor authz-class — the request is refused before authorization is consulted),
named in §6.5's chain, and `handler_not_found`'s §6.2 definition is scoped so it can no longer
absorb this input. §6.5 states that step 3 is **a gate, not an ordering preference**: an
implementation MUST NOT reach the refusal by stripping the foreign peer id, resolving the local
handler and letting §5.2 Dimension 4 deny — that returns `403`/`404` for what is specified as
`400`, and it **allows the request outright** whenever the presented grant carries a matching
`peers` scope, which is a foreign-namespace privilege escalation.

### 0.8.2.3 — Edit E's `resources` narrowing, withdrawn

`0.8.2.2` pinned the default per-handler self-grant's `resources` to `["/{local_peer_id}/*"]`.
`entity-core-go` implemented the rest of PD-1, declined that clause, and filed a measured
refutation; arch upheld it in full. A peer's store is one local address space keyed by peer id, so
`/{remote_peer_id}/…` names a **local** region holding cached or mirrored data — writing there is a
local write, not a remote reach, and §6.3 already said so. The network bound is carried entirely by
`peers`, which the default omits and which is still checked. The default is back to `["/*/*"]`.

**No generated peer implements this**, so it is recorded here for completeness and costs the cohort
nothing. It is in the snapshot because the version string has to be right, not because behaviour
moved.

### Also in the window, and it reaches no peer

§3.13's `EXTENSION-NETWORK` citation dropped its amendment number; two `SPECIFICATION-FORMAT`
citations gained their owning repo (the two authoring standards are now single-homed in
`entity-system-architecture`); a `9-vs-64` provenance parenthetical was trimmed; and F40's
consequence note now says "an implementation" where it said "a cohort peer".

## Conformance scaffolding NOT in this snapshot (read before generating)

Unchanged from `v0.8.2`: the **§7a conformance test-handlers** (`system/validate/echo`,
`system/validate/dispatch-outbound`), the **§7b concurrency gate**, the **§4.10 `resource_bounds`
probe**, and the **generator-menu defaults** live in `GUIDE-CONFORMANCE.md` (non-normative,
arch-owned) plus the keystone generator menu — **not in these three files**.

| Field | Value |
|---|---|
| File | `GUIDE-CONFORMANCE.md` |
| Source repo | `entity-system-architecture`, path `guides/` |
| SHA-256 | `f7d4191df7717f054de13660b1826d223f86e57705db572754651769ce60b0ec` |
| Status label | **Draft** |

**The guide moved under the previous pin and nobody routed it.** `v0.8.2/MANIFEST.md` pins
`7d59fee6…`; the live file is `f7d4191d…`. The change is a rewritten **§5.1 Corpus identity**
(`[MUST]`, revised 2026-08-22) retiring integer corpus versions in favour of
`(spec-version, corpus-name, artifact sha256)`, plus a new §5.1a splitting corpus authoring from
byte production. That MUST governs how this repo vendors its test corpora, so it is a change to our
inputs, not to arch's prose. Recorded here because a pinned input that moves silently is the defect
the pin exists to prevent — see the re-vendor recorded in `protocol-generator/shared/test-vectors/`.

## Status in this repo

**This snapshot is the regeneration target and is being consumed now.** The `0.8.2.3` sweep is the
first time a snapshot delta has reached the whole cohort: FM-1 and PD-1 are both wire-observable and
both are gated by the oracle at `tools/oracle-pin.env` (`connect_prehello_authenticate`,
`dispatch_inbound_foreign_namespace_refused`). See `CONFORMANCE-MATRIX.md` for per-peer state.

`pd`'s F37 `system/identity/peer-id` debt, carried against `v0.8.2`, is unchanged by this snapshot.
