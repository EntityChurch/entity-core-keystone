# HANDOFF TO ARCH — the §5.2 `peers` dimension is unreachable in 40 of 46 peers

**Date:** 2026-08-30
**From:** entity-core-keystone
**Spec snapshot:** `v0.8.2` (`ENTITY-CORE-PROTOCOL.md` `4be521f7…`)
**Oracle:** the 755-check set, `core_executed_check_set_digest = 95edd774…`
**Check:** `authz/authz_peers_target_from_uri`
**Status:** ⛔ **CLOSED 2026-09-01 — and the central premise below was WRONG.** See the
correction immediately following. Everything after it is preserved unedited, because the
error is the useful part.

---

## CORRECTION AND CLOSURE (2026-09-01)

**This finding asked for a normative sentence that was already in the snapshot it cites in
its own header.** The question was real, the cohort measurement was correct, and the answer
had been sitting in §1.4 — the section this document is *about* — the whole time.

`ENTITY-CORE-PROTOCOL.md` §1.4 *URI and Path Model*, line 300, **byte-identical in `v0.8.2`
and `v0.8.2.3`** (`sha256(line) = 376953b9…`):

> **Inbound dispatch (wire listener).** When a peer receives an EXECUTE over the wire, the
> path MUST target the local peer's namespace. If the peer ID does not match the local peer,
> the peer MUST reject with status 400 (`invalid_request`).

So the sentence *"The spec answers this nowhere we can find"*, four lines below, is false
against our own pinned copy. **The majority reading was right — refuse at routing — and both
sides of the cohort had the disposition wrong**: the 40 answered `404 handler_not_found`
(including `go`), the 6 answered `403 capability_denied` or `200`, and the spec says `400
invalid_request`. This document's leading argument — that the `peers` default is dead weight
under the majority reading, therefore *"the strongest argument we have that the minority of 6
is right"* — argued for the side the spec had already ruled against. It was explicitly framed
as an argument from construction rather than from normative text, which is the one thing that
kept it honest; it was still pointing the wrong way.

**How it was missed, because the mechanism is reusable and dull.** The search was for the
vocabulary of the question — `peers`, `target_peer`, `check_permission`, `extract_peer` — and
this document even names where it expected the answer to be added: *"in §5.2 beside
`extract_peer`, or in §6.6 beside handler resolution."* The actual rule is phrased in the
vocabulary of **addressing**, not authorization, and lives in neither. It contains none of
those four terms. **A negative claim about a document is only as good as the words you
thought to search it for** — and "we could not find it" is a claim about the search, which is
then published as a claim about the spec.

**What the 0.8.2.2/0.8.2.3 line actually changed** — worth separating from what it settled,
because they are not the same and the difference is the whole reason this looked open. The
*status* (400) was already pinned. What arrived later is the **code name** and the explicit
prohibition on the two wrong dispositions: §3.3's 400 table now names `invalid_request` for
this case; §6.2 says a foreign path *"is refused earlier, at §1.4 canonicalization (§6.5
step 3), with 400 `invalid_request`, and MUST NOT be reported as `handler_not_found`"*; §6.5
step 3 forbids reaching the refusal *"by resolving a local handler for the foreign path and
letting §5.2 decide"*. Reading that as *"the ambiguity was resolved upstream"* would be a
second, more flattering error: **the sharpening is real, and the underlying MUST predates
this finding.**

**Consequences, all discharged:**

- The oracle **deleted** `authz_peers_target_from_uri` rather than re-pointing it — its PASS
  branch required the foreign-namespace resolution the spec forbids, so it was a check
  rewarding the defect. It does not exist at the current pin (`strings validate-peer` → 0
  occurrences, measured). Its replacement is `authz/dispatch_inbound_foreign_namespace_refused`.
- **All six peers that PASSed this check needed the gate** — `forth` and `smalltalk` in the
  0.8.2.3 sweep, `pd` `asm-x86_64` `asm-arm64` `riscv64` on 2026-09-01. That is not a
  coincidence: passing required exactly the behaviour §6.5 step 3 forbids.
- A seventh, `wasm-wat`, WARNed here and still needed it — it refused, but *by resolving
  locally and then failing authz*. **A WARN on this check never meant a peer was safe**, only
  that this check could not attribute its refusal.
- `CONFORMANCE-MATRIX.md` §3's row is retired; the cohort is 46 of 46 at `756 · 0F`.

**The durable lesson, and it is the second time in two days this shape has cost us.** The
`dart`/`ruby` NUL-byte case was a grep that *could not see* the file and reported "absent".
This is a grep that *looked in the wrong vocabulary* and reported "the spec does not say".
Both publish as a confident negative. The standing rule — *prove a negative before you claim
it* — needs its enforcement stated for prose: **search the SECTION the behaviour belongs to,
not the words the question is phrased in**, and say which sections you read, so the next
reader can see the hole rather than inherit the conclusion.

---

## Original finding, unedited below this line

## The ask, in one sentence

**When an EXECUTE names a URI in a FOREIGN peer's namespace (`/{other_peer}/system/tree`),
is a core peer required to resolve its own handler for it and let §5.2 decide — or may it
refuse at routing with `404 handler_not_found`?**

The spec answers this nowhere we can find, the cohort splits 40/6 on it, and the reference
implementation is in the majority. Whichever way it goes, one side of the cohort is
non-conformant and does not currently know it.

## Why it matters: the dimension's own default is dead weight under the majority reading

§5.2's `check_permission` (spec line ~2163) reads:

```
target_peer = extract_peer(execute.data.uri, local_peer_id)
...
peers_scope = grant.peers or {include: [local_peer_id]}
if not matches_scope(target_peer, peers_scope, local_peer_id):
    continue
```

and §3.6's field table says of `peers`: *"When absent, defaults to local peer only
(`{include: [local_peer_id]}` constructed at evaluation time)."*

**That default only does work if `target_peer` can differ from `local_peer_id` at the point
the check runs.** On a peer that refuses every foreign-namespace URI at routing,
`target_peer` is *always* `local_peer_id` by the time `check_permission` executes, so the
defaulted scope always matches, and the entire `peers` dimension is a no-op. Constructing a
default whose only purpose is to deny a case that can never arrive is not a thing a spec
does on purpose — which is the strongest argument we have that the **minority of 6 is
right**. It is an argument from construction, not from normative text, which is why this is
a question and not a bug report.

## The measurement

Measured across all 46 committed `status/CONFORMANCE-REPORT.json` at the pinned check set.

| | Peers | `authz_peers_target_from_uri` |
|---|---|---|
| **Routes foreign targets** (6) | `asm-x86_64` `asm-arm64` `riscv64` `forth` `pd` `smalltalk` | **PASS** |
| **Refuses at routing** (40) | everything else, including `go` `rust` `python` `haskell` `ocaml` `swift` `lean` | **WARN** |

The PASS verdict is a real three-row differential, not a lucky default:

> `§5.2 peers dimension correct: foreign-scoped grant ALLOWs the foreign target (P1 s=200),`
> `while local-scoped (P2 s=403 "capability_denied") and absent-peers (P3 s=403`
> `"capability_denied") grants DENY it — target read from the URI, absent defaulted-and-checked`

The WARN verdict is all three rows at `404 handler_not_found`, and **the oracle itself
declines to score it**:

> `the foreign-scoped control (P1) also denied, so the denials are unattributable to the`
> `peers dimension (unrelated deny, or the peer refuses all foreign-namespace targets).`
> `This is NOT the local_peer_id escalation bug, which ALLOWs P2/P3. Investigate the P1`
> `control before scoring.`

**The split is one line of routing and the correlation is perfect: no PASS peer has a
local-target gate, and every peer carrying one is in the WARN group** — 24 confirmed by the
literal string `"not local peer"`, 0 counterexamples. `go`'s form (`src/peer/peer.go:388`):

```go
if extractPeer(p.localPeer, path) != p.localPeer {
    return errOutcome(404, "handler_not_found", "not local peer")
}
```

This runs **before** handler resolution, so `check_permission` — and with it the `peers`
dimension — is never reached. The 6 PASS peers simply have no such gate.

Note the disposition also differs: the majority answers `404 handler_not_found` (a routing
verdict), the minority `403 capability_denied` (the §5.2 disposition). If the minority
reading is correct, the majority is also returning the wrong status class for an
authorization outcome.

## What we are NOT claiming

- **Not that 40 peers are broken.** Under the majority reading they are correct and the 6
  are over-permissive — a peer that resolves handlers for namespaces it does not own is a
  larger attack surface, and "refuse anything not addressed to me" is a defensible posture.
- **Not that the oracle is wrong.** It scores WARN and says why. It is behaving exactly as
  an oracle should on an under-specified surface.
- **Not derived from the oracle's Go source.** Per our own boundary rule, reading
  `cmd/internal/validate` to decide what the peer should do would invert the keystone's
  purpose. Everything above comes from the spec text, the peers' own source, and the
  measured results.

## What we would like

1. **A normative sentence** on whether a core peer resolves handlers for foreign-namespace
   URIs — in §5.2 beside `extract_peer`, or in §6.6 beside handler resolution.
2. **If the minority reading is correct:** confirmation that the refusal is `403
   capability_denied` via §5.2, not `404 handler_not_found`, so the disposition is pinned
   too. We would then propagate the fix to 40 peers — a known quantity, roughly the CAP
   propagation's shape.
3. **If the majority reading is correct:** we would like §3.6's *"defaults to local peer
   only"* to say what that default is for, since under this reading it can never deny
   anything on a single peer; and the 6 PASS peers need the gate added. It would also be
   worth knowing whether the dimension is intended to become live only under RELAY or a
   dispatch-forwarding deployment, which would make this a correctly-deferred surface
   rather than an ambiguous one.

## How this was found, and the process lesson we are keeping

This sat in `CONFORMANCE-MATRIX.md` §3 for two weeks as:

> **`authz_peers_target_from_uri`** — WARN on every peer | all | Low — inconclusive by
> design | A single standalone peer cannot resolve `target_peer` against a synthetic foreign
> URI; needs a real two-peer harness to exercise. Not attempted since it was found
> 2026-08-16.

Every clause of that is wrong. It is not every peer (40 of 46). It is not inconclusive — six
peers return a full verdict. And a two-peer harness was never needed. **The entry was an
exculpation we wrote about ourselves and then never re-checked**, and it survived because
nobody diffed the check's severity across the cohort — the same one-command move that has
repeatedly been the highest-yield diagnostic in this repo. Our standing rule was *"verify a
routed claim before acting on it, especially the exculpatory half"*; the gap was that it
only ever pointed at **inbound** claims. It is now ratcheted to cover our own.

---

*Drafted in this repo per the no-cross-repo-writes boundary. Architecture pulls this in on its own
schedule. Registered as **F51** in `research/stewardship/SPEC-FINDINGS-LOG.md`.*

*Filed here rather than in `research/stewardship/` deliberately: the register that indexes this
finding is a declared canonical document and PUBLISHES, while `research/**` is stripped at release.
An index whose evidence is deleted from the public tree is a documented failure mode of this repo,
and `protocol-generator/**` publishes with no declaration at all. Companion to
`peers-grant-dimension-oracle-gap.md` (2026-08-13), which closed the oracle-coverage half of this
dimension; this is the reachability half that one exposed.*
