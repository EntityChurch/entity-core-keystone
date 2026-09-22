# HANDOFF TO ARCH — the §5.2 `peers` dimension is unreachable in 40 of 46 peers

**Date:** 2026-08-30
**From:** entity-core-keystone
**Spec snapshot:** `v0.8.2` (`ENTITY-CORE-PROTOCOL.md` `4be521f7…`)
**Oracle:** the 755-check set, `core_executed_check_set_digest = 95edd774…`
**Check:** `authz/authz_peers_target_from_uri`
**Status:** open question — **not** a peer defect, and deliberately not fixed here

---

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
